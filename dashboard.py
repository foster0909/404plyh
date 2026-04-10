#!/usr/bin/env python3
"""
Recon Engine — Dashboard Server v2

Multi-target project explorer + scan runner.
Zero external dependencies — stdlib only.

Usage:
    python3 dashboard.py                         # projects dir = ./
    python3 dashboard.py -p ~/projects/          # custom projects dir
    python3 dashboard.py -p ~/projects/ -P 8888  # custom port

Then open http://<your-pi-ip>:9090 in any browser on your network.
"""

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import unquote, parse_qs, urlparse

SCRIPT_DIR = Path(__file__).resolve().parent
DASHBOARD_HTML = SCRIPT_DIR / "dashboard.html"
DASHBOARD_JS = SCRIPT_DIR / "dashboard.js"
RECON_SCRIPT = SCRIPT_DIR / "recon_engine.sh"
MONITOR_SCRIPT = SCRIPT_DIR / "monitor.sh"

# ── Scan manager (one scan at a time) ────────────────────────────────────────

class ScanManager:
    def __init__(self, projects_dir):
        self.projects_dir = Path(projects_dir).resolve()
        self.lock = threading.Lock()
        self.process = None
        self.domain = None
        self.log_path = None
        self.started_at = None
        self.finished = False

    def is_running(self):
        with self.lock:
            if self.process is None:
                return False
            ret = self.process.poll()
            if ret is not None:
                self.finished = True
                return False
            return True

    def start(self, domain, skip_modules=None, threads=None, rate=None, top_ports=None, custom_cmd=None):
        if self.is_running():
            return False, "A scan is already running"

        with self.lock:
            self.domain = domain
            self.finished = False
            output_dir = self.projects_dir / domain
            output_dir.mkdir(parents=True, exist_ok=True)

            if custom_cmd:
                cmd = custom_cmd
            else:
                cmd = ["bash", str(RECON_SCRIPT), "-d", domain, "-o", str(output_dir)]

                if threads:
                    cmd += ["-t", str(threads)]
                if rate:
                    cmd += ["--rate", str(rate)]
                if top_ports:
                    cmd += ["--top-ports", str(top_ports)]

                for mod in (skip_modules or []):
                    flag = f"--skip-{mod}"
                    cmd.append(flag)

            # Log to a file we can tail
            log_dir = output_dir / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)
            ts = time.strftime("%Y%m%d_%H%M%S")
            self.log_path = log_dir / f"scan_{ts}.log"

            log_fh = open(self.log_path, "w")
            self.process = subprocess.Popen(
                cmd,
                stdout=log_fh,
                stderr=subprocess.STDOUT,
                cwd=str(self.projects_dir),
                preexec_fn=os.setsid,  # own process group for clean kill
            )
            self.started_at = time.time()
            return True, f"Scan started for {domain} (PID {self.process.pid})"

    def stop(self):
        with self.lock:
            if self.process and self.process.poll() is None:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                self.process.wait(timeout=5)
                self.finished = True
                return True, "Scan stopped"
            return False, "No scan running"

    def status(self):
        running = self.is_running()
        result = {
            "running": running,
            "domain": self.domain,
            "started_at": self.started_at,
            "finished": self.finished,
            "log_tail": [],
        }
        if self.log_path and self.log_path.exists():
            try:
                with open(self.log_path, "r", errors="replace") as f:
                    lines = f.readlines()
                    result["log_tail"] = [l.rstrip() for l in lines[-80:]]
            except Exception:
                pass
        if running and self.started_at:
            result["elapsed"] = int(time.time() - self.started_at)
        return result


# ── Monitor config persistence ───────────────────────────────────────────────

def get_monitor_config_path(projects_dir):
    return Path(projects_dir).resolve() / ".monitor_config.json"

def load_monitor_config(projects_dir):
    p = get_monitor_config_path(projects_dir)
    if p.exists():
        try:
            with open(p) as f:
                return json.load(f)
        except Exception:
            pass
    return {"enabled_targets": []}

def save_monitor_config(projects_dir, config):
    p = get_monitor_config_path(projects_dir)
    with open(p, "w") as f:
        json.dump(config, f, indent=2)


# ── Helpers ──────────────────────────────────────────────────────────────────

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def count_lines(filepath):
    try:
        with open(filepath, "r", errors="replace") as f:
            return sum(1 for line in f if line.strip())
    except FileNotFoundError:
        return 0


def count_screenshots(ss_dir):
    try:
        return len([
            f for f in os.listdir(ss_dir)
            if f.lower().endswith((".png", ".jpg", ".jpeg"))
        ])
    except FileNotFoundError:
        return 0


def is_recon_dir(path):
    """Check if a directory looks like recon output (has at least one expected subdir)."""
    expected = {"subs", "dns", "httpx", "ports", "js", "endpoints", "infra",
                "screenshots", "historical", "reports", "logs"}
    if not path.is_dir():
        return False
    children = {c.name for c in path.iterdir() if c.is_dir()}
    return bool(children & expected)


def build_stats(target_dir):
    d = Path(target_dir)
    summary = {}
    summary_path = d / "reports" / "summary.json"
    if summary_path.exists():
        try:
            with open(summary_path) as f:
                summary = json.load(f)
        except Exception:
            pass

    # Get last modified time
    try:
        mtime = max(
            f.stat().st_mtime
            for f in d.rglob("*")
            if f.is_file()
        )
    except (ValueError, OSError):
        mtime = 0

    return {
        "domain": summary.get("target", d.name.replace("recon_", "")),
        "scan_date": summary.get("scan_date", ""),
        "last_modified": mtime,
        "output_dir": str(d),
        "statistics": {
            "total_subdomains": count_lines(d / "subs" / "all.txt"),
            "resolved_hosts": count_lines(d / "dns" / "resolved.txt"),
            "alive_services": count_lines(d / "httpx" / "alive.txt"),
            "screenshots": count_screenshots(d / "screenshots"),
            "open_ports": count_lines(d / "ports" / "naabu.txt"),
            "js_endpoints": count_lines(d / "js" / "endpoints.txt"),
            "historical_urls": count_lines(d / "historical" / "all_urls.txt"),
            "crawled_endpoints": count_lines(d / "endpoints" / "all.txt"),
            "dork_findings": count_lines(d / "dorks" / "all_findings.txt"),
        },
    }


def list_targets(projects_dir):
    """List all target directories with quick stats."""
    projects = Path(projects_dir).resolve()
    monitor_cfg = load_monitor_config(projects_dir)
    targets = []
    for child in sorted(projects.iterdir()):
        if child.is_dir() and not child.name.startswith(".") and is_recon_dir(child):
            stats = build_stats(child)
            targets.append({
                "name": child.name,
                "domain": stats["domain"],
                "scan_date": stats["scan_date"],
                "last_modified": stats["last_modified"],
                "stats": stats["statistics"],
                "monitor_enabled": child.name in monitor_cfg.get("enabled_targets", []),
            })
    return targets


# ── HTTP Handler ─────────────────────────────────────────────────────────────

def make_handler(projects_dir, scan_manager):
    projects_path = Path(projects_dir).resolve()

    class DashboardHandler(SimpleHTTPRequestHandler):
        def log_message(self, fmt, *args):
            sys.stderr.write(f"  \033[0;36m{args[0]}\033[0m {args[1]}\n")

        def send_json(self, data, status=200):
            body = json.dumps(data, indent=2).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(body))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)

        def send_text(self, text, status=200):
            body = text.encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", len(body))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)

        def send_file_data(self, filepath, content_type=None):
            try:
                with open(filepath, "rb") as f:
                    data = f.read()
            except FileNotFoundError:
                self.send_json({"error": "File not found"}, 404)
                return

            if content_type is None:
                ext = Path(filepath).suffix.lower()
                content_type = {
                    ".html": "text/html",
                    ".json": "application/json",
                    ".txt": "text/plain",
                    ".png": "image/png",
                    ".jpg": "image/jpeg",
                    ".jpeg": "image/jpeg",
                    ".svg": "image/svg+xml",
                    ".xml": "text/xml",
                    ".nmap": "text/plain",
                    ".gnmap": "text/plain",
                }.get(ext, "application/octet-stream")

            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", len(data))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(data)

        def read_body(self):
            length = int(self.headers.get("Content-Length", 0))
            if length == 0:
                return {}
            try:
                return json.loads(self.rfile.read(length))
            except Exception:
                return {}

        def resolve_target_path(self, target, rel_path=""):
            """Resolve a path within a target dir, with traversal protection."""
            target_dir = (projects_path / target).resolve()
            if not str(target_dir).startswith(str(projects_path)):
                return None
            if rel_path:
                full = (target_dir / rel_path).resolve()
                if not str(full).startswith(str(target_dir)):
                    return None
                return full
            return target_dir

        def do_GET(self):
            parsed = urlparse(self.path)
            path = unquote(parsed.path)
            qs = parse_qs(parsed.query)

            # ─── Dashboard HTML ───
            if path == "/" or path == "/index.html":
                self.send_file_data(DASHBOARD_HTML, "text/html; charset=utf-8")
                return

            # ─── Dashboard JS ───
            if path == "/dashboard.js":
                self.send_file_data(DASHBOARD_JS, "application/javascript; charset=utf-8")
                return

            # ─── API: List all targets ───
            if path == "/api/targets":
                self.send_json({"targets": list_targets(projects_path)})
                return

            # ─── API: Stats for a target ───
            if path == "/api/stats":
                target = qs.get("target", [None])[0]
                if not target:
                    self.send_json({"error": "target param required"}, 400)
                    return
                target_dir = self.resolve_target_path(target)
                if not target_dir or not target_dir.is_dir():
                    self.send_json({"error": "Target not found"}, 404)
                    return
                self.send_json(build_stats(target_dir))
                return

            # ─── API: Read file within a target ───
            if path.startswith("/api/file/"):
                rest = path[len("/api/file/"):]
                parts = rest.split("/", 1)
                if len(parts) < 2:
                    self.send_json({"error": "Invalid path"}, 400)
                    return
                target, rel = parts[0], parts[1]
                resolved = self.resolve_target_path(target, rel)
                if not resolved:
                    self.send_json({"error": "Access denied"}, 403)
                    return
                if not resolved.exists():
                    self.send_text("", 200)
                    return
                self.send_file_data(resolved)
                return

            # ─── API: List screenshots ───
            if path == "/api/screenshots":
                target = qs.get("target", [None])[0]
                if not target:
                    self.send_json({"files": []})
                    return
                ss_dir = self.resolve_target_path(target, "screenshots")
                files = []
                if ss_dir and ss_dir.exists():
                    files = sorted([
                        f for f in os.listdir(ss_dir)
                        if f.lower().endswith((".png", ".jpg", ".jpeg"))
                    ])
                self.send_json({"files": files})
                return

            # ─── Serve screenshot images ───
            if path.startswith("/screenshots/"):
                rest = path[len("/screenshots/"):]
                parts = rest.split("/", 1)
                if len(parts) < 2:
                    self.send_json({"error": "Invalid path"}, 400)
                    return
                target, filename = parts
                resolved = self.resolve_target_path(target, f"screenshots/{filename}")
                if not resolved:
                    self.send_json({"error": "Access denied"}, 403)
                    return
                self.send_file_data(resolved)
                return

            # ─── API: Scan status ───
            if path == "/api/scan/status":
                self.send_json(scan_manager.status())
                return

            # ─── API: Available modules ───
            if path == "/api/modules":
                self.send_json({"modules": [
                    {"id": "subdomains", "label": "Subdomain Discovery"},
                    {"id": "dns", "label": "DNS Resolution"},
                    {"id": "http", "label": "HTTP Probing"},
                    {"id": "screenshots", "label": "Screenshots"},
                    {"id": "ports", "label": "Port Scanning"},
                    {"id": "js", "label": "JavaScript Analysis"},
                    {"id": "historical", "label": "Historical URLs"},
                    {"id": "crawl", "label": "Endpoint Crawling"},
                    {"id": "dorks", "label": "Dork-Style Discovery"},
                    {"id": "infra", "label": "Infrastructure Mapping"},
                    {"id": "report", "label": "Report Generation"},
                ]})
                return

            # ─── API: Monitor — list change records ───
            if path == "/api/monitor/changes":
                target = qs.get("target", [None])[0]
                if not target:
                    self.send_json({"error": "target param required"}, 400)
                    return
                changes_dir = self.resolve_target_path(target, "monitor/changes")
                records = []
                if changes_dir and changes_dir.is_dir():
                    for f in sorted(changes_dir.glob("*.json"), reverse=True):
                        try:
                            with open(f) as fh:
                                data = json.load(fh)
                                data["_filename"] = f.name
                                records.append(data)
                        except Exception:
                            pass
                self.send_json({"changes": records})
                return

            # ─── API: Monitor — specific change record ───
            if path.startswith("/api/monitor/changes/"):
                rest = path[len("/api/monitor/changes/"):]
                parts = rest.split("/", 1)
                if len(parts) < 2:
                    self.send_json({"error": "Invalid path"}, 400)
                    return
                target, filename = parts
                resolved = self.resolve_target_path(target, f"monitor/changes/{filename}")
                if not resolved or not resolved.exists():
                    self.send_json({"error": "Not found"}, 404)
                    return
                self.send_file_data(resolved, "application/json")
                return

            # ─── API: Monitor — status / baseline info ───
            if path == "/api/monitor/status":
                target = qs.get("target", [None])[0]
                if not target:
                    self.send_json({"error": "target param required"}, 400)
                    return
                baselines_dir = self.resolve_target_path(target, "monitor/baselines")
                changes_dir = self.resolve_target_path(target, "monitor/changes")
                result = {
                    "has_baselines": False,
                    "baseline_subdomains": 0,
                    "baseline_ports": 0,
                    "total_changes": 0,
                    "last_check": None,
                }
                if baselines_dir and baselines_dir.is_dir():
                    subs_file = baselines_dir / "subdomains.txt"
                    ports_file = baselines_dir / "ports.txt"
                    result["has_baselines"] = subs_file.exists() or ports_file.exists()
                    result["baseline_subdomains"] = count_lines(subs_file) if subs_file.exists() else 0
                    result["baseline_ports"] = count_lines(ports_file) if ports_file.exists() else 0
                if changes_dir and changes_dir.is_dir():
                    change_files = sorted(changes_dir.glob("*.json"), reverse=True)
                    result["total_changes"] = len(change_files)
                    if change_files:
                        try:
                            result["last_check"] = change_files[0].stat().st_mtime
                        except OSError:
                            pass
                self.send_json(result)
                return

            # ─── Fallback ───
            self.send_json({"error": "Not found"}, 404)

        def do_POST(self):
            parsed = urlparse(self.path)
            path = unquote(parsed.path)

            # ─── API: Start scan ───
            if path == "/api/scan/start":
                body = self.read_body()
                domain = body.get("domain", "").strip()
                if not domain:
                    self.send_json({"error": "domain is required"}, 400)
                    return
                skip = body.get("skip", [])
                threads = body.get("threads")
                rate = body.get("rate")
                top_ports = body.get("top_ports")
                ok, msg = scan_manager.start(domain, skip, threads, rate, top_ports)
                self.send_json({"ok": ok, "message": msg}, 200 if ok else 409)
                return

            # ─── API: Stop scan ───
            if path == "/api/scan/stop":
                ok, msg = scan_manager.stop()
                self.send_json({"ok": ok, "message": msg})
                return

            # ─── API: Start monitor scan ───
            if path == "/api/monitor/start":
                body = self.read_body()
                domain = body.get("domain", "").strip()
                if not domain:
                    self.send_json({"error": "domain is required"}, 400)
                    return
                init = body.get("init", False)
                threads = body.get("threads")
                rate = body.get("rate")
                top_ports = body.get("top_ports")

                target_dir = projects_path / domain
                cmd = ["bash", str(MONITOR_SCRIPT), "-d", domain, "-o", str(target_dir)]
                if init:
                    cmd.append("--init")
                if threads:
                    cmd += ["-t", str(threads)]
                if rate:
                    cmd += ["--rate", str(rate)]
                if top_ports:
                    cmd += ["--top-ports", str(top_ports)]

                ok, msg = scan_manager.start(
                    domain, skip_modules=None, threads=threads,
                    rate=rate, top_ports=top_ports,
                    custom_cmd=cmd
                )
                self.send_json({"ok": ok, "message": msg}, 200 if ok else 409)
                return

            # ─── API: Toggle monitor for a target ───
            if path == "/api/monitor/toggle":
                body = self.read_body()
                target = body.get("target", "").strip()
                enabled = body.get("enabled", True)
                if not target:
                    self.send_json({"error": "target is required"}, 400)
                    return
                cfg = load_monitor_config(projects_path)
                targets_list = cfg.get("enabled_targets", [])
                if enabled and target not in targets_list:
                    targets_list.append(target)
                elif not enabled and target in targets_list:
                    targets_list.remove(target)
                cfg["enabled_targets"] = targets_list
                save_monitor_config(projects_path, cfg)
                self.send_json({"ok": True, "enabled": enabled, "target": target})
                return

            # ─── API: Get monitor config ───
            if path == "/api/monitor/config":
                cfg = load_monitor_config(projects_path)
                self.send_json(cfg)
                return

            self.send_json({"error": "Not found"}, 404)

        def do_OPTIONS(self):
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()

    return DashboardHandler


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Recon Engine — Dashboard Server"
    )
    parser.add_argument(
        "-p", "--projects-dir", default=".",
        help="Path to the projects directory containing target folders (default: current dir)"
    )
    parser.add_argument(
        "-P", "--port", type=int, default=9090,
        help="Port to serve on (default: 9090)"
    )
    parser.add_argument(
        "--bind", default="0.0.0.0",
        help="Address to bind to (default: 0.0.0.0 — all interfaces)"
    )
    args = parser.parse_args()

    projects_dir = Path(args.projects_dir).resolve()
    if not projects_dir.is_dir():
        print(f"\033[0;31m[✗]\033[0m Directory not found: {projects_dir}")
        sys.exit(1)

    if not DASHBOARD_HTML.exists():
        print(f"\033[0;31m[✗]\033[0m dashboard.html not found at: {DASHBOARD_HTML}")
        sys.exit(1)

    scan_mgr = ScanManager(projects_dir)
    handler = make_handler(projects_dir, scan_mgr)
    server = HTTPServer((args.bind, args.port), handler)

    local_ip = get_local_ip()
    existing = list_targets(projects_dir)

    print()
    print("\033[0;36m  ╔══════════════════════════════════════════════════════╗\033[0m")
    print("\033[0;36m  ║\033[0m        \033[1mRecon Engine — Dashboard Server v2\033[0m           \033[0;36m║\033[0m")
    print("\033[0;36m  ╚══════════════════════════════════════════════════════╝\033[0m")
    print()
    print(f"  \033[0;34m[*]\033[0m Projects dir: \033[1m{projects_dir}\033[0m")
    print(f"  \033[0;34m[*]\033[0m Targets found: \033[1m{len(existing)}\033[0m")
    print(f"  \033[0;34m[*]\033[0m Listening:     \033[1m{args.bind}:{args.port}\033[0m")
    print()
    print(f"  \033[0;32m[+]\033[0m Dashboard:     \033[1;36mhttp://{local_ip}:{args.port}\033[0m")
    if args.bind == "0.0.0.0":
        print(f"  \033[0;32m[+]\033[0m Local:         \033[1;36mhttp://localhost:{args.port}\033[0m")
    print()
    print("  \033[0;90mPress Ctrl+C to stop\033[0m")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  \033[0;33m[!]\033[0m Shutting down...")
        scan_mgr.stop()
        server.server_close()


if __name__ == "__main__":
    main()
