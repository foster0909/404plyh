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
import gzip
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from collections import OrderedDict, deque
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import unquote, parse_qs, urlparse

from db import ReconDB, categorize_url, STATIC_EXTS

def get_target_db(target_dir):
    db_path = Path(target_dir) / 'recon.db'
    db = ReconDB(str(db_path))
    return db

SCRIPT_DIR = Path(__file__).resolve().parent

# Response tuning: gzip bodies in this size range; stream files larger than
# _GZIP_MAX in chunks instead of loading them into memory.
_GZIP_MIN = 1024
_GZIP_MAX = 16 * 1024 * 1024
_STREAM_CHUNK = 256 * 1024
DASHBOARD_HTML = SCRIPT_DIR / "dashboard.html"
DASHBOARD_JS = SCRIPT_DIR / "dashboard.js"
RECON_SCRIPT = SCRIPT_DIR / "recon_engine.sh"
MONITOR_SCRIPT = SCRIPT_DIR / "monitor.sh"

# ── Agent (triage-results skill) runs ────────────────────────────────────────
# Launching the triage skill runs an AI agent that makes outbound requests to
# targets, so it is OFF by default and must be explicitly enabled at startup
# (E=1, or lowercase e=1). This is deliberately a separate, stronger gate than a
# recon scan. The command is overridable for non-default CLI installs.
#
# The default passes a scoped --allowedTools rather than bypassing all permission
# checks: the headless agent gets exactly the tools the skill needs (shell for
# curl/sqlite, file read/write for the report, web fetch) and anything else is
# auto-denied instead of hanging on an unanswerable prompt. The skill also
# carries its own scope/rate/read-only guardrails. Override TRIAGE_AGENT_ARGS to
# widen/narrow this for your install.
def _envflag(name):
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")

ENABLE_AGENT_RUNS = _envflag("E") or _envflag("e")
CLAUDE_BIN = os.environ.get("CLAUDE_BIN", "claude")
TRIAGE_AGENT_ARGS = os.environ.get(
    "TRIAGE_AGENT_ARGS", "--allowedTools Bash Read Write WebFetch"
).split()

# ── Scan manager (one scan at a time) ────────────────────────────────────────

# Canonical pipeline stages, in run order. `key` matches the TIMING/timing.jsonl
# stage names emitted by recon_engine's stage() wrapper; `header` is a substring
# of the module banner printed to the log; `label` is for display. Progress is
# derived from these so the UI and the engine never drift.
PIPELINE_STAGES = [
    ("subdomains",         "Subdomain Discovery",          "Subdomain Discovery"),
    ("dns",                "DNS Resolution",               "DNS Resolution"),
    ("http",               "HTTP Probing",                 "HTTP Service Discovery"),
    ("screenshots",        "Screenshots",                  "Visual Surface Mapping"),
    ("ports",              "Port Scanning",                "Network Service Enumeration"),
    ("js",                 "JS Analysis",                  "JavaScript Deep Intelligence"),
    ("historical",         "Historical URLs",              "Historical Surface Discovery"),
    ("crawl",              "Endpoint Crawling",            "Endpoint & Path Enumeration"),
    ("dorks",              "Dork Discovery",               "Dork-Style Sensitive File"),
    ("validate_historical","Historical Validation",        "Historical URL Validation"),
    ("infra",              "Infrastructure Mapping",       "Asset & Infrastructure Mapping"),
    ("report",             "Report Generation",            "Report Generation"),
]

# Canonical triage phases, in run order. A triage run is an AI agent, not the
# recon engine, so it does not emit `Module N:` banners. Instead the triage
# skill echoes a `TRIAGE PHASE: <header>` marker line at the start of each phase;
# `_progress_from_log` matches those headers here to drive the same UI tracker.
# Keep these headers in sync with the markers the skill prints.
TRIAGE_STAGES = [
    ("preflight",  "Preflight",            "Preflight"),
    ("load",       "Load & orient",        "Load & orient"),
    ("prune",      "Prune & budget",       "Prune & budget"),
    ("validate",   "Live validation",      "Live validation"),
    ("chain",      "Chain signals",        "Chain signals"),
    ("writeback",  "Write-back & report",  "Write-back & report"),
]
_ANSI_RE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

# A scan/monitor domain is passed to the engine as argv and used as the output
# directory name, so it must be a plain hostname (no "/", "..", leading "-").
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$",
    re.IGNORECASE)


def valid_domain(domain):
    return bool(domain) and bool(_DOMAIN_RE.match(domain)) and not domain[-1] == "-"


class ScanManager:
    """Runs recon/monitor subprocesses, several targets concurrently.

    Each target gets at most one active run; a configurable cap bounds how many
    run at once. Completed runs are retained in memory for the session so the
    Explorer can show recent history; full scans are auto-ingested into SQLite
    from each run's watcher thread on exit.
    """

    def __init__(self, projects_dir, max_concurrent=None):
        self.projects_dir = Path(projects_dir).resolve()
        self.lock = threading.Lock()
        self.runs = {}            # target -> run dict
        self._log_lock = threading.Lock()
        self._log_state = {}      # log path -> incremental parse state
        try:
            self.max_concurrent = int(max_concurrent or os.environ.get("MAX_CONCURRENT_SCANS", 3))
        except (TypeError, ValueError):
            self.max_concurrent = 3
        if self.max_concurrent < 1:
            self.max_concurrent = 1

    # ── internal helpers ──
    def _run_alive(self, run):
        return run and run["process"] is not None and run["process"].poll() is None

    def _active_count(self):
        return sum(1 for r in self.runs.values() if self._run_alive(r))

    def is_running(self, target=None):
        with self.lock:
            if target is not None:
                return self._run_alive(self.runs.get(target))
            return self._active_count() > 0

    def active_count(self):
        with self.lock:
            return self._active_count()

    def start(self, domain, skip_modules=None, threads=None, rate=None,
              top_ports=None, custom_cmd=None, kind="scan",
              http_rate=None, active_rate=None, headers=None, target=None):
        target = target or domain
        with self.lock:
            if self._run_alive(self.runs.get(target)):
                return False, f"A run is already in progress for {target}"
            if self._active_count() >= self.max_concurrent:
                return False, (f"Max concurrent runs reached ({self.max_concurrent}). "
                               "Wait for one to finish or stop it.")

            output_dir = self.projects_dir / target
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
                if http_rate:
                    cmd += ["--http-rate", str(http_rate)]
                if active_rate:
                    cmd += ["--active-rate", str(active_rate)]
                # Custom headers: one --header per non-empty line. Passed as
                # discrete argv entries (no shell), so values can't inject.
                for hline in (headers or []):
                    hline = (hline or "").strip()
                    if hline:
                        cmd += ["--header", hline]
                for mod in (skip_modules or []):
                    cmd.append(f"--skip-{mod}")

            log_dir = output_dir / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)
            ts = time.strftime("%Y%m%d_%H%M%S")
            log_path = log_dir / f"scan_{ts}.log"

            log_fh = open(log_path, "w", buffering=1)
            proc = subprocess.Popen(
                cmd, stdout=log_fh, stderr=subprocess.STDOUT,
                cwd=str(self.projects_dir), preexec_fn=os.setsid,
            )
            run = {
                "target": target, "domain": domain, "kind": kind,
                "process": proc, "log_path": log_path,
                "started_at": time.time(), "finished": False,
                "finished_at": None, "returncode": None, "pid": proc.pid,
            }
            self.runs[target] = run

        watcher = threading.Thread(target=self._watch, args=(run, log_fh), daemon=True)
        watcher.start()
        return True, f"{kind.capitalize()} started for {target} (PID {proc.pid})"

    def _watch(self, run, log_fh):
        proc = run["process"]
        try:
            proc.wait()
        finally:
            try:
                log_fh.close()
            except Exception:
                pass
        with self.lock:
            run["finished"] = True
            run["finished_at"] = time.time()
            run["returncode"] = proc.returncode
        if run["kind"] == "scan":
            self._ingest(run["domain"], run["target"])
        elif run["kind"] == "triage":
            # The skill writes verdicts via /api/finding/state (already
            # invalidates), but refresh once more so the queue reflects the
            # finished run even if the last write raced the watcher.
            try:
                finding_summaries.invalidate(self.projects_dir / run["target"])
            except Exception:
                pass

    def _ingest(self, domain, target=None):
        target_dir = self.projects_dir / (target or domain)
        if not target_dir.is_dir():
            return
        try:
            db = get_target_db(target_dir)
            db.ingest_scan(str(target_dir))
            db.close()
            finding_summaries.invalidate(target_dir)
        except Exception as e:
            sys.stderr.write(f"Auto-ingest failed for {target or domain}: {e}\n")

    def stop(self, target=None):
        with self.lock:
            if target is None:
                alive = [t for t, r in self.runs.items() if self._run_alive(r)]
                if len(alive) == 1:
                    target = alive[0]
                elif len(alive) == 0:
                    return False, "No run in progress"
                else:
                    return False, "Multiple runs active — specify a target to stop"
            run = self.runs.get(target)
            if not self._run_alive(run):
                return False, f"No run in progress for {target}"
            try:
                os.killpg(os.getpgid(run["process"].pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
        # Wait outside the lock so progress polls aren't blocked meanwhile.
        try:
            run["process"].wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        with self.lock:
            run["finished"] = True
            run["finished_at"] = run["finished_at"] or time.time()
        return True, f"Run stopped for {target}"

    def _progress_from_log(self, log_path, kind="scan"):
        """Return (current_step, progress_percent, log_tail) parsed from a log.

        Incremental: per log file we remember the byte offset, the last stage
        seen and an 80-line tail, and only parse bytes appended since the last
        poll (the UI polls every couple of seconds while a scan runs).

        A scan log is driven by the recon engine's `Module N:` banners against
        PIPELINE_STAGES; a triage log is driven by the agent's
        `TRIAGE PHASE: <header>` markers against TRIAGE_STAGES.
        """
        if not log_path:
            return "Initializing", 0, []
        stages = TRIAGE_STAGES if kind == "triage" else PIPELINE_STAGES
        key = str(log_path)
        try:
            size = os.path.getsize(key)
        except OSError:
            return "Initializing", 0, []
        with self._log_lock:
            st = self._log_state.get(key)
            if st is None or size < st["offset"]:
                st = {"offset": 0, "step": "Initializing", "pct": 0,
                      "tail": deque(maxlen=80), "partial": b""}
                self._log_state[key] = st
                while len(self._log_state) > 32:
                    self._log_state.pop(next(iter(self._log_state)))
            if size > st["offset"]:
                try:
                    with open(key, "rb") as f:
                        f.seek(st["offset"])
                        data = f.read(size - st["offset"])
                    st["offset"] = size
                    data = st["partial"] + data
                    lines = data.split(b"\n")
                    st["partial"] = lines.pop()  # incomplete last line
                    total = len(stages)
                    for raw in lines:
                        line = raw.decode("utf-8", "replace").rstrip()
                        st["tail"].append(line)
                        clean = _ANSI_RE.sub('', line)
                        if kind == "triage" and "TRIAGE PHASE:" in clean:
                            m = re.search(r'TRIAGE PHASE:\s*([^\r\n]+)', clean)
                            if m:
                                st["step"] = m.group(1).strip()
                                for i, (_k, _lbl, hdr) in enumerate(stages):
                                    if hdr in st["step"]:
                                        st["pct"] = int((i + 1) / total * 100)
                                        break
                        elif kind != "triage" and "Module" in line:
                            m = re.search(r'Module\s*(?:\d+)?:\s*([^\r\n]+)', clean)
                            if m:
                                st["step"] = m.group(1).strip()
                                for i, (_k, _lbl, hdr) in enumerate(stages):
                                    if hdr in st["step"]:
                                        st["pct"] = int((i + 1) / total * 100)
                                        break
                except OSError:
                    pass
            tail = list(st["tail"])
            if st["partial"]:
                tail = (tail + [st["partial"].decode("utf-8", "replace").rstrip()])[-80:]
            return st["step"], st["pct"], tail

    def status(self, target=None):
        """Status of one run (target given) or the most relevant run otherwise.

        Kept backwards-compatible: with no target it returns the single active
        run, else the most recently started one.
        """
        with self.lock:
            run = None
            if target is not None:
                run = self.runs.get(target)
            else:
                active = [r for r in self.runs.values() if self._run_alive(r)]
                pool = active or list(self.runs.values())
                if pool:
                    run = max(pool, key=lambda r: r["started_at"])
            if run is None:
                return {"running": False, "domain": None, "kind": None,
                        "started_at": None, "finished": False, "log_tail": [],
                        "current_step": "Initializing", "progress_percent": 0}
            running = self._run_alive(run)
            log_path, started_at = run["log_path"], run["started_at"]
            result = {
                "running": running, "domain": run["domain"], "target": run["target"],
                "kind": run["kind"], "started_at": started_at,
                "finished": run["finished"], "returncode": run["returncode"],
            }
        step, pct, tail = self._progress_from_log(log_path, result["kind"])
        result.update(current_step=step, progress_percent=pct, log_tail=tail)
        if started_at:
            end = time.time() if result["running"] else (run["finished_at"] or time.time())
            result["elapsed"] = int(end - started_at)
        return result

    def list_runs(self):
        """Summary of every in-session run (active + finished), newest first."""
        with self.lock:
            runs = sorted(self.runs.values(), key=lambda r: r["started_at"], reverse=True)
            snap = [(r["target"], r["domain"], r["kind"], r["log_path"],
                     r["started_at"], r["finished_at"], self._run_alive(r),
                     r["returncode"]) for r in runs]
        out = []
        for target, domain, kind, log_path, started, finished_at, alive, rc in snap:
            step, pct, _tail = self._progress_from_log(log_path, kind)
            end = time.time() if alive else (finished_at or time.time())
            out.append({
                "target": target, "domain": domain, "kind": kind,
                "running": alive, "started_at": started,
                "elapsed": int(end - started) if started else 0,
                "current_step": step if alive else ("Done" if rc == 0 else step),
                "progress_percent": 100 if (not alive and rc == 0) else pct,
                "returncode": rc,
            })
        return out

    def progress(self, target_dir, running=False, started_at=None):
        """Detailed stage timeline for a target, from disk (works post-restart).

        Reads reports/timing.jsonl for completed-stage durations and the latest
        logs/scan_*.log for the current stage + a log tail, so a run can be
        inspected while live or long after it finished.
        """
        target_dir = Path(target_dir)
        timings = {}
        tf = target_dir / "reports" / "timing.jsonl"
        if tf.exists():
            try:
                with open(tf, "r", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            o = json.loads(line)
                            if o.get("stage"):
                                timings[o["stage"]] = o.get("seconds")
                        except Exception:
                            continue
            except OSError:
                pass

        logs = sorted((target_dir / "logs").glob("scan_*.log")) if (target_dir / "logs").is_dir() else []
        log_path = logs[-1] if logs else None
        step, pct, tail = self._progress_from_log(log_path)

        # Match the current log stage back to a canonical key.
        current_key = None
        for k, _lbl, hdr in PIPELINE_STAGES:
            if hdr in step:
                current_key = k
                break

        stages = []
        seen_current = False
        for k, lbl, _hdr in PIPELINE_STAGES:
            if k in timings:
                st = "done"
            elif running and k == current_key and not seen_current:
                st = "active"; seen_current = True
            else:
                st = "pending"
            stages.append({"key": k, "label": lbl, "status": st,
                           "seconds": timings.get(k)})
        return {
            "stages": stages, "current_step": step,
            "progress_percent": 100 if (not running and (target_dir / "reports" / "timing.jsonl").exists() and current_key == "report") else pct,
            "log_tail": tail, "running": running,
        }


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
    """Non-empty line count (binary mode: no decoding, much faster on big files)."""
    try:
        with open(filepath, "rb") as f:
            return sum(1 for line in f if line.strip())
    except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
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


def shallow_signature(target_dir):
    """A cheap change-signature for a target dir, avoiding a full tree walk.

    Combines the target dir's own mtime, each immediate child's mtime (directory
    mtimes change when files are added/removed inside them, which is how the
    recon pipeline writes output), and the summary.json mtime (changes each
    scan). Good enough to invalidate the stats cache without rglob()'ing the
    whole tree on every /api/targets request.
    """
    d = Path(target_dir)
    sig = []
    try:
        sig.append(("", d.stat().st_mtime))
    except OSError:
        return None
    try:
        for child in d.iterdir():
            try:
                sig.append((child.name, child.stat().st_mtime))
            except OSError:
                continue
    except OSError:
        pass
    return tuple(sorted(sig))


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

    # Last-modified is derived from the cheap shallow signature rather than a
    # full rglob() of the tree (which was O(files) on every targets listing).
    sig = shallow_signature(d)
    mtime = max((m for _, m in sig), default=0) if sig else 0

    return {
        "domain": summary.get("target", d.name.replace("recon_", "")),
        "scan_date": summary.get("scan_date", ""),
        "last_modified": mtime,
        "output_dir": str(d),
        "statistics": {
            "total_subdomains": cached_line_count(d / "subs" / "all.txt"),
            "resolved_hosts": cached_line_count(d / "dns" / "resolved.txt"),
            "alive_services": cached_line_count(d / "httpx" / "alive.txt"),
            "screenshots": count_screenshots(d / "screenshots"),
            "open_ports": cached_line_count(d / "ports" / "naabu.txt"),
            "js_endpoints": cached_line_count(d / "js" / "endpoints.txt"),
            "js_secrets": cached_line_count(d / "js" / "secrets.txt"),
            "js_scripts": cached_line_count(d / "js" / "scripts_alive.txt"),
            "js_leakage": cached_line_count(d / "js" / "leakage.txt"),
            "js_comments": cached_line_count(d / "js" / "comments.txt"),
            "historical_urls": cached_line_count(d / "historical" / "all_urls.txt"),
            "crawled_endpoints": cached_line_count(d / "endpoints" / "all.txt"),
            "dork_findings": cached_line_count(d / "dorks" / "all_findings.txt"),
            "historical_validated": cached_line_count(d / "historical" / "validated_interesting.json"),
        },
    }


class StatsCache:
    """Memoizes build_stats() per target, keyed on the shallow signature.

    Avoids recomputing counts (which read ~14 files) on every request when the
    target has not changed. Thread-safe for the threaded HTTP server.
    """

    def __init__(self):
        self.cache = {}
        self.lock = threading.Lock()

    def get(self, target_dir):
        d = Path(target_dir)
        key = str(d)
        sig = shallow_signature(d)
        with self.lock:
            cached = self.cache.get(key)
            if cached and cached[0] == sig and sig is not None:
                return cached[1]
        stats = build_stats(d)
        with self.lock:
            self.cache[key] = (sig, stats)
        return stats


stats_cache = StatsCache()


def list_targets(projects_dir):
    """List all target directories with quick stats."""
    projects = Path(projects_dir).resolve()
    monitor_cfg = load_monitor_config(projects_dir)
    targets = []
    for child in sorted(projects.iterdir()):
        if child.is_dir() and not child.name.startswith(".") and is_recon_dir(child):
            stats = stats_cache.get(child)
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

class HistoricalIndex:
    """In-memory categorized index of historical/all_urls.txt.

    This is the single serving path for historical URLs — it reads the flat file
    directly, so the view works immediately after a scan with no DB ingest
    required. Categorization uses the shared db.categorize_url() so it can never
    drift from the DB ingest logic. The cache is a bounded LRU to keep memory in
    check when many large targets are browsed.
    """

    # Each cached target holds every historical URL in RAM; keep few by default.
    MAX_CACHED_TARGETS = max(1, int(os.environ.get("DASH_HIST_CACHE_TARGETS", 2)))

    def __init__(self):
        self.cache = OrderedDict()
        self.lock = threading.Lock()
        self.static_exts = set(STATIC_EXTS)

    def get_index(self, target_name, file_path):
        if not file_path.exists():
            return None

        mtime = file_path.stat().st_mtime

        with self.lock:
            cached = self.cache.get(target_name)
            if cached and cached['mtime'] == mtime:
                self.cache.move_to_end(target_name)
                return cached['data']

        counts = {k: 0 for k in ("interesting", "auth", "apis", "sensitive", "static", "all")}
        categorized = {k: [] for k in counts}

        try:
            with open(file_path, "r", errors="replace") as f:
                for line in f:
                    url = line.strip()
                    if not url:
                        continue
                    for cat in categorize_url(url):
                        if cat in categorized:
                            counts[cat] += 1
                            categorized[cat].append(url)

            data = {"counts": counts, "categorized": categorized}

            with self.lock:
                self.cache[target_name] = {"mtime": mtime, "data": data}
                self.cache.move_to_end(target_name)
                while len(self.cache) > self.MAX_CACHED_TARGETS:
                    self.cache.popitem(last=False)

            return data
        except Exception:
            return None

historical_index = HistoricalIndex()


# ── Parsed-file cache + server-side paging ───────────────────────────────────
# The data views used to download whole result files and parse them in the
# browser (tens of MB on large scopes — slow on a Pi, fatal on phones). Files
# are now parsed once on the server, cached by (mtime, size), and served one
# filtered/sorted page at a time.

class ParsedFileCache:
    """LRU of parsed files keyed by path + (mtime_ns, size), bounded by memory.

    Parsed Python objects cost a few times the file size, so each entry is
    weighted at ~3x its file size and the total is capped at DASH_CACHE_MB
    (default 64 MB). A file too large to fit is parsed for the request but not
    kept, so the dashboard's memory use has a hard ceiling on small hosts.
    """

    WEIGHT = 3

    def __init__(self):
        try:
            self.cap = int(os.environ.get("DASH_CACHE_MB", 64)) * 1024 * 1024
        except ValueError:
            self.cap = 64 * 1024 * 1024
        self.cache = OrderedDict()   # key -> (sig, data, weight)
        self.used = 0
        self.lock = threading.Lock()

    def get(self, path, kind, parser):
        try:
            st = os.stat(path)
        except OSError:
            return None
        key = (str(path), kind)
        sig = (st.st_mtime_ns, st.st_size)
        with self.lock:
            hit = self.cache.get(key)
            if hit and hit[0] == sig:
                self.cache.move_to_end(key)
                return hit[1]
        data = parser(path)
        weight = max(1, st.st_size * self.WEIGHT) if kind != "count" else 64
        if weight > self.cap:
            return data
        with self.lock:
            old = self.cache.pop(key, None)
            if old:
                self.used -= old[2]
            self.cache[key] = (sig, data, weight)
            self.used += weight
            while self.used > self.cap and self.cache:
                _k, (_s, _d, w) = self.cache.popitem(last=False)
                self.used -= w
        return data


parsed_cache = ParsedFileCache()


# ── Hunt Queue summaries ─────────────────────────────────────────────────────

_SS_NAME_RE = re.compile(r'^(https?)-+(.+?)(?:-(\d+))?\.(?:png|jpe?g)$', re.IGNORECASE)


def screenshot_index(ss_dir):
    """host -> screenshot filename, parsed from gowitness names.

    gowitness names files like "https---host.example.com-443.jpeg". Matching by
    a parsed host is O(files); the old client did a substring search of every
    file for every asset (O(assets x files)) and never matched this format.
    https wins over http when both exist.
    """
    idx = {}
    try:
        names = os.listdir(ss_dir)
    except OSError:
        return idx
    for f in sorted(names):
        m = _SS_NAME_RE.match(f)
        if not m:
            continue
        scheme, host = m.group(1).lower(), m.group(2).lower()
        for h in {host, host.replace("_", ".")}:
            if h not in idx or scheme == "https":
                idx[h] = f
    return idx


class FindingSummaryCache:
    """Per-target cache of db.get_asset_summaries + screenshot matches.

    Keyed on the DB files' (mtime, size) and the screenshots dir mtime, and
    explicitly invalidated when a verdict changes or a scan is ingested, so it
    is rebuilt only when something actually changed. Bounded to a few targets.
    """

    MAX_TARGETS = 3

    def __init__(self):
        self.cache = OrderedDict()
        self.lock = threading.Lock()

    @staticmethod
    def _sig(target_dir):
        sig = []
        for name in ("recon.db", "recon.db-wal", "screenshots"):
            try:
                st = os.stat(Path(target_dir) / name)
                sig.append((st.st_mtime_ns, st.st_size))
            except OSError:
                sig.append(None)
        return tuple(sig)

    def invalidate(self, target_dir):
        with self.lock:
            self.cache.pop(str(Path(target_dir).resolve()), None)

    def get(self, target_dir):
        key = str(Path(target_dir).resolve())
        sig = self._sig(target_dir)
        with self.lock:
            hit = self.cache.get(key)
            if hit and hit[0] == sig:
                self.cache.move_to_end(key)
                return hit[1]
        if not (Path(target_dir) / "recon.db").exists():
            data = {"scan_id": None, "counts": {}, "assets": [], "search": {}}
        else:
            db = get_target_db(target_dir)
            try:
                data = db.get_asset_summaries()
            finally:
                db.close()
            shots = screenshot_index(Path(target_dir) / "screenshots")
            target_name = Path(target_dir).name
            for a in data["assets"]:
                f = shots.get(a["host"].lower())
                a["screenshot"] = ("/screenshots/%s/%s" % (target_name, f)) if f else None
        with self.lock:
            self.cache[key] = (sig, data)
            self.cache.move_to_end(key)
            while len(self.cache) > self.MAX_TARGETS:
                self.cache.popitem(last=False)
        return data


finding_summaries = FindingSummaryCache()


def parse_lines(path):
    """Non-empty, trimmed lines (same rule as the client's parseLines)."""
    out = []
    with open(path, "r", errors="replace") as f:
        for line in f:
            v = line.strip()
            if v:
                out.append(v)
    return out


def parse_httpx(path):
    """Slim records from httpx JSON lines (only the fields the UI shows)."""
    out = []
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except Exception:
                continue
            if not isinstance(o, dict):
                continue
            tech = o.get("tech") if isinstance(o.get("tech"), list) else []
            a = o.get("a")
            ip = (a[0] if a else "") if isinstance(a, list) else (a or o.get("host") or "")
            host = o.get("input") or ""
            if not host and o.get("url"):
                host = urlparse(o["url"]).hostname or ""
            out.append({
                "url": o.get("url", "") or "",
                "status_code": o.get("status_code"),
                "title": o.get("title", "") or "",
                "webserver": o.get("webserver", "") or "",
                "tech": tech,
                "host": host,
                "ip": str(ip),
            })
    return out


def parse_jsonl(path):
    """JSON-lines file -> list of dict records (bad lines skipped)."""
    out = []
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except Exception:
                continue
            if isinstance(o, dict):
                out.append(o)
    return out


def parse_naabu(path):
    out = []
    for ln in parse_lines(path):
        parts = ln.split(":")
        out.append({"host": parts[0] if parts else "", "port": parts[1] if len(parts) > 1 else ""})
    return out


def cached_line_count(path):
    """Non-empty line count, cached by (mtime, size)."""
    if not Path(path).exists():
        return 0
    return parsed_cache.get(path, "count", count_lines) or 0


def _sort_key(v):
    """Mirror the client table sort: strings case-insensitively, numbers as is."""
    if v is None:
        return (0, "")
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return (1, v)
    if isinstance(v, list):
        v = ", ".join(str(x) for x in v)
    return (2, str(v).lower())


def page_params(qs, default_size=50):
    try:
        page = max(0, int(qs.get("page", ["0"])[0]))
    except ValueError:
        page = 0
    try:
        size = int(qs.get("pageSize", [str(default_size)])[0])
    except ValueError:
        size = default_size
    return page, max(1, min(size, 500))


def paginate(items, qs, default_size=50):
    """Sort (optional ?sort=<key>&dir=asc|desc) and slice one page."""
    sort = qs.get("sort", [""])[0]
    if sort:
        desc = qs.get("dir", ["asc"])[0] == "desc"
        if items and isinstance(items[0], dict):
            items = sorted(items, key=lambda it: _sort_key(it.get(sort)), reverse=desc)
        else:
            items = sorted(items, key=_sort_key, reverse=desc)
    page, size = page_params(qs, default_size)
    pages = max(1, -(-len(items) // size))
    page = min(page, pages - 1)
    start = page * size
    return {"items": items[start:start + size], "total": len(items),
            "page": page, "pageSize": size}

class ScopeEngine:
    def __init__(self, projects_dir):
        self.config_path = Path(projects_dir) / '.scope_config.json'
        self.lock = threading.Lock()
        self.rules = self.load_rules()

    def load_rules(self):
        if self.config_path.exists():
            try:
                with open(self.config_path) as f:
                    return json.load(f)
            except Exception:
                pass
        return {'global_rules': {'in_scope': [], 'out_of_scope': []}, 'target_overrides': {}}

    def save_rules(self, rules):
        with self.lock:
            self.rules = rules
            with open(self.config_path, 'w') as f:
                json.dump(rules, f, indent=2)

    def get_rules(self, target=None):
        with self.lock:
            rules = self.rules
            base = dict(rules.get('global_rules', {}))
            if target and target in rules.get('target_overrides', {}):
                override = rules['target_overrides'][target]
                base['in_scope'] = override.get('in_scope', base.get('in_scope', []))
                base['out_of_scope'] = override.get('out_of_scope', base.get('out_of_scope', []))
        return base
    
    def is_in_scope(self, hostname, target=None):
        import fnmatch, ipaddress
        rules = self.get_rules(target)
        in_scope = rules.get('in_scope', [])
        out_of_scope = rules.get('out_of_scope', [])
        
        if not in_scope:
            allowed = True
        else:
            allowed = False
            for pattern in in_scope:
                if '/' in pattern:
                    try:
                        if ipaddress.ip_address(hostname) in ipaddress.ip_network(pattern, strict=False):
                            allowed = True
                            break
                    except ValueError:
                        pass
                elif fnmatch.fnmatch(hostname.lower(), pattern.lower()):
                    allowed = True
                    break
        
        if not allowed:
            return False
        
        for pattern in out_of_scope:
            if '/' in pattern:
                try:
                    if ipaddress.ip_address(hostname) in ipaddress.ip_network(pattern, strict=False):
                        return False
                except ValueError:
                    pass
            elif fnmatch.fnmatch(hostname.lower(), pattern.lower()):
                return False
        
        return True

def make_handler(projects_dir, scan_manager):
    projects_path = Path(projects_dir).resolve()
    scope_engine = ScopeEngine(projects_dir)

    class DashboardHandler(SimpleHTTPRequestHandler):
        def log_message(self, fmt, *args):
            sys.stderr.write(f"  \033[0;36m{args[0]}\033[0m {args[1]}\n")

        # ── Response helpers ──
        # Compact JSON + gzip (when the client accepts it) cut transfer size
        # several-fold; recon text compresses extremely well. ETag/304 lets the
        # browser revalidate unchanged files without re-downloading them.
        def _accepts_gzip(self):
            return "gzip" in (self.headers.get("Accept-Encoding") or "")

        def _send_body(self, body, content_type, status=200, extra=None, compress=True):
            if (compress and _GZIP_MIN <= len(body) <= _GZIP_MAX
                    and self._accepts_gzip()):
                body = gzip.compress(body, compresslevel=1)
                gz = True
            else:
                gz = False
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", len(body))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "X-Truncated, X-Total-Size")
            if gz:
                self.send_header("Content-Encoding", "gzip")
            self.send_header("Vary", "Accept-Encoding")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def send_json(self, data, status=200):
            body = json.dumps(data, separators=(",", ":")).encode()
            self._send_body(body, "application/json", status)

        def send_text(self, text, status=200):
            self._send_body(text.encode(), "text/plain; charset=utf-8", status)

        def send_file_data(self, filepath, content_type=None, max_bytes=None, tail_bytes=None):
            try:
                st = os.stat(filepath)
            except (FileNotFoundError, NotADirectoryError):
                self.send_json({"error": "File not found"}, 404)
                return

            # No explicit type => a file from a target dir. Its content is
            # attacker-influenced (reconstructed source maps, page titles in
            # report.html, SVGs), so never let it run script on this origin.
            untrusted = content_type is None
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

            if tail_bytes and st.st_size > tail_bytes:
                max_bytes = None
                truncated, mode = True, "e%d" % tail_bytes
            else:
                tail_bytes = None
                truncated = bool(max_bytes and st.st_size > max_bytes)
                mode = "t%d" % max_bytes if truncated else ""
            etag = '"%x-%x%s"' % (st.st_mtime_ns, st.st_size, "-" + mode if mode else "")
            if self.headers.get("If-None-Match") == etag:
                self.send_response(304)
                self.send_header("ETag", etag)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                return

            extra = {"Cache-Control": "no-cache", "ETag": etag}
            if untrusted:
                extra["Content-Security-Policy"] = "sandbox"
                extra["X-Content-Type-Options"] = "nosniff"
            compressible = not content_type.startswith("image/")
            try:
                if truncated:
                    # Head of a huge file (e.g. the raw viewer on a phone): cut
                    # at the last newline so no partial line is shown.
                    with open(filepath, "rb") as f:
                        if tail_bytes:
                            f.seek(st.st_size - tail_bytes)
                            data = f.read(tail_bytes)
                            nl = data.find(b"\n")
                            if 0 <= nl < len(data) - 1:
                                data = data[nl + 1:]
                        else:
                            data = f.read(max_bytes)
                            nl = data.rfind(b"\n")
                            if nl > 0:
                                data = data[:nl + 1]
                    extra["X-Truncated"] = "1"
                    extra["X-Total-Size"] = str(st.st_size)
                    self._send_body(data, content_type, 200, extra, False)
                    return
                if st.st_size <= _GZIP_MAX:
                    with open(filepath, "rb") as f:
                        data = f.read()
                    self._send_body(data, content_type, 200, extra, compressible)
                    return
                # Very large file: stream it instead of holding it in memory.
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", st.st_size)
                self.send_header("Access-Control-Allow-Origin", "*")
                for k, v in extra.items():
                    self.send_header(k, v)
                self.end_headers()
                with open(filepath, "rb") as f:
                    while True:
                        chunk = f.read(_STREAM_CHUNK)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
            except FileNotFoundError:
                self.send_json({"error": "File not found"}, 404)
            except (BrokenPipeError, ConnectionResetError):
                pass

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
            if target_dir != projects_path and projects_path not in target_dir.parents:
                return None
            if rel_path:
                full = (target_dir / rel_path).resolve()
                # Must be the target dir itself or inside it (a plain string
                # prefix check would also accept a sibling like "<target>2").
                if full != target_dir and target_dir not in full.parents:
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
                self.send_json(stats_cache.get(target_dir))
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
                # Optional ?max=<bytes>: serve only the head of a huge file.
                # ?tail=<bytes>: only the end (logs are read from the bottom).
                try:
                    max_bytes = int(qs.get("max", ["0"])[0]) or None
                    tail_bytes = int(qs.get("tail", ["0"])[0]) or None
                except ValueError:
                    max_bytes = tail_bytes = None
                self.send_file_data(resolved, max_bytes=max_bytes, tail_bytes=tail_bytes)
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
                if "page" not in qs:
                    self.send_json({"files": files})
                    return
                # Paged mode (gallery): thousands of <img> at once crash phones.
                q = qs.get("q", [""])[0].strip().lower()
                if q:
                    files = [f for f in files if q in f.lower()]
                res = paginate(files, qs, default_size=48)
                self.send_json({"files": res["items"], "total": res["total"],
                                "page": res["page"], "pageSize": res["pageSize"]})
                return

            # ─── API: List raw files within a target ───
            if path == "/api/target/files":
                target = qs.get("target", [None])[0]
                if not target:
                    self.send_json({"error": "target param required"}, 400)
                    return
                target_dir = self.resolve_target_path(target)
                if not target_dir or not target_dir.is_dir():
                    self.send_json({"error": "Target not found"}, 404)
                    return
                files = []
                for root, dirnames, filenames in os.walk(target_dir):
                    if Path(root) == target_dir:
                        # Don't descend into screenshots (thousands of images
                        # that are filtered out below anyway).
                        dirnames[:] = [d for d in dirnames if d != "screenshots"]
                    for filename in filenames:
                        full_p = Path(root) / filename
                        rel_p = full_p.relative_to(target_dir)
                        # Filter out binary screenshots, scan log history, hidden files
                        if rel_p.name.startswith(".") or "screenshots/" in str(rel_p) or (rel_p.parts and rel_p.parts[0] == "screenshots"):
                            continue
                        if str(rel_p).startswith("logs/scan_"):
                            continue
                        files.append(str(rel_p))
                self.send_json({"files": sorted(files)})
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

            # ─── API: List scan logs ───
            if path == "/api/logs":
                target = qs.get("target", [None])[0]
                if not target:
                    self.send_json({"error": "target param required"}, 400)
                    return
                target_dir = self.resolve_target_path(target)
                if not target_dir or not target_dir.is_dir():
                    self.send_json({"error": "Target not found"}, 404)
                    return
                log_dir = target_dir / "logs"
                files = []
                if log_dir.is_dir():
                    files = sorted([
                        f.name for f in log_dir.glob("scan_*.log")
                    ], reverse=True)
                self.send_json({"files": files})
                return

            # ─── API: Server-side paginated/filtered historical URLs ───
            if path == "/api/data/historical":
                target = qs.get("target", [None])[0]
                if not target:
                    self.send_json({"error": "target param required"}, 400)
                    return
                
                tab = qs.get("tab", ["interesting"])[0]
                query = qs.get("query", [""])[0].strip().lower()
                host = qs.get("host", [""])[0].strip().lower()
                ext = qs.get("ext", [""])[0].strip().lower()
                hide_static = qs.get("hideStatic", ["false"])[0].lower() == "true"
                hide_404 = qs.get("hide404", ["false"])[0].lower() == "true"
                hide_dupes = qs.get("hideDupes", ["false"])[0].lower() == "true"
                
                try:
                    page = int(qs.get("page", ["0"])[0])
                    page_size = int(qs.get("pageSize", ["50"])[0])
                except ValueError:
                    page = 0
                    page_size = 50

                target_dir = self.resolve_target_path(target)
                if not target_dir or not target_dir.is_dir():
                    self.send_json({"error": "Target not found"}, 404)
                    return

                counts = {
                    "interesting": 0,
                    "validated": 0,
                    "auth": 0,
                    "apis": 0,
                    "sensitive": 0,
                    "static": 0,
                    "all": 0
                }
                
                val_file = target_dir / "historical" / "validated_interesting.json"
                if val_file.exists():
                    counts["validated"] = cached_line_count(val_file)
                
                file_path = target_dir / "historical" / "all_urls.txt"
                items = []
                active_match_count = 0
                start_idx = page * page_size
                end_idx = start_idx + page_size
                
                if file_path.exists():
                    idx_data = historical_index.get_index(target, file_path)
                    if idx_data:
                        for k, v in idx_data["counts"].items():
                            counts[k] = v
                        
                        if tab != "validated":
                            category_list = idx_data["categorized"].get(tab, [])
                            seen_active = set()
                            
                            for url in category_list:
                                url_lower = url.lower()
                                path_part = url_lower.split("?")[0]
                                
                                if hide_static and tab != "static":
                                    if any(path_part.endswith(e) for e in historical_index.static_exts):
                                        continue
                                
                                if host and host not in url_lower:
                                    continue
                                if ext and not path_part.endswith("." + ext):
                                    continue
                                if query and query not in url_lower:
                                    continue
                                
                                if hide_dupes:
                                    if url in seen_active:
                                        continue
                                    seen_active.add(url)
                                
                                if active_match_count >= start_idx and active_match_count < end_idx:
                                    items.append(url)
                                active_match_count += 1
                            
                if tab == "validated" and val_file.exists():
                    seen_active = set()
                    # Parsed once per file version (cached), not on every request.
                    records = parsed_cache.get(val_file, "jsonl", parse_jsonl) or []
                    for item in records:
                            url = item.get("url", "")
                            if not url:
                                continue
                            url_lower = url.lower()
                            
                            if hide_404 and item.get("status_code") == 404:
                                continue
                            if host and host not in url_lower:
                                continue
                            if ext and not url_lower.split("?")[0].endswith("." + ext):
                                continue
                            if query:
                                title = (item.get("title") or "").lower()
                                if query not in url_lower and query not in title:
                                    continue
                            
                            if hide_dupes:
                                if url in seen_active:
                                    continue
                                seen_active.add(url)
                                
                            if active_match_count >= start_idx and active_match_count < end_idx:
                                items.append(item)
                            active_match_count += 1

                self.send_json({
                    "counts": counts,
                    "items": items,
                    "total": active_match_count,
                    "page": page,
                    "pageSize": page_size
                })
                return

            # ─── API: Server-paged single-column list from any target file ───
            if path == "/api/data/list":
                target = qs.get("target", [None])[0]
                rel = qs.get("file", [""])[0]
                if not target or not rel:
                    self.send_json({"error": "target and file params required"}, 400)
                    return
                resolved = self.resolve_target_path(target, rel)
                if not resolved:
                    self.send_json({"error": "Access denied"}, 403)
                    return
                lines = parsed_cache.get(resolved, "lines", parse_lines) if resolved.is_file() else []
                lines = lines or []
                q = qs.get("q", [""])[0].strip().lower()
                if q:
                    lines = [v for v in lines if q in v.lower()]
                self.send_json(paginate(lines, qs))
                return

            # ─── API: Server-paged tables (webapps / dns / ports) ───
            if path == "/api/data/table":
                target = qs.get("target", [None])[0]
                kind = qs.get("kind", [""])[0]
                target_dir = self.resolve_target_path(target) if target else None
                if not target_dir or not target_dir.is_dir():
                    self.send_json({"error": "Target not found"}, 404)
                    return
                q = qs.get("q", [""])[0].strip().lower()
                httpx_path = target_dir / "httpx" / "results.json"

                if kind == "webapps":
                    rows = (parsed_cache.get(httpx_path, "httpx", parse_httpx) or []) if httpx_path.exists() else []
                    if qs.get("hideDupes", ["false"])[0] == "true":
                        seen, kept = set(), []
                        for r in rows:
                            t = r["title"].lower()
                            if t:
                                if t in seen:
                                    continue
                                seen.add(t)
                            kept.append(r)
                        rows = kept
                    status = qs.get("status", [""])[0].strip()
                    if status:
                        rows = [r for r in rows if str(r["status_code"]).startswith(status)]
                    if q:
                        rows = [r for r in rows if q in " ".join(
                            [r["url"], r["title"], r["webserver"], " ".join(r["tech"])]).lower()]
                elif kind == "dns":
                    dns_path = target_dir / "dns" / "resolved.txt"
                    hosts = (parsed_cache.get(dns_path, "lines", parse_lines) or []) if dns_path.exists() else []
                    ipmap = {}
                    if httpx_path.exists():
                        for r in parsed_cache.get(httpx_path, "httpx", parse_httpx) or []:
                            if r["host"] and r["ip"]:
                                ipmap[r["host"]] = r["ip"]
                    rows = [{"host": h, "ip": ipmap.get(h, "")} for h in hosts]
                    if q:
                        rows = [r for r in rows if q in (r["host"] + " " + r["ip"]).lower()]
                elif kind == "ports":
                    naabu = target_dir / "ports" / "naabu.txt"
                    rows = (parsed_cache.get(naabu, "naabu", parse_naabu) or []) if naabu.exists() else []
                    if q:
                        rows = [r for r in rows if q in (r["host"] + " " + r["port"]).lower()]
                else:
                    self.send_json({"error": "unknown kind"}, 400)
                    return
                self.send_json(paginate(rows, qs))
                return

            # ─── API: Line counts for several target files (tab badges) ───
            if path == "/api/data/counts":
                target = qs.get("target", [None])[0]
                files = [f for f in qs.get("files", [""])[0].split(",") if f][:40]
                counts = {}
                for rel in files:
                    resolved = self.resolve_target_path(target, rel) if target else None
                    counts[rel] = cached_line_count(resolved) if resolved and resolved.is_file() else 0
                self.send_json({"counts": counts})
                return

            # ─── API: Scan status ───
            if path == "/api/scan/status":
                target = qs.get("target", [None])[0]
                self.send_json(scan_manager.status(target))
                return

            # ─── API: All in-session runs (active + recently finished) ───
            if path == "/api/scans/active":
                self.send_json({"runs": scan_manager.list_runs(),
                                "max_concurrent": scan_manager.max_concurrent,
                                "active": scan_manager.active_count(),
                                "agent_runs_enabled": ENABLE_AGENT_RUNS})
                return

            # ─── API: Detailed stage progression for a target ───
            if path == "/api/scan/progress":
                target = qs.get("target", [None])[0]
                if not target:
                    self.send_json({"error": "target param required"}, 400)
                    return
                target_dir = self.resolve_target_path(target)
                if not target_dir or not target_dir.is_dir():
                    self.send_json({"error": "Target not found"}, 404)
                    return
                running = scan_manager.is_running(target)
                self.send_json(scan_manager.progress(target_dir, running=running))
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

            # ─── API: List scans for a target ───
            if path == '/api/scans':
                target = qs.get('target', [None])[0]
                if not target:
                    self.send_json({'error': 'target param required'}, 400)
                    return
                target_dir = self.resolve_target_path(target)
                if not target_dir or not target_dir.is_dir():
                    self.send_json({'error': 'Target not found'}, 404)
                    return
                try:
                    db = get_target_db(target_dir)
                    scans = db.get_scans()
                    db.close()
                    self.send_json({'scans': scans})
                except Exception as e:
                    self.send_json({'scans': [], 'error': str(e)})
                return

            # ─── API: Diff between two scans ───
            if path == '/api/diff':
                target = qs.get('target', [None])[0]
                scan_a = qs.get('scan_a', [None])[0]
                scan_b = qs.get('scan_b', [None])[0]
                if not target or not scan_a or not scan_b:
                    self.send_json({'error': 'target, scan_a, scan_b params required'}, 400)
                    return
                target_dir = self.resolve_target_path(target)
                if not target_dir or not target_dir.is_dir():
                    self.send_json({'error': 'Target not found'}, 404)
                    return
                try:
                    db = get_target_db(target_dir)
                    diff = db.get_diff(int(scan_a), int(scan_b))
                    db.close()
                    self.send_json(diff)
                except Exception as e:
                    self.send_json({'error': str(e)}, 500)
                return

            # ─── API: Scope rules ───
            if path == '/api/scope':
                target = qs.get('target', [None])[0]
                rules = scope_engine.get_rules(target)
                self.send_json({'rules': rules, 'all_rules': scope_engine.rules})
                return

            # ─── API: System health ───
            if path == '/api/system/health':
                health = {'cpu_load': 0, 'memory_percent': 0}
                try:
                    with open('/proc/loadavg') as f:
                        parts = f.read().split()
                        health['cpu_load'] = float(parts[0])
                    with open('/proc/meminfo') as f:
                        info = {}
                        for line in f:
                            k, v = line.split(':')[:2]
                            info[k.strip()] = int(v.split()[0])
                        total = info.get('MemTotal', 1)
                        available = info.get('MemAvailable', total)
                        health['memory_percent'] = round((1 - available / total) * 100, 1)
                except Exception:
                    pass
                health['scan_running'] = scan_manager.is_running()
                health['scans_active'] = scan_manager.active_count()
                self.send_json(health)
                return

            # ─── API: Unified findings for a target (latest scan) ───
            if path == '/api/findings':
                target = qs.get('target', [None])[0]
                if not target:
                    self.send_json({'error': 'target param required'}, 400)
                    return
                target_dir = self.resolve_target_path(target)
                if not target_dir or not target_dir.is_dir():
                    self.send_json({'error': 'Target not found'}, 404)
                    return
                tier = qs.get('tier', [None])[0]
                ftype = qs.get('type', [None])[0]
                asset = qs.get('asset', [None])[0]
                source = qs.get('source', [None])[0]
                try:
                    db = get_target_db(target_dir)
                    result = db.get_findings(tier=tier, ftype=ftype, asset=asset, source=source)
                    db.close()
                    self.send_json(result)
                except Exception as e:
                    self.send_json({'findings': [], 'counts': {}, 'error': str(e)})
                return

            # ─── API: Hunt Queue — one compact row per asset (cached) ───
            # ?q=<text> instead returns the hosts whose finding labels match,
            # so the client can search all findings without downloading them.
            if path == '/api/findings/assets':
                target = qs.get('target', [None])[0]
                target_dir = self.resolve_target_path(target) if target else None
                if not target_dir or not target_dir.is_dir():
                    self.send_json({'error': 'Target not found'}, 404)
                    return
                try:
                    data = finding_summaries.get(target_dir)
                except Exception as e:
                    self.send_json({'assets': [], 'counts': {}, 'error': str(e)})
                    return
                q = qs.get('q', [''])[0].strip().lower()
                if q:
                    hosts = [h for h, blob in data['search'].items() if q in blob]
                    self.send_json({'hosts': hosts})
                    return
                self.send_json({'scan_id': data['scan_id'], 'counts': data['counts'],
                                'assets': data['assets']})
                return

            # ─── API: Triage state (starred / ignored hosts) for a target ───
            if path == '/api/triage':
                target = qs.get('target', [None])[0]
                if not target:
                    self.send_json({'error': 'target param required'}, 400)
                    return
                triage_path = self.resolve_target_path(target, '.triage.json')
                state = {'starred': [], 'ignored': []}
                if triage_path and triage_path.exists():
                    try:
                        with open(triage_path) as f:
                            loaded = json.load(f)
                        state['starred'] = list(loaded.get('starred', []))
                        state['ignored'] = list(loaded.get('ignored', []))
                    except Exception:
                        pass
                self.send_json(state)
                return

            # ─── Fallback ───
            self.send_json({"error": "Not found"}, 404)

        def _cross_origin(self):
            """True for a browser request sent from another site. read_body
            parses JSON whatever the Content-Type, so without this any web page
            open in the user's browser could POST here (start/stop scans, agent
            runs, verdicts). Same-origin dashboard requests carry a matching
            Origin; non-browser clients (curl, scripts) send none."""
            origin = self.headers.get("Origin")
            if origin is None:
                return self.headers.get("Sec-Fetch-Site") == "cross-site"
            return urlparse(origin).netloc.lower() != (self.headers.get("Host") or "").lower()

        def do_POST(self):
            parsed = urlparse(self.path)
            path = unquote(parsed.path)

            if self._cross_origin():
                self.send_json({"error": "Cross-origin request refused"}, 403)
                return

            # ─── API: Start scan ───
            if path == "/api/scan/start":
                body = self.read_body()
                domain = body.get("domain", "").strip()
                if not domain:
                    self.send_json({"error": "domain is required"}, 400)
                    return
                if not valid_domain(domain) or not self.resolve_target_path(domain):
                    self.send_json({"ok": False, "message": f'Invalid domain "{domain}".'}, 400)
                    return
                if not scope_engine.is_in_scope(domain, domain):
                    self.send_json({'ok': False, 'message': f'Domain "{domain}" is out of scope. Update scope rules to allow it.'}, 403)
                    return
                skip = body.get("skip", [])
                threads = body.get("threads")
                rate = body.get("rate")
                top_ports = body.get("top_ports")
                http_rate = body.get("http_rate")
                active_rate = body.get("active_rate")

                # Headers may arrive as a list or a newline-separated string.
                # Split on newlines, drop control chars, keep "Name: Value" lines.
                raw_headers = body.get("headers") or []
                if isinstance(raw_headers, str):
                    raw_headers = raw_headers.splitlines()
                headers = []
                for h in raw_headers:
                    h = re.sub(r"[\r\n\x00]", "", str(h)).strip()
                    if h and ":" in h:
                        headers.append(h)

                # Numeric guard: active must not exceed http (engine clamps too).
                def _num(v):
                    try:
                        return int(v) if v not in (None, "") else None
                    except (TypeError, ValueError):
                        return None
                http_rate = _num(http_rate)
                active_rate = _num(active_rate)
                if http_rate and active_rate and active_rate > http_rate:
                    active_rate = http_rate

                ok, msg = scan_manager.start(domain, skip, threads, rate, top_ports,
                                             http_rate=http_rate, active_rate=active_rate,
                                             headers=headers, target=domain)
                self.send_json({"ok": ok, "message": msg}, 200 if ok else 409)
                return

            # ─── API: Start triage-results skill (agent run) for a target ───
            if path == "/api/triage/start":
                if not ENABLE_AGENT_RUNS:
                    self.send_json({"ok": False, "message": "Agent runs are disabled. "
                                    "Restart the dashboard with E=1 to enable."}, 403)
                    return
                body = self.read_body()
                target = (body.get("target") or "").strip()
                if not target:
                    self.send_json({"error": "target is required"}, 400)
                    return
                # Containment: resolve_target_path rejects traversal and anything
                # outside the projects dir, so `target` is a real target folder.
                target_dir = self.resolve_target_path(target)
                if not target_dir or not target_dir.is_dir():
                    self.send_json({"error": "Target not found"}, 404)
                    return
                # argv (no shell): the skill works out projects_dir from cwd.
                cmd = [CLAUDE_BIN, "-p", f"/triage-results {target}"] + TRIAGE_AGENT_ARGS
                ok, msg = scan_manager.start(target, kind="triage",
                                             custom_cmd=cmd, target=target)
                self.send_json({"ok": ok, "message": msg}, 200 if ok else 409)
                return

            # ─── API: Stop scan (optionally a specific target) ───
            if path == "/api/scan/stop":
                body = self.read_body() or {}
                target = (body.get("target") or "").strip() or None
                ok, msg = scan_manager.stop(target)
                self.send_json({"ok": ok, "message": msg})
                return

            # ─── API: Start monitor scan ───
            if path == "/api/monitor/start":
                body = self.read_body()
                domain = body.get("domain", "").strip()
                target = body.get("target", "").strip()
                if not domain:
                    self.send_json({"error": "domain is required"}, 400)
                    return
                init = body.get("init", False)
                threads = body.get("threads")
                rate = body.get("rate")
                top_ports = body.get("top_ports")

                if not valid_domain(domain):
                    self.send_json({"ok": False, "message": f'Invalid domain "{domain}".'}, 400)
                    return
                # Use target dir name if provided, otherwise fall back to domain
                target_name = target or domain
                # Containment: the output dir must be a folder in projects_dir.
                target_dir = self.resolve_target_path(target_name)
                if not target_dir or target_dir == projects_path:
                    self.send_json({"error": "Access denied"}, 403)
                    return
                # Monitoring actively port-scans, so it is scope-gated like a scan.
                if not scope_engine.is_in_scope(domain, target_name):
                    self.send_json({'ok': False, 'message': f'Domain "{domain}" is out of scope. Update scope rules to allow it.'}, 403)
                    return
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
                    custom_cmd=cmd, kind="monitor", target=target_name
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
                # monitor_all.sh runs monitor.sh in projects_dir/<target>, so
                # only accept a real target folder (no traversal).
                target_dir = self.resolve_target_path(target)
                if enabled and (not target_dir or target_dir == projects_path
                                or not target_dir.is_dir()):
                    self.send_json({"error": "Target not found"}, 404)
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

            # ─── API: Update scope rules ───
            if path == '/api/scope':
                body = self.read_body()
                scope_engine.save_rules(body)
                self.send_json({'ok': True})
                return

            # ─── API: Trigger manual DB ingest ───
            if path == '/api/db/ingest':
                body = self.read_body()
                target = body.get('target', '').strip()
                if not target:
                    self.send_json({'error': 'target is required'}, 400)
                    return
                target_dir = self.resolve_target_path(target)
                if not target_dir or not target_dir.is_dir():
                    self.send_json({'error': 'Target not found'}, 404)
                    return
                try:
                    db = get_target_db(target_dir)
                    scan_id = db.ingest_scan(str(target_dir))
                    db.close()
                    finding_summaries.invalidate(target_dir)
                    self.send_json({'ok': True, 'scan_id': scan_id})
                except Exception as e:
                    err = str(e)
                    if 'readonly' in err.lower():
                        # Typically recon.db was created by a sudo scan and is root-owned.
                        err += (f" — {target_dir / 'recon.db'} is not writable by the dashboard "
                                f"user; fix ownership (e.g. sudo chown -R $USER: {target_dir})")
                    self.send_json({'ok': False, 'error': err}, 500)
                return

            # ─── API: Persist human state on a finding (verdict/severity/notes) ───
            if path == '/api/finding/state':
                body = self.read_body()
                target = (body.get('target') or '').strip()
                fp = (body.get('fingerprint') or '').strip()
                if not target or not fp:
                    self.send_json({'error': 'target and fingerprint are required'}, 400)
                    return
                target_dir = self.resolve_target_path(target)
                if not target_dir or not target_dir.is_dir():
                    self.send_json({'error': 'Target not found'}, 404)
                    return
                try:
                    db = get_target_db(target_dir)
                    db.set_finding_state(
                        fp,
                        verdict=body.get('verdict'),
                        severity=body.get('severity'),
                        starred=body.get('starred'),
                        notes=body.get('notes'),
                    )
                    db.close()
                    finding_summaries.invalidate(target_dir)
                    self.send_json({'ok': True})
                except Exception as e:
                    self.send_json({'ok': False, 'error': str(e)}, 500)
                return

            # ─── API: Persist triage state (starred / ignored hosts) ───
            if path == '/api/triage':
                body = self.read_body()
                target = (body.get('target') or '').strip()
                if not target:
                    self.send_json({'error': 'target is required'}, 400)
                    return
                triage_path = self.resolve_target_path(target, '.triage.json')
                if not triage_path:
                    self.send_json({'error': 'Access denied'}, 403)
                    return
                if not triage_path.parent.is_dir():
                    self.send_json({'error': 'Target not found'}, 404)
                    return
                state = {
                    'starred': sorted(set(body.get('starred', []))),
                    'ignored': sorted(set(body.get('ignored', []))),
                }
                try:
                    with open(triage_path, 'w') as f:
                        json.dump(state, f, indent=2)
                    self.send_json({'ok': True})
                except Exception as e:
                    self.send_json({'ok': False, 'error': str(e)}, 500)
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
    server = ThreadingHTTPServer((args.bind, args.port), handler)
    server.daemon_threads = True

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
