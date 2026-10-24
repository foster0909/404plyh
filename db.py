import sqlite3
import json
import os
import re
import hashlib
import datetime
from pathlib import Path
from urllib.parse import urlparse

# ── Shared URL categorization (single source of truth) ───────────────────────
# Used by both DB ingest and the dashboard's in-memory HistoricalIndex so the
# two paths can never drift apart.

INTERESTING_WORDS = [
    "admin", "login", "api", "auth", "debug", "config", "backup", "swagger",
    "graphql", "upload", "internal", "dev", "staging", "test", ".env",
    ".json", ".xml", "db", "sql",
]
STATIC_EXTS = [
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".ico",
]
_AUTH_RE = re.compile(r"(login|admin|dashboard|portal|panel|auth)", re.IGNORECASE)
_API_RE = re.compile(r"(/api/|/v[0-9]+/|graphql|rest|swagger|openapi)", re.IGNORECASE)
_SENS_RE = re.compile(r"\.(json|xml|yaml|yml|conf|config|env|bak|old|sql|log)", re.IGNORECASE)


def categorize_url(url):
    """Return the set of categories a URL belongs to. Always includes 'all'."""
    categories = {"all"}
    url_lower = url.lower()
    path_part = url_lower.split("?")[0]
    if any(w in url_lower for w in INTERESTING_WORDS):
        categories.add("interesting")
    if _AUTH_RE.search(url_lower):
        categories.add("auth")
    if _API_RE.search(url_lower):
        categories.add("apis")
    if _SENS_RE.search(url_lower):
        categories.add("sensitive")
    if any(path_part.endswith(ext) for ext in STATIC_EXTS):
        categories.add("static")
    return categories


# ══════════════════════════════════════════════════════════════════════════════
# Unified finding model
#
# A finding is ONE normalized signal about an asset. It carries three independent
# axes that must never be collapsed:
#   - tier:  observation | suspicious | confirmed  (confidence the signal is real
#            & live — NOT a severity, NOT a vulnerability claim)
#   - score: attention priority for triage ordering (NOT severity)
#   - human state (verdict/severity/notes): set only by a person, stored in a
#            separate finding_state table keyed by fingerprint so it survives
#            re-ingest and rescans.
#
# Firewall rules:
#   * a heuristic / regex / keyword match may produce AT MOST `suspicious`.
#   * only active verification (dork active-probe, validated historical, etc.)
#     may produce `confirmed` — and `confirmed` means "verified live", never
#     "exploitable".
#   * `severity` is NULL unless a human sets it. Nothing here calls a recon
#     signal a vulnerability.
# ══════════════════════════════════════════════════════════════════════════════

ADMIN_TECH = [
    "jenkins", "jira", "kubernetes", "docker", "tomcat", "grafana", "kibana",
    "prometheus", "sonarqube", "gitlab", "nexus", "artifactory", "confluence",
    "bitbucket", "phpmyadmin", "kong", "consul", "rabbitmq",
]
# Hostname labels that suggest a non-production / privileged surface. Matched
# against whole host labels (split on "." and "-"), never as substrings, so
# "contest.example.com" does not count as "test".
STRONG_HOST_WORDS = {
    "dev", "development", "staging", "stage", "stg", "internal", "admin",
    "uat", "test", "qa", "preprod", "sandbox", "jenkins", "jira", "git",
    "gitlab", "vpn", "corp", "intranet", "mgmt", "manage", "legacy", "beta",
}
WEAK_HOST_WORDS = {"api", "portal"}
AUTH_TITLE_WORDS = ["login", "sign in", "log in", "admin", "portal", "dashboard"]
STD_PORTS = {"80", "443"}
# nmap service names that indicate a management / remote-administration surface.
MGMT_SERVICES = {
    "ssh", "telnet", "ms-wbt-server", "rdp", "vnc", "snmp", "winrm",
    "docker", "kubernetes", "elasticsearch", "redis", "mongodb", "mysql",
    "postgresql", "ms-sql-s", "memcached", "rabbitmq", "zookeeper",
}

_PARAM_RE = re.compile(
    r"[?&](redirect|url|next|target|dest|return|returnurl|continue|file|path|"
    r"page|id|token|key|secret|debug|admin|config|callback|ref|redir|load|"
    r"include|require|src|source|template|cmd|exec|command|shell|api_key|"
    r"apikey|access_token)=", re.IGNORECASE)
_SENS_HIST_RE = re.compile(
    r"(/api/|/admin|/login|/auth|/config|/debug|/backup|/staging|/internal|"
    r"/dev/|\.env|\.json|\.xml|\.sql|\.log|\.bak|/graphql|/swagger|/v[0-9]+/)",
    re.IGNORECASE)

# ── Hunt Queue scoring (attention priority, NOT severity) ────────────────────
# Each finding yields zero or more (category, points, reason) signals. An
# asset's score counts every category ONCE (its strongest instance), so 50
# copies of the same weak signal never outrank two different strong ones.
# Priority needs correlation: HIGH requires several distinct strong signals.

# Params worth a closer look (object refs, redirects/fetches, file access).
_HOT_PARAM_RE = re.compile(
    r"[?&](id|[a-z]+_id|file|filename|path|url|uri|redirect|redirect_uri|"
    r"return|returnurl|next|dest|callback|token)=", re.IGNORECASE)
# API paths touching ownership / tenancy / privileged resources.
_SENS_RESOURCE_RE = re.compile(
    r"/(users?|accounts?|orgs?|organizations?|projects?|roles?|permissions?|"
    r"files?|uploads?|documents?|owners?|members?|teams?|tenants?|billing|"
    r"invoices?|payments?|subscriptions?|admin|private)(/|$|\?)", re.IGNORECASE)
# Object identifiers in a path segment: {id}, :id, numeric, uuid, *_id.
_OBJ_ID_RE = re.compile(
    r"(\{[a-z_]*id\}|/:[a-z_]*id\b|/\d{1,12}(/|$|\?)|"
    r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|"
    r"[?&/](user_id|account_id|org_id|project_id|file_id|owner_id)\b)",
    re.IGNORECASE)
# Public-content APIs that are almost never interesting by themselves.
_GENERIC_API_RE = re.compile(
    r"/api/(v\d+/)?(contact|menu|menus|hours|notices?|news|faq|locations?|"
    r"stores?|health|healthz|status|ping|version|config/public|i18n|"
    r"translations?|locales?|countries|currencies|categories|tags|search|"
    r"newsletter|feedback|events?)(/|$|\?)", re.IGNORECASE)
# Vendor / framework / static noise that should never drive priority.
_NOISE_RE = re.compile(
    r"(www\.w3\.org/|xmlns|<svg|svg\+xml|react(-dom)?(\.production|\.development)|"
    r"__next|_next/static|next/dist|webpack|__webpack|node_modules|polyfill|"
    r"core-js|regenerator|babel|@license|@preserve|license|copyright|"
    r"sourceMappingURL|fonts\.googleapis|fonts\.gstatic|cdnjs\.cloudflare|"
    r"cdn\.jsdelivr|unpkg\.com|googletagmanager|google-analytics|"
    r"jquery|lodash|moment(\.min)?\.js|reactjs\.org|react\.dev|nextjs\.org)",
    re.IGNORECASE)
_STATIC_PATH_RE = re.compile(
    r"\.(css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|otf|mp4|webm|mp3|map)"
    r"(\?|$)|/(static|assets|images|img|fonts|media|_next)/", re.IGNORECASE)
_PLACEHOLDER_RE = re.compile(
    r"(example|your[_-]?|xxxx|placeholder|dummy|sample|changeme|<[a-z_]+>|"
    r"\$\{|\{\{|insert[_-]?|replace[_-]?me|test[_-]?key)", re.IGNORECASE)
_SENS_FILE_RE = re.compile(
    r"(\.env\b|\.git/|\.svn/|\.sql\b|\.bak\b|\.old\b|\.backup\b|"
    r"\.ya?ml\b|\.conf\b|\.config\b|\.ini\b|\.pem\b|\.key\b|"
    r"backup|dump|credentials|secrets?\b|wp-config|web\.config|"
    r"phpinfo|server-status|actuator)", re.IGNORECASE)

# Category → (points, reason). Points are deliberately small integers so the
# breakdown reads like "+5 exposed JS secret / +3 staging hostname".
SIGNALS = {
    "secret":        (5, "exposed secret / credential pattern"),
    "exposed-live":  (5, "sensitive file verified live"),
    "source-map":    (4, "source map exposes application code"),
    "admin-tech":    (4, "admin/management product fingerprint"),
    "mgmt-service":  (3, "management service exposed"),
    "bucket":        (3, "cloud storage bucket reference"),
    "host-strong":   (3, "dev/staging/internal/admin hostname"),
    "hist-live":     (3, "live legacy/historical endpoint"),
    "sens-file":     (2, "sensitive file/config path"),
    "object-api":    (2, "object-based API endpoint"),
    "hot-param":     (2, "interesting parameter"),
    "nonstd-port":   (2, "unusual non-standard port"),
    "cred-comment":  (2, "developer comment mentions a credential"),
    "sens-api":      (1, "API touching a sensitive resource"),
    "hist-protected": (1, "live protected (401/403) historical page"),
    "hist-passive":  (1, "sensitive-looking historical URL (unverified)"),
    "info-leak":     (1, "internal host/IP leaked in JS"),
    "auth":          (1, "auth/login surface"),
    "host-weak":     (1, "api/portal hostname"),
    "new":           (1, "new since last monitor run"),
}
# Correlation thresholds. A category counts as "strong" at >= 2 points.
HIGH_SCORE, HIGH_MIN_STRONG = 8, 2
MED_SCORE = 4

# ── Verdict-aware ranking (human/triage axis → display order) ────────────────
# This does NOT touch the per-finding `score` column or the tier firewall; it
# only lets the human verdict influence the *correlated asset rank* shown in the
# Hunt Queue. Policy:
#   - dismissed verdicts contribute nothing (their signals are skipped), so an
#     asset whose only signals were false positives sinks on its own;
#   - a `confirmed` (human/skill live-verified) finding boosts the asset score
#     and pins the asset to HIGH priority, so verified work is always on top.
DISMISSED_FOR_SCORE = ("false_positive", "wont_fix")
CONFIRMED_VERDICTS = ("confirmed",)
CONFIRMED_BOOST = 5          # points added once per asset that has a confirmed finding


def host_signals(host):
    """Hostname-label signals for an asset (counted once per asset)."""
    labels = set(re.split(r"[.-]", (host or "").lower())[:-2] or [])
    if labels & STRONG_HOST_WORDS:
        return [("host-strong", "%s hostname" % "/".join(sorted(labels & STRONG_HOST_WORDS)))]
    if labels & WEAK_HOST_WORDS:
        return [("host-weak", None)]
    return []


def url_signals(text):
    """API / parameter / file signals derivable from a URL or path."""
    t = text or ""
    out = []
    if _NOISE_RE.search(t) or _STATIC_PATH_RE.search(t.split("?")[0]):
        return out
    generic = bool(_GENERIC_API_RE.search(t))
    if not generic and _SENS_RESOURCE_RE.search(t):
        out.append(("object-api", None) if _OBJ_ID_RE.search(t) else ("sens-api", None))
    m = _HOT_PARAM_RE.search(t)
    if m:
        out.append(("hot-param", "interesting parameter: %s" % m.group(1).lower()))
    if _SENS_FILE_RE.search(t.split("?")[0]):
        out.append(("sens-file", None))
    return out


def is_noise(text):
    """True for vendor/framework/static/license strings that should not rank."""
    t = text or ""
    return bool(_NOISE_RE.search(t)) or bool(_STATIC_PATH_RE.search(t.split("?")[0].split()[-1] if t.split() else ""))


def score_assets(findings):
    """Correlate per-finding signals into one explainable score per asset.

    Each category contributes once per asset (its strongest instance), and
    host-level context (hostname words) is added once. The human verdict axis
    adjusts the correlated rank (see DISMISSED_FOR_SCORE / CONFIRMED_BOOST):
    dismissed findings are skipped, and an asset with a confirmed finding is
    boosted and pinned HIGH. A finding's `verdict` is read if present; absent
    (e.g. a pre-triage scan) it is treated as "new", so rankings are unchanged
    until someone triages. Returns
    {asset: {"score", "priority", "reasons": ["+5 exposed secret", ...]}}.
    """
    per = {}
    confirmed = set()
    for f in findings:
        a = f.get("asset") or "(unattributed)"
        verdict = f.get("verdict") or "new"
        if verdict in DISMISSED_FOR_SCORE:
            continue                                  # dismissed: contributes nothing
        if verdict in CONFIRMED_VERDICTS:
            confirmed.add(a)
        sd = f.get("score_detail") or {}
        cats = per.setdefault(a, {})
        for cat, pts, why in sd.get("signals", []):
            if pts > cats.get(cat, (0, ""))[0]:
                cats[cat] = (pts, why)
    out = {}
    for a, cats in per.items():
        if a != "(unattributed)":
            for cat, why in host_signals(a):
                pts, default = SIGNALS[cat]
                cats.setdefault(cat, (pts, why or default))
        items = sorted(cats.items(), key=lambda kv: -kv[1][0])
        score = sum(p for _, (p, _) in items)
        strong = sum(1 for _, (p, _) in items if p >= 2)
        reasons = ["+%d %s" % (p, w) for _, (p, w) in items if p > 0]
        is_confirmed = a in confirmed
        if is_confirmed:
            score += CONFIRMED_BOOST
            reasons.insert(0, "+%d live-confirmed (triage)" % CONFIRMED_BOOST)
        if is_confirmed:
            prio = "HIGH"                              # verified work is always on top
        elif score >= HIGH_SCORE and strong >= HIGH_MIN_STRONG:
            prio = "HIGH"
        elif score >= MED_SCORE:
            prio = "MED"
        else:
            prio = "LOW"
        out[a] = {"score": score, "priority": prio, "strong": strong,
                  "reasons": reasons}
    return out


# Per-source caps so huge files (historical/crawl) can't flood the table; the
# raw data stays browsable through the existing views.
_CAP = 500


def finding_fingerprint(source, ftype, asset, key):
    raw = "{}|{}|{}|{}".format(source, ftype, asset or "", (key or "")).lower()
    return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()


_HOSTNAME_RE = re.compile(r"^[a-z0-9.-]+$")

# Developer comments that name a credential/secret are a stronger signal than a
# generic TODO/FIXME. The scanner already keeps only "interesting" comments; this
# promotes the credential-bearing subset to `suspicious` (still never a vuln).
_COMMENT_SECRET_RE = re.compile(
    r"(?i)(password|passwd|secret|credential|api[_-]?key|token|private[_-]?key)")


def parse_nmap_gnmap(target_path):
    """Parse nmap's grepable output into {(host, port): (service, version)}.

    Uses the `.gnmap` file (stdlib-only, no XML parser needed). The expensive
    `nmap -sV` service/version data was previously written to disk and never
    read back; this makes it available to both the ports table and the finding
    model. Missing/garbled files degrade to an empty map.
    """
    p = Path(target_path) / "ports" / "nmap_results.gnmap"
    out = {}
    if not p.exists():
        return out
    try:
        with open(p, "r", errors="replace") as f:
            for line in f:
                if not line.startswith("Host:") or "Ports:" not in line:
                    continue
                try:
                    host = line.split()[1].strip()
                except IndexError:
                    continue
                ports_seg = line.split("Ports:", 1)[1]
                ports_seg = ports_seg.split("Ignored State:", 1)[0]
                for entry in ports_seg.split(","):
                    fields = entry.strip().split("/")
                    if len(fields) < 5 or fields[1] != "open":
                        continue
                    port = fields[0].strip()
                    service = fields[4].strip()
                    version = fields[6].strip() if len(fields) > 6 else ""
                    if port:
                        out[(host, port)] = (service, version)
    except OSError:
        pass
    return out


def _host_from(s, known_hosts=()):
    """Best-effort host extraction from a URL or raw line.

    Only trusts urlparse when the result is a plausible hostname (free-text
    lines like "token=X api.example.com/app.js" otherwise produce junk), and
    falls back to matching a known host as a substring.
    """
    s = (s or "").strip()
    if not s:
        return ""
    try:
        u = s if "://" in s else "https://" + s
        h = urlparse(u).hostname
        if h and "." in h and _HOSTNAME_RE.match(h):
            return h
    except Exception:
        pass
    for kh in known_hosts:
        if kh and kh in s:
            return kh
    return ""


class ReconDB:
    def __init__(self, db_path):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute('PRAGMA journal_mode=WAL;')
        self.setup()

    def setup(self):
        cur = self.conn.cursor()
        cur.executescript("""
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    domain TEXT NOT NULL,
    duration_minutes INTEGER DEFAULT 0,
    modules_run TEXT DEFAULT '',
    ingested_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    hostname TEXT NOT NULL,
    source TEXT DEFAULT 'unknown',
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_subs_scan ON subdomains(scan_id);
CREATE INDEX IF NOT EXISTS idx_subs_host ON subdomains(hostname);

CREATE TABLE IF NOT EXISTS dns_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    hostname TEXT NOT NULL,
    ip TEXT DEFAULT '',
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_dns_scan ON dns_records(scan_id);

CREATE TABLE IF NOT EXISTS web_apps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    status_code INTEGER DEFAULT 0,
    title TEXT DEFAULT '',
    webserver TEXT DEFAULT '',
    tech TEXT DEFAULT '',
    content_length INTEGER DEFAULT 0,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_webapps_scan ON web_apps(scan_id);
CREATE INDEX IF NOT EXISTS idx_webapps_status ON web_apps(status_code);

CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    service TEXT DEFAULT '',
    version TEXT DEFAULT '',
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_ports_scan ON ports(scan_id);

CREATE TABLE IF NOT EXISTS historical_urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'all',
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_hist_scan ON historical_urls(scan_id);
CREATE INDEX IF NOT EXISTS idx_hist_cat ON historical_urls(scan_id, category);
CREATE INDEX IF NOT EXISTS idx_hist_url ON historical_urls(url);

CREATE TABLE IF NOT EXISTS js_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    finding_type TEXT NOT NULL,
    value TEXT NOT NULL,
    source_url TEXT DEFAULT '',
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_js_scan ON js_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_js_type ON js_findings(finding_type);

CREATE TABLE IF NOT EXISTS dork_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    category TEXT NOT NULL,
    url TEXT NOT NULL,
    source_file TEXT DEFAULT '',
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_dork_scan ON dork_findings(scan_id);

-- Unified finding model: one normalized signal per row (see module header).
CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER NOT NULL,
    fingerprint  TEXT NOT NULL,
    asset        TEXT DEFAULT '',
    url          TEXT DEFAULT '',
    source       TEXT NOT NULL,
    type         TEXT NOT NULL,
    tier         TEXT NOT NULL,
    detector     TEXT DEFAULT '',
    title        TEXT DEFAULT '',
    evidence     TEXT DEFAULT '{}',
    score        INTEGER DEFAULT 0,
    score_detail TEXT DEFAULT '{}',
    state        TEXT DEFAULT 'active',
    first_seen   TEXT,
    last_seen    TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_find_scan  ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_find_asset ON findings(asset);
CREATE INDEX IF NOT EXISTS idx_find_fp    ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_find_tier  ON findings(tier, type);

-- Human triage state, keyed by fingerprint so it SURVIVES re-ingest / rescans.
-- severity is NULL unless a human sets it; the pipeline never writes it.
CREATE TABLE IF NOT EXISTS finding_state (
    fingerprint TEXT PRIMARY KEY,
    verdict     TEXT DEFAULT 'new',
    severity    TEXT,
    starred     INTEGER DEFAULT 0,
    notes       TEXT DEFAULT '',
    updated_at  TEXT
);
        """)
        self.conn.commit()

    def ingest_scan(self, target_dir):
        target_path = Path(target_dir)
        domain = target_path.name
        
        timestamp = None
        duration_minutes = 0
        modules_run = ''
        summary_path = target_path / 'reports' / 'summary.json'
        if summary_path.exists():
            try:
                with open(summary_path) as f:
                    summary = json.load(f)
                    timestamp = summary.get('timestamp')
                    duration_minutes = summary.get('duration_minutes', 0)
                    modules_run = summary.get('modules_run', '')
            except Exception:
                pass

        # Derive a STABLE timestamp key so repeated ingests of the same scan are
        # idempotent. Prefer the summary's own timestamp; fall back to the
        # summary file's mtime; only use "now" when neither exists (that case
        # cannot be deduplicated, which is acceptable for a scan with no report).
        if not timestamp:
            if summary_path.exists():
                try:
                    timestamp = datetime.datetime.fromtimestamp(
                        summary_path.stat().st_mtime).isoformat()
                except OSError:
                    timestamp = datetime.datetime.now().isoformat()
            else:
                timestamp = datetime.datetime.now().isoformat()

        cur = self.conn.cursor()

        # Idempotency: if this scan (same domain + stable timestamp) was already
        # ingested, remove it and its child rows, then re-insert fresh. This keeps
        # manual re-ingests from creating phantom scans in the Diff picker.
        cur.execute(
            "SELECT id FROM scans WHERE domain = ? AND timestamp = ?",
            (domain, timestamp),
        )
        for row in cur.fetchall():
            old_id = row['id']
            for tbl in ('subdomains', 'dns_records', 'web_apps', 'ports',
                        'historical_urls', 'js_findings', 'dork_findings',
                        'findings'):
                cur.execute(f"DELETE FROM {tbl} WHERE scan_id = ?", (old_id,))
            cur.execute("DELETE FROM scans WHERE id = ?", (old_id,))

        cur.execute(
            "INSERT INTO scans (timestamp, domain, duration_minutes, modules_run, ingested_at) VALUES (?, ?, ?, ?, ?)",
            (timestamp, domain, duration_minutes, modules_run, datetime.datetime.now().isoformat())
        )
        scan_id = cur.lastrowid
        
        subs_path = target_path / 'subs' / 'all.txt'
        if subs_path.exists():
            subs = []
            with open(subs_path) as f:
                for line in f:
                    host = line.strip()
                    if host:
                        subs.append((scan_id, host))
            if subs:
                cur.executemany("INSERT INTO subdomains (scan_id, hostname) VALUES (?, ?)", subs)
                
        dns_path = target_path / 'dns' / 'resolved.txt'
        if dns_path.exists():
            dns = []
            with open(dns_path) as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        dns.append((scan_id, parts[0], parts[1]))
            if dns:
                cur.executemany("INSERT INTO dns_records (scan_id, hostname, ip) VALUES (?, ?, ?)", dns)
                
        httpx_path = target_path / 'httpx' / 'results.json'
        if httpx_path.exists():
            apps = []
            with open(httpx_path) as f:
                for line in f:
                    try:
                        obj = json.loads(line)
                        url = obj.get('url', '')
                        if url:
                            apps.append((
                                scan_id, url, obj.get('status_code', 0),
                                obj.get('title', ''), obj.get('webserver', ''),
                                json.dumps(obj.get('tech', [])) if 'tech' in obj else '',
                                obj.get('content_length', 0)
                            ))
                    except Exception:
                        pass
            if apps:
                cur.executemany("INSERT INTO web_apps (scan_id, url, status_code, title, webserver, tech, content_length) VALUES (?, ?, ?, ?, ?, ?, ?)", apps)
                
        ports_path = target_path / 'ports' / 'naabu.txt'
        if ports_path.exists():
            # Enrich host:port pairs with nmap -sV service/version where available
            # (the deep scan runs on the same hosts; keys are matched by both the
            # resolved hostname and bare host that naabu emits).
            nmap = parse_nmap_gnmap(target_path)
            ports = []
            with open(ports_path) as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 2:
                        try:
                            port_int = int(parts[1])
                        except ValueError:
                            continue
                        svc, ver = nmap.get((parts[0], parts[1]), ("", ""))
                        ports.append((scan_id, parts[0], port_int, svc, ver))
            if ports:
                cur.executemany(
                    "INSERT INTO ports (scan_id, host, port, service, version) "
                    "VALUES (?, ?, ?, ?, ?)", ports)
                
        # Historical URLs are served from the file by the dashboard's in-memory
        # HistoricalIndex; nothing reads this table. On large scopes it is
        # millions of rows (minutes of SD-card writes on small hosts), so it is
        # opt-in: set RECON_DB_HISTORICAL=1 to populate it. Streamed, never
        # materialized in memory.
        hist_path = target_path / 'historical' / 'all_urls.txt'
        if hist_path.exists() and os.environ.get('RECON_DB_HISTORICAL', '0') == '1':
            def _hist_rows():
                with open(hist_path, errors='replace') as f:
                    for line in f:
                        url = line.strip()
                        if not url:
                            continue
                        for cat in categorize_url(url):
                            yield (scan_id, url, cat)
            cur.executemany("INSERT INTO historical_urls (scan_id, url, category) VALUES (?, ?, ?)", _hist_rows())

        js_files = [
            ('endpoints.txt', 'endpoint'), ('secrets.txt', 'secret'),
            ('leakage.txt', 'leakage'), ('comments.txt', 'comment'),
            ('api_endpoints.txt', 'api_endpoint')
        ]
        js_records = []
        for fname, ftype in js_files:
            jpath = target_path / 'js' / fname
            if jpath.exists():
                with open(jpath) as f:
                    for line in f:
                        val = line.strip()
                        if val:
                            js_records.append((scan_id, ftype, val, ''))
        if js_records:
            cur.executemany("INSERT INTO js_findings (scan_id, finding_type, value, source_url) VALUES (?, ?, ?, ?)", js_records)
            
        dorks_dir = target_path / 'dorks'
        if dorks_dir.exists():
            dork_records = []
            for dfile in dorks_dir.glob('*.txt'):
                if dfile.name == 'all_findings.txt' or dfile.name.startswith('passive_'):
                    with open(dfile) as f:
                        for line in f:
                            url = line.strip()
                            if url:
                                dork_records.append((scan_id, dfile.stem, url, dfile.name))
            if dork_records:
                cur.executemany("INSERT INTO dork_findings (scan_id, category, url, source_file) VALUES (?, ?, ?, ?)", dork_records)

        # Build the unified finding model from the same on-disk files.
        self.normalize_findings(target_path, scan_id)

        self.conn.commit()
        return scan_id

    # ── Unified finding normalizer ────────────────────────────────────────────
    def normalize_findings(self, target_path, scan_id):
        """Translate the on-disk recon output into tiered finding rows.

        Reads the existing flat files only (no pipeline change required) and
        applies the tier firewall: heuristics => at most 'suspicious';
        'confirmed' only from the active-verification artifacts.
        """
        target_path = Path(target_path)
        now = datetime.datetime.now().isoformat()
        rows = []

        def _read_lines(rel, cap=None):
            # Generator: large files (historical, crawl) are streamed instead of
            # being loaded whole into memory just to be filtered.
            p = target_path / rel
            if not p.exists():
                return
            n = 0
            with open(p, "r", errors="replace") as f:
                for line in f:
                    v = line.strip()
                    if v:
                        yield v
                        n += 1
                        if cap and n >= cap:
                            break

        # Known host set for attribution of host-less lines (JS secrets, etc.)
        known = set()
        for h in _read_lines("subs/all.txt"):
            known.add(h)
        for ln in _read_lines("dns/resolved.txt"):
            known.add(ln.split()[0])

        def sig(*cats):
            """Build a signal list from category names (point/reason from SIGNALS).

            A string entry uses the default reason; a (cat, custom_reason) tuple
            overrides it. Unknown/empty entries are dropped.
            """
            out = []
            for c in cats:
                if not c:
                    continue
                name, why = (c if isinstance(c, tuple) else (c, None))
                if name not in SIGNALS:
                    continue
                pts, default = SIGNALS[name]
                out.append((name, pts, why or default))
            return out

        def add(source, ftype, tier, asset, url, detector, title, evidence,
                signals=None):
            signals = signals or []
            # Per-finding score = sum of ITS OWN signals (orders findings within
            # an asset). Asset-level priority is correlated later in score_assets,
            # which also folds in hostname context once per asset.
            score = sum(p for _, p, _ in signals)
            reasons = ["+%d %s" % (p, w) for _, p, w in signals if p > 0]
            key = url or (evidence.get("match") if isinstance(evidence, dict) else "") or title
            fp = finding_fingerprint(source, ftype, asset, key)
            rows.append((scan_id, fp, asset or "", url or "", source, ftype, tier,
                         detector, title, json.dumps(evidence), score,
                         json.dumps({"signals": [[c, p, w] for c, p, w in signals],
                                     "reasons": reasons}),
                         "active", now, now))

        # ── HTTP probing (observations + suspicious surfaces) ──
        hp = target_path / "httpx" / "results.json"
        if hp.exists():
            with open(hp, "r", errors="replace") as f:
                for line in f:
                    try:
                        o = json.loads(line)
                    except Exception:
                        continue
                    url = o.get("url", "")
                    if not url:
                        continue
                    host = o.get("input") or _host_from(url, known) or ""
                    if host:
                        known.add(host)
                    sc = o.get("status_code", 0)
                    title = o.get("title", "") or ""
                    tech = o.get("tech", []) if isinstance(o.get("tech"), list) else []
                    # Generic "a web service exists here" carries no scoring signal
                    # (existence, ports 80/443, and a bare page are not leads).
                    add("http", "web-service", "observation", host, url, "httpx",
                        title or url, {"status_code": sc, "title": title,
                                       "webserver": o.get("webserver", "")})
                    admin = [t for t in tech if any(a in t.lower() for a in ADMIN_TECH)]
                    if admin:
                        add("http", "tech-fingerprint", "suspicious", host, url, "httpx",
                            "Admin-class tech: " + ", ".join(admin), {"tech": admin},
                            sig(("admin-tech", "admin product: " + ", ".join(admin[:3]))))
                    tl = title.lower()
                    if any(w in tl for w in AUTH_TITLE_WORDS) or _AUTH_RE.search(url.lower()):
                        add("http", "auth-surface", "suspicious", host, url, "httpx",
                            "Auth/login surface" + (': "%s"' % title if title else ""),
                            {"title": title, "status_code": sc}, sig("auth"))
                    if sc in (401, 403):
                        # A bare 401/403 by itself is weak — keep it as a live
                        # signal but give it NO score (it only matters in context).
                        add("http", "access-control-signal", "suspicious", host, url, "httpx",
                            "HTTP %s on %s" % (sc, host), {"status_code": sc})

        # ── Ports ──
        nmap = parse_nmap_gnmap(target_path)
        for ln in _read_lines("ports/naabu.txt"):
            parts = ln.split(":")
            if len(parts) < 2:
                continue
            host, port = parts[0], parts[1]
            nonstd = port not in STD_PORTS
            add("ports", "open-port", "suspicious" if nonstd else "observation",
                host, "", "naabu", "Port %s open on %s" % (port, host),
                {"port": port},
                sig(("nonstd-port", "unusual port %s" % port) if nonstd else None))

        # nmap -sV service/version identification — the expensive deep-scan data
        # that was previously written to disk and never read back. A fingerprinted
        # service (esp. with a version banner) is a concrete recon lead, not just
        # an open port, so it ranks above a bare open-port observation.
        for (host, port), (service, version) in nmap.items():
            if not service or service in ("unknown", "tcpwrapped"):
                continue
            banner = (service + (" " + version if version else "")).strip()
            nonstd = port not in STD_PORTS
            svc_l = service.lower()
            mgmt = any(m in svc_l for m in MGMT_SERVICES)
            add("ports", "service-banner",
                "suspicious" if (version or nonstd or mgmt) else "observation",
                host, "", "nmap",
                "%s on %s:%s" % (banner, host, port),
                {"port": port, "service": service, "version": version},
                sig(("mgmt-service", "management service: " + service) if mgmt else None,
                    ("nonstd-port", "unusual port %s" % port) if nonstd else None))

        # ── JS analysis ──
        # Secrets: skip obvious placeholders/examples (the scanner can match
        # `apiKey: "YOUR_KEY_HERE"`); a real-looking secret is a strong signal.
        for ln in _read_lines("js/secrets.txt", _CAP):
            host = _host_from(ln, known)
            # Scanner lines are "[file:line] [Type] value" — only the value
            # should be placeholder-tested (the file path legitimately contains
            # words like "example" that must not trigger the filter).
            val = ln.rsplit("] ", 1)[-1] if "] " in ln else ln
            if _PLACEHOLDER_RE.search(val):
                continue
            add("js", "secret", "suspicious", host, ln if "://" in ln else "",
                "js:secret", ln[:120], {"match": ln[:300]}, sig("secret"))

        # Internal-IP / dev-domain leakage.
        for ln in _read_lines("js/leakage.txt", _CAP):
            host = _host_from(ln, known)
            add("js", "info-leak", "suspicious", host, ln if "://" in ln else "",
                "js:leakage", ln[:120], {"match": ln[:300]}, sig("info-leak"))

        # Cloud storage buckets.
        for ln in _read_lines("js/buckets.txt", _CAP):
            host = _host_from(ln, known)
            add("js", "bucket", "suspicious", host, ln if "://" in ln else "",
                "js:bucket", ln[:120], {"match": ln[:300]}, sig("bucket"))

        # Reconstructed source-map files = application source code on disk.
        for ln in _read_lines("js/maps_files.txt", _CAP):
            if is_noise(ln):        # vendor chunk (node_modules, polyfills, …)
                continue
            host = _host_from(ln, known)
            add("js", "source-map", "suspicious", host, "", "js:sourcemap",
                ln[:120], {"match": ln[:300]}, sig("source-map"))

        for ln in _read_lines("js/websockets.txt", _CAP):
            host = _host_from(ln, known)
            add("js", "websocket", "observation", host, ln if "://" in ln else "",
                "js:websocket", ln[:120], {"match": ln[:300]})

        # API endpoints & generic endpoints: only signal when the URL itself is
        # interesting (object id / sensitive resource / hot param). Vendor,
        # framework, static and generic public APIs are kept as observations
        # with no score so they never float to the top of the Hunt Queue.
        for rel, ftype, det in (("js/api_endpoints.txt", "api-endpoint", "js:api"),
                                 ("js/endpoints.txt", "endpoint", "js:endpoint")):
            for ln in _read_lines(rel, _CAP):
                host = _host_from(ln, known)
                noise = is_noise(ln) or bool(_GENERIC_API_RE.search(ln))
                usig = [] if noise else sig(*url_signals(ln))
                tier = "suspicious" if usig else "observation"
                add("js", ftype, tier, host, ln if "://" in ln else "",
                    det, ln[:120], {"match": ln[:300], "noise": noise}, usig)

        # Developer comments: the scanner keeps only "interesting" comments, so
        # these are already filtered. Promote credential-bearing ones to
        # `suspicious` (firewall: keyword match can go no higher); the rest stay
        # observations. Lines look like "[<url-or-file>:<line>] // TODO ...".
        for ln in _read_lines("js/comments.txt", _CAP):
            host = _host_from(ln, known)
            secret = bool(_COMMENT_SECRET_RE.search(ln))
            add("js", "comment", "suspicious" if secret else "observation",
                host, host and ln if "://" in ln else "", "js:comment",
                ln[:160], {"match": ln[:300]},
                sig("cred-comment") if secret else [])

        # ── Dorks: passive => suspicious, active_confirmed => confirmed, 403 => acl ──
        for ln in _read_lines("dorks/active_confirmed.txt", _CAP):
            host = _host_from(ln, known)
            add("dorks", "exposed-file", "confirmed", host, ln if "://" in ln else "",
                "dork:active", "Exposed file (live): " + ln[:120], {"match": ln[:300]},
                sig("exposed-live",
                    "sens-file" if _SENS_FILE_RE.search(ln.split("?")[0]) else None))
        for ln in _read_lines("dorks/active_403.txt", _CAP):
            host = _host_from(ln, known)
            # Forbidden path — live but unauthorised; no score on its own.
            add("dorks", "access-control-signal", "suspicious", host, ln if "://" in ln else "",
                "dork:active", "Forbidden (403) path: " + ln[:120], {"match": ln[:300], "status_code": 403})
        dorks_dir = target_path / "dorks"
        if dorks_dir.exists():
            passive_total = 0
            for pf in sorted(dorks_dir.glob("passive_*.txt")):
                cat = pf.stem.replace("passive_", "")
                with open(pf, "r", errors="replace") as f:
                    for line in f:
                        ln = line.strip()
                        if not ln:
                            continue
                        host = _host_from(ln, known)
                        # Passive dork hits are unverified; signal only the ones
                        # that look like a sensitive file/config path.
                        sf = bool(_SENS_FILE_RE.search(ln.split("?")[0]))
                        add("dorks", "exposed-file", "suspicious", host,
                            ln if "://" in ln else "", "dork:passive",
                            "Dork hit (%s): %s" % (cat, ln[:100]),
                            {"match": ln[:300], "category": cat},
                            sig("sens-file") if sf else [])
                        passive_total += 1
                        if passive_total >= _CAP:
                            break
                if passive_total >= _CAP:
                    break

        # ── Historical: sensitive patterns => suspicious; validated-live => confirmed ──
        hist_sens = 0
        for ln in _read_lines("historical/all_urls.txt"):
            if not _SENS_HIST_RE.search(ln):
                continue
            host = _host_from(ln, known)
            add("historical", "historical-url", "suspicious", host, ln, "historical:passive",
                ln[:120], {"match": ln[:300]},
                sig("hist-passive", *url_signals(ln)))
            hist_sens += 1
            if hist_sens >= _CAP:
                break
        vf = target_path / "historical" / "validated_interesting.json"
        if vf.exists():
            with open(vf, "r", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        it = json.loads(line)
                    except Exception:
                        continue
                    url = it.get("url", "")
                    if not url:
                        continue
                    host = _host_from(url, known)
                    sc = it.get("status_code")
                    ev = {"status_code": sc, "title": it.get("title", ""),
                          "content_type": it.get("content_type", "")}
                    if isinstance(sc, int) and 200 <= sc < 300:
                        add("historical", "historical-url", "confirmed", host, url,
                            "historical:validated", "Live historical page [%s]: %s" % (sc, url[:90]),
                            ev, sig("hist-live", *url_signals(url)))
                    elif sc in (401, 403):
                        add("historical", "access-control-signal", "confirmed", host, url,
                            "historical:validated", "Live protected page [%s]: %s" % (sc, url[:90]),
                            ev, sig("hist-protected", *url_signals(url)))

        # ── Crawling: interesting params / api paths / sensitive files ──
        cap = 0
        for ln in _read_lines("endpoints/all.txt"):
            if not _PARAM_RE.search(ln):
                continue
            host = _host_from(ln, known)
            us = url_signals(ln)
            add("crawl", "interesting-param", "suspicious", host, ln, "katana",
                ln[:120], {"match": ln[:300]}, sig(*us) or sig("hot-param"))
            cap += 1
            if cap >= _CAP:
                break
        for ln in _read_lines("endpoints/api_paths.txt", _CAP):
            host = _host_from(ln, known)
            noise = is_noise(ln) or bool(_GENERIC_API_RE.search(ln))
            us = [] if noise else sig(*url_signals(ln))
            add("crawl", "api-path", "suspicious" if us else "observation", host,
                ln if "://" in ln else "", "crawl", ln[:120],
                {"match": ln[:300], "noise": noise}, us)
        for ln in _read_lines("endpoints/sensitive_files.txt", _CAP):
            host = _host_from(ln, known)
            add("crawl", "sensitive-file", "suspicious", host, ln if "://" in ln else "",
                "crawl", ln[:120], {"match": ln[:300]}, sig("sens-file"))

        # ── Infrastructure: shared-IP grouping (high-value recon pivot) ──
        ip_hosts = {}
        for ln in _read_lines("infra/ip_host_map.txt"):
            parts = ln.split()
            if len(parts) >= 2:
                ip_hosts.setdefault(parts[0], set()).add(parts[1])
        ip_orgs = {}
        for ln in _read_lines("infra/ip_orgs.txt"):
            if "=>" in ln:
                ip, org = ln.split("=>", 1)
                ip_orgs[ip.strip()] = org.strip()
        infra_emitted = 0
        for ip, hosts in ip_hosts.items():
            if len(hosts) < 2:            # only *shared* infrastructure is a pivot
                continue
            ordered = sorted(hosts)
            for host in ordered:
                if infra_emitted >= _CAP:
                    break
                co = [h for h in ordered if h != host]
                ev = {"ip": ip, "host_count": len(hosts), "shared_with": co[:20]}
                if ip in ip_orgs:
                    ev["org"] = ip_orgs[ip]
                org_txt = (" (" + ip_orgs[ip] + ")") if ip in ip_orgs else ""
                add("infra", "shared-infra", "observation", host, "", "infra",
                    "Shares %s%s with %d other host%s" % (ip, org_txt, len(co), "" if len(co) == 1 else "s"),
                    ev)
                infra_emitted += 1
            if infra_emitted >= _CAP:
                break

        # ── Monitoring: latest change record => change observations/signals ──
        changes_dir = target_path / "monitor" / "changes"
        if changes_dir.is_dir():
            files = sorted(changes_dir.glob("*.json"), reverse=True)
            if files:
                try:
                    with open(files[0], "r", errors="replace") as f:
                        chg = json.load(f)
                except Exception:
                    chg = None
                if chg:
                    for h in (chg.get("new_subdomains") or [])[:_CAP]:
                        add("monitor", "change", "observation", h, "", "monitor",
                            "New subdomain: " + h, {"change": "new_subdomain"},
                            sig("new"))
                    for hp2 in (chg.get("new_ports") or [])[:_CAP]:
                        host = hp2.split(":")[0] if ":" in hp2 else hp2
                        port = hp2.split(":")[1] if ":" in hp2 else ""
                        nonstd = port and port not in STD_PORTS
                        add("monitor", "change", "suspicious" if nonstd else "observation",
                            host, "", "monitor", "New port: " + hp2,
                            {"change": "new_port", "port": port},
                            sig("new", ("nonstd-port", "unusual port %s" % port) if nonstd else None))

        if rows:
            cur = self.conn.cursor()
            cur.executemany(
                "INSERT INTO findings (scan_id, fingerprint, asset, url, source, type, "
                "tier, detector, title, evidence, score, score_detail, state, "
                "first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        return len(rows)

    # ── Finding queries & human state ─────────────────────────────────────────
    def get_findings(self, tier=None, ftype=None, asset=None, source=None, scan_id=None):
        cur = self.conn.cursor()
        if scan_id is None:
            cur.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
            scan_id = row["id"] if row else None
        if scan_id is None:
            return {"findings": [], "counts": {}, "scan_id": None}

        q = "SELECT * FROM findings WHERE scan_id = ?"
        p = [scan_id]
        if tier:
            q += " AND tier = ?"; p.append(tier)
        if ftype:
            q += " AND type = ?"; p.append(ftype)
        if asset is not None:
            # The queue groups host-less findings under "(unattributed)".
            q += " AND asset = ?"; p.append("" if asset == "(unattributed)" else asset)
        if source:
            q += " AND source = ?"; p.append(source)
        q += " ORDER BY score DESC, id ASC"
        cur.execute(q, p)
        rows = [dict(r) for r in cur.fetchall()]

        cur.execute("SELECT * FROM finding_state")
        states = {r["fingerprint"]: dict(r) for r in cur.fetchall()}
        for r in rows:
            st = states.get(r["fingerprint"])
            r["verdict"] = st["verdict"] if st else "new"
            r["severity"] = st["severity"] if st else None
            r["starred"] = bool(st["starred"]) if st else False
            r["notes"] = st["notes"] if st else ""
            for jf in ("evidence", "score_detail"):
                try:
                    r[jf] = json.loads(r[jf])
                except Exception:
                    r[jf] = {}

        cur.execute("SELECT tier, COUNT(*) c FROM findings WHERE scan_id = ? GROUP BY tier", [scan_id])
        counts = {row["tier"]: row["c"] for row in cur.fetchall()}
        # Correlated per-asset priority/score/reasons (single source of truth).
        assets = score_assets(rows)
        return {"findings": rows, "counts": counts, "scan_id": scan_id, "assets": assets}

    # Verdicts that dismiss a finding (mirrors DISMISSED_VERDICTS in the client).
    DISMISSED_VERDICTS = ("false_positive", "wont_fix")
    PREVIEW_PER_ASSET = 8   # list rows show <=5 groups; the dossier loads the rest

    def get_asset_summaries(self, scan_id=None):
        """Per-asset Hunt Queue rows for the latest (or given) scan.

        The queue used to ship every finding with full evidence to the browser
        and group/score them there. This returns one compact row per asset
        (server-side priority/score/reasons from score_assets, tier counts, a
        dismissed flag, and a short preview of its top findings) plus a
        lowercase label blob per asset for full-text search. The full findings
        for one asset are fetched on demand via get_findings(asset=...).
        """
        cur = self.conn.cursor()
        if scan_id is None:
            cur.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
            scan_id = row["id"] if row else None
        if scan_id is None:
            return {"scan_id": None, "counts": {}, "assets": [], "search": {}}

        cur.execute("SELECT fingerprint, verdict FROM finding_state")
        verdicts = {r["fingerprint"]: r["verdict"] for r in cur.fetchall()}

        cur.execute(
            "SELECT asset, url, source, type, tier, title, evidence, score, "
            "score_detail, fingerprint FROM findings WHERE scan_id = ? "
            "ORDER BY score DESC, id ASC", (scan_id,))
        per = {}
        scoring = []
        for r in cur:
            a = r["asset"] or "(unattributed)"
            try:
                sd = json.loads(r["score_detail"] or "{}")
            except Exception:
                sd = {}
            verdict = verdicts.get(r["fingerprint"]) or "new"
            # Pass verdict into the correlation so dismissed findings are
            # excluded and confirmed ones boost/pin the asset (score_assets).
            scoring.append({"asset": a, "score_detail": sd, "verdict": verdict})
            try:
                ev = json.loads(r["evidence"] or "{}")
            except Exception:
                ev = {}
            if not isinstance(ev, dict):
                ev = {}
            e = per.get(a)
            if e is None:
                e = per[a] = {"host": a, "n": 0, "tiers": {}, "live": False,
                              "web": None, "tech": None, "any_url": "",
                              "status": None, "preview": [], "labels": []}
            e["n"] += 1
            e["tiers"][r["tier"]] = e["tiers"].get(r["tier"], 0) + 1
            if verdict not in self.DISMISSED_VERDICTS:
                e["live"] = True
            if r["type"] == "web-service" and e["web"] is None:
                e["web"] = (r["url"], ev)
            if r["type"] == "tech-fingerprint" and e["tech"] is None:
                e["tech"] = ev.get("tech") or []
            if r["url"] and not e["any_url"]:
                e["any_url"] = r["url"]
            if e["status"] is None and ev.get("status_code"):
                e["status"] = ev.get("status_code")
            label = r["title"] or r["url"] or r["type"]
            e["labels"].append(label.lower())
            if len(e["preview"]) < self.PREVIEW_PER_ASSET:
                slim_ev = {}
                for k in ("match", "source"):
                    if ev.get(k):
                        slim_ev[k] = str(ev[k])[:200]   # chips show ~140 chars
                # Chip fields only: fingerprints/sources come with the full
                # findings the dossier loads before showing verdict controls.
                e["preview"].append({
                    "type": r["type"], "tier": r["tier"], "title": r["title"],
                    "url": r["url"], "score": r["score"], "verdict": verdict,
                    "evidence": slim_ev,
                })

        scored = score_assets(scoring)
        del scoring
        assets, search = [], {}
        for a, e in per.items():
            sc = scored.get(a) or {"score": 0, "priority": "LOW", "reasons": []}
            web_url, web_ev = e["web"] if e["web"] else ("", {})
            assets.append({
                "host": a,
                "url": web_url or e["any_url"] or ("http://" + a),
                "title": (web_ev or {}).get("title", "") or "",
                "status_code": (web_ev or {}).get("status_code") or e["status"],
                "tech": e["tech"] or [],
                "priority": sc["priority"], "score": sc["score"],
                "reasons": sc.get("reasons", []),
                "n": e["n"], "tiers": e["tiers"],
                "dismissed": not e["live"],
                "preview": e["preview"],
            })
            search[a] = "\n".join(e["labels"])
        pm = {"HIGH": 3, "MED": 2, "LOW": 1}
        assets.sort(key=lambda x: (-pm.get(x["priority"], 0), -x["score"], -x["n"]))

        cur.execute("SELECT tier, COUNT(*) c FROM findings WHERE scan_id = ? GROUP BY tier", (scan_id,))
        counts = {row["tier"]: row["c"] for row in cur.fetchall()}
        return {"scan_id": scan_id, "counts": counts, "assets": assets, "search": search}

    def set_finding_state(self, fingerprint, verdict=None, severity=None, starred=None, notes=None):
        now = datetime.datetime.now().isoformat()
        cur = self.conn.cursor()
        cur.execute("SELECT fingerprint FROM finding_state WHERE fingerprint = ?", (fingerprint,))
        if cur.fetchone() is None:
            cur.execute(
                "INSERT INTO finding_state (fingerprint, verdict, severity, starred, notes, updated_at) "
                "VALUES (?,?,?,?,?,?)",
                (fingerprint, verdict or "new", severity, 1 if starred else 0, notes or "", now))
        else:
            sets, vals = [], []
            if verdict is not None:
                sets.append("verdict = ?"); vals.append(verdict)
            if severity is not None:
                sets.append("severity = ?"); vals.append(severity or None)
            if starred is not None:
                sets.append("starred = ?"); vals.append(1 if starred else 0)
            if notes is not None:
                sets.append("notes = ?"); vals.append(notes)
            sets.append("updated_at = ?"); vals.append(now)
            vals.append(fingerprint)
            cur.execute("UPDATE finding_state SET %s WHERE fingerprint = ?" % ", ".join(sets), vals)
        self.conn.commit()
        return True

    def get_scans(self):
        cur = self.conn.cursor()
        cur.execute("SELECT id, timestamp, domain, duration_minutes, modules_run FROM scans ORDER BY timestamp DESC")
        return [dict(row) for row in cur.fetchall()]

    def get_diff(self, scan_a, scan_b):
        cur = self.conn.cursor()
        diff = {
            'subdomains': {'added': [], 'removed': []},
            'ports': {'added': [], 'removed': []},
            'web_apps': {'added': [], 'removed': [], 'status_changed': []}
        }
        
        cur.execute("SELECT hostname FROM subdomains WHERE scan_id=? EXCEPT SELECT hostname FROM subdomains WHERE scan_id=?", (scan_b, scan_a))
        diff['subdomains']['added'] = [row['hostname'] for row in cur.fetchall()]
        cur.execute("SELECT hostname FROM subdomains WHERE scan_id=? EXCEPT SELECT hostname FROM subdomains WHERE scan_id=?", (scan_a, scan_b))
        diff['subdomains']['removed'] = [row['hostname'] for row in cur.fetchall()]
        
        cur.execute("SELECT host, port FROM ports WHERE scan_id=? EXCEPT SELECT host, port FROM ports WHERE scan_id=?", (scan_b, scan_a))
        diff['ports']['added'] = [{'host': row['host'], 'port': row['port']} for row in cur.fetchall()]
        cur.execute("SELECT host, port FROM ports WHERE scan_id=? EXCEPT SELECT host, port FROM ports WHERE scan_id=?", (scan_a, scan_b))
        diff['ports']['removed'] = [{'host': row['host'], 'port': row['port']} for row in cur.fetchall()]
        
        cur.execute("SELECT url FROM web_apps WHERE scan_id=? EXCEPT SELECT url FROM web_apps WHERE scan_id=?", (scan_b, scan_a))
        diff['web_apps']['added'] = [row['url'] for row in cur.fetchall()]
        cur.execute("SELECT url FROM web_apps WHERE scan_id=? EXCEPT SELECT url FROM web_apps WHERE scan_id=?", (scan_a, scan_b))
        diff['web_apps']['removed'] = [row['url'] for row in cur.fetchall()]
        
        cur.execute('''
            SELECT a.url, a.status_code as old_status, b.status_code as new_status
            FROM web_apps a
            JOIN web_apps b ON a.url = b.url
            WHERE a.scan_id = ? AND b.scan_id = ? AND a.status_code != b.status_code
        ''', (scan_a, scan_b))
        diff['web_apps']['status_changed'] = [
            {'url': row['url'], 'old_status': row['old_status'], 'new_status': row['new_status']} 
            for row in cur.fetchall()
        ]
        
        return diff

    def close(self):
        self.conn.close()
