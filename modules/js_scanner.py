#!/usr/bin/env python3
import sys
import os
import re
import json
from bisect import bisect_right
from multiprocessing import Pool

# Regex definitions for secrets
SECRET_PATTERNS = {
    "AWS Access Key": r'\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b',
    "AWS Secret Key": r'\b[a-zA-Z0-9+/]{40}\b', # Checked via context or length, let's keep it specific in JS
    "Google API Key": r'\bAIza[yA-Z0-9_-]{35}\b',
    "Firebase URL": r'https://[a-zA-Z0-9-]+\.firebaseio\.com',
    "Slack Webhook": r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
    "GitHub Token": r'\b(gh[psour]_[a-zA-Z0-9]{36,40})\b',
    "Stripe API Key": r'\b(sk|rk)_(live|test)_[0-9a-zA-Z]{24,34}\b',
    "Discord Webhook": r'https://discord\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+',
    "Facebook OAuth": r'\b[fF]acebook|[fF][bB]_?[aA]pp_?[iI]d\b.*?\b[0-9a-f]{32}\b',
    "JWT Token": r'\beyJhbGciOi[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\b',
    "Mailgun API Key": r'\bkey-[a-f0-9]{32}\b',
    "API Key (Generic)": r"(?i)\b(api_key|apikey|secret_key|secretkey|auth_token|authtoken|access_token|accesstoken|session_token|sessiontoken)\s*[:=]\s*[\"']([a-zA-Z0-9_-]{16,64})[\"']",
    "Private Key": r'-----BEGIN[ A-Z0-9_-]+PRIVATE KEY-----',
}

# Regex for internal IPs & Dev domains
INTERNAL_IP_PATTERN = r'\b(127\.0\.0\.1|localhost|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'
DEV_DOMAIN_PATTERN = r'\b([a-zA-Z0-9_-]+\.(?:local|internal|dev|test|staging|localhost))\b'

# Regex for relative endpoints in JS strings
ENDPOINT_PATTERN = r'["\x27](/[a-zA-Z0-9_\-\.\:\/\{\}]+)["\x27]'

# Cloud storage buckets (S3, GCS, Azure Blob, DigitalOcean Spaces, etc.)
BUCKET_PATTERN = (
    r'(?i)\b('
    r'[a-z0-9.\-]+\.s3[a-z0-9.\-]*\.amazonaws\.com'
    r'|s3[a-z0-9.\-]*\.amazonaws\.com/[a-z0-9._\-]+'
    r'|[a-z0-9._\-]+\.storage\.googleapis\.com'
    r'|storage\.googleapis\.com/[a-z0-9._\-]+'
    r'|[a-z0-9._\-]+\.blob\.core\.windows\.net'
    r'|[a-z0-9._\-]+\.[a-z0-9\-]+\.digitaloceanspaces\.com'
    r'|[a-z0-9._\-]+\.r2\.cloudflarestorage\.com'
    r')\b'
)

# WebSocket endpoints
WEBSOCKET_PATTERN = r'(wss?://[a-zA-Z0-9._\-]+(?::\d+)?(?:/[^\s"\x27<>]*)?)'

# Regex for developer comments
# Matches // comments and /* ... */ comments
COMMENT_PATTERN = r'(//.*|/\*.*?\*/)'
INTERESTING_COMMENT_KEYWORDS = r'(?i)\b(todo|fixme|bug|hack|password|username|creds|credential|secret|key|deprecated|remove|temp|bypass|debug)\b'

# ── Noise filters ────────────────────────────────────────────────────────────
# Obvious vendor / framework / build-tool paths that are not application
# endpoints. Filtered out before results reach the Hunt Queue so minified React/
# Next.js internals, polyfills, source-map URLs and CDN assets stop dominating.
VENDOR_ENDPOINT_RE = re.compile(
    r'(?i)('
    r'/_next/|/node_modules/|/webpack|/__webpack|/static/chunks/|'
    r'\.(css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|otf|mp4|map)$|'
    r'/polyfill|/core-js|/regenerator|/vendors?[-.]|/runtime[-.]|'
    r'/react(-dom)?[-.]|/chunk[-.]|\.min\.js$'
    r')')
# Secret matches that are clearly placeholders / examples, not real values.
PLACEHOLDER_SECRET_RE = re.compile(
    r'(?i)(example|your[_-]?|xxxx+|placeholder|dummy|sample|changeme|'
    r'<[a-z_]+>|\$\{|\{\{|insert[_-]?|replace[_-]?me|test[_-]?key|'
    r'000000|123456|abcdef)')
# Framework/library noise in a comment (e.g. bundled license banners).
VENDOR_COMMENT_RE = re.compile(
    r'(?i)(@license|@preserve|copyright|all rights reserved|'
    r'licensed under|\(c\)\s*\d{4}|react|webpack|babel|polyfill)')

# Precompiled once (the per-line re.findall(str) path re-resolved every pattern
# through the re cache on every line — the dominant cost on big bundles).
_SECRET_RES = [(name, re.compile(p)) for name, p in SECRET_PATTERNS.items()]
_IP_RE = re.compile(INTERNAL_IP_PATTERN)
_DEV_RE = re.compile(DEV_DOMAIN_PATTERN)
_COMMENT_RE = re.compile(COMMENT_PATTERN)
_COMMENT_KW_RE = re.compile(INTERESTING_COMMENT_KEYWORDS)
_ENDPOINT_RE = re.compile(ENDPOINT_PATTERN)
_BUCKET_RE = re.compile(BUCKET_PATTERN)
_WEBSOCKET_RE = re.compile(WEBSOCKET_PATTERN)

# Files larger than this are only scanned up to the limit (memory bound for
# small hosts). Override with JS_SCAN_MAX_BYTES.
MAX_FILE_BYTES = int(os.environ.get("JS_SCAN_MAX_BYTES", 25 * 1024 * 1024))

# The scanner's own outputs live in the same directory it scans; re-reading
# them only re-finds already-reported values with the wrong file attribution.
OWN_OUTPUTS = {"endpoints.txt", "secrets.txt", "leakage.txt", "comments.txt",
               "buckets.txt", "websockets.txt"}


# Literal prefilters: a pattern can only match if one of its required literals
# occurs in the file, so skipping it otherwise is exact (same output) and avoids
# running expensive \b-prefixed scans over multi-MB bundles. (cs = case-
# sensitive needles checked on the raw text, ci = lowercase needles checked on
# the lowercased text.) Patterns without an entry always run.
_NEEDLES = {
    "AWS Access Key": ("cs", ("A3T", "AKIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASIA")),
    "Google API Key": ("cs", ("AIza",)),
    "Firebase URL": ("cs", (".firebaseio.com",)),
    "Slack Webhook": ("cs", ("https://hooks.slack.com/services/T",)),
    "GitHub Token": ("cs", ("ghp_", "ghs_", "gho_", "ghu_", "ghr_")),
    "Stripe API Key": ("cs", ("_live_", "_test_")),
    "Discord Webhook": ("cs", ("https://discord.com/api/webhooks/",)),
    "JWT Token": ("cs", ("eyJhbGciOi",)),
    "Mailgun API Key": ("cs", ("key-",)),
    "API Key (Generic)": ("ci", ("api_key", "apikey", "secret_key", "secretkey", "auth_token",
                                 "authtoken", "access_token", "accesstoken", "session_token",
                                 "sessiontoken")),
    "Private Key": ("cs", ("-----BEGIN",)),
    "_IP": ("cs", ("127.0.0.1", "localhost", "10.", "172.", "192.168.")),
    "_DEV": ("cs", (".local", ".internal", ".dev", ".test", ".staging")),
    "_BUCKET": ("ci", ("amazonaws.com", "storage.googleapis.com", "blob.core.windows.net",
                       "digitaloceanspaces.com", "r2.cloudflarestorage.com")),
    "_WS": ("cs", ("ws://", "wss://")),
}


def _may_match(key, content, lower):
    spec = _NEEDLES.get(key)
    if key == "Facebook OAuth":
        # alt 1 needs "[fF]acebook", alt 2 needs "[fF][bB]..." => "fb" (any case)
        return "acebook" in content or "fb" in lower
    if not spec:
        return True
    mode, needles = spec
    hay = content if mode == "cs" else lower
    return any(n in hay for n in needles)


def _group0(m):
    """Value of a findall-style match: group 1 if the pattern has groups."""
    return m.group(1) if m.re.groups else m.group(0)


def scan_file(file_path, base_dir):
    rel_path = os.path.relpath(file_path, base_dir)
    results = {
        "endpoints": set(),
        "secrets": [],
        "leakage": set(),
        "comments": [],
        "buckets": set(),
        "websockets": set(),
    }

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read(MAX_FILE_BYTES)
    except Exception:
        return results

    # Line starts, so whole-content matches can report the same 1-based line
    # numbers (and line text) the old line-by-line scan produced.
    starts = [0]
    find = content.find
    i = find('\n')
    while i != -1:
        starts.append(i + 1)
        i = find('\n', i + 1)

    def line_of(pos):
        return bisect_right(starts, pos)

    def line_text(n):
        a = starts[n - 1]
        b = starts[n] - 1 if n < len(starts) else len(content)
        return content[a:b]

    lower = content.lower()
    placeholder_line = {}   # line -> bool; a minified bundle is one huge line

    # 1. Secrets check (per pattern, in file order — same order as before)
    found = []
    for idx, (name, rx) in enumerate(_SECRET_RES):
        if not _may_match(name, content, lower):
            continue
        for m in rx.finditer(content):
            # findall semantics: tuple when >1 group (take [1]), else group/whole
            if rx.groups > 1:
                match_str = m.group(2)
            elif rx.groups == 1:
                match_str = m.group(1)
            else:
                match_str = m.group(0)
            if match_str is None:
                match_str = ""
            if name == "AWS Secret Key" and (match_str.upper() == match_str or match_str.lower() == match_str):
                continue
            if PLACEHOLDER_SECRET_RE.search(match_str):
                continue
            ln = line_of(m.start())
            ph = placeholder_line.get(ln)
            if ph is None:
                ph = placeholder_line[ln] = bool(PLACEHOLDER_SECRET_RE.search(line_text(ln).strip()))
            if ph:
                continue
            found.append((ln, idx, m.start(), name, match_str))
    found.sort()
    for ln, _idx, _pos, name, match_str in found:
        results["secrets"].append({"file": rel_path, "line": ln, "type": name, "match": match_str})

    # 2. Leakage check (IPs / Dev domains)
    if _may_match("_IP", content, lower):
        for m in _IP_RE.finditer(content):
            results["leakage"].add(_group0(m))
    if _may_match("_DEV", content, lower):
        for m in _DEV_RE.finditer(content):
            results["leakage"].add(_group0(m))

    # 3. Comments check
    for m in _COMMENT_RE.finditer(content):
        comment = m.group(1)
        if _COMMENT_KW_RE.search(comment) and not VENDOR_COMMENT_RE.search(comment):
            results["comments"].append({
                "file": rel_path,
                "line": line_of(m.start()),
                "comment": comment[:200].strip()  # Truncate long comments
            })

    # 4. Global endpoint extraction (across multiple lines / entire content)
    for m in _ENDPOINT_RE.finditer(content):
        ep = m.group(1)
        # Basic validation: ensure it's a path, not just a slash, and doesn't look like file extension metadata or HTML tags
        if (len(ep) > 1 and not ep.startswith('//') and not ep.startswith('/<')
                and not ep.endswith('/') and not ep.endswith('.css')
                and not ep.endswith('.png') and not ep.endswith('.jpg')
                and not ep.endswith('.jpeg') and not ep.endswith('.gif')
                and not VENDOR_ENDPOINT_RE.search(ep)):
            results["endpoints"].add(ep)

    # 5. Cloud storage buckets
    if _may_match("_BUCKET", content, lower):
        for m in _BUCKET_RE.finditer(content):
            bucket = _group0(m)
            if bucket:
                results["buckets"].add(bucket)

    # 6. WebSocket endpoints
    if _may_match("_WS", content, lower):
        for m in _WEBSOCKET_RE.finditer(content):
            ws = _group0(m)
            if ws:
                results["websockets"].add(ws)

    return results


def _scan_job(args):
    return scan_file(*args)


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 js_scanner.py <input_dir> <output_dir>")
        sys.exit(1)

    input_dir = sys.argv[1]
    output_dir = sys.argv[2]

    if not os.path.exists(input_dir):
        print(f"[-] Input directory not found: {input_dir}")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    endpoints_all = set()
    secrets_all = []
    leakage_all = set()
    comments_all = []
    buckets_all = set()
    websockets_all = set()

    # Recurse and scan
    jobs = []
    for root, _, files in os.walk(input_dir):
        for f in files:
            if root == input_dir and f in OWN_OUTPUTS:
                continue
            if f.endswith('.js') or f.endswith('.txt') or f.endswith('.json'):
                jobs.append((os.path.join(root, f), input_dir))

    # Parallel across files, but leave half the CPUs free (small hosts run the
    # rest of the pipeline and the dashboard alongside). JS_SCAN_WORKERS overrides.
    try:
        workers = int(os.environ.get("JS_SCAN_WORKERS", 0))
    except ValueError:
        workers = 0
    if workers <= 0:
        workers = max(1, min(4, (os.cpu_count() or 2) // 2))

    def _results():
        if workers > 1 and len(jobs) > 1:
            with Pool(workers, maxtasksperchild=50) as pool:
                # imap keeps file order, so output order matches a serial run
                for res in pool.imap(_scan_job, jobs, chunksize=1):
                    yield res
        else:
            for job in jobs:
                yield _scan_job(job)

    for res in _results():
        endpoints_all.update(res["endpoints"])
        secrets_all.extend(res["secrets"])
        leakage_all.update(res["leakage"])
        comments_all.extend(res["comments"])
        buckets_all.update(res["buckets"])
        websockets_all.update(res["websockets"])

    # Write endpoints
    with open(os.path.join(output_dir, "endpoints.txt"), "w") as f:
        for ep in sorted(endpoints_all):
            f.write(ep + "\n")

    # Write secrets (structured output)
    with open(os.path.join(output_dir, "secrets.txt"), "w") as f:
        for s in secrets_all:
            f.write(f"[{s['file']}:{s['line']}] [{s['type']}] {s['match']}\n")

    # Write leakage
    with open(os.path.join(output_dir, "leakage.txt"), "w") as f:
        for leak in sorted(leakage_all):
            f.write(leak + "\n")

    # Write comments
    with open(os.path.join(output_dir, "comments.txt"), "w") as f:
        for c in comments_all:
            f.write(f"[{c['file']}:{c['line']}] {c['comment']}\n")

    # Write buckets
    with open(os.path.join(output_dir, "buckets.txt"), "w") as f:
        for b in sorted(buckets_all):
            f.write(b + "\n")

    # Write websockets
    with open(os.path.join(output_dir, "websockets.txt"), "w") as f:
        for ws in sorted(websockets_all):
            f.write(ws + "\n")

    print(f"[+] JS Scanner complete: {len(endpoints_all)} endpoints, {len(secrets_all)} secrets, "
          f"{len(leakage_all)} leakage, {len(comments_all)} comments, {len(buckets_all)} buckets, "
          f"{len(websockets_all)} websockets found.")

if __name__ == '__main__':
    main()
