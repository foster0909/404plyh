#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# RECON ENGINE — Configuration, Colors & Logging
# ─────────────────────────────────────────────────────────────────────────────

# Configuration defaults
# NOTE: These defaults are intentionally conservative to avoid triggering
# WAFs, rate-limiters, or IP bans. Override with CLI flags or env vars
# if you need more speed on permissive targets.
THREADS="${THREADS:-15}"
RATE_LIMIT="${RATE_LIMIT:-150}"
# ── Target-facing HTTP rate limits (req/s) ────────────────────────────────────
# HTTP_RATE   : general cap for target-facing HTTP (httpx probing). Defaults to
#               the project's conservative RATE_LIMIT so general scanning keeps
#               today's behaviour (the one change: httpx, previously uncapped,
#               now honours this cap).
# ACTIVE_RATE : stricter cap for noisy / block-prone stages (crawl, JS fetching,
#               dork probing, historical validation). Must stay <= HTTP_RATE.
# Neither touches DNS resolution, passive enumeration, or local processing.
HTTP_RATE="${HTTP_RATE:-${RATE_LIMIT:-150}}"
ACTIVE_RATE="${ACTIVE_RATE:-10}"
# Custom HTTP headers (newline-separated "Name: Value"), applied ONLY to requests
# sent directly to the target (httpx / katana / JS fetches), never to passive
# sources or DNS. Loadable via --header (repeatable) or the CUSTOM_HEADERS env.
CUSTOM_HEADERS="${CUSTOM_HEADERS:-}"
RESOLVERS="${RESOLVERS:-}"
OUTPUT_DIR="${OUTPUT_DIR:-}"
DOMAIN="${DOMAIN:-}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
RECURSIVE_ROUNDS="${RECURSIVE_ROUNDS:-2}"
NAABU_TOP_PORTS="${NAABU_TOP_PORTS:-1000}"
KATANA_DEPTH="${KATANA_DEPTH:-3}"
HAKRAWLER_DEPTH="${HAKRAWLER_DEPTH:-2}"
HTTPX_TIMEOUT="${HTTPX_TIMEOUT:-10}"
DORK_THREADS="${DORK_THREADS:-10}"
# ── Screenshots (gowitness / headless Chrome) ─────────────────────────────────
# Each gowitness thread is a headless Chrome tab, so these are sized for RAM,
# not network. Large target sets (10k+ URLs) on small boxes (e.g. a Raspberry
# Pi) previously exhausted memory and hung the machine. The URL list is fed in
# batches (a fresh Chrome per batch releases its memory), each batch is capped
# by a timeout, and available memory is checked between batches.
SCREENSHOT_THREADS="${SCREENSHOT_THREADS:-4}"
SCREENSHOT_BATCH="${SCREENSHOT_BATCH:-250}"
SCREENSHOT_BATCH_TIMEOUT="${SCREENSHOT_BATCH_TIMEOUT:-1800}"
SCREENSHOT_MIN_MEM_MB="${SCREENSHOT_MIN_MEM_MB:-1024}"
# ── Port scanning scale controls ──────────────────────────────────────────────
# NAABU_EXCLUDE_CDN : CDN/WAF-fronted hosts only get 80/443 probed (naabu -ec);
#                     on large scopes most hosts are CDN, so this is the main
#                     reduction in probe volume (rate itself is unchanged).
# NMAP_MAX_HOSTS    : cap on hosts given to the nmap -sV/-sC deep scan. Hosts
#                     with non-web ports are prioritised; nmap only scans the
#                     ports naabu actually found open.
# NMAP_HOST_TIMEOUT : per-host nmap time budget so one slow host can't stall.
NAABU_EXCLUDE_CDN="${NAABU_EXCLUDE_CDN:-true}"
NMAP_MAX_HOSTS="${NMAP_MAX_HOSTS:-100}"
NMAP_HOST_TIMEOUT="${NMAP_HOST_TIMEOUT:-5m}"
# ── Host resource protection (small boxes such as a Raspberry Pi) ─────────────
# SCAN_NICE         : CPU niceness for the whole pipeline (0 disables) so the
#                     host, sshd and the dashboard stay responsive.
# RESOURCE_MIN_MEM_MB: before each stage, wait (up to RESOURCE_WAIT_MAX s) while
#                     available memory is below this, instead of piling on load.
SCAN_NICE="${SCAN_NICE:-10}"
RESOURCE_MIN_MEM_MB="${RESOURCE_MIN_MEM_MB:-512}"
RESOURCE_WAIT_MAX="${RESOURCE_WAIT_MAX:-300}"
VALIDATE_HISTORICAL="${VALIDATE_HISTORICAL:-false}"
# Run historical URL discovery in the background (launched after HTTP probing,
# joined before the dork pool is built) so it overlaps screenshots/ports/JS
# instead of sitting on the critical path. Historical only needs $DOMAIN and
# hits third-party archive APIs, so it does not add load to the target.
PARALLEL_HISTORICAL="${PARALLEL_HISTORICAL:-true}"

# Python tool paths (override with env vars)
LINKFINDER_PATH="${LINKFINDER_PATH:-linkfinder.py}"
SECRETFINDER_PATH="${SECRETFINDER_PATH:-SecretFinder.py}"

# Module skip flags
SKIP_SUBDOMAINS=false
SKIP_DNS=false
SKIP_HTTP=false
SKIP_SCREENSHOTS=false
SKIP_PORTS=false
SKIP_JS=false
SKIP_HISTORICAL=false
SKIP_CRAWL=false
SKIP_INFRA=false
SKIP_DORKS=false
SKIP_REPORT=false
CHECK_DEPS_ONLY=false

# JS recursion tracking
RECURSION_ROUND=0
NEW_DOMAINS_FOUND=false

# ─── Colors ──────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ─── Logging ─────────────────────────────────────────────────────────────────

LOG_FILE=""

init_logging() {
    local log_dir="$OUTPUT_DIR/logs"
    mkdir -p "$log_dir"
    LOG_FILE="$log_dir/recon_${TIMESTAMP}.log"
    touch "$LOG_FILE"
}

log() {
    [[ -z "$LOG_FILE" || ! -f "$LOG_FILE" ]] && return 0
    local level="$1"
    shift
    local msg="$*"
    local ts
    ts=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$ts] [$level] $msg" >> "$LOG_FILE" 2>/dev/null
}

# ─── Output helpers ──────────────────────────────────────────────────────────

banner() {
    echo -e "${CYAN}"
    echo '  ____                          _____             _            '
    echo ' |  _ \ ___  ___ ___  _ __     | ____|_ __   __ _(_)_ __   ___ '
    echo ' | |_) / _ \/ __/ _ \| '\''_ \    |  _| | '\''_ \ / _` | | '\''_ \ / _ \'
    echo ' |  _ <  __/ (_| (_) | | | |   | |___| | | | (_| | | | | |  __/'
    echo ' |_| \_\___|\___\___/|_| |_|   |_____|_| |_|\__, |_|_| |_|\___|'
    echo '                                             |___/              '
    echo -e "${RESET}"
    echo -e "${DIM}  Deep Reconnaissance & Enumeration Framework v1.0${RESET}"
    echo ""
}

info()    { echo -e "${BLUE}[*]${RESET} $*"; log "INFO" "$*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; log "SUCCESS" "$*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; log "WARN" "$*"; }
error()   { echo -e "${RED}[✗]${RESET} $*"; log "ERROR" "$*"; }
header()  { echo -e "\n${MAGENTA}${BOLD}═══════════════════════════════════════════════════════════════${RESET}"; echo -e "${MAGENTA}${BOLD}  $*${RESET}"; echo -e "${MAGENTA}${BOLD}═══════════════════════════════════════════════════════════════${RESET}\n"; log "HEADER" "$*"; }
step()    { echo -e "  ${CYAN}→${RESET} $*"; log "STEP" "$*"; }
count()   { local n; if [[ -f "$1" ]]; then n=$(wc -l < "$1" 2>/dev/null); else n=0; fi; echo "${n// /}"; }

# ── Central rate-limit / custom-header emitters ───────────────────────────────
# Single source of truth so every module applies the same target-facing policy.
# All output is pre-quoted for the `eval` in run_safe (header values are
# untrusted user input, so they are single-quote escaped to prevent injection).

# Shell-quote a string safely for eval (wraps in single quotes, escapes any ').
shq() {
    local s="$1"
    printf "'%s'" "${s//\'/\'\\\'\'}"
}

# Echo "-rate-limit <n>" for the given tier: "active" uses ACTIVE_RATE, anything
# else uses HTTP_RATE. Used by httpx (and, with --rl, katana via katana_rate).
http_rate_flag() {
    local tier="$1" n
    if [[ "$tier" == "active" ]]; then n="${ACTIVE_RATE:-10}"; else n="${HTTP_RATE:-150}"; fi
    [[ -n "$n" && "$n" -gt 0 ]] 2>/dev/null && echo "-rate-limit $n"
}

# katana expresses req/s as -rl.
katana_rate_flag() {
    local tier="$1" n
    if [[ "$tier" == "active" ]]; then n="${ACTIVE_RATE:-10}"; else n="${HTTP_RATE:-150}"; fi
    [[ -n "$n" && "$n" -gt 0 ]] 2>/dev/null && echo "-rl $n"
}

# Emit repeated "-H '<header>'" flags (httpx / katana / curl all accept -H).
header_flags() {
    [[ -z "${CUSTOM_HEADERS:-}" ]] && return 0
    local line out=""
    while IFS= read -r line; do
        line="${line#"${line%%[![:space:]]*}"}"   # ltrim
        [[ -z "$line" ]] && continue
        out+=" -H $(shq "$line")"
    done <<< "$CUSTOM_HEADERS"
    echo "$out"
}

# Seconds to sleep between manual (curl) target requests to honour ACTIVE_RATE.
# Echoes nothing when no throttle is needed.
active_sleep() {
    local n="${ACTIVE_RATE:-10}"
    [[ -n "$n" && "$n" -gt 0 ]] 2>/dev/null || { echo ""; return; }
    awk -v r="$n" 'BEGIN { if (r > 0) printf "%.3f", 1.0/r }'
}

# ── Per-stage timing ──────────────────────────────────────────────────────────
# Wraps a pipeline stage, logging its wall-clock duration as a machine-readable
# TIMING line (parsed by the dashboard) and appending to reports/timing.jsonl.
# Transparent: the wrapped function's own output/return code is passed through.
stage() {
    local name="$1"; shift
    local s e dur
    s=$(date +%s)
    "$@"
    local rc=$?
    e=$(date +%s)
    dur=$((e - s))
    log "TIMING" "stage=$name seconds=$dur"
    if [[ -n "${OUTPUT_DIR:-}" && -d "$OUTPUT_DIR" ]]; then
        mkdir -p "$OUTPUT_DIR/reports" 2>/dev/null
        printf '{"stage":"%s","seconds":%d,"ended":"%s"}\n' \
            "$name" "$dur" "$(date +%Y-%m-%dT%H:%M:%S)" \
            >> "$OUTPUT_DIR/reports/timing.jsonl" 2>/dev/null || true
    fi
    return $rc
}
