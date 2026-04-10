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
