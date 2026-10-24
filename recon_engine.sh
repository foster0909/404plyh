#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                           RECON ENGINE v1.0                                ║
# ║      Deep Reconnaissance & Enumeration Framework for Attack Surface        ║
# ║                          Mapping and Analysis                              ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
#
# Orchestrates multiple industry-standard reconnaissance tools into a unified
# pipeline — from subdomain discovery through infrastructure mapping — producing
# a structured intelligence dataset optimized for manual security research.
#
# Usage: ./recon_engine.sh -d <domain> [options]
#
# Author: Recon Engine Project
# License: MIT

set -uo pipefail

# Ensure standard bin paths are available (crucial for python subprocesses)
export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin:$HOME/.cargo/bin:/usr/local/go/bin:$HOME/Tools:/home/void/Tools:/home/void/go/bin"

# ─────────────────────────────────────────────────────────────────────────────
# Resolve script directory (works even if symlinked)
# ─────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$SCRIPT_DIR/modules"

# Load environment variables (API keys) from .env file if it exists
# (KEY=VALUE lines; optional "export " prefix and surrounding quotes. Parsed,
# not sourced/word-split, so values with spaces, quotes or globs stay intact.)
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    while IFS= read -r _env_line || [[ -n "$_env_line" ]]; do
        _env_line="${_env_line%$'\r'}"
        _env_line="${_env_line#"${_env_line%%[![:space:]]*}"}"
        [[ -z "$_env_line" || "$_env_line" == \#* ]] && continue
        _env_line="${_env_line#export }"
        [[ "$_env_line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || continue
        _env_key="${BASH_REMATCH[1]}"
        _env_val="${BASH_REMATCH[2]}"
        if [[ "$_env_val" =~ ^\"(.*)\"$ || "$_env_val" =~ ^\'(.*)\'$ ]]; then
            _env_val="${BASH_REMATCH[1]}"
        fi
        export "$_env_key=$_env_val"
    done < "$SCRIPT_DIR/.env"
    unset _env_line _env_key _env_val
fi

# ─────────────────────────────────────────────────────────────────────────────
# Source all modules
# ─────────────────────────────────────────────────────────────────────────────

source "$MODULES_DIR/config.sh"       # Config defaults, colors, logging
source "$MODULES_DIR/utils.sh"        # Utility functions
source "$MODULES_DIR/deps.sh"         # Dependency checker

source "$MODULES_DIR/subdomain.sh"    # Module 1: Subdomain Discovery
source "$MODULES_DIR/dns.sh"          # Module 2: DNS Resolution
source "$MODULES_DIR/http.sh"         # Module 3: HTTP Probing
source "$MODULES_DIR/screenshots.sh"  # Module 4: Screenshots
source "$MODULES_DIR/ports.sh"        # Module 5: Port Scanning
source "$MODULES_DIR/js_deep.sh"     # Module 6: Deep JS Analysis
source "$MODULES_DIR/historical.sh"   # Module 7: Historical URLs
source "$MODULES_DIR/crawl.sh"        # Module 8: Endpoint Crawling
source "$MODULES_DIR/dorks.sh"        # Module: Dork-Style Sensitive File Discovery
source "$MODULES_DIR/validate_historical.sh"   # Module: Optional Historical URL Validation
source "$MODULES_DIR/infra.sh"        # Module 9: Infrastructure Mapping
source "$MODULES_DIR/report.sh"       # Module 10: Report Generation
source "$MODULES_DIR/notify.sh"       # Discord notifications
source "$MODULES_DIR/rate_guard.sh"   # Adaptive rate limiting

# ─────────────────────────────────────────────────────────────────────────────
# CLI Usage
# ─────────────────────────────────────────────────────────────────────────────

usage() {
    banner
    echo -e "${WHITE}Usage:${RESET} $0 -d <domain> [options]"
    echo ""
    echo -e "${WHITE}Required:${RESET}"
    echo "  -d, --domain <domain>        Target domain to enumerate"
    echo ""
    echo -e "${WHITE}Options:${RESET}"
    echo "  -o, --output <dir>           Output directory (default: recon_<domain>)"
    echo "  -t, --threads <n>            Thread count for tools (default: $THREADS)"
    echo "  -r, --resolvers <file>       DNS resolver list for puredns"
    echo "      --rate <n>               Port-scan (naabu) packet rate (default: $RATE_LIMIT)"
    echo "      --http-rate <n>          Target-facing HTTP req/s, general (default: $HTTP_RATE)"
    echo "      --active-rate <n>        Target-facing HTTP req/s, noisy stages (default: $ACTIVE_RATE)"
    echo "      --header <'K: V'>        Custom header for target requests (repeatable)"
    echo "      --headers-file <file>    Read custom headers from a file (one per line)"
    echo "      --top-ports <n>          Top ports for naabu (default: $NAABU_TOP_PORTS)"
    echo "      --katana-depth <n>       Crawl depth for katana (default: $KATANA_DEPTH)"
    echo "      --recursive-rounds <n>   Max JS recursion rounds (default: $RECURSIVE_ROUNDS)"
    echo ""
    echo -e "${WHITE}Skip Modules:${RESET}"
    echo "      --skip-subdomains        Skip subdomain discovery"
    echo "      --skip-dns               Skip DNS resolution"
    echo "      --skip-http              Skip HTTP probing"
    echo "      --skip-screenshots       Skip screenshot capture"
    echo "      --skip-ports             Skip port scanning"
    echo "      --skip-js                Skip JavaScript analysis"
    echo "      --skip-historical        Skip historical URL discovery"
    echo "      --skip-crawl             Skip endpoint crawling"
    echo "      --skip-dorks             Skip dork-style sensitive file discovery"
    echo "      --validate-historical    Validate interesting historical URLs (slow/stealthy)"
    echo "      --no-parallel-historical Run historical discovery inline instead of in the background"
    echo "      --skip-infra             Skip infrastructure mapping"
    echo "      --skip-report            Skip report generation"
    echo ""
    echo -e "${WHITE}Utility:${RESET}"
    echo "      --check-deps             Check tool dependencies and exit"
    echo "  -h, --help                   Show this help message"
    echo ""
    echo -e "${WHITE}Examples:${RESET}"
    echo "  $0 -d example.com"
    echo "  $0 -d example.com -o output/ -t 100 --resolvers resolvers.txt"
    echo "  $0 -d example.com --skip-screenshots --skip-ports"
    echo "  $0 --check-deps"
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# Argument Parsing
# ─────────────────────────────────────────────────────────────────────────────

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--domain)         DOMAIN="$2"; shift 2 ;;
            -o|--output)         OUTPUT_DIR="$2"; shift 2 ;;
            -t|--threads)        THREADS="$2"; shift 2 ;;
            -r|--resolvers)      RESOLVERS="$2"; shift 2 ;;
            --rate)              RATE_LIMIT="$2"; shift 2 ;;
            --http-rate)         HTTP_RATE="$2"; shift 2 ;;
            --active-rate)       ACTIVE_RATE="$2"; shift 2 ;;
            --header)            CUSTOM_HEADERS+="${CUSTOM_HEADERS:+$'\n'}$2"; shift 2 ;;
            --headers-file)      [[ -f "$2" ]] && CUSTOM_HEADERS+="${CUSTOM_HEADERS:+$'\n'}$(cat "$2")"; shift 2 ;;
            --top-ports)         NAABU_TOP_PORTS="$2"; shift 2 ;;
            --katana-depth)      KATANA_DEPTH="$2"; shift 2 ;;
            --recursive-rounds)  RECURSIVE_ROUNDS="$2"; shift 2 ;;
            --skip-subdomains)   SKIP_SUBDOMAINS=true; shift ;;
            --skip-dns)          SKIP_DNS=true; shift ;;
            --skip-http)         SKIP_HTTP=true; shift ;;
            --skip-screenshots)  SKIP_SCREENSHOTS=true; shift ;;
            --skip-ports)        SKIP_PORTS=true; shift ;;
            --skip-js)           SKIP_JS=true; shift ;;
            --skip-historical)   SKIP_HISTORICAL=true; shift ;;
            --skip-crawl)        SKIP_CRAWL=true; shift ;;
            --skip-dorks)        SKIP_DORKS=true; shift ;;
            --validate-historical) VALIDATE_HISTORICAL=true; shift ;;
            --no-parallel-historical) PARALLEL_HISTORICAL=false; shift ;;
            --skip-infra)        SKIP_INFRA=true; shift ;;
            --skip-report)       SKIP_REPORT=true; shift ;;
            --check-deps)        CHECK_DEPS_ONLY=true; shift ;;
            -h|--help)           usage; exit 0 ;;
            *)
                error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    if [[ "$CHECK_DEPS_ONLY" == true ]]; then
        return 0
    fi

    if [[ -z "$DOMAIN" ]]; then
        error "Domain is required. Use -d <domain>"
        usage
        exit 1
    fi

    if [[ -z "$OUTPUT_DIR" ]]; then
        OUTPUT_DIR="recon_${DOMAIN}"
    fi

    # Strip trailing slash to prevent double-slash paths
    OUTPUT_DIR="${OUTPUT_DIR%/}"

    # Rate-limit sanity: the active (noisy-stage) rate must stay within the
    # general HTTP rate. Clamp with a warning rather than silently proceeding.
    if [[ "$ACTIVE_RATE" -gt "$HTTP_RATE" ]] 2>/dev/null; then
        warn "Active scan rate ($ACTIVE_RATE/s) exceeds HTTP rate ($HTTP_RATE/s); clamping to $HTTP_RATE/s"
        ACTIVE_RATE="$HTTP_RATE"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# JS Recursion Handler
# ─────────────────────────────────────────────────────────────────────────────

handle_recursion() {
    if [[ "$NEW_DOMAINS_FOUND" == true && $RECURSION_ROUND -lt $RECURSIVE_ROUNDS ]]; then
        ((RECURSION_ROUND++))
        info "Starting recursion round $RECURSION_ROUND / $RECURSIVE_ROUNDS"
        NEW_DOMAINS_FOUND=false

        module_dns_resolution
        module_http_probing
        module_js_deep
        handle_recursion
    elif [[ "$NEW_DOMAINS_FOUND" == true ]]; then
        warn "Maximum recursion rounds ($RECURSIVE_ROUNDS) reached. Stopping recursion."
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Cleanup on interrupt
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# Background historical discovery (parallel mode)
#   Launched right after HTTP probing and joined before the dork URL pool is
#   built. Historical only reads $DOMAIN and writes only to historical/, so it
#   is safe to overlap with screenshots/ports/JS. Console output is captured to
#   historical/.bg.log so it does not interleave with the main pipeline; the
#   module's own log() calls still land in the main LOG_FILE for traceability.
# ─────────────────────────────────────────────────────────────────────────────
HISTORICAL_BG_PID=""
HISTORICAL_BG_LOG=""
HISTORICAL_BG_START=0

start_historical_bg() {
    HISTORICAL_BG_LOG="$OUTPUT_DIR/historical/.bg.log"
    mkdir -p "$OUTPUT_DIR/historical" 2>/dev/null
    info "Historical discovery running in background (parallel mode)"
    HISTORICAL_BG_START=$(date +%s)
    ( module_historical ) >"$HISTORICAL_BG_LOG" 2>&1 &
    HISTORICAL_BG_PID=$!
}

join_historical_bg() {
    [[ -z "$HISTORICAL_BG_PID" ]] && return 0
    step "Joining background historical discovery"
    wait "$HISTORICAL_BG_PID" 2>/dev/null
    local rc=$? dur=$(( $(date +%s) - HISTORICAL_BG_START ))
    log "TIMING" "stage=historical seconds=$dur"
    if [[ -n "${OUTPUT_DIR:-}" ]]; then
        printf '{"stage":"%s","seconds":%d,"ended":"%s"}\n' \
            "historical" "$dur" "$(date +%Y-%m-%dT%H:%M:%S)" \
            >> "$OUTPUT_DIR/reports/timing.jsonl" 2>/dev/null || true
    fi
    if [[ $rc -eq 0 ]]; then
        success "Historical discovery complete ($(count "$OUTPUT_DIR/historical/all_urls.txt") URLs, ${dur}s, overlapped)"
    else
        warn "Background historical discovery exited with code $rc (see $HISTORICAL_BG_LOG)"
    fi
    HISTORICAL_BG_PID=""
}

cleanup() {
    echo ""
    warn "Interrupt received. Cleaning up..."
    # Stop a still-running background historical job and its process group.
    if [[ -n "$HISTORICAL_BG_PID" ]]; then
        kill "$HISTORICAL_BG_PID" 2>/dev/null || true
    fi
    if [[ -n "$LOG_FILE" ]]; then
        log "WARN" "Scan interrupted by user signal"
    fi
    exit 130
}

trap cleanup SIGINT SIGTERM

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

main() {
    parse_args "$@"

    banner

    # Dependency check mode
    if [[ "$CHECK_DEPS_ONLY" == true ]]; then
        check_dependencies
        exit $?
    fi

    info "Target domain: ${BOLD}${DOMAIN}${RESET}"
    create_directories
    init_logging
    log "INFO" "Recon Engine started for domain: $DOMAIN"
    log "INFO" "Output directory: $OUTPUT_DIR"
    log "INFO" "Threads: $THREADS | Ports rate: $RATE_LIMIT | HTTP rate: $HTTP_RATE/s | Active rate: $ACTIVE_RATE/s"
    if [[ -n "${CUSTOM_HEADERS:-}" ]]; then
        info "Custom headers active for target requests ($(grep -c . <<< "$CUSTOM_HEADERS") line(s))"
    fi

    check_dependencies || exit 1

    # Run the whole pipeline (and every tool it spawns) at lower CPU/IO
    # priority so the host stays responsive (important on small boxes).
    if [[ "${SCAN_NICE:-0}" -gt 0 ]] 2>/dev/null; then
        renice -n "$SCAN_NICE" -p $$ >/dev/null 2>&1 || true
        command -v ionice >/dev/null 2>&1 && ionice -c 2 -n 7 -p $$ >/dev/null 2>&1 || true
    fi

    # Initialize adaptive rate guard
    rate_guard_init

    local start_time
    start_time=$(date +%s)

    # ═══ PIPELINE ═══
    # A parallel-friendly flag controls whether historical discovery runs in the
    # background (overlapping screenshots/ports/JS) or inline at its old slot.
    local run_historical_parallel=false
    if [[ "$PARALLEL_HISTORICAL" == true && "$SKIP_HISTORICAL" != true ]]; then
        run_historical_parallel=true
    fi

    rate_guard_check
    stage subdomains module_subdomain_discovery   # 1. Discover subdomains
    rate_guard_check
    stage dns module_dns_resolution               # 2. Resolve DNS
    rate_guard_check
    stage http module_http_probing                # 3. Probe HTTP services

    # Launch historical in the background now (parallel mode): it only needs the
    # domain and hits archive APIs, so it overlaps the next three stages.
    if [[ "$run_historical_parallel" == true ]]; then
        start_historical_bg
    fi

    rate_guard_check
    stage screenshots module_screenshots          # 4. Capture screenshots
    rate_guard_check
    stage ports module_port_scanning              # 5. Scan ports
    rate_guard_check
    stage js module_js_deep                       # 6. Deep JS Analysis
    handle_recursion                              #    (recursive JS discovery)
    rate_guard_check

    # Historical URLs: join the background job (parallel) or run it inline. Both
    # paths complete before the dork pool / crawl, the first hard consumers.
    if [[ "$run_historical_parallel" == true ]]; then
        join_historical_bg                        # 7. Historical URLs (parallel)
    else
        stage historical module_historical        # 7. Historical URLs (inline)
    fi
    rate_guard_check
    stage crawl module_crawl_endpoints            # 8. Crawl endpoints
    rate_guard_check
    stage dorks module_dorks                      #    Dork-style sensitive file discovery
    stage validate_historical module_validate_historical  # Optional historical validation
    rate_guard_check
    stage infra module_infra_mapping              # 9. Map infrastructure
    stage report module_report                    # 10. Generate reports

    # ── Send scan-complete Discord notification ──
    notify_scan_complete "$DOMAIN" "$OUTPUT_DIR"

    local end_time elapsed_min
    end_time=$(date +%s)
    elapsed_min=$(( (end_time - start_time) / 60 ))

    echo ""
    header "Scan Complete"
    success "Target:   $DOMAIN"
    success "Duration: ${elapsed_min} minutes"
    success "Output:   $OUTPUT_DIR/"
    echo ""
    log "INFO" "Scan completed in ${elapsed_min} minutes"
}

# Run the pipeline only when executed directly, so tests can source this file
# to exercise individual functions (e.g. the parallel-historical helpers).
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
