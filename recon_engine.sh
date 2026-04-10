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

# ─────────────────────────────────────────────────────────────────────────────
# Resolve script directory (works even if symlinked)
# ─────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$SCRIPT_DIR/modules"

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
source "$MODULES_DIR/js.sh"           # Module 6: JS Analysis
source "$MODULES_DIR/historical.sh"   # Module 7: Historical URLs
source "$MODULES_DIR/crawl.sh"        # Module 8: Endpoint Crawling
source "$MODULES_DIR/dorks.sh"        # Module: Dork-Style Sensitive File Discovery
source "$MODULES_DIR/infra.sh"        # Module 9: Infrastructure Mapping
source "$MODULES_DIR/report.sh"       # Module 10: Report Generation

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
    echo "      --rate <n>               Rate limit for scanning (default: $RATE_LIMIT)"
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
        module_js_analysis
        handle_recursion
    elif [[ "$NEW_DOMAINS_FOUND" == true ]]; then
        warn "Maximum recursion rounds ($RECURSIVE_ROUNDS) reached. Stopping recursion."
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Cleanup on interrupt
# ─────────────────────────────────────────────────────────────────────────────

cleanup() {
    echo ""
    warn "Interrupt received. Cleaning up..."
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
    log "INFO" "Threads: $THREADS | Rate: $RATE_LIMIT"

    check_dependencies || exit 1

    local start_time
    start_time=$(date +%s)

    # ═══ PIPELINE ═══
    module_subdomain_discovery      # 1. Discover subdomains
    module_dns_resolution           # 2. Resolve DNS
    module_http_probing             # 3. Probe HTTP services
    module_screenshots              # 4. Capture screenshots
    module_port_scanning            # 5. Scan ports
    module_js_analysis              # 6. Analyze JavaScript
    handle_recursion                #    (recursive JS discovery)
    module_historical               # 7. Historical URLs
    module_crawl_endpoints          # 8. Crawl endpoints
    module_dorks                    #    Dork-style sensitive file discovery
    module_infra_mapping            # 9. Map infrastructure
    module_report                   # 10. Generate reports

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

main "$@"
