#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                      RECON ENGINE — LIVE MONITOR                           ║
# ║     Continuous Change Detection for Subdomains & Ports                     ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
#
# Runs lightweight recon and diffs against previous baselines to detect
# new subdomains and newly opened ports. Designed for daily cron execution.
#
# Usage:
#   ./monitor.sh -d <domain> [options]
#   ./monitor.sh -d <domain> --init          # First run: create baseline
#   ./monitor.sh -d <domain>                 # Subsequent: detect changes
#
# Cron example (daily at 2am):
#   0 2 * * * /path/to/monitor.sh -d example.com >> /var/log/recon_monitor.log 2>&1
#
# Discord alerts:
#   export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
#   Or add to ~/.recon_engine.conf:
#     DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
#
# Author: Recon Engine Project
# License: MIT

set -uo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Resolve script directory
# ─────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$SCRIPT_DIR/modules"

# ─────────────────────────────────────────────────────────────────────────────
# Source modules
# ─────────────────────────────────────────────────────────────────────────────

source "$MODULES_DIR/config.sh"
source "$MODULES_DIR/utils.sh"
source "$MODULES_DIR/deps.sh"
source "$MODULES_DIR/notify.sh"
source "$MODULES_DIR/monitor.sh"

# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

MONITOR_INIT=false

monitor_usage() {
    banner
    echo -e "${WHITE}Recon Engine — Live Monitor${RESET}"
    echo -e "Continuous change detection for subdomains & ports."
    echo ""
    echo -e "${WHITE}Usage:${RESET} $0 -d <domain> [options]"
    echo ""
    echo -e "${WHITE}Required:${RESET}"
    echo "  -d, --domain <domain>        Target domain to monitor"
    echo ""
    echo -e "${WHITE}Options:${RESET}"
    echo "  -o, --output <dir>           Output directory (default: recon_<domain>)"
    echo "  -t, --threads <n>            Thread count (default: $THREADS)"
    echo "  -r, --resolvers <file>       DNS resolver list"
    echo "      --rate <n>               Rate limit (default: $RATE_LIMIT)"
    echo "      --top-ports <n>          Top ports for naabu (default: $NAABU_TOP_PORTS)"
    echo "      --init                   Initialize baseline (first run)"
    echo "  -h, --help                   Show this help"
    echo ""
    echo -e "${WHITE}Examples:${RESET}"
    echo "  $0 -d example.com --init                  # First run — create baseline"
    echo "  $0 -d example.com                         # Subsequent — detect changes"
    echo "  $0 -d example.com --top-ports 100          # Fast check, top 100 ports only"
    echo ""
    echo -e "${WHITE}Cron:${RESET}"
    echo "  0 2 * * * $0 -d example.com"
    echo ""
    echo -e "${WHITE}Discord Alerts:${RESET}"
    echo "  export DISCORD_WEBHOOK_URL='https://discord.com/api/webhooks/...'"
    echo "  Or add to ~/.recon_engine.conf:"
    echo "    DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/..."
    echo ""
}

monitor_parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--domain)         DOMAIN="$2"; shift 2 ;;
            -o|--output)         OUTPUT_DIR="$2"; shift 2 ;;
            -t|--threads)        THREADS="$2"; shift 2 ;;
            -r|--resolvers)      RESOLVERS="$2"; shift 2 ;;
            --rate)              RATE_LIMIT="$2"; shift 2 ;;
            --top-ports)         NAABU_TOP_PORTS="$2"; shift 2 ;;
            --init)              MONITOR_INIT=true; shift ;;
            -h|--help)           monitor_usage; exit 0 ;;
            *)
                error "Unknown option: $1"
                monitor_usage
                exit 1
                ;;
        esac
    done

    if [[ -z "$DOMAIN" ]]; then
        error "Domain is required. Use -d <domain>"
        monitor_usage
        exit 1
    fi

    if [[ -z "$OUTPUT_DIR" ]]; then
        OUTPUT_DIR="recon_${DOMAIN}"
    fi

    OUTPUT_DIR="${OUTPUT_DIR%/}"
}

# ─────────────────────────────────────────────────────────────────────────────
# Cleanup
# ─────────────────────────────────────────────────────────────────────────────

cleanup() {
    echo ""
    warn "Interrupt received. Cleaning up..."
    # Clean up temp scan dir if it exists
    rm -rf "$OUTPUT_DIR/monitor/scan_tmp" 2>/dev/null || true
    exit 130
}

trap cleanup SIGINT SIGTERM

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

main() {
    monitor_parse_args "$@"

    banner

    info "Target domain: ${BOLD}${DOMAIN}${RESET}"

    # Create directories (including monitor dirs)
    mkdir -p "$OUTPUT_DIR"/{subs,dns,httpx,ports,monitor/baselines,monitor/changes,logs}

    init_logging
    log "INFO" "Monitor started for domain: $DOMAIN"

    local start_time
    start_time=$(date +%s)

    run_monitor "$MONITOR_INIT"

    local end_time elapsed_sec
    end_time=$(date +%s)
    elapsed_sec=$(( end_time - start_time ))

    echo ""
    header "Monitor Complete"
    success "Target:   $DOMAIN"
    success "Duration: ${elapsed_sec}s"
    success "Output:   $OUTPUT_DIR/monitor/"
    echo ""
    log "INFO" "Monitor completed in ${elapsed_sec}s"
}

main "$@"
