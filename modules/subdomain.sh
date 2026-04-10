#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# MODULE 1: Subdomain Discovery
# Tools: subfinder, amass, assetfinder, chaos, crt.sh
# ─────────────────────────────────────────────────────────────────────────────

module_subdomain_discovery() {
    if [[ "$SKIP_SUBDOMAINS" == true ]]; then
        info "Skipping subdomain discovery (--skip-subdomains)"
        return 0
    fi

    header "Module 1: Subdomain Discovery"
    local subs_dir="$OUTPUT_DIR/subs"
    local combined="$subs_dir/all_raw.txt"

    # ── subfinder ──
    if require_tool "subfinder"; then
        run_safe "subfinder" \
            "subfinder -d '$DOMAIN' -all -silent -t $THREADS -o '$subs_dir/subfinder.txt'"
        report_count "$subs_dir/subfinder.txt" "subfinder results"
    fi

    # ── amass (passive) ──
    if require_tool "amass"; then
        run_safe "amass passive" \
            "amass enum -passive -d '$DOMAIN' -o '$subs_dir/amass.txt' 2>>'$LOG_FILE'"
        report_count "$subs_dir/amass.txt" "amass results"
    fi

    # ── assetfinder ──
    if require_tool "assetfinder"; then
        run_safe "assetfinder" \
            "assetfinder --subs-only '$DOMAIN' > '$subs_dir/assetfinder.txt'"
        report_count "$subs_dir/assetfinder.txt" "assetfinder results"
    fi

    # ── chaos ──
    if require_tool "chaos"; then
        run_safe "chaos" \
            "chaos -d '$DOMAIN' -silent -o '$subs_dir/chaos.txt'"
        report_count "$subs_dir/chaos.txt" "chaos results"
    fi

    # ── crt.sh ──
    step "Querying crt.sh (Certificate Transparency)"
    local crtsh_url="https://crt.sh/?q=%25.${DOMAIN}&output=json"
    curl -s "$crtsh_url" 2>/dev/null \
        | jq -r '.[].name_value' 2>/dev/null \
        | sed 's/\*\.//g' \
        | sort -u > "$subs_dir/crtsh.txt" || true
    report_count "$subs_dir/crtsh.txt" "crt.sh results"

    # ── Merge and normalize ──
    step "Merging and normalizing all subdomain results"
    cat "$subs_dir"/*.txt 2>/dev/null | sort -u > "$combined"

    normalize_hosts "$combined" "$subs_dir/all.txt"
    report_count "$subs_dir/all.txt" "Total unique subdomains"

    success "Subdomain discovery complete."
}
