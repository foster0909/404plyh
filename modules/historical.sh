#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# MODULE 7: Historical Surface Discovery
# Tools: gau, waybackurls
# ─────────────────────────────────────────────────────────────────────────────

module_historical() {
    if [[ "$SKIP_HISTORICAL" == true ]]; then
        info "Skipping historical URL discovery (--skip-historical)"
        return 0
    fi

    header "Module 7: Historical Surface Discovery"
    local hist_dir="$OUTPUT_DIR/historical"

    # ── gau ──
    if require_tool "gau"; then
        run_safe "gau" \
            "gau '$DOMAIN' --subs --o '$hist_dir/gau.txt' 2>>'$LOG_FILE'"
        report_count "$hist_dir/gau.txt" "gau URLs"
    fi

    # ── waybackurls ──
    if require_tool "waybackurls"; then
        run_safe "waybackurls" \
            "echo '$DOMAIN' | waybackurls > '$hist_dir/waybackurls.txt' 2>>'$LOG_FILE'"
        report_count "$hist_dir/waybackurls.txt" "waybackurls URLs"
    fi

    # ── Merge and dedup ──
    step "Merging historical URL datasets"
    merge_dedup "$hist_dir/all_urls.txt" \
        "$hist_dir/gau.txt" \
        "$hist_dir/waybackurls.txt"
    report_count "$hist_dir/all_urls.txt" "Total unique historical URLs"

    # NOTE: We intentionally do NOT httpx-probe the full all_urls.txt here.
    # That probe (previously written to alive.txt) was expensive — often tens of
    # thousands of requests — its output was consumed by nothing, and the
    # --validate-historical stage already re-probes the *interesting* subset
    # (historical/validated_interesting.json), which is what the dashboard and
    # finding model use. Live validation of the sensitive subset lives there.

    success "Historical discovery complete."
}
