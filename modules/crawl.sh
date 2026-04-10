#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# MODULE 8: Endpoint & Path Enumeration
# Tools: katana, hakrawler
# ─────────────────────────────────────────────────────────────────────────────

module_crawl_endpoints() {
    if [[ "$SKIP_CRAWL" == true ]]; then
        info "Skipping endpoint crawling (--skip-crawl)"
        return 0
    fi

    header "Module 8: Endpoint & Path Enumeration"
    local ep_dir="$OUTPUT_DIR/endpoints"
    local input="$OUTPUT_DIR/httpx/alive.txt"

    if [[ ! -s "$input" ]]; then
        warn "No alive URLs. Skipping crawling."
        return 0
    fi

    # ── katana ──
    if require_tool "katana"; then
        run_safe "katana crawl" \
            "katana -list '$input' \
                -d $KATANA_DEPTH \
                -jc \
                -c $THREADS \
                -o '$ep_dir/katana.txt' 2>>'$LOG_FILE'"
        report_count "$ep_dir/katana.txt" "katana endpoints"
    fi

    # ── hakrawler ──
    if require_tool "hakrawler"; then
        run_safe "hakrawler crawl" \
            "cat '$input' | hakrawler -d $HAKRAWLER_DEPTH -subs > '$ep_dir/hakrawler.txt' 2>>'$LOG_FILE'"
        report_count "$ep_dir/hakrawler.txt" "hakrawler endpoints"
    fi

    # ── Merge ──
    step "Merging crawled endpoints"
    merge_dedup "$ep_dir/all.txt" \
        "$ep_dir/katana.txt" \
        "$ep_dir/hakrawler.txt"
    report_count "$ep_dir/all.txt" "Total unique endpoints"

    # ── Categorize interesting paths ──
    if [[ -s "$ep_dir/all.txt" ]]; then
        grep -iE '(login|admin|dashboard|portal|panel|auth|signup|register)' \
            "$ep_dir/all.txt" 2>/dev/null \
            | sort -u > "$ep_dir/interesting_paths.txt" || true

        grep -iE '(/api/|/v[0-9]+/|/graphql|/rest/|swagger|openapi)' \
            "$ep_dir/all.txt" 2>/dev/null \
            | sort -u > "$ep_dir/api_paths.txt" || true

        grep -iE '\.(json|xml|yaml|yml|conf|config|env|bak|old|sql|log)' \
            "$ep_dir/all.txt" 2>/dev/null \
            | sort -u > "$ep_dir/sensitive_files.txt" || true

        report_count "$ep_dir/interesting_paths.txt" "Interesting paths (auth/admin)"
        report_count "$ep_dir/api_paths.txt" "API-related paths"
        report_count "$ep_dir/sensitive_files.txt" "Potentially sensitive files"
    fi

    success "Endpoint crawling complete."
}
