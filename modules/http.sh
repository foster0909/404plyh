#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# MODULE 3: HTTP Service Discovery
# Tools: httpx
# ─────────────────────────────────────────────────────────────────────────────

module_http_probing() {
    if [[ "$SKIP_HTTP" == true ]]; then
        info "Skipping HTTP probing (--skip-http)"
        return 0
    fi

    header "Module 3: HTTP Service Discovery"
    local httpx_dir="$OUTPUT_DIR/httpx"
    local input="$OUTPUT_DIR/dns/resolved.txt"

    if [[ ! -s "$input" ]]; then
        warn "No resolved hosts. Skipping HTTP probing."
        return 0
    fi

    if ! require_tool "httpx"; then
        warn "httpx not available. Skipping HTTP probing."
        return 0
    fi

    run_safe "httpx probe" \
        "httpx -l '$input' \
            -sc -title -tech-detect -server -ip -follow-redirects \
            -t $THREADS -timeout $HTTPX_TIMEOUT \
            -json -o '$httpx_dir/results.json' 2>>'$LOG_FILE'"

    # Extract alive URLs
    if [[ -s "$httpx_dir/results.json" ]]; then
        jq -r '.url' "$httpx_dir/results.json" 2>/dev/null \
            | sort -u > "$httpx_dir/alive.txt"

        # Extract text summary
        jq -r '"\(.url) [\(.status_code)] [\(.title // "N/A")] [\(.webserver // "N/A")]"' \
            "$httpx_dir/results.json" 2>/dev/null \
            > "$httpx_dir/summary.txt"
    fi

    report_count "$httpx_dir/alive.txt" "Alive URLs"

    success "HTTP probing complete."
}
