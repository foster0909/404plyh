#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# MODULE: Optional Historical URL Validation
# Filters historical + crawled URLs for interesting patterns, then validates
# each one with httpx using highly conservative rate limits.
#
# Output:
#   historical/probed_interesting.txt        — filtered URLs matching patterns
#   historical/validated_interesting.json     — httpx JSON probe data
#   historical/validated_interesting.txt      — text list of alive interesting URLs
# ─────────────────────────────────────────────────────────────────────────────

# ── Interesting URL patterns ────────────────────────────────────────────────

HIST_PROBE_PATTERNS=(
    # Path keywords
    '/admin'
    '/login'
    '/api/'
    '/auth'
    '/debug'
    '/config'
    '/backup'
    '/swagger'
    '/graphql'
    '/upload'
    '/internal'
    '/dev/'
    '/staging'
    '/test/'
    '/panel'
    '/console'
    '/dashboard'
    '/setup'
    '/install'
    '/phpinfo'
    '/phpmyadmin'
    '/wp-admin'
    '/wp-login'
    '/actuator'
    '/health'
    '/metrics'
    '/status'
    '/server-status'
    '/server-info'
    '/cgi-bin'
    '/manager'
    '/portal'
    '/jenkins'
    '/jira'
    '/grafana'
    '/kibana'
    '/solr'
    '/adminer'
    # File extensions and dotfiles
    '\.env'
    '\.json'
    '\.xml'
    '\.yml'
    '\.yaml'
    '\.conf'
    '\.cfg'
    '\.ini'
    '\.bak'
    '\.sql'
    '\.log'
    '\.git'
    '\.svn'
    '\.htaccess'
    '\.htpasswd'
    '\.DS_Store'
    '\.npmrc'
    '\.dockerenv'
    'Dockerfile'
    'docker-compose'
    'package\.json'
    'composer\.json'
    'web\.config'
    'robots\.txt'
    'sitemap\.xml'
    'crossdomain\.xml'
    '\.well-known'
    'phpunit'
    'wp-config'
)

# ── Build grep pattern ──────────────────────────────────────────────────────

_build_hist_probe_regex() {
    local regex=""
    for p in "${HIST_PROBE_PATTERNS[@]}"; do
        if [[ -n "$regex" ]]; then
            regex="${regex}|${p}"
        else
            regex="$p"
        fi
    done
    echo "$regex"
}

# ── Main module ─────────────────────────────────────────────────────────────

module_validate_historical() {
    if [[ "$VALIDATE_HISTORICAL" != true ]]; then
        info "Skipping optional historical URL validation (use --validate-historical to enable)"
        return 0
    fi

    header "Module: Historical URL Validation"
    local hist_dir="$OUTPUT_DIR/historical"
    local url_pool="$hist_dir/.probe_pool.tmp"

    # ── 1. Build URL pool from all sources ──
    step "Building URL pool from historical + endpoint data"
    > "$url_pool"

    for src in \
        "$hist_dir/all_urls.txt" \
        "$OUTPUT_DIR/endpoints/all.txt" \
        "$OUTPUT_DIR/endpoints/interesting_paths.txt" \
        "$OUTPUT_DIR/endpoints/api_paths.txt" \
        "$OUTPUT_DIR/endpoints/sensitive_files.txt" \
        "$OUTPUT_DIR/js/endpoints.txt" \
        "$OUTPUT_DIR/js/api_endpoints.txt"; do
        [[ -s "$src" ]] && cat "$src" >> "$url_pool"
    done

    if [[ ! -s "$url_pool" ]]; then
        warn "No URLs available for validation. Skipping."
        rm -f "$url_pool"
        return 0
    fi

    local total_pool
    total_pool=$(sort -u "$url_pool" | wc -l | tr -d ' ')
    info "Total URL pool: $total_pool URLs"

    # ── 2. Filter for interesting patterns ──
    step "Filtering for interesting URL patterns"
    local regex
    regex=$(_build_hist_probe_regex)

    sort -u "$url_pool" | grep -iE "$regex" | sort -u > "$hist_dir/probed_interesting.txt"
    rm -f "$url_pool"

    local interesting_count
    interesting_count=$(count "$hist_dir/probed_interesting.txt")
    info "Interesting URLs matched: ${GREEN}${interesting_count}${RESET} (from $total_pool total)"

    if [[ "$interesting_count" -eq 0 ]]; then
        info "No interesting URLs found. Skipping validation."
        return 0
    fi

    # ── 3. Validate with httpx ──
    if ! require_tool "httpx"; then
        warn "httpx not available. Skipping validation."
        return 0
    fi

    # Safe defaults requested by user:
    # rate limit: 10 req/sec, threads: 5, timeout: 8, retries: 0
    step "Validating $interesting_count interesting URLs (rate=10, threads=5, timeout=8)"
    info "This step uses highly conservative rate limits to avoid blockages."

    run_safe "httpx validation (historical)" \
        "httpx -l '$hist_dir/probed_interesting.txt' \
            -sc -title -content-type -content-length -location \
            -follow-redirects \
            -timeout 8 \
            -retries 0 \
            -rate-limit 10 \
            -threads 5 \
            -json \
            -o '$hist_dir/validated_interesting.json' 2>>'$LOG_FILE'"

    # ── 4. Generate clean text list & report ──
    if [[ -s "$hist_dir/validated_interesting.json" ]]; then
        jq -r '.url' "$hist_dir/validated_interesting.json" | sort -u > "$hist_dir/validated_interesting.txt"
        local validated_count
        validated_count=$(count "$hist_dir/validated_interesting.txt")
        success "Validated $validated_count alive interesting URLs."

        # Quick summary of status codes
        local code_2xx code_3xx code_4xx code_5xx
        code_2xx=$(grep -c '"status_code":2' "$hist_dir/validated_interesting.json" 2>/dev/null || echo 0)
        code_3xx=$(grep -c '"status_code":3' "$hist_dir/validated_interesting.json" 2>/dev/null || echo 0)
        code_4xx=$(grep -c '"status_code":4' "$hist_dir/validated_interesting.json" 2>/dev/null || echo 0)
        code_5xx=$(grep -c '"status_code":5' "$hist_dir/validated_interesting.json" 2>/dev/null || echo 0)

        info "  ${GREEN}2xx: $code_2xx${RESET}  ${BLUE}3xx: $code_3xx${RESET}  ${YELLOW}4xx: $code_4xx${RESET}  ${RED}5xx: $code_5xx${RESET}"
    else
        warn "No live interesting URLs resolved."
        > "$hist_dir/validated_interesting.txt"
    fi

    success "Historical URL validation complete."
}
