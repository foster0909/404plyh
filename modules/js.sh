#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# MODULE 6: JavaScript Intelligence Extraction
# Tools: linkfinder.py, SecretFinder.py (via python3)
# ─────────────────────────────────────────────────────────────────────────────

module_js_analysis() {
    if [[ "$SKIP_JS" == true ]]; then
        info "Skipping JavaScript analysis (--skip-js)"
        return 0
    fi

    header "Module 6: JavaScript Intelligence Extraction"
    local js_dir="$OUTPUT_DIR/js"
    local input="$OUTPUT_DIR/httpx/alive.txt"

    if [[ ! -s "$input" ]]; then
        warn "No alive URLs. Skipping JS analysis."
        return 0
    fi

    local has_linkfinder=false
    local has_secretfinder=false
    require_py_tool "$LINKFINDER_PATH" "linkfinder.py" && has_linkfinder=true
    require_py_tool "$SECRETFINDER_PATH" "SecretFinder.py" && has_secretfinder=true

    if [[ "$has_linkfinder" == false && "$has_secretfinder" == false ]]; then
        warn "Neither linkfinder.py nor SecretFinder.py available. Skipping JS analysis."
        return 0
    fi

    local url_count
    url_count=$(count "$input")
    info "Analyzing JavaScript across $url_count URLs"

    # ── LinkFinder (python3 linkfinder.py) ──
    if [[ "$has_linkfinder" == true ]]; then
        step "Running LinkFinder for endpoint extraction"
        local lf_count=0
        while IFS= read -r url; do
            python3 "$LINKFINDER_PATH" -i "$url" -o cli 2>/dev/null >> "$js_dir/linkfinder_raw.txt" || true
            ((lf_count++))
            # Progress indicator every 25 URLs
            if (( lf_count % 25 == 0 )); then
                echo -e "    ${GRAY}LinkFinder progress: $lf_count / $url_count${RESET}"
            fi
        done < "$input"

        if [[ -s "$js_dir/linkfinder_raw.txt" ]]; then
            sort -u "$js_dir/linkfinder_raw.txt" > "$js_dir/endpoints.txt"
            report_count "$js_dir/endpoints.txt" "JS endpoints discovered"
        fi
    fi

    # ── SecretFinder (python3 SecretFinder.py) ──
    if [[ "$has_secretfinder" == true ]]; then
        step "Running SecretFinder for secret/token detection"
        while IFS= read -r url; do
            python3 "$SECRETFINDER_PATH" -i "$url" -o cli 2>/dev/null >> "$js_dir/secrets_raw.txt" || true
        done < "$input"

        if [[ -s "$js_dir/secrets_raw.txt" ]]; then
            sort -u "$js_dir/secrets_raw.txt" > "$js_dir/secrets.txt"
            report_count "$js_dir/secrets.txt" "Potential secrets/tokens found"
        fi
    fi

    # ── Extract new hostnames from JS endpoints ──
    step "Extracting new hostnames from JavaScript intelligence"
    if [[ -s "$js_dir/endpoints.txt" ]]; then
        grep -oP 'https?://([a-zA-Z0-9._-]+\.'"$DOMAIN"')' "$js_dir/endpoints.txt" 2>/dev/null \
            | sed 's|https\?://||' \
            | sort -u > "$js_dir/new_hostnames.txt" || true

        if [[ -s "$js_dir/new_hostnames.txt" ]]; then
            local new_count
            new_count=$(count "$js_dir/new_hostnames.txt")
            local existing_count
            existing_count=$(count "$OUTPUT_DIR/subs/all.txt")

            # Add new hostnames back into the subdomain list
            cat "$js_dir/new_hostnames.txt" >> "$OUTPUT_DIR/subs/all.txt"
            sort -u -o "$OUTPUT_DIR/subs/all.txt" "$OUTPUT_DIR/subs/all.txt"

            local updated_count
            updated_count=$(count "$OUTPUT_DIR/subs/all.txt")
            local actually_new=$((updated_count - existing_count))

            if [[ $actually_new -gt 0 ]]; then
                success "Discovered $actually_new NEW hostnames from JavaScript. Recursion flag set."
                NEW_DOMAINS_FOUND=true
            else
                info "No new unique hostnames from JavaScript analysis."
            fi
        fi
    fi

    # ── Extract other intelligence ──
    if [[ -s "$js_dir/endpoints.txt" ]]; then
        # API endpoints
        grep -iE '(/api/|/v[0-9]+/|/graphql|/rest/)' "$js_dir/endpoints.txt" 2>/dev/null \
            | sort -u > "$js_dir/api_endpoints.txt" || true

        # S3 / storage buckets
        grep -oiE '[a-z0-9.-]+\.s3\.amazonaws\.com|[a-z0-9.-]+\.storage\.googleapis\.com|[a-z0-9.-]+\.blob\.core\.windows\.net' \
            "$js_dir/endpoints.txt" 2>/dev/null \
            | sort -u > "$js_dir/buckets.txt" || true

        # Websocket endpoints
        grep -oiE 'wss?://[a-zA-Z0-9./_-]+' "$js_dir/endpoints.txt" 2>/dev/null \
            | sort -u > "$js_dir/websockets.txt" || true
    fi

    success "JavaScript analysis complete."
}
