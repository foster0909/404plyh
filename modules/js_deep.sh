#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# MODULE 6: JavaScript Deep Intelligence Engine
# Discovers, probes, downloads, and extracts exposed source maps.
# Then runs local Python-based static analysis.
# ─────────────────────────────────────────────────────────────────────────────

module_js_deep() {
    if [[ "$SKIP_JS" == true ]]; then
        info "Skipping JavaScript analysis (--skip-js)"
        return 0
    fi

    header "Module 6: JavaScript Deep Intelligence Engine"
    local js_dir="$OUTPUT_DIR/js"
    local files_dir="$js_dir/files"
    local maps_dir="$js_dir/extracted_maps"
    local input="$OUTPUT_DIR/httpx/alive.txt"

    mkdir -p "$files_dir" "$maps_dir"

    if [[ ! -s "$input" ]]; then
        warn "No alive URLs. Skipping JS analysis."
        return 0
    fi

    local url_count
    url_count=$(count "$input")
    info "Initiating deep JS discovery across $url_count web services"

    # ── Step 1: Discover JS URLs ──
    step "Extracting script tags & JS URLs"
    local raw_js="$js_dir/discovered_raw.txt"
    > "$raw_js"

    # 1. Use katana to extract JS links from base HTML
    if require_tool "katana"; then
        run_safe "katana JS discovery" \
            "katana -list '$input' -d 1 -jc -silent -o '$js_dir/.katana_js.tmp' 2>>'$LOG_FILE'"
        if [[ -s "$js_dir/.katana_js.tmp" ]]; then
            cat "$js_dir/.katana_js.tmp" >> "$raw_js"
            rm -f "$js_dir/.katana_js.tmp"
        fi
    fi

    # 2. Add any other existing JS files from crawlers or history if they exist
    if [[ -f "$OUTPUT_DIR/endpoints/all.txt" ]]; then
        grep -iE '\.js(\?|$)' "$OUTPUT_DIR/endpoints/all.txt" >> "$raw_js" 2>/dev/null || true
    fi
    if [[ -f "$OUTPUT_DIR/historical/all_urls.txt" ]]; then
        grep -iE '\.js(\?|$)' "$OUTPUT_DIR/historical/all_urls.txt" >> "$raw_js" 2>/dev/null || true
    fi

    # Filter, clean, and dedup
    local js_list="$js_dir/discovered_scripts.txt"
    if [[ -s "$raw_js" ]]; then
        # Clean query parameters for downloading, keep unique URLs
        sort -u "$raw_js" | grep -iE '\.js(\?|$)' | grep -vE '\.(png|jpg|jpeg|gif|css|woff|woff2|ttf|svg)\b' > "$js_list"
        rm -f "$raw_js"
    else
        # Fallback: scrape directly using curl & grep if katana failed
        step "Katana JS discovery returned empty. Falling back to curl scraping."
        while IFS= read -r url; do
            curl -s -k --connect-timeout 5 --max-time 10 "$url" \
                | grep -oiE "src=[\"']([^\"']+\.js[^\"']*)" \
                | cut -d'"' -f2 | cut -d"'" -f2 \
                | while read -r script; do
                    if [[ "$script" =~ ^http ]]; then
                        echo "$script" >> "$js_list"
                    elif [[ "$script" =~ ^// ]]; then
                        echo "https:$script" >> "$js_list"
                    else
                        # Build absolute URL
                        local base
                        base=$(echo "$url" | grep -oP '^https?://[^/]+')
                        echo "$base/$script" >> "$js_list"
                    fi
                done
        done < "$input"
        [[ -f "$js_list" ]] && sort -u -o "$js_list" "$js_list"
    fi

    local js_count
    js_count=$(count "$js_list")
    if [[ $js_count -eq 0 ]]; then
        warn "No JS files discovered. Skipping deep JS analysis."
        return 0
    fi
    info "Discovered $js_count unique JavaScript scripts."

    # ── Step 2: Probe & Download JS files ──
    step "Validating and downloading JS files locally"
    local alive_json="$js_dir/scripts_alive.json"
    local alive_list="$js_dir/scripts_alive.txt"
    > "$alive_list"

    if require_tool "httpx"; then
        # Check status codes and content lengths
        run_safe "httpx scripts check" \
            "httpx -l '$js_list' -sc -cl -follow-redirects -timeout $HTTPX_TIMEOUT -rate-limit 100 -json -o '$alive_json' 2>>'$LOG_FILE'"
        if [[ -s "$alive_json" ]]; then
            jq -r 'select(.status_code == 200) | .url' "$alive_json" > "$alive_list"
        fi
    fi

    # Fallback to discovered list if httpx failed or returned empty
    if [[ ! -s "$alive_list" ]]; then
        cat "$js_list" > "$alive_list"
    fi

    local alive_count
    alive_count=$(count "$alive_list")
    info "Found $alive_count active JS files. Downloading..."

    local count=0
    while IFS= read -r url; do
        ((count++))
        # Hash or sanitize filename to store locally
        local safe_name
        safe_name=$(echo -n "$url" | md5sum | cut -d' ' -f1).js
        curl -s -k --connect-timeout 5 --max-time 15 "$url" > "$files_dir/$safe_name"
        # Write metadata mapping (filename -> URL)
        echo "$safe_name => $url" >> "$js_dir/scripts_map.txt"
    done < "$alive_list"

    # ── Step 3: Check and extract Source Maps ──
    step "Checking for exposed JS source maps (.js.map)"
    local map_check_list="$js_dir/source_maps_probed.txt"
    > "$map_check_list"

    # Build .map URLs
    while IFS= read -r url; do
        echo "${url}.map" >> "$map_check_list"
    done < "$alive_list"

    local live_maps_json="$js_dir/maps_alive.json"
    local live_maps_list="$js_dir/maps_alive.txt"
    > "$live_maps_list"

    if require_tool "httpx"; then
        run_safe "httpx source maps check" \
            "httpx -l '$map_check_list' -sc -follow-redirects -timeout $HTTPX_TIMEOUT -rate-limit 100 -json -o '$live_maps_json' 2>>'$LOG_FILE'"
        if [[ -s "$live_maps_json" ]]; then
            jq -r 'select(.status_code == 200) | .url' "$live_maps_json" > "$live_maps_list"
        fi
    fi

    local map_count
    map_count=$(count "$live_maps_list")
    if [[ $map_count -gt 0 ]]; then
        success "Exposed source maps found: ${GREEN}${map_count}${RESET}"
        local map_idx=0
        while IFS= read -r map_url; do
            ((map_idx++))
            local map_name
            map_name=$(echo -n "$map_url" | md5sum | cut -d' ' -f1).js.map
            curl -s -k --connect-timeout 5 --max-time 20 "$map_url" > "$js_dir/$map_name"
            # Reconstruct source code using Python helper
            python3 "$SCRIPT_DIR/modules/sourcemap_extractor.py" "$js_dir/$map_name" "$maps_dir" >> "$LOG_FILE" 2>&1
            # Add to map files index
            echo "$map_name => $map_url" >> "$js_dir/maps_map.txt"
            rm -f "$js_dir/$map_name" # Clean raw map JSON once extracted
        done < "$live_maps_list"
        # Write list of reconstructed source map files
        find "$maps_dir" -type f | sed "s|${maps_dir}/||" > "$js_dir/maps_files.txt"
    else
        info "No exposed source maps detected."
    fi

    # ── Step 4: Run local Static Analysis Scanner ──
    step "Running static analysis regex scanner on local JS code"
    # Scan both raw files and reconstructed map files
    python3 "$SCRIPT_DIR/modules/js_scanner.py" "$js_dir" "$js_dir" >> "$LOG_FILE" 2>&1

    # Map raw filenames back to original URLs in reports
    if [[ -f "$js_dir/scripts_map.txt" ]]; then
        step "Mapping scanned local filenames back to original URLs"
        for report in secrets.txt comments.txt; do
            local rep_file="$js_dir/$report"
            if [[ -s "$rep_file" ]]; then
                # Replace hashes with original URLs
                while IFS=" => " read -r hash url; do
                    # Strip leading spaces/formatting
                    hash=$(echo "$hash" | xargs)
                    url=$(echo "$url" | xargs)
                    if [[ -n "$hash" && -n "$url" ]]; then
                        sed -i "s|files/$hash|${url}|g" "$rep_file" 2>/dev/null || true
                    fi
                done < "$js_dir/scripts_map.txt"
            fi
        done
    fi

    # ── Step 5: Extract new subdomains for recursion ──
    step "Extracting subdomains from endpoints list"
    if [[ -s "$js_dir/endpoints.txt" ]]; then
        grep -oP 'https?://([a-zA-Z0-9._-]+\.'"$DOMAIN"')' "$js_dir/endpoints.txt" 2>/dev/null \
            | sed 's|https\?://||' \
            | sort -u > "$js_dir/new_hostnames.txt" || true

        if [[ -s "$js_dir/new_hostnames.txt" ]]; then
            local new_count
            new_count=$(count "$js_dir/new_hostnames.txt")
            local existing_count
            existing_count=$(count "$OUTPUT_DIR/subs/all.txt")

            cat "$js_dir/new_hostnames.txt" >> "$OUTPUT_DIR/subs/all.txt"
            sort -u -o "$OUTPUT_DIR/subs/all.txt" "$OUTPUT_DIR/subs/all.txt"

            local updated_count
            updated_count=$(count "$OUTPUT_DIR/subs/all.txt")
            local actually_new=$((updated_count - existing_count))

            if [[ $actually_new -gt 0 ]]; then
                success "Discovered $actually_new NEW hostnames from JS analysis. Recursion flag set."
                NEW_DOMAINS_FOUND=true
            fi
        fi
    fi

    # Deduplicate and sort outputs
    [[ -f "$js_dir/endpoints.txt" ]] && sort -u -o "$js_dir/endpoints.txt" "$js_dir/endpoints.txt"
    [[ -f "$js_dir/secrets.txt" ]] && sort -u -o "$js_dir/secrets.txt" "$js_dir/secrets.txt"
    [[ -f "$js_dir/leakage.txt" ]] && sort -u -o "$js_dir/leakage.txt" "$js_dir/leakage.txt"
    [[ -f "$js_dir/comments.txt" ]] && sort -u -o "$js_dir/comments.txt" "$js_dir/comments.txt"

    # Extract API endpoints separately for tech-stack matrix convenience
    if [[ -s "$js_dir/endpoints.txt" ]]; then
        grep -iE '(/api/|/v[0-9]+/|/graphql|/rest/|swagger|openapi)' "$js_dir/endpoints.txt" \
            | sort -u > "$js_dir/api_endpoints.txt" 2>/dev/null || true
    fi

    # Clean up temp check files
    rm -f "$js_dir/discovered_raw.txt" "$js_dir/discovered_scripts.txt" "$js_dir/source_maps_probed.txt" "$js_dir/maps_alive.txt" "$js_dir/maps_alive.json"

    success "Deep JavaScript analysis complete."
}
