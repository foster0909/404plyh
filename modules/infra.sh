#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# MODULE 9: Asset & Infrastructure Mapping
# Tools: amass intel, whois, jq
# ─────────────────────────────────────────────────────────────────────────────

module_infra_mapping() {
    if [[ "$SKIP_INFRA" == true ]]; then
        info "Skipping infrastructure mapping (--skip-infra)"
        return 0
    fi

    header "Module 9: Asset & Infrastructure Mapping"
    local infra_dir="$OUTPUT_DIR/infra"

    # ── amass intel ──
    if require_tool "amass"; then
        run_safe "amass intel" \
            "amass intel -d '$DOMAIN' -whois -o '$infra_dir/amass_intel.txt' 2>>'$LOG_FILE'"
        report_count "$infra_dir/amass_intel.txt" "amass intel results"
    fi

    # ── IP aggregation from httpx results ──
    step "Aggregating IP data from HTTP probe results"
    if [[ -s "$OUTPUT_DIR/httpx/results.json" ]]; then
        # Extract IP → hostname mapping
        jq -r 'select(.a != null) | "\(.a[]) \(.input)"' \
            "$OUTPUT_DIR/httpx/results.json" 2>/dev/null \
            | sort -u > "$infra_dir/ip_host_map.txt" || true

        # Unique IPs
        awk '{print $1}' "$infra_dir/ip_host_map.txt" 2>/dev/null \
            | sort -u > "$infra_dir/unique_ips.txt" || true

        report_count "$infra_dir/unique_ips.txt" "Unique IP addresses"

        # Group hosts by IP
        step "Grouping hosts by shared IP addresses"
        awk '{ips[$1] = ips[$1] ? ips[$1] ", " $2 : $2} END {for (ip in ips) print ip " => " ips[ip]}' \
            "$infra_dir/ip_host_map.txt" 2>/dev/null \
            | sort > "$infra_dir/ip_groups.txt" || true
    fi

    # ── CDN detection from server headers ──
    step "Detecting CDN and hosting providers"
    if [[ -s "$OUTPUT_DIR/httpx/results.json" ]]; then
        jq -r 'select(.webserver != null) | "\(.input) => \(.webserver)"' \
            "$OUTPUT_DIR/httpx/results.json" 2>/dev/null \
            | sort -u > "$infra_dir/server_headers.txt" || true

        # Common CDN signatures
        grep -iE '(cloudflare|akamai|fastly|cloudfront|incapsula|sucuri|varnish|nginx|apache)' \
            "$infra_dir/server_headers.txt" 2>/dev/null \
            | sort > "$infra_dir/cdn_hosts.txt" || true

        report_count "$infra_dir/cdn_hosts.txt" "CDN/proxy-detected hosts"
    fi

    # ── WHOIS lookups for unique IPs (limited to avoid rate-limiting) ──
    if require_tool "whois"; then
        step "Running WHOIS lookups on unique IPs"
        if [[ -s "$infra_dir/unique_ips.txt" ]]; then
            local ip_count=0
            while IFS= read -r ip; do
                # Limit to first 20 IPs to avoid spamming WHOIS
                if (( ip_count >= 20 )); then
                    warn "WHOIS lookup limited to 20 IPs."
                    break
                fi
                local org
                org=$(whois "$ip" 2>/dev/null | grep -iE '^(org-name|orgname|organization|descr):' | head -1 | sed 's/^[^:]*:\s*//')
                if [[ -n "$org" ]]; then
                    echo "$ip => $org" >> "$infra_dir/ip_orgs.txt"
                fi
                ((ip_count++))
            done < "$infra_dir/unique_ips.txt"
            report_count "$infra_dir/ip_orgs.txt" "IP → organization mappings"
        fi
    fi

    # ── Build infrastructure JSON ──
    step "Building infrastructure map (JSON)"
    if [[ -s "$infra_dir/ip_host_map.txt" ]]; then
        {
            echo "{"
            echo '  "domain": "'"$DOMAIN"'",'
            echo '  "scan_date": "'"$(date -Iseconds)"'",'
            echo '  "infrastructure": {'

            # IP groups
            echo '    "ip_groups": {'
            local first=true
            while IFS=' => ' read -r ip hosts; do
                if [[ "$first" == true ]]; then
                    first=false
                else
                    echo ","
                fi
                printf '      "%s": ["%s"]' "$ip" "$(echo "$hosts" | sed 's/, /", "/g')"
            done < "$infra_dir/ip_groups.txt"
            echo ""
            echo '    }'

            echo "  }"
            echo "}"
        } > "$infra_dir/infra_map.json" 2>/dev/null || true
    fi

    success "Infrastructure mapping complete."
}
