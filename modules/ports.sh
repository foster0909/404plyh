#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# MODULE 5: Network Service Enumeration
# Tools: naabu, nmap
#
# Scale notes (large scopes / small hosts):
#   - naabu runs ONCE (JSON) and naabu.txt is derived from it; previously the
#     whole scan ran twice just to get both formats.
#   - CDN/WAF hosts only get 80/443 (NAABU_EXCLUDE_CDN) — same packet rate,
#     far fewer packets.
#   - nmap deep-scans only the ports naabu found, on at most NMAP_MAX_HOSTS
#     hosts (non-web ports first), with a per-host timeout.
#   - The httpx re-probe only covers non-80/443 ports (the HTTP stage already
#     probed those) and writes plain URLs, so alive.txt stays a clean URL list.
# ─────────────────────────────────────────────────────────────────────────────

module_port_scanning() {
    if [[ "$SKIP_PORTS" == true ]]; then
        info "Skipping port scanning (--skip-ports)"
        return 0
    fi

    header "Module 5: Network Service Enumeration"
    local ports_dir="$OUTPUT_DIR/ports"
    local input="$OUTPUT_DIR/dns/resolved.txt"

    # Fallback: if no resolved hosts (e.g. DNS was skipped), scan the domain directly
    if [[ ! -s "$input" ]]; then
        warn "No resolved hosts found. Falling back to target domain: $DOMAIN"
        echo "$DOMAIN" > "$ports_dir/fallback_targets.txt"
        input="$ports_dir/fallback_targets.txt"
    fi

    # ── naabu (fast discovery) ──
    if require_tool "naabu"; then
        local cdn_flag=""
        [[ "$NAABU_EXCLUDE_CDN" == true ]] && cdn_flag=" -exclude-cdn"
        local naabu_base="naabu -l '$input' -top-ports $NAABU_TOP_PORTS -rate $RATE_LIMIT -silent"

        if command -v jq >/dev/null 2>&1; then
            # One scan, JSON output; derive the plain host:port list from it.
            if ! run_safe "naabu scan" \
                "$naabu_base$cdn_flag -json -o '$ports_dir/naabu.json' >/dev/null 2>>'$LOG_FILE'" \
                && [[ -n "$cdn_flag" && ! -s "$ports_dir/naabu.json" ]]; then
                warn "naabu failed with -exclude-cdn (older naabu?). Retrying without it."
                run_safe "naabu scan (no CDN exclusion)" \
                    "$naabu_base -json -o '$ports_dir/naabu.json' >/dev/null 2>>'$LOG_FILE'"
            fi
            if [[ -s "$ports_dir/naabu.json" ]]; then
                jq -r 'select(.port != null)
                       | "\(.host // .ip):\(if (.port|type) == "object" then .port.Port else .port end)"' \
                    "$ports_dir/naabu.json" 2>>"$LOG_FILE" | sort -u > "$ports_dir/naabu.txt"
            else
                : > "$ports_dir/naabu.txt"
            fi
        else
            # No jq: plain text only (naabu.json is optional and has no readers).
            if ! run_safe "naabu scan" \
                "$naabu_base$cdn_flag -o '$ports_dir/naabu.txt' >/dev/null 2>>'$LOG_FILE'" \
                && [[ -n "$cdn_flag" && ! -s "$ports_dir/naabu.txt" ]]; then
                warn "naabu failed with -exclude-cdn (older naabu?). Retrying without it."
                run_safe "naabu scan (no CDN exclusion)" \
                    "$naabu_base -o '$ports_dir/naabu.txt' >/dev/null 2>>'$LOG_FILE'"
            fi
        fi
        report_count "$ports_dir/naabu.txt" "naabu host:port pairs"

        if [[ -s "$ports_dir/naabu.txt" ]]; then
            awk -F':' '{print $1}' "$ports_dir/naabu.txt" 2>/dev/null \
                | sort -u > "$ports_dir/hosts_with_ports.txt"
        fi
    fi

    # ── nmap (deep service scan on discovered hosts) ──
    if require_tool "nmap"; then
        local nmap_targets="$ports_dir/nmap_targets.txt"
        local port_list=""
        local max_hosts="$NMAP_MAX_HOSTS"
        [[ "$max_hosts" -gt 0 ]] 2>/dev/null || max_hosts=100

        if [[ -s "$ports_dir/naabu.txt" ]]; then
            # Hosts exposing something other than 80/443 first (those are the
            # interesting service-scan targets), then the rest, capped.
            awk -F':' '
                $2 != 80 && $2 != 443 { odd[$1] = 1 }
                { all[$1] = 1 }
                END {
                    for (h in odd) print h
                    for (h in all) if (!(h in odd)) print h
                }' "$ports_dir/naabu.txt" | head -n "$max_hosts" > "$nmap_targets"
            # Only the ports naabu actually saw open (on the selected hosts).
            port_list=$(awk -F':' 'NR==FNR { sel[$1] = 1; next } ($1 in sel) { print $2 }' \
                "$nmap_targets" "$ports_dir/naabu.txt" | sort -un | paste -sd, -)
            local total_hosts
            total_hosts=$(count "$ports_dir/hosts_with_ports.txt")
            if [[ "$total_hosts" -gt "$max_hosts" ]]; then
                warn "nmap limited to ${max_hosts} of ${total_hosts} hosts with open ports (NMAP_MAX_HOSTS)."
            fi
        else
            warn "No naabu results. Running nmap against resolved hosts (limited to first 50)."
            head -50 "$input" > "$nmap_targets"
        fi

        local port_arg="--top-ports 100"
        [[ -n "$port_list" ]] && port_arg="-p $port_list"

        if [[ -s "$nmap_targets" ]]; then
            run_safe "nmap service scan" \
                "nmap -sV -sC $port_arg \
                    --host-timeout $NMAP_HOST_TIMEOUT \
                    -iL '$nmap_targets' \
                    -oA '$ports_dir/nmap_results' >/dev/null 2>>'$LOG_FILE'"
        fi
    fi

    # ── Re-probe non-standard ports with httpx ──
    if [[ -s "$ports_dir/naabu.txt" ]] && command -v httpx &>/dev/null; then
        local reprobe="$ports_dir/reprobe_targets.txt"
        awk -F':' '$2 != 80 && $2 != 443' "$ports_dir/naabu.txt" > "$reprobe"
        if [[ -s "$reprobe" ]]; then
            step "Re-probing $(count "$reprobe") non-standard ports with httpx"
            eval "httpx -l '$reprobe' -silent -follow-redirects \
                -t $THREADS -timeout $HTTPX_TIMEOUT $(http_rate_flag http)$(header_flags) \
                -o '$ports_dir/httpx_ports.txt' >/dev/null 2>>'$LOG_FILE'" || true

            # Append new alive URLs (plain URLs only — alive.txt is a URL list)
            if [[ -s "$ports_dir/httpx_ports.txt" ]]; then
                grep -Eo '^https?://[^[:space:]]+' "$ports_dir/httpx_ports.txt" \
                    >> "$OUTPUT_DIR/httpx/alive.txt"
                sort -u -o "$OUTPUT_DIR/httpx/alive.txt" "$OUTPUT_DIR/httpx/alive.txt"
                info "Updated alive URLs with port-based discoveries."
            fi
        fi
        rm -f "$reprobe"
    fi

    success "Port scanning complete."
}
