#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# MODULE 5: Network Service Enumeration
# Tools: naabu, nmap
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
        # Plain text output: host:port pairs
        run_safe "naabu scan" \
            "naabu -l '$input' \
                -top-ports $NAABU_TOP_PORTS \
                -rate $RATE_LIMIT \
                -o '$ports_dir/naabu.txt' 2>>'$LOG_FILE'"
        report_count "$ports_dir/naabu.txt" "naabu host:port pairs"

        # JSON output (separate run to avoid corrupting the plain text file)
        if [[ -s "$ports_dir/naabu.txt" ]]; then
            run_safe "naabu JSON export" \
                "naabu -l '$input' \
                    -top-ports $NAABU_TOP_PORTS \
                    -rate $RATE_LIMIT \
                    -json \
                    -o '$ports_dir/naabu.json' 2>>'$LOG_FILE'"

            # Extract unique hosts with open ports for nmap deep scan
            awk -F':' '{print $1}' "$ports_dir/naabu.txt" 2>/dev/null \
                | sort -u > "$ports_dir/hosts_with_ports.txt"
        fi
    fi

    # ── nmap (deep service scan on discovered hosts) ──
    if require_tool "nmap"; then
        local nmap_input="$ports_dir/hosts_with_ports.txt"
        if [[ ! -s "$nmap_input" ]]; then
            nmap_input="$input"
            warn "No naabu results. Running nmap against all resolved hosts (limited)."
            # Limit to first 50 hosts to avoid extremely long scans
            head -50 "$input" > "$ports_dir/nmap_targets.txt"
            nmap_input="$ports_dir/nmap_targets.txt"
        fi

        run_safe "nmap service scan" \
            "nmap -sV -sC --top-ports 100 \
                -iL '$nmap_input' \
                -oA '$ports_dir/nmap_results' 2>>'$LOG_FILE'"
    fi

    # ── Re-probe discovered ports with httpx ──
    if [[ -s "$ports_dir/naabu.txt" ]] && command -v httpx &>/dev/null; then
        step "Re-probing discovered ports with httpx"
        httpx -l "$ports_dir/naabu.txt" \
            -sc -title -follow-redirects \
            -o "$ports_dir/httpx_ports.txt" 2>>"$LOG_FILE" || true

        # Append new alive URLs
        if [[ -s "$ports_dir/httpx_ports.txt" ]]; then
            cat "$ports_dir/httpx_ports.txt" >> "$OUTPUT_DIR/httpx/alive.txt"
            sort -u -o "$OUTPUT_DIR/httpx/alive.txt" "$OUTPUT_DIR/httpx/alive.txt"
            info "Updated alive URLs with port-based discoveries."
        fi
    fi

    success "Port scanning complete."
}
