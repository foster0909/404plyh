#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# RECON ENGINE — Live Monitor Module
# Lightweight recon + diff engine for continuous change detection.
# Tracks new/removed subdomains and newly opened/closed ports.
# ─────────────────────────────────────────────────────────────────────────────

# ── Baseline management ─────────────────────────────────────────────────────

monitor_init_baselines() {
    local monitor_dir="$OUTPUT_DIR/monitor"
    local baselines_dir="$monitor_dir/baselines"
    mkdir -p "$baselines_dir" "$monitor_dir/changes"

    # Initialize subdomain baseline from existing recon data
    if [[ -s "$OUTPUT_DIR/subs/all.txt" ]]; then
        cp "$OUTPUT_DIR/subs/all.txt" "$baselines_dir/subdomains.txt"
        info "Subdomain baseline initialized: $(count "$baselines_dir/subdomains.txt") hosts"
    else
        touch "$baselines_dir/subdomains.txt"
        info "Subdomain baseline initialized (empty — first scan)"
    fi

    # Initialize port baseline from existing recon data
    if [[ -s "$OUTPUT_DIR/ports/naabu.txt" ]]; then
        cp "$OUTPUT_DIR/ports/naabu.txt" "$baselines_dir/ports.txt"
        info "Port baseline initialized: $(count "$baselines_dir/ports.txt") host:port pairs"
    else
        touch "$baselines_dir/ports.txt"
        info "Port baseline initialized (empty — first scan)"
    fi

    success "Baselines created at $baselines_dir/"
    log "INFO" "Monitor baselines initialized"
}

# ── Lightweight subdomain scan ──────────────────────────────────────────────

monitor_scan_subdomains() {
    header "Monitor: Subdomain Scan"
    local scan_dir="$OUTPUT_DIR/monitor/scan_tmp"
    mkdir -p "$scan_dir"

    local combined="$scan_dir/subs_raw.txt"
    > "$combined"

    # subfinder
    if require_tool "subfinder"; then
        run_safe "subfinder (monitor)" \
            "timeout 120 subfinder -d '$DOMAIN' -all -silent -t $THREADS -o '$scan_dir/subfinder.txt'"
        [[ -s "$scan_dir/subfinder.txt" ]] && cat "$scan_dir/subfinder.txt" >> "$combined"
    fi

    # amass (passive)
    if require_tool "amass"; then
        run_safe "amass passive (monitor)" \
            "timeout 120 amass enum -passive -d '$DOMAIN' -o '$scan_dir/amass.txt' 2>>'$LOG_FILE'"
        [[ -s "$scan_dir/amass.txt" ]] && cat "$scan_dir/amass.txt" >> "$combined"
    fi

    # assetfinder
    if require_tool "assetfinder"; then
        run_safe "assetfinder (monitor)" \
            "timeout 60 assetfinder --subs-only '$DOMAIN' > '$scan_dir/assetfinder.txt'"
        [[ -s "$scan_dir/assetfinder.txt" ]] && cat "$scan_dir/assetfinder.txt" >> "$combined"
    fi

    # crt.sh
    step "Querying crt.sh"
    local crtsh_url="https://crt.sh/?q=%25.${DOMAIN}&output=json"
    curl -s --connect-timeout 10 --max-time 30 "$crtsh_url" 2>/dev/null \
        | jq -r '.[].name_value' 2>/dev/null \
        | sed 's/\*\.//g' \
        | sort -u >> "$combined" || true

    # Normalize and dedup
    normalize_hosts "$combined" "$scan_dir/subdomains.txt"
    report_count "$scan_dir/subdomains.txt" "Monitor: subdomains discovered"
}

# ── Lightweight port scan ───────────────────────────────────────────────────

monitor_scan_ports() {
    header "Monitor: Port Scan"
    local scan_dir="$OUTPUT_DIR/monitor/scan_tmp"
    local sub_input="$scan_dir/subdomains.txt"

    if [[ ! -s "$sub_input" ]]; then
        warn "No subdomains to port scan."
        touch "$scan_dir/ports.txt"
        return 0
    fi

    # Resolve DNS first if puredns is available
    if require_tool "puredns"; then
        local puredns_cmd="timeout 180 puredns resolve '$sub_input' -w '$scan_dir/resolved.txt' -t $THREADS"
        if [[ -n "$RESOLVERS" && -f "$RESOLVERS" ]]; then
            puredns_cmd+=" -r '$RESOLVERS'"
        elif [[ -f "$SCRIPT_DIR/resolvers.txt" ]]; then
            puredns_cmd+=" -r '$SCRIPT_DIR/resolvers.txt'"
        fi
        run_safe "puredns resolve (monitor)" "$puredns_cmd"

        if [[ -s "$scan_dir/resolved.txt" ]]; then
            sub_input="$scan_dir/resolved.txt"
        fi
    fi

    # naabu port scan
    if require_tool "naabu"; then
        run_safe "naabu scan (monitor)" \
            "timeout 300 naabu -l '$sub_input' \
                -top-ports $NAABU_TOP_PORTS \
                -rate $RATE_LIMIT \
                -o '$scan_dir/ports.txt' 2>>'$LOG_FILE'"
        report_count "$scan_dir/ports.txt" "Monitor: host:port pairs discovered"
    else
        touch "$scan_dir/ports.txt"
        warn "naabu not available. Skipping port scan."
    fi
}

# ── Diff engine ─────────────────────────────────────────────────────────────

monitor_diff() {
    header "Monitor: Computing Diff"
    local baselines_dir="$OUTPUT_DIR/monitor/baselines"
    local scan_dir="$OUTPUT_DIR/monitor/scan_tmp"
    local changes_dir="$OUTPUT_DIR/monitor/changes"

    local baseline_subs="$baselines_dir/subdomains.txt"
    local baseline_ports="$baselines_dir/ports.txt"
    local current_subs="$scan_dir/subdomains.txt"
    local current_ports="$scan_dir/ports.txt"

    # Ensure files exist and are sorted
    for f in "$baseline_subs" "$baseline_ports" "$current_subs" "$current_ports"; do
        [[ -f "$f" ]] || touch "$f"
        sort -u -o "$f" "$f"
    done

    # Compute subdomain diffs
    local new_subs_file="$scan_dir/new_subdomains.txt"
    local removed_subs_file="$scan_dir/removed_subdomains.txt"
    comm -13 "$baseline_subs" "$current_subs" > "$new_subs_file" 2>/dev/null || true
    comm -23 "$baseline_subs" "$current_subs" > "$removed_subs_file" 2>/dev/null || true

    # Compute port diffs
    local new_ports_file="$scan_dir/new_ports.txt"
    local removed_ports_file="$scan_dir/removed_ports.txt"
    comm -13 "$baseline_ports" "$current_ports" > "$new_ports_file" 2>/dev/null || true
    comm -23 "$baseline_ports" "$current_ports" > "$removed_ports_file" 2>/dev/null || true

    local new_subs_count removed_subs_count new_ports_count removed_ports_count
    new_subs_count=$(count "$new_subs_file")
    removed_subs_count=$(count "$removed_subs_file")
    new_ports_count=$(count "$new_ports_file")
    removed_ports_count=$(count "$removed_ports_file")
    local total_changes=$(( new_subs_count + removed_subs_count + new_ports_count + removed_ports_count ))

    # Display results in terminal
    echo ""
    if [[ $total_changes -eq 0 ]]; then
        info "No changes detected since last baseline."
    else
        if [[ $new_subs_count -gt 0 ]]; then
            success "🆕 New subdomains: ${GREEN}+${new_subs_count}${RESET}"
            while IFS= read -r sub; do
                echo -e "    ${GREEN}+ ${sub}${RESET}"
            done < "$new_subs_file"
        fi
        if [[ $removed_subs_count -gt 0 ]]; then
            warn "❌ Removed subdomains: ${RED}-${removed_subs_count}${RESET}"
            while IFS= read -r sub; do
                echo -e "    ${RED}- ${sub}${RESET}"
            done < "$removed_subs_file"
        fi
        if [[ $new_ports_count -gt 0 ]]; then
            success "🚪 New ports: ${GREEN}+${new_ports_count}${RESET}"
            while IFS= read -r port; do
                echo -e "    ${GREEN}+ ${port}${RESET}"
            done < "$new_ports_file"
        fi
        if [[ $removed_ports_count -gt 0 ]]; then
            warn "🔒 Removed ports: ${RED}-${removed_ports_count}${RESET}"
            while IFS= read -r port; do
                echo -e "    ${RED}- ${port}${RESET}"
            done < "$removed_ports_file"
        fi
    fi
    echo ""

    # Build change record JSON
    local ts
    ts=$(date -Iseconds 2>/dev/null || date +"%Y-%m-%dT%H:%M:%S")
    local ts_file
    ts_file=$(date +"%Y%m%d_%H%M%S")

    local change_file="$changes_dir/${ts_file}.json"

    # Build JSON arrays for new/removed items
    local new_subs_json removed_subs_json new_ports_json removed_ports_json
    new_subs_json=$(jq -R -s 'split("\n") | map(select(length > 0))' < "$new_subs_file" 2>/dev/null || echo '[]')
    removed_subs_json=$(jq -R -s 'split("\n") | map(select(length > 0))' < "$removed_subs_file" 2>/dev/null || echo '[]')
    new_ports_json=$(jq -R -s 'split("\n") | map(select(length > 0))' < "$new_ports_file" 2>/dev/null || echo '[]')
    removed_ports_json=$(jq -R -s 'split("\n") | map(select(length > 0))' < "$removed_ports_file" 2>/dev/null || echo '[]')

    cat > "$change_file" <<ENDJSON
{
  "timestamp": "$ts",
  "domain": "$DOMAIN",
  "new_subdomains": $new_subs_json,
  "removed_subdomains": $removed_subs_json,
  "new_ports": $new_ports_json,
  "removed_ports": $removed_ports_json,
  "summary": {
    "subdomains_added": $new_subs_count,
    "subdomains_removed": $removed_subs_count,
    "ports_added": $new_ports_count,
    "ports_removed": $removed_ports_count,
    "total_changes": $total_changes
  },
  "baseline_stats": {
    "total_subdomains": $(count "$current_subs"),
    "total_ports": $(count "$current_ports")
  }
}
ENDJSON

    success "Change record saved: $change_file"
    log "INFO" "Monitor diff: +${new_subs_count}/-${removed_subs_count} subs, +${new_ports_count}/-${removed_ports_count} ports"

    # Update baselines with current data
    step "Updating baselines"
    cp "$current_subs" "$baseline_subs"
    cp "$current_ports" "$baseline_ports"
    success "Baselines updated."

    # Also update the main recon data
    if [[ -s "$current_subs" ]]; then
        cat "$current_subs" >> "$OUTPUT_DIR/subs/all.txt" 2>/dev/null || true
        sort -u -o "$OUTPUT_DIR/subs/all.txt" "$OUTPUT_DIR/subs/all.txt" 2>/dev/null || true
    fi

    # Clean up temp scan dir
    rm -rf "$scan_dir"

    # Return the change file path (for notifications)
    MONITOR_CHANGE_FILE="$change_file"
    MONITOR_TOTAL_CHANGES=$total_changes
}

# ── Main monitor entrypoint ─────────────────────────────────────────────────

run_monitor() {
    local init_mode="${1:-false}"

    header "Recon Engine — Live Monitor"
    info "Target: ${BOLD}${DOMAIN}${RESET}"
    info "Output: $OUTPUT_DIR"

    local monitor_dir="$OUTPUT_DIR/monitor"
    local baselines_dir="$monitor_dir/baselines"
    mkdir -p "$baselines_dir" "$monitor_dir/changes"

    # Init mode: just create baselines
    if [[ "$init_mode" == "true" ]]; then
        info "Initializing baselines (no diff will be performed)"
        monitor_scan_subdomains
        monitor_scan_ports

        # Set baselines from scan results
        local scan_dir="$OUTPUT_DIR/monitor/scan_tmp"
        [[ -s "$scan_dir/subdomains.txt" ]] && cp "$scan_dir/subdomains.txt" "$baselines_dir/subdomains.txt"
        [[ -s "$scan_dir/ports.txt" ]] && cp "$scan_dir/ports.txt" "$baselines_dir/ports.txt"

        report_count "$baselines_dir/subdomains.txt" "Baseline subdomains"
        report_count "$baselines_dir/ports.txt" "Baseline host:port pairs"

        rm -rf "$scan_dir"
        success "Monitor baselines initialized. Run without --init for change detection."
        return 0
    fi

    # Check if baselines exist
    if [[ ! -f "$baselines_dir/subdomains.txt" && ! -f "$baselines_dir/ports.txt" ]]; then
        warn "No baselines found. Running init first..."
        run_monitor "true"
        info "Baselines created. Run monitor again to detect changes."
        return 0
    fi

    # Normal mode: scan, diff, notify
    monitor_scan_subdomains
    monitor_scan_ports
    monitor_diff

    # Send Discord notification if configured
    if [[ -n "${MONITOR_CHANGE_FILE:-}" ]]; then
        notify_monitor_changes "$DOMAIN" "$MONITOR_CHANGE_FILE"
    fi

    success "Monitor scan complete."
}
