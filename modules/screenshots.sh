#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# MODULE 4: Visual Surface Mapping
# Tools: gowitness
# ─────────────────────────────────────────────────────────────────────────────

# Available memory in MB (from /proc/meminfo); prints nothing if unknown.
mem_available_mb() {
    [[ -r /proc/meminfo ]] || return 0
    awk '/^MemAvailable:/ {print int($2 / 1024); exit}' /proc/meminfo
}

# Wait for memory to recover above SCREENSHOT_MIN_MEM_MB. Returns 1 if it
# never does (caller decides whether to degrade or stop).
wait_for_memory() {
    local need="$SCREENSHOT_MIN_MEM_MB" avail tries=0
    avail=$(mem_available_mb)
    [[ -z "$avail" ]] && return 0
    while [[ "$avail" -lt "$need" ]]; do
        if [[ $tries -ge 8 ]]; then
            return 1
        fi
        warn "Low memory (${avail} MB available, need ${need} MB). Pausing screenshots..."
        sleep 15
        ((tries++))
        avail=$(mem_available_mb)
    done
    return 0
}

module_screenshots() {
    if [[ "$SKIP_SCREENSHOTS" == true ]]; then
        info "Skipping screenshots (--skip-screenshots)"
        return 0
    fi

    header "Module 4: Visual Surface Mapping"
    local ss_dir="$OUTPUT_DIR/screenshots"
    local input="$OUTPUT_DIR/httpx/alive.txt"

    if [[ ! -s "$input" ]]; then
        warn "No alive URLs. Skipping screenshots."
        return 0
    fi

    if ! require_tool "gowitness"; then
        warn "gowitness not available. Skipping screenshots."
        return 0
    fi

    local threads="$SCREENSHOT_THREADS"
    local batch_size="$SCREENSHOT_BATCH"
    [[ "$batch_size" -gt 0 ]] 2>/dev/null || batch_size=250

    local total
    total=$(count "$input")

    # Split the URL list into batches. Each batch is a separate gowitness run,
    # so its headless Chrome exits and frees memory before the next one starts.
    local batch_dir
    batch_dir=$(mktemp -d "${TMPDIR:-/tmp}/recon_ss.XXXXXX") || {
        warn "Could not create batch directory. Skipping screenshots."
        return 0
    }
    split -l "$batch_size" -d -a 5 "$input" "$batch_dir/batch_"

    local -a batches=("$batch_dir"/batch_*)
    local nbatches=${#batches[@]}
    info "Screenshotting ${total} URLs in ${nbatches} batch(es) of ${batch_size} (threads: ${threads})"

    # Bound each batch so a hung Chrome cannot stall the pipeline forever.
    local -a timeout_cmd=()
    if command -v timeout >/dev/null 2>&1 && [[ "$SCREENSHOT_BATCH_TIMEOUT" -gt 0 ]] 2>/dev/null; then
        timeout_cmd=(timeout --kill-after=30 "$SCREENSHOT_BATCH_TIMEOUT")
    fi
    # Lower CPU priority so the rest of the system (sshd, watchdog daemon)
    # stays responsive while Chrome is busy.
    local -a nice_cmd=()
    command -v nice >/dev/null 2>&1 && nice_cmd=(nice -n 10)

    local i=0 batch rc stopped=false
    for batch in "${batches[@]}"; do
        ((i++))
        if ! wait_for_memory; then
            if [[ "$threads" -gt 1 ]]; then
                threads=$(( threads / 2 ))
                warn "Memory still low; reducing screenshot threads to ${threads}"
            else
                warn "Memory still low at 1 thread. Stopping screenshots at batch ${i}/${nbatches} to protect the host."
                log "WARN" "Screenshots stopped early (low memory) at batch ${i}/${nbatches}"
                stopped=true
                break
            fi
        fi

        step "Screenshot batch ${i}/${nbatches} ($(count "$batch") URLs, ${threads} threads, $(mem_available_mb) MB free)"
        "${timeout_cmd[@]}" "${nice_cmd[@]}" gowitness scan file -f "$batch" \
            --screenshot-path "$ss_dir/" \
            --threads "$threads" 2>>"$LOG_FILE"
        rc=$?
        if [[ $rc -eq 124 || $rc -eq 137 ]]; then
            warn "Screenshot batch ${i} timed out after ${SCREENSHOT_BATCH_TIMEOUT}s. Continuing with next batch."
        elif [[ $rc -ne 0 ]]; then
            warn "gowitness returned ${rc} on batch ${i}. Continuing..."
        fi
    done
    rm -rf "$batch_dir"

    # Count screenshots
    local ss_count
    ss_count=$(find "$ss_dir" -name "*.png" -o -name "*.jpg" 2>/dev/null | wc -l)
    info "Screenshots captured: ${GREEN}${ss_count}${RESET}"

    if [[ "$stopped" == true ]]; then
        warn "Screenshot capture incomplete (stopped on low memory)."
    else
        success "Screenshot capture complete."
    fi
}
