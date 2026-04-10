#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# MODULE 4: Visual Surface Mapping
# Tools: gowitness
# ─────────────────────────────────────────────────────────────────────────────

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

    run_safe "gowitness scan" \
        "gowitness scan file -f '$input' \
            --screenshot-path '$ss_dir/' \
            --threads $THREADS 2>>'$LOG_FILE'"

    # Count screenshots
    local ss_count
    ss_count=$(find "$ss_dir" -name "*.png" -o -name "*.jpg" 2>/dev/null | wc -l)
    info "Screenshots captured: ${GREEN}${ss_count}${RESET}"

    success "Screenshot capture complete."
}
