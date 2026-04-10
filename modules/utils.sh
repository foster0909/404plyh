#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# RECON ENGINE — Utility Functions
# ─────────────────────────────────────────────────────────────────────────────

# Normalize hostnames: lowercase, strip wildcards, strip trailing dots, dedup
normalize_hosts() {
    local input="$1"
    local output="$2"
    if [[ -f "$input" ]]; then
        cat "$input" \
            | tr '[:upper:]' '[:lower:]' \
            | sed 's/^\*\.//g' \
            | sed 's/\.$//' \
            | sed '/^$/d' \
            | grep -E "\.${DOMAIN}$" \
            | sort -u > "$output"
    else
        touch "$output"
    fi
}

# Merge multiple files into one, dedup
merge_dedup() {
    local output="$1"
    shift
    cat "$@" 2>/dev/null | sort -u > "$output"
}

# Count and report
report_count() {
    local file="$1"
    local label="$2"
    local n
    n=$(count "$file")
    info "$label: ${GREEN}${n}${RESET}"
}

# Check if a CLI tool is available
require_tool() {
    local tool="$1"
    if ! command -v "$tool" &>/dev/null; then
        warn "Tool '${tool}' not found. Skipping this step."
        return 1
    fi
    return 0
}

# Check if a Python script file exists
require_py_tool() {
    local path="$1"
    local label="$2"
    if [[ -f "$path" ]] || command -v "$path" &>/dev/null; then
        return 0
    else
        warn "Python tool '${label}' not found at '${path}'. Skipping this step."
        return 1
    fi
}

# Run a command with error handling
run_safe() {
    local label="$1"
    shift
    step "Running: $label"
    if eval "$@" 2>>"$LOG_FILE"; then
        success "$label completed."
        return 0
    else
        warn "$label failed or returned non-zero. Continuing..."
        return 1
    fi
}

# Create the output directory tree
create_directories() {
    info "Creating output directory structure: ${OUTPUT_DIR}/"
    local dirs=(
        "$OUTPUT_DIR/subs"
        "$OUTPUT_DIR/dns"
        "$OUTPUT_DIR/httpx"
        "$OUTPUT_DIR/screenshots"
        "$OUTPUT_DIR/ports"
        "$OUTPUT_DIR/js"
        "$OUTPUT_DIR/historical"
        "$OUTPUT_DIR/endpoints"
        "$OUTPUT_DIR/infra"
        "$OUTPUT_DIR/dorks"
        "$OUTPUT_DIR/reports"
        "$OUTPUT_DIR/logs"
        "$OUTPUT_DIR/monitor/baselines"
        "$OUTPUT_DIR/monitor/changes"
    )
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
    done
    success "Directory structure created."
}
