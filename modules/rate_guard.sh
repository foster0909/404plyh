#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# RECON ENGINE — Adaptive Rate Guard
# Automatically throttles scan rate based on CPU load and HTTP 429 responses.
# ─────────────────────────────────────────────────────────────────────────────

RATE_GUARD_ENABLED=false
RATE_GUARD_ORIGINAL_RATE="$RATE_LIMIT"
RATE_GUARD_ADJUSTMENTS=0
RATE_GUARD_NCPUS=""
RATE_GUARD_LAST_REASON="init"

rate_guard_init() {
    RATE_GUARD_ORIGINAL_RATE="${RATE_LIMIT:-150}"
    RATE_GUARD_ENABLED=true
    RATE_GUARD_ADJUSTMENTS=0
    RATE_GUARD_LAST_REASON="init"
    
    if command -v nproc >/dev/null 2>&1; then
        RATE_GUARD_NCPUS=$(nproc)
    else
        RATE_GUARD_NCPUS=1
    fi
    
    if [[ -n "${OUTPUT_DIR:-}" ]]; then
        rate_guard_write_state
    fi
    
    info "Rate Guard: initialized at rate=${RATE_LIMIT:-150}"
}

rate_guard_check() {
    if [[ "$RATE_GUARD_ENABLED" != true ]]; then return; fi
    if [[ ! -f /proc/loadavg ]]; then return; fi

    local load_1min
    load_1min=$(awk '{print $1}' /proc/loadavg)
    
    local load_pct
    if command -v bc >/dev/null 2>&1; then
        load_pct=$(echo "($load_1min / $RATE_GUARD_NCPUS) * 100" | bc -l)
        load_pct=${load_pct%%.*} # Convert to integer
        if [[ -z "$load_pct" ]]; then load_pct=0; fi
    else
        load_pct=$(awk -v l="$load_1min" -v n="$RATE_GUARD_NCPUS" 'BEGIN {print int((l/n)*100)}')
    fi

    local old_rate="${RATE_LIMIT:-150}"
    local new_rate="$old_rate"

    if [[ "$load_pct" -gt 80 ]]; then
        new_rate=$(( old_rate * 50 / 100 ))
        RATE_GUARD_LAST_REASON="cpu_high"
    elif [[ "$load_pct" -gt 60 ]]; then
        new_rate=$(( old_rate * 75 / 100 ))
        RATE_GUARD_LAST_REASON="cpu_med"
    elif [[ "$load_pct" -lt 30 && "$old_rate" -lt "$RATE_GUARD_ORIGINAL_RATE" ]]; then
        new_rate="$RATE_GUARD_ORIGINAL_RATE"
        RATE_GUARD_LAST_REASON="cpu_low_restore"
    fi

    if [[ "$new_rate" -lt 10 ]]; then
        new_rate=10
    fi

    if [[ "$old_rate" -ne "$new_rate" ]]; then
        RATE_LIMIT="$new_rate"
        ((RATE_GUARD_ADJUSTMENTS++))
        warn "Rate Guard: CPU load at ${load_pct}%. Throttling rate: $old_rate -> $new_rate"
        rate_guard_write_state
    fi
}

rate_guard_http_backoff() {
    if [[ "$RATE_GUARD_ENABLED" != true ]]; then return; fi
    local log_file="$1"
    if [[ ! -f "$log_file" ]]; then return; fi

    local count
    count=$(grep -c '429' "$log_file" || true)

    local old_rate="${RATE_LIMIT:-150}"
    local new_rate="$old_rate"

    if [[ "$count" -gt 5 ]]; then
        new_rate=$(( old_rate * 50 / 100 ))
        RATE_GUARD_LAST_REASON="http_429_high"
        warn "Rate Guard: Detected $count HTTP 429s. Throttling rate: $old_rate -> $new_rate"
    elif [[ "$count" -gt 0 ]]; then
        new_rate=$(( old_rate * 75 / 100 ))
        RATE_GUARD_LAST_REASON="http_429_low"
        warn "Rate Guard: Detected $count HTTP 429s. Throttling rate: $old_rate -> $new_rate"
    fi

    if [[ "$new_rate" -lt 10 ]]; then
        new_rate=10
    fi

    if [[ "$old_rate" -ne "$new_rate" ]]; then
        RATE_LIMIT="$new_rate"
        ((RATE_GUARD_ADJUSTMENTS++))
        rate_guard_write_state
    fi
}

rate_guard_write_state() {
    if [[ -z "${OUTPUT_DIR:-}" ]]; then return; fi
    cat <<EOF > "$OUTPUT_DIR/.rate_state"
ORIGINAL_RATE=$RATE_GUARD_ORIGINAL_RATE
CURRENT_RATE=$RATE_LIMIT
ADJUSTMENTS=$RATE_GUARD_ADJUSTMENTS
LAST_REASON=$RATE_GUARD_LAST_REASON
LAST_CHECK=$(date +%s)
EOF
}
