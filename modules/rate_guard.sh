#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# RECON ENGINE — Adaptive Rate Guard
# Automatically throttles scan rate based on CPU load AND observed HTTP 429
# responses. Scales every target-facing rate together (general HTTP_RATE, the
# stricter ACTIVE_RATE, and the naabu port RATE_LIMIT) by a single factor so the
# ACTIVE_RATE <= HTTP_RATE invariant always holds.
# ─────────────────────────────────────────────────────────────────────────────

RATE_GUARD_ENABLED=false
RATE_GUARD_ADJUSTMENTS=0
RATE_GUARD_NCPUS=""
RATE_GUARD_LAST_REASON="init"

# Baselines captured at init (the user-chosen limits we scale down from).
RATE_GUARD_ORIG_HTTP=150
RATE_GUARD_ORIG_ACTIVE=10
RATE_GUARD_ORIG_PORTS=150
RATE_GUARD_ORIG_THREADS=15

# Independent pressure factors (percent); effective factor is their minimum.
RATE_GUARD_CPU_FACTOR=100
RATE_GUARD_429_FACTOR=100
RATE_GUARD_429_SEEN=0

rate_guard_init() {
    RATE_GUARD_ENABLED=true
    RATE_GUARD_ADJUSTMENTS=0
    RATE_GUARD_LAST_REASON="init"
    RATE_GUARD_ORIG_HTTP="${HTTP_RATE:-150}"
    RATE_GUARD_ORIG_ACTIVE="${ACTIVE_RATE:-10}"
    RATE_GUARD_ORIG_PORTS="${RATE_LIMIT:-150}"
    RATE_GUARD_ORIG_THREADS="${THREADS:-15}"
    RATE_GUARD_CPU_FACTOR=100
    RATE_GUARD_429_FACTOR=100
    RATE_GUARD_429_SEEN=0

    if command -v nproc >/dev/null 2>&1; then
        RATE_GUARD_NCPUS=$(nproc)
    else
        RATE_GUARD_NCPUS=1
    fi

    if [[ -n "${OUTPUT_DIR:-}" ]]; then
        rate_guard_write_state
    fi

    info "Rate Guard: initialized (http=${RATE_GUARD_ORIG_HTTP}/s active=${RATE_GUARD_ORIG_ACTIVE}/s ports=${RATE_GUARD_ORIG_PORTS})"
}

# Apply the effective factor (min of CPU and 429 pressure) to all tiers.
rate_guard_apply() {
    local factor=$RATE_GUARD_CPU_FACTOR
    [[ "$RATE_GUARD_429_FACTOR" -lt "$factor" ]] && factor=$RATE_GUARD_429_FACTOR

    local new_http new_active new_ports new_threads
    new_http=$(( RATE_GUARD_ORIG_HTTP  * factor / 100 ))
    new_active=$(( RATE_GUARD_ORIG_ACTIVE * factor / 100 ))
    new_ports=$(( RATE_GUARD_ORIG_PORTS * factor / 100 ))
    # Concurrency follows CPU pressure only (local load, not target-facing).
    new_threads=$(( RATE_GUARD_ORIG_THREADS * RATE_GUARD_CPU_FACTOR / 100 ))
    [[ "$new_threads" -lt 2 ]] && new_threads=2
    [[ "$new_threads" -gt "$RATE_GUARD_ORIG_THREADS" ]] && new_threads=$RATE_GUARD_ORIG_THREADS
    THREADS=$new_threads

    # Floors so we never throttle to zero.
    [[ "$new_http"   -lt 1  ]] && new_http=1
    [[ "$new_active" -lt 1  ]] && new_active=1
    [[ "$new_ports"  -lt 10 ]] && new_ports=10
    # Preserve the invariant.
    [[ "$new_active" -gt "$new_http" ]] && new_active=$new_http

    if [[ "$new_http" -ne "${HTTP_RATE:-}" || "$new_active" -ne "${ACTIVE_RATE:-}" || "$new_ports" -ne "${RATE_LIMIT:-}" ]]; then
        HTTP_RATE=$new_http
        ACTIVE_RATE=$new_active
        RATE_LIMIT=$new_ports
        ((RATE_GUARD_ADJUSTMENTS++))
        warn "Rate Guard: ${RATE_GUARD_LAST_REASON} → http=${HTTP_RATE}/s active=${ACTIVE_RATE}/s ports=${RATE_LIMIT} threads=${THREADS} (factor ${factor}%)"
        rate_guard_write_state
    fi
}

# Block (bounded) while the host is short on memory, so a new stage doesn't
# start on top of a box that is already swapping. Never aborts the scan.
resource_guard_wait() {
    local need="${RESOURCE_MIN_MEM_MB:-512}" max="${RESOURCE_WAIT_MAX:-300}"
    [[ -r /proc/meminfo && "$need" -gt 0 ]] 2>/dev/null || return 0
    local avail waited=0
    avail=$(awk '/^MemAvailable:/ {print int($2 / 1024); exit}' /proc/meminfo)
    [[ -z "$avail" ]] && return 0
    while [[ "$avail" -lt "$need" && "$waited" -lt "$max" ]]; do
        [[ "$waited" -eq 0 ]] && warn "Resource Guard: low memory (${avail} MB < ${need} MB). Waiting before next stage..."
        sleep 10
        waited=$(( waited + 10 ))
        avail=$(awk '/^MemAvailable:/ {print int($2 / 1024); exit}' /proc/meminfo)
    done
    if [[ "$avail" -lt "$need" ]]; then
        warn "Resource Guard: memory still low after ${max}s (${avail} MB). Continuing with reduced concurrency."
        RESOURCE_LOW_MEM=true
    else
        RESOURCE_LOW_MEM=false
    fi
}

rate_guard_check() {
    if [[ "$RATE_GUARD_ENABLED" != true ]]; then return; fi
    resource_guard_wait
    if [[ ! -f /proc/loadavg ]]; then return; fi

    local load_1min load_pct
    load_1min=$(awk '{print $1}' /proc/loadavg)
    if command -v bc >/dev/null 2>&1; then
        load_pct=$(echo "($load_1min / $RATE_GUARD_NCPUS) * 100" | bc -l)
        load_pct=${load_pct%%.*}
        [[ -z "$load_pct" ]] && load_pct=0
    else
        load_pct=$(awk -v l="$load_1min" -v n="$RATE_GUARD_NCPUS" 'BEGIN {print int((l/n)*100)}')
    fi

    if [[ "$load_pct" -gt 80 ]]; then
        RATE_GUARD_CPU_FACTOR=50;  RATE_GUARD_LAST_REASON="cpu_high(${load_pct}%)"
    elif [[ "$load_pct" -gt 60 ]]; then
        RATE_GUARD_CPU_FACTOR=75;  RATE_GUARD_LAST_REASON="cpu_med(${load_pct}%)"
    elif [[ "$load_pct" -lt 30 ]]; then
        RATE_GUARD_CPU_FACTOR=100; RATE_GUARD_LAST_REASON="cpu_low(${load_pct}%)"
    fi

    # Memory pressure (from resource_guard_wait) also holds concurrency down.
    if [[ "${RESOURCE_LOW_MEM:-false}" == true && "$RATE_GUARD_CPU_FACTOR" -gt 50 ]]; then
        RATE_GUARD_CPU_FACTOR=50
    fi
    rate_guard_apply
    # Also react to any 429s accumulated in the main log.
    rate_guard_http_backoff "${LOG_FILE:-}"
}

# React to HTTP 429s. Only acts on *new* 429s since the last check so repeated
# calls across stages don't double-count. Restores toward 100% when 429s stop.
rate_guard_http_backoff() {
    if [[ "$RATE_GUARD_ENABLED" != true ]]; then return; fi
    local log_file="$1"
    [[ -z "$log_file" || ! -f "$log_file" ]] && return

    local total delta
    # grep -c prints "0" AND exits non-zero on no matches, so `|| echo 0` would
    # yield a two-line "0\n0" and break the arithmetic below. Capture directly
    # and normalise to a single integer instead.
    total=$(grep -c '429' "$log_file" 2>/dev/null)
    total=${total//[^0-9]/}
    total=${total:-0}
    delta=$(( total - RATE_GUARD_429_SEEN ))
    [[ "$delta" -lt 0 ]] && delta=0
    RATE_GUARD_429_SEEN=$total

    if [[ "$delta" -gt 5 ]]; then
        RATE_GUARD_429_FACTOR=50;  RATE_GUARD_LAST_REASON="http_rate_limited(${delta} new)"
    elif [[ "$delta" -gt 0 ]]; then
        RATE_GUARD_429_FACTOR=75;  RATE_GUARD_LAST_REASON="http_rate_limited(${delta} new)"
    else
        RATE_GUARD_429_FACTOR=100  # no new 429s → allow restore
    fi

    rate_guard_apply
}

rate_guard_write_state() {
    if [[ -z "${OUTPUT_DIR:-}" ]]; then return; fi
    cat <<EOF > "$OUTPUT_DIR/.rate_state"
ORIG_HTTP=$RATE_GUARD_ORIG_HTTP
ORIG_ACTIVE=$RATE_GUARD_ORIG_ACTIVE
ORIG_PORTS=$RATE_GUARD_ORIG_PORTS
HTTP_RATE=${HTTP_RATE:-}
ACTIVE_RATE=${ACTIVE_RATE:-}
RATE_LIMIT=${RATE_LIMIT:-}
CPU_FACTOR=$RATE_GUARD_CPU_FACTOR
HTTP_429_FACTOR=$RATE_GUARD_429_FACTOR
ADJUSTMENTS=$RATE_GUARD_ADJUSTMENTS
LAST_REASON=$RATE_GUARD_LAST_REASON
LAST_CHECK=$(date +%s)
EOF
}
