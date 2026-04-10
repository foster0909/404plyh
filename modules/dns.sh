#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# MODULE 2: DNS Resolution & Validation
# Tools: puredns
# ─────────────────────────────────────────────────────────────────────────────

module_dns_resolution() {
    if [[ "$SKIP_DNS" == true ]]; then
        info "Skipping DNS resolution (--skip-dns)"
        return 0
    fi

    header "Module 2: DNS Resolution & Validation"
    local dns_dir="$OUTPUT_DIR/dns"
    local input="$OUTPUT_DIR/subs/all.txt"

    if [[ ! -s "$input" ]]; then
        warn "No subdomains found. Skipping DNS resolution."
        return 0
    fi

    if ! require_tool "puredns"; then
        warn "puredns not available. Copying raw subdomains as resolved."
        cp "$input" "$dns_dir/resolved.txt"
        return 0
    fi

    # Build puredns command
    local puredns_cmd="puredns resolve '$input' -w '$dns_dir/resolved.txt' -t $THREADS"

    if [[ -n "$RESOLVERS" && -f "$RESOLVERS" ]]; then
        puredns_cmd+=" -r '$RESOLVERS'"
        step "Using custom resolvers: $RESOLVERS"
    elif [[ -f "$SCRIPT_DIR/resolvers.txt" ]]; then
        puredns_cmd+=" -r '$SCRIPT_DIR/resolvers.txt'"
        step "Using bundled resolvers: $SCRIPT_DIR/resolvers.txt"
    else
        warn "No resolver file found. puredns may fail — create resolvers.txt or use --resolvers."
    fi

    run_safe "puredns resolve" "$puredns_cmd"

    # Fallback: if puredns failed and resolved.txt doesn't exist, copy raw subdomains
    if [[ ! -s "$dns_dir/resolved.txt" ]]; then
        warn "puredns produced no results (massdns may be missing). Using raw subdomains as fallback."
        cp "$input" "$dns_dir/resolved.txt"
    fi

    # Identify unresolved hosts (preserved per README design)
    if [[ -s "$dns_dir/resolved.txt" ]]; then
        comm -23 \
            <(sort "$input") \
            <(sort "$dns_dir/resolved.txt") \
            > "$dns_dir/unresolved.txt" 2>/dev/null || true
    fi

    report_count "$dns_dir/resolved.txt" "Resolved hosts"
    report_count "$dns_dir/unresolved.txt" "Unresolved hosts (preserved)"

    success "DNS resolution complete."
}
