#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# MODULE 2: DNS Resolution & Validation
# Tools: dnsx (primary), puredns (fallback)
#
# Resolves the subdomain list down to the hostnames that actually have DNS
# records. Output contract is unchanged: dns/resolved.txt holds one resolvable
# hostname per line, so every downstream reader (http/ports modules, db.py) is
# unaffected by the tool swap.
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

    # Resolve the active resolver file once (custom flag > bundled > none).
    local resolver_file=""
    if [[ -n "$RESOLVERS" && -f "$RESOLVERS" ]]; then
        resolver_file="$RESOLVERS"
        step "Using custom resolvers: $RESOLVERS"
    elif [[ -f "$SCRIPT_DIR/resolvers.txt" ]]; then
        resolver_file="$SCRIPT_DIR/resolvers.txt"
        step "Using bundled resolvers: $SCRIPT_DIR/resolvers.txt"
    else
        info "No resolver file found; using the resolver's defaults."
    fi

    if require_tool "dnsx"; then
        # dnsx prints hostnames that resolve (have >=1 record); -silent keeps the
        # output to bare hostnames so resolved.txt stays a clean host list.
        local dnsx_cmd="dnsx -l '$input' -silent -t $THREADS -o '$dns_dir/resolved.txt'"
        [[ -n "$resolver_file" ]] && dnsx_cmd+=" -r '$resolver_file'"
        run_safe "dnsx resolve" "$dnsx_cmd"
    elif require_tool "puredns"; then
        warn "dnsx not found; falling back to puredns."
        local puredns_cmd="puredns resolve '$input' -w '$dns_dir/resolved.txt' -t $THREADS"
        [[ -n "$resolver_file" ]] && puredns_cmd+=" -r '$resolver_file'"
        run_safe "puredns resolve" "$puredns_cmd"
    else
        warn "Neither dnsx nor puredns available. Copying raw subdomains as resolved."
        cp "$input" "$dns_dir/resolved.txt"
        return 0
    fi

    # Fallback: if resolution produced nothing, preserve the raw subdomains so
    # the rest of the pipeline can still proceed.
    if [[ ! -s "$dns_dir/resolved.txt" ]]; then
        warn "DNS resolution produced no results. Using raw subdomains as fallback."
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
