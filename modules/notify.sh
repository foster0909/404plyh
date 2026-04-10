#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# RECON ENGINE — Discord Notification Module
# Sends formatted alerts via Discord webhooks when monitor detects changes.
# ─────────────────────────────────────────────────────────────────────────────

# ── Config loading ───────────────────────────────────────────────────────────

load_notify_config() {
    # Load from config file if it exists
    local conf_file="$HOME/.recon_engine.conf"
    if [[ -f "$conf_file" ]]; then
        while IFS='=' read -r key val; do
            key=$(echo "$key" | xargs)
            val=$(echo "$val" | xargs | sed 's/^["'"'"']//;s/["'"'"']$//')
            case "$key" in
                DISCORD_WEBHOOK_URL)       export DISCORD_WEBHOOK_URL="$val" ;;
                MONITOR_NOTIFY_ON_NO_CHANGES) export MONITOR_NOTIFY_ON_NO_CHANGES="$val" ;;
            esac
        done < <(grep -v '^#' "$conf_file" | grep -v '^$')
    fi

    DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL:-}"
    MONITOR_NOTIFY_ON_NO_CHANGES="${MONITOR_NOTIFY_ON_NO_CHANGES:-false}"
}

# ── Discord webhook sender ──────────────────────────────────────────────────

discord_send() {
    local payload="$1"

    if [[ -z "$DISCORD_WEBHOOK_URL" ]]; then
        warn "DISCORD_WEBHOOK_URL not set. Skipping Discord notification."
        warn "Set it via: export DISCORD_WEBHOOK_URL='https://discord.com/api/webhooks/...'"
        warn "Or add it to ~/.recon_engine.conf"
        return 1
    fi

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Content-Type: application/json" \
        -d "$payload" \
        "$DISCORD_WEBHOOK_URL" 2>/dev/null)

    if [[ "$http_code" =~ ^2 ]]; then
        success "Discord notification sent successfully."
        return 0
    else
        error "Discord notification failed (HTTP $http_code)."
        return 1
    fi
}

# ── Build and send monitor alert ─────────────────────────────────────────────

notify_monitor_changes() {
    local domain="$1"
    local change_file="$2"

    load_notify_config

    if [[ -z "$DISCORD_WEBHOOK_URL" ]]; then
        info "No DISCORD_WEBHOOK_URL configured. Skipping notification."
        return 0
    fi

    if [[ ! -f "$change_file" ]]; then
        warn "Change file not found: $change_file"
        return 1
    fi

    # Parse the change record
    local new_subs_count removed_subs_count new_ports_count removed_ports_count
    new_subs_count=$(jq -r '.summary.subdomains_added // 0' "$change_file" 2>/dev/null)
    removed_subs_count=$(jq -r '.summary.subdomains_removed // 0' "$change_file" 2>/dev/null)
    new_ports_count=$(jq -r '.summary.ports_added // 0' "$change_file" 2>/dev/null)
    removed_ports_count=$(jq -r '.summary.ports_removed // 0' "$change_file" 2>/dev/null)

    local total_changes=$(( new_subs_count + removed_subs_count + new_ports_count + removed_ports_count ))

    # Skip if no changes and not configured to notify
    if [[ $total_changes -eq 0 ]]; then
        if [[ "$MONITOR_NOTIFY_ON_NO_CHANGES" != "true" ]]; then
            info "No changes detected. Skipping Discord notification."
            return 0
        fi
    fi

    # Pick embed color based on severity
    local color=5763719  # green
    if [[ $new_subs_count -gt 5 || $new_ports_count -gt 5 ]]; then
        color=16776960  # yellow
    fi
    if [[ $new_subs_count -gt 20 || $new_ports_count -gt 20 ]]; then
        color=15548997  # red
    fi

    local timestamp
    timestamp=$(date -Iseconds 2>/dev/null || date +"%Y-%m-%dT%H:%M:%S")

    # Build each section as a Discord embed field using jq
    # jq handles all JSON escaping and newline formatting properly
    local fields="[]"

    if [[ $new_subs_count -gt 0 ]]; then
        local new_subs_val
        new_subs_val=$(jq -r '
            [.new_subdomains[:15][] | "` \(.) `"] | join("\n")
        ' "$change_file" 2>/dev/null)
        if [[ $new_subs_count -gt 15 ]]; then
            new_subs_val=$(printf '%s\n_%s more_' "$new_subs_val" "$((new_subs_count - 15))")
        fi
        fields=$(echo "$fields" | jq \
            --arg name "🆕 New Subdomains ($new_subs_count)" \
            --arg val "$new_subs_val" \
            '. + [{"name": $name, "value": $val, "inline": false}]')
    fi

    if [[ $removed_subs_count -gt 0 ]]; then
        local rem_subs_val
        rem_subs_val=$(jq -r '
            [.removed_subdomains[:10][] | "~~` \(.) `~~"] | join("\n")
        ' "$change_file" 2>/dev/null)
        if [[ $removed_subs_count -gt 10 ]]; then
            rem_subs_val=$(printf '%s\n_%s more_' "$rem_subs_val" "$((removed_subs_count - 10))")
        fi
        fields=$(echo "$fields" | jq \
            --arg name "❌ Removed Subdomains ($removed_subs_count)" \
            --arg val "$rem_subs_val" \
            '. + [{"name": $name, "value": $val, "inline": false}]')
    fi

    if [[ $new_ports_count -gt 0 ]]; then
        local new_ports_val
        new_ports_val=$(jq -r '
            [.new_ports[:15][] | "` \(.) `"] | join("\n")
        ' "$change_file" 2>/dev/null)
        if [[ $new_ports_count -gt 15 ]]; then
            new_ports_val=$(printf '%s\n_%s more_' "$new_ports_val" "$((new_ports_count - 15))")
        fi
        fields=$(echo "$fields" | jq \
            --arg name "🚪 New Ports ($new_ports_count)" \
            --arg val "$new_ports_val" \
            '. + [{"name": $name, "value": $val, "inline": false}]')
    fi

    if [[ $removed_ports_count -gt 0 ]]; then
        local rem_ports_val
        rem_ports_val=$(jq -r '
            [.removed_ports[:10][] | "~~` \(.) `~~"] | join("\n")
        ' "$change_file" 2>/dev/null)
        if [[ $removed_ports_count -gt 10 ]]; then
            rem_ports_val=$(printf '%s\n_%s more_' "$rem_ports_val" "$((removed_ports_count - 10))")
        fi
        fields=$(echo "$fields" | jq \
            --arg name "🔒 Removed Ports ($removed_ports_count)" \
            --arg val "$rem_ports_val" \
            '. + [{"name": $name, "value": $val, "inline": false}]')
    fi

    # Description line
    local desc="Target: \`$domain\`"
    if [[ $total_changes -eq 0 ]]; then
        desc="✅ No changes detected for \`$domain\`"
    fi

    # Build the full payload with jq (guarantees valid JSON + proper newlines)
    local payload
    payload=$(jq -n \
        --arg title "🔍 Recon Engine — Monitor Alert" \
        --arg desc "$desc" \
        --argjson color "$color" \
        --argjson fields "$fields" \
        --arg footer "Recon Engine Monitor" \
        --arg ts "$timestamp" \
        --argjson total "$total_changes" \
        '{
            embeds: [{
                title: $title,
                description: $desc,
                color: $color,
                fields: ($fields + [
                    {name: "━━━━━━━━━━━━━━━━━━━━", value: "Summary", inline: false},
                    {name: "Total Changes", value: ($total | tostring), inline: true},
                    {name: "\u200b", value: "\u200b", inline: true},
                    {name: "\u200b", value: "\u200b", inline: true}
                ]),
                footer: {text: $footer},
                timestamp: $ts
            }]
        }')

    step "Sending Discord notification for $domain"
    discord_send "$payload"
}
