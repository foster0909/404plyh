#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# RECON ENGINE — Monitor All Enabled Targets
# Reads .monitor_config.json and runs monitor.sh for each enabled target.
# Designed for cron: 0 2 * * * /path/to/monitor_all.sh /path/to/projects
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECTS_DIR="${1:-$(pwd)}"
CONFIG_FILE="$PROJECTS_DIR/.monitor_config.json"

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "[!] No monitor config found at $CONFIG_FILE"
    echo "    Enable monitoring for targets via the dashboard first."
    exit 1
fi

# Read enabled targets from the config
TARGETS=$(jq -r '.enabled_targets[]' "$CONFIG_FILE" 2>/dev/null)

if [[ -z "$TARGETS" ]]; then
    echo "[*] No targets have monitoring enabled."
    exit 0
fi

echo "═══════════════════════════════════════════════════════════════"
echo "  Recon Engine — Daily Monitor Run"
echo "  $(date)"
echo "═══════════════════════════════════════════════════════════════"
echo ""

COUNT=0
TOTAL=$(echo "$TARGETS" | wc -l)

while IFS= read -r target_dir; do
    [[ -z "$target_dir" ]] && continue
    COUNT=$((COUNT + 1))

    # Extract domain from directory name (strip recon_ prefix if present)
    domain="${target_dir#recon_}"
    target_path="$PROJECTS_DIR/$target_dir"

    echo ""
    echo "── [$COUNT/$TOTAL] $domain ──"

    if [[ ! -d "$target_path" ]]; then
        echo "[!] Target directory not found: $target_path — skipping"
        continue
    fi

    # Run monitor
    bash "$SCRIPT_DIR/monitor.sh" -d "$domain" -o "$target_path"

    echo "[✓] Done: $domain"
done <<< "$TARGETS"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Completed $COUNT/$TOTAL targets"
echo "═══════════════════════════════════════════════════════════════"
