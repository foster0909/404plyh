#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Recon Engine — Monitor Integration Test
# Tests the diff engine with synthetic data (no real tools needed).
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="/tmp/recon_test_monitor_$$"
FAILURES=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RESET='\033[0m'

pass() { echo -e "  ${GREEN}✓${RESET} $*"; }
fail() { echo -e "  ${RED}✗${RESET} $*"; ((FAILURES++)); }
info() { echo -e "  ${YELLOW}→${RESET} $*"; }

cleanup() { rm -rf "$TEST_DIR"; }
trap cleanup EXIT

# ─────────────────────────────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Recon Engine — Monitor Integration Tests"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ── Setup ──
info "Setting up test environment at $TEST_DIR"
mkdir -p "$TEST_DIR"/{subs,dns,httpx,ports,monitor/baselines,monitor/changes,logs}

# Source modules (we need config, utils, and monitor logic)
export DOMAIN="test.example.com"
export OUTPUT_DIR="$TEST_DIR"
export THREADS=10
export RATE_LIMIT=100
export NAABU_TOP_PORTS=100
export RESOLVERS=""
export LOG_FILE="$TEST_DIR/logs/test.log"
export KATANA_DEPTH=2
export HAKRAWLER_DEPTH=2
export HTTPX_TIMEOUT=5
export RECURSIVE_ROUNDS=2
export LINKFINDER_PATH="linkfinder.py"
export SECRETFINDER_PATH="SecretFinder.py"

source "$SCRIPT_DIR/modules/config.sh"
source "$SCRIPT_DIR/modules/utils.sh"
# Suppress output for test (override logging functions)
info() { :; }
success() { :; }
warn() { :; }
error() { :; }
header() { :; }
step() { :; }
# Keep count and log working
init_logging

echo ""
echo "── Test 1: Baseline Creation ──"
echo ""

# Create initial baseline data
cat > "$TEST_DIR/monitor/baselines/subdomains.txt" <<EOF
api.test.example.com
blog.test.example.com
docs.test.example.com
mail.test.example.com
www.test.example.com
EOF

cat > "$TEST_DIR/monitor/baselines/ports.txt" <<EOF
api.test.example.com:443
blog.test.example.com:80
docs.test.example.com:443
mail.test.example.com:25
mail.test.example.com:443
www.test.example.com:80
www.test.example.com:443
EOF

sort -u -o "$TEST_DIR/monitor/baselines/subdomains.txt" "$TEST_DIR/monitor/baselines/subdomains.txt"
sort -u -o "$TEST_DIR/monitor/baselines/ports.txt" "$TEST_DIR/monitor/baselines/ports.txt"

if [[ -f "$TEST_DIR/monitor/baselines/subdomains.txt" ]]; then
    pass "Baseline subdomains created ($(wc -l < "$TEST_DIR/monitor/baselines/subdomains.txt") hosts)"
else
    fail "Baseline subdomains not created"
fi

if [[ -f "$TEST_DIR/monitor/baselines/ports.txt" ]]; then
    pass "Baseline ports created ($(wc -l < "$TEST_DIR/monitor/baselines/ports.txt") host:port pairs)"
else
    fail "Baseline ports not created"
fi

echo ""
echo "── Test 2: Diff Detection ──"
echo ""

# Simulate a new scan with changes:
# - Added: staging.test.example.com, dev.test.example.com
# - Removed: blog.test.example.com
mkdir -p "$TEST_DIR/monitor/scan_tmp"

cat > "$TEST_DIR/monitor/scan_tmp/subdomains.txt" <<EOF
api.test.example.com
dev.test.example.com
docs.test.example.com
mail.test.example.com
staging.test.example.com
www.test.example.com
EOF

# Ports changes:
# - Added: staging.test.example.com:8443, dev.test.example.com:3000
# - Removed: blog.test.example.com:80, mail.test.example.com:25
cat > "$TEST_DIR/monitor/scan_tmp/ports.txt" <<EOF
api.test.example.com:443
dev.test.example.com:3000
docs.test.example.com:443
mail.test.example.com:443
staging.test.example.com:8443
www.test.example.com:80
www.test.example.com:443
EOF

sort -u -o "$TEST_DIR/monitor/scan_tmp/subdomains.txt" "$TEST_DIR/monitor/scan_tmp/subdomains.txt"
sort -u -o "$TEST_DIR/monitor/scan_tmp/ports.txt" "$TEST_DIR/monitor/scan_tmp/ports.txt"

# Now source the monitor module and run diff
source "$SCRIPT_DIR/modules/notify.sh"
source "$SCRIPT_DIR/modules/monitor.sh"

# Run the diff logic directly
monitor_diff 2>/dev/null

# Check results
if [[ -n "${MONITOR_CHANGE_FILE:-}" && -f "$MONITOR_CHANGE_FILE" ]]; then
    pass "Change record JSON created: $(basename "$MONITOR_CHANGE_FILE")"
else
    fail "Change record JSON not created"
    echo "  MONITOR_CHANGE_FILE=$MONITOR_CHANGE_FILE"
fi

# Validate JSON content
if command -v jq &>/dev/null && [[ -f "${MONITOR_CHANGE_FILE:-}" ]]; then
    # Check new subdomains
    new_subs=$(jq -r '.new_subdomains | length' "$MONITOR_CHANGE_FILE")
    if [[ "$new_subs" == "2" ]]; then
        pass "Detected 2 new subdomains"
    else
        fail "Expected 2 new subdomains, got $new_subs"
    fi

    # Check specific new subs
    has_staging=$(jq -r '.new_subdomains | map(select(. == "staging.test.example.com")) | length' "$MONITOR_CHANGE_FILE")
    has_dev=$(jq -r '.new_subdomains | map(select(. == "dev.test.example.com")) | length' "$MONITOR_CHANGE_FILE")
    if [[ "$has_staging" == "1" && "$has_dev" == "1" ]]; then
        pass "Correctly identified staging + dev as new"
    else
        fail "Missing specific new subdomains"
    fi

    # Check removed subdomains
    removed_subs=$(jq -r '.removed_subdomains | length' "$MONITOR_CHANGE_FILE")
    if [[ "$removed_subs" == "1" ]]; then
        pass "Detected 1 removed subdomain"
    else
        fail "Expected 1 removed subdomain, got $removed_subs"
    fi

    removed_blog=$(jq -r '.removed_subdomains | map(select(. == "blog.test.example.com")) | length' "$MONITOR_CHANGE_FILE")
    if [[ "$removed_blog" == "1" ]]; then
        pass "Correctly identified blog as removed"
    else
        fail "Missing blog.test.example.com in removed"
    fi

    # Check new ports
    new_ports=$(jq -r '.new_ports | length' "$MONITOR_CHANGE_FILE")
    if [[ "$new_ports" == "2" ]]; then
        pass "Detected 2 new ports"
    else
        fail "Expected 2 new ports, got $new_ports"
    fi

    # Check removed ports
    removed_ports=$(jq -r '.removed_ports | length' "$MONITOR_CHANGE_FILE")
    if [[ "$removed_ports" == "2" ]]; then
        pass "Detected 2 removed ports"
    else
        fail "Expected 2 removed ports, got $removed_ports"
    fi

    # Check summary totals
    total=$(jq -r '.summary.total_changes' "$MONITOR_CHANGE_FILE")
    if [[ "$total" == "7" ]]; then
        pass "Total changes count: 7 (2+1+2+2)"
    else
        fail "Expected total_changes=7, got $total"
    fi
else
    fail "jq not available or change file missing — skipping JSON validation"
fi

echo ""
echo "── Test 3: Baseline Update ──"
echo ""

# After diff, baselines should be updated to match current data
updated_subs=$(wc -l < "$TEST_DIR/monitor/baselines/subdomains.txt" 2>/dev/null || echo 0)
if [[ "$updated_subs" == "6" ]]; then
    pass "Baseline subdomains updated to 6 hosts"
else
    fail "Expected 6 hosts in updated baseline, got $updated_subs"
fi

# Check that blog is gone and staging/dev are in the baseline
if grep -q "staging.test.example.com" "$TEST_DIR/monitor/baselines/subdomains.txt" 2>/dev/null; then
    pass "staging.test.example.com is in updated baseline"
else
    fail "staging.test.example.com missing from updated baseline"
fi

if ! grep -q "blog.test.example.com" "$TEST_DIR/monitor/baselines/subdomains.txt" 2>/dev/null; then
    pass "blog.test.example.com correctly removed from baseline"
else
    fail "blog.test.example.com still in baseline after update"
fi

echo ""
echo "── Test 4: No-Changes Scenario ──"
echo ""

# Small delay to ensure different timestamp for filename
sleep 1

# Run diff again with identical data (should produce 0 changes)
mkdir -p "$TEST_DIR/monitor/scan_tmp"
cp "$TEST_DIR/monitor/baselines/subdomains.txt" "$TEST_DIR/monitor/scan_tmp/subdomains.txt"
cp "$TEST_DIR/monitor/baselines/ports.txt" "$TEST_DIR/monitor/scan_tmp/ports.txt"

MONITOR_CHANGE_FILE=""
MONITOR_TOTAL_CHANGES=999  # will be overwritten
monitor_diff 2>/dev/null

if [[ "$MONITOR_TOTAL_CHANGES" == "0" ]]; then
    pass "No-changes scenario: total_changes=0"
else
    fail "Expected 0 changes on identical data, got $MONITOR_TOTAL_CHANGES"
fi

if [[ -f "${MONITOR_CHANGE_FILE:-}" ]]; then
    no_change_total=$(jq -r '.summary.total_changes' "$MONITOR_CHANGE_FILE" 2>/dev/null)
    if [[ "$no_change_total" == "0" ]]; then
        pass "Change record JSON shows 0 changes"
    else
        fail "Change record shows $no_change_total changes (expected 0)"
    fi
fi

echo ""
echo "── Test 5: CLI Script Syntax ──"
echo ""

# Check that monitor.sh is syntactically valid
if bash -n "$SCRIPT_DIR/monitor.sh" 2>/dev/null; then
    pass "monitor.sh syntax valid"
else
    fail "monitor.sh has syntax errors"
fi

# Check all module files
for mod in notify.sh monitor.sh; do
    if bash -n "$SCRIPT_DIR/modules/$mod" 2>/dev/null; then
        pass "modules/$mod syntax valid"
    else
        fail "modules/$mod has syntax errors"
    fi
done

echo ""
echo "── Test 6: JSON Structure Validation ──"
echo ""

# Validate all change JSONs are valid
change_count=$(find "$TEST_DIR/monitor/changes" -name "*.json" | wc -l)
if [[ "$change_count" -ge 2 ]]; then
    pass "Multiple change records exist ($change_count files)"
else
    fail "Expected at least 2 change records, found $change_count"
fi

for f in "$TEST_DIR/monitor/changes"/*.json; do
    if jq empty "$f" 2>/dev/null; then
        pass "$(basename "$f") is valid JSON"
    else
        fail "$(basename "$f") is invalid JSON"
    fi

    # Check required fields
    has_fields=$(jq 'has("timestamp") and has("domain") and has("new_subdomains") and has("removed_subdomains") and has("new_ports") and has("removed_ports") and has("summary")' "$f" 2>/dev/null)
    if [[ "$has_fields" == "true" ]]; then
        pass "$(basename "$f") has all required fields"
    else
        fail "$(basename "$f") missing required fields"
    fi
done

echo ""
echo "═══════════════════════════════════════════════════════════════"
if [[ $FAILURES -eq 0 ]]; then
    echo -e "  ${GREEN}ALL TESTS PASSED${RESET}"
else
    echo -e "  ${RED}$FAILURES TEST(S) FAILED${RESET}"
fi
echo "═══════════════════════════════════════════════════════════════"
echo ""

exit $FAILURES
