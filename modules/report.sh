#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# MODULE 10: Structured Report Generation
# Generates: summary.txt, summary.json, report.html
# ─────────────────────────────────────────────────────────────────────────────

module_report() {
    if [[ "$SKIP_REPORT" == true ]]; then
        info "Skipping report generation (--skip-report)"
        return 0
    fi

    header "Module 10: Report Generation"
    local report_dir="$OUTPUT_DIR/reports"

    # ── Gather statistics ──
    local total_subs resolved alive screenshots ports js_endpoints historical crawled
    total_subs=$(count "$OUTPUT_DIR/subs/all.txt")
    resolved=$(count "$OUTPUT_DIR/dns/resolved.txt")
    alive=$(count "$OUTPUT_DIR/httpx/alive.txt")
    screenshots=$(find "$OUTPUT_DIR/screenshots" -name "*.png" -o -name "*.jpg" 2>/dev/null | wc -l)
    ports=$(count "$OUTPUT_DIR/ports/naabu.txt")
    js_endpoints=$(count "$OUTPUT_DIR/js/endpoints.txt")
    historical=$(count "$OUTPUT_DIR/historical/all_urls.txt")
    crawled=$(count "$OUTPUT_DIR/endpoints/all.txt")

    # ── Text summary ──
    step "Generating text summary"
    {
        echo "═══════════════════════════════════════════════════════════════"
        echo "  RECON ENGINE — SUMMARY REPORT"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""
        echo "  Target Domain:    $DOMAIN"
        echo "  Scan Date:        $(date)"
        echo "  Output Directory: $OUTPUT_DIR"
        echo ""
        echo "───────────────────────────────────────────────────────────────"
        echo "  STATISTICS"
        echo "───────────────────────────────────────────────────────────────"
        echo ""
        echo "  Subdomains Discovered:     $total_subs"
        echo "  DNS Resolved Hosts:        $resolved"
        echo "  Alive Web Services:        $alive"
        echo "  Screenshots Captured:      $screenshots"
        echo "  Open Port Pairs:           $ports"
        echo "  JS Endpoints Extracted:    $js_endpoints"
        echo "  Historical URLs Found:     $historical"
        echo "  Crawled Endpoints:         $crawled"
        echo ""
        echo "───────────────────────────────────────────────────────────────"
        echo "  KEY FILES"
        echo "───────────────────────────────────────────────────────────────"
        echo ""
        echo "  All Subdomains:        subs/all.txt"
        echo "  Resolved Hosts:        dns/resolved.txt"
        echo "  Alive URLs:            httpx/alive.txt"
        echo "  HTTP Probe Data:       httpx/results.json"
        echo "  Port Scan:             ports/naabu.txt"
        echo "  JS Endpoints:          js/endpoints.txt"
        echo "  JS Secrets:            js/secrets.txt"
        echo "  Historical URLs:       historical/all_urls.txt"
        echo "  Crawled Endpoints:     endpoints/all.txt"
        echo "  Infrastructure Map:    infra/infra_map.json"
        echo "  Interesting Paths:     endpoints/interesting_paths.txt"
        echo "  API Paths:             endpoints/api_paths.txt"
        echo "  Sensitive Files:       endpoints/sensitive_files.txt"
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
    } > "$report_dir/summary.txt"

    # ── JSON summary ──
    step "Generating JSON summary"
    {
        cat <<ENDJSON
{
  "target": "$DOMAIN",
  "scan_date": "$(date -Iseconds)",
  "output_dir": "$OUTPUT_DIR",
  "statistics": {
    "total_subdomains": $total_subs,
    "resolved_hosts": $resolved,
    "alive_services": $alive,
    "screenshots": $screenshots,
    "open_ports": $ports,
    "js_endpoints": $js_endpoints,
    "historical_urls": $historical,
    "crawled_endpoints": $crawled
  },
  "key_files": {
    "subdomains": "subs/all.txt",
    "resolved": "dns/resolved.txt",
    "alive_urls": "httpx/alive.txt",
    "httpx_json": "httpx/results.json",
    "ports": "ports/naabu.txt",
    "js_endpoints": "js/endpoints.txt",
    "js_secrets": "js/secrets.txt",
    "historical": "historical/all_urls.txt",
    "crawled": "endpoints/all.txt",
    "infra_map": "infra/infra_map.json"
  }
}
ENDJSON
    } > "$report_dir/summary.json"

    # ── HTML report (browsable) ──
    step "Generating HTML report"
    generate_html_report "$report_dir/report.html" \
        "$total_subs" "$resolved" "$alive" "$screenshots" \
        "$ports" "$js_endpoints" "$historical" "$crawled"

    success "Report generation complete."
    echo ""
    info "Summary report: ${CYAN}$report_dir/summary.txt${RESET}"
    info "JSON data:      ${CYAN}$report_dir/summary.json${RESET}"
    info "HTML report:    ${CYAN}$report_dir/report.html${RESET}"
    echo ""
    info "To launch the interactive dashboard:"
    info "  ${BOLD}python3 $SCRIPT_DIR/dashboard.py -p $(dirname $OUTPUT_DIR)${RESET}"
}

generate_html_report() {
    local output_file="$1"
    local total_subs="$2" resolved="$3" alive="$4" screenshots="$5"
    local ports="$6" js_endpoints="$7" historical="$8" crawled="$9"

    cat > "$output_file" <<'HTMLHEAD'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Recon Engine Report</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: #0a0e17; color: #c9d1d9; line-height: 1.6; }
  .container { max-width: 1100px; margin: 0 auto; padding: 2rem; }
  h1 { color: #58a6ff; font-size: 2rem; margin-bottom: 0.25rem; }
  .subtitle { color: #8b949e; margin-bottom: 2rem; }
  .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.25rem; text-align: center; }
  .stat-card .value { font-size: 2rem; font-weight: 700; color: #58a6ff; }
  .stat-card .label { color: #8b949e; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .section { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }
  .section h2 { color: #58a6ff; font-size: 1.2rem; margin-bottom: 1rem; border-bottom: 1px solid #30363d; padding-bottom: 0.5rem; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 0.5rem 0.75rem; text-align: left; border-bottom: 1px solid #21262d; }
  th { color: #8b949e; font-size: 0.8rem; text-transform: uppercase; }
  td { font-family: 'SFMono-Regular', Consolas, monospace; font-size: 0.9rem; color: #c9d1d9; }
  .footer { text-align: center; color: #484f58; padding: 2rem 0; font-size: 0.8rem; }
</style>
</head>
<body>
<div class="container">
HTMLHEAD

    cat >> "$output_file" <<HTMLBODY
<h1>🔍 Recon Engine Report</h1>
<p class="subtitle">Target: <strong>${DOMAIN}</strong> — Scanned: $(date)</p>

<div class="stats-grid">
  <div class="stat-card"><div class="value">${total_subs}</div><div class="label">Subdomains</div></div>
  <div class="stat-card"><div class="value">${resolved}</div><div class="label">Resolved</div></div>
  <div class="stat-card"><div class="value">${alive}</div><div class="label">Alive Services</div></div>
  <div class="stat-card"><div class="value">${screenshots}</div><div class="label">Screenshots</div></div>
  <div class="stat-card"><div class="value">${ports}</div><div class="label">Open Ports</div></div>
  <div class="stat-card"><div class="value">${js_endpoints}</div><div class="label">JS Endpoints</div></div>
  <div class="stat-card"><div class="value">${historical}</div><div class="label">Historical URLs</div></div>
  <div class="stat-card"><div class="value">${crawled}</div><div class="label">Crawled Paths</div></div>
</div>
HTMLBODY

    # Alive URLs table
    if [[ -s "$OUTPUT_DIR/httpx/summary.txt" ]]; then
        echo '<div class="section"><h2>Alive Web Services</h2><table><tr><th>URL</th><th>Status</th><th>Title</th><th>Server</th></tr>' >> "$output_file"
        head -100 "$OUTPUT_DIR/httpx/summary.txt" | while IFS= read -r line; do
            local url status title server
            url=$(echo "$line" | awk '{print $1}')
            status=$(echo "$line" | grep -oP '\[\K[0-9]+(?=\])' | head -1)
            title=$(echo "$line" | grep -oP '\[\K[^\]]+(?=\])' | sed -n '2p')
            server=$(echo "$line" | grep -oP '\[\K[^\]]+(?=\])' | tail -1)
            echo "<tr><td>${url}</td><td>${status:-N/A}</td><td>${title:-N/A}</td><td>${server:-N/A}</td></tr>" >> "$output_file"
        done
        echo '</table></div>' >> "$output_file"
    fi

    # Key files reference
    cat >> "$output_file" <<'HTMLFOOTER'
<div class="section">
  <h2>Output Directory Structure</h2>
  <table>
    <tr><th>File</th><th>Description</th></tr>
    <tr><td>subs/all.txt</td><td>All discovered subdomains (deduplicated)</td></tr>
    <tr><td>dns/resolved.txt</td><td>DNS-validated hosts</td></tr>
    <tr><td>httpx/alive.txt</td><td>Live web service URLs</td></tr>
    <tr><td>httpx/results.json</td><td>Full HTTP probe data (JSON)</td></tr>
    <tr><td>ports/naabu.txt</td><td>Open host:port pairs</td></tr>
    <tr><td>js/endpoints.txt</td><td>Extracted JS endpoints</td></tr>
    <tr><td>js/secrets.txt</td><td>Potential secrets and tokens</td></tr>
    <tr><td>historical/all_urls.txt</td><td>Historical/archived URLs</td></tr>
    <tr><td>endpoints/all.txt</td><td>Crawled endpoints</td></tr>
    <tr><td>endpoints/interesting_paths.txt</td><td>Auth/admin paths</td></tr>
    <tr><td>infra/infra_map.json</td><td>Infrastructure relationship map</td></tr>
  </table>
</div>

<div class="footer">
  Generated by Recon Engine v1.0
</div>
</div>
</body>
</html>
HTMLFOOTER

}
