#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# MODULE: Google Dork-Style Sensitive File Discovery
# Passive pattern matching + active path probing for exposed files.
#
# Phase 1 (Passive): Grep known dork patterns across collected URLs
#         (historical, crawled endpoints, JS endpoints)
# Phase 2 (Active):  Probe alive hosts for ~80 common sensitive paths
#         using httpx, flagging 200/403 responses.
# ─────────────────────────────────────────────────────────────────────────────

# ── Dork pattern definitions ────────────────────────────────────────────────
# Each category maps to a grep -iE regex pattern.

declare -A DORK_PATTERNS=(
    # Configuration files that should never be public
    [config_files]='(\.env($|\?|#)|\.git/(config|HEAD|index)|\.gitignore|\.htaccess|\.htpasswd|wp-config\.php|web\.config|\.npmrc|\.dockerenv|Dockerfile|docker-compose\.ya?ml|\.aws/credentials|\.ssh/(id_rsa|authorized_keys)|composer\.json|package\.json|Gemfile|requirements\.txt|\.editorconfig|\.babelrc|tsconfig\.json|Gruntfile|Gulpfile|Makefile|\.travis\.yml|\.circleci|\.gitlab-ci\.yml|Jenkinsfile|Vagrantfile|\.terraform)'

    # Backup and database dump files
    [backup_files]='(\.(bak|backup|old|orig|original|save|copy|tmp|temp|swp|swo)(\..*)?($|\?)|~$|\.sql($|\?|\.gz|\.zip|\.bak)|\.dump($|\?)|\.tar($|\?|\.gz|\.bz2|\.xz)|\.zip($|\?)|\.rar($|\?)|\.7z($|\?)|\.(db|sqlite|sqlite3|mdb)($|\?))'

    # Log and debug files
    [log_files]='(\.(log|logs)($|\?|/)|access[\._-]?log|error[\._-]?log|debug[\._-]?log|application[\._-]?log|laravel[\._-]?log|catalina\.out|\.log\.(txt|old|[0-9]+))'

    # Admin and management panels
    [admin_panels]='(/(admin|administrator|wp-admin|wp-login|login|signin|phpmyadmin|cpanel|webmail|plesk|adminer|manager|console|dashboard|_debug|elmah|trace\.axd|server-status|server-info|jmx-console|web-console|axis2-admin|solr)(/|$|\?))'

    # Exposed sensitive documents
    [exposed_docs]='(\.(pdf|docx?|xlsx?|pptx?|csv)($|\?)|/?(readme|changelog|license|copying|todo|notes|install)(\.md|\.txt|\.html|\.rst)?($|\?|#))'

    # Development artifacts and IDE files
    [dev_artifacts]='(\.(swp|swo|DS_Store|idea/|vscode/|project|classpath|sass-cache|cache/|iml)($|\?)|/?(thumbs\.db|desktop\.ini|\.buildpath|\.settings/|nbproject/|\.svn/|CVS/))'

    # Cloud storage and bucket references
    [cloud_assets]='((s3\.amazonaws\.com|s3[\.-].*\.amazonaws\.com|\.s3\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net|digitaloceanspaces\.com|\.r2\.cloudflarestorage\.com|firebasestorage\.googleapis\.com|supabase\.(com|co)/storage))'

    # Authentication tokens, API keys, and credentials in URLs
    [auth_tokens]='([?&](api[_-]?key|apikey|token|secret|password|passwd|pwd|auth|access[_-]?token|client[_-]?secret|private[_-]?key|session[_-]?id|jwt|bearer)=)'

    # Information disclosure / directory listing signatures
    [info_disclosure]='(/(\.listing|_vti_cnf|_vti_pvt|cgi-bin/|fckeditor|kcfinder|elfinder|crossdomain\.xml|clientaccesspolicy\.xml|sitemap\.xml|robots\.txt|\.well-known/|security\.txt|humans\.txt|\.version|phpinfo\.php|info\.php|test\.php|server-status|\.svn/entries|\.hg/|\.bzr/))'
)

# ── Sensitive paths for active probing ──────────────────────────────────────
# These paths are appended to alive URLs and probed with httpx.

SENSITIVE_PATHS=(
    # Git / source control exposure
    ".git/HEAD"
    ".git/config"
    ".svn/entries"
    ".svn/wc.db"
    ".hg/dirstate"
    ".bzr/README"

    # Environment / config files
    ".env"
    ".env.local"
    ".env.production"
    ".env.backup"
    ".env.old"
    ".env.bak"
    "wp-config.php"
    "wp-config.php.bak"
    "wp-config.php.old"
    "web.config"
    "config.php"
    "configuration.php"
    "config.yml"
    "config.yaml"
    "config.json"
    "config.xml"
    "config.inc.php"
    "settings.py"
    "database.yml"
    ".htaccess"
    ".htpasswd"
    "composer.json"
    "composer.lock"
    "package.json"
    "package-lock.json"
    "yarn.lock"
    "Gemfile"
    "Gemfile.lock"
    "requirements.txt"
    "Pipfile"
    "Pipfile.lock"

    # Info disclosure endpoints
    "phpinfo.php"
    "info.php"
    "test.php"
    "robots.txt"
    "sitemap.xml"
    "sitemap_index.xml"
    ".well-known/security.txt"
    "humans.txt"
    "crossdomain.xml"
    "clientaccesspolicy.xml"
    "browserconfig.xml"
    "manifest.json"
    ".version"

    # Server status & debug
    "server-status"
    "server-info"
    "_debug"
    "debug"
    "trace.axd"
    "elmah.axd"
    "actuator"
    "actuator/env"
    "actuator/health"
    "actuator/info"
    "actuator/beans"
    "actuator/metrics"

    # Backup files
    "backup.sql"
    "backup.zip"
    "backup.tar.gz"
    "db.sql"
    "database.sql"
    "dump.sql"
    "site.sql"

    # Admin panels
    "admin"
    "administrator"
    "login"
    "wp-login.php"
    "wp-admin"
    "phpmyadmin"
    "adminer.php"

    # Docker / CI files
    "Dockerfile"
    "docker-compose.yml"
    ".dockerenv"
    ".travis.yml"
    ".gitlab-ci.yml"
    "Jenkinsfile"

    # Error pages / stack traces
    "error"
    "errors"
    "error_log"
    "debug.log"
    "laravel.log"
    "storage/logs/laravel.log"
)


# ── Main module function ────────────────────────────────────────────────────

module_dorks() {
    if [[ "$SKIP_DORKS" == true ]]; then
        info "Skipping dork-style discovery (--skip-dorks)"
        return 0
    fi

    header "Module: Google Dork-Style Sensitive File Discovery"
    local dorks_dir="$OUTPUT_DIR/dorks"

    # ── Phase 1: Passive Pattern Matching ────────────────────────────────
    header "Phase 1: Passive Dork Pattern Matching"
    info "Scanning collected URLs for dork signatures..."

    # Gather all collected URLs into one temporary file
    local url_pool="$dorks_dir/.url_pool.tmp"
    > "$url_pool"

    local sources=(
        "$OUTPUT_DIR/historical/all_urls.txt"
        "$OUTPUT_DIR/endpoints/all.txt"
        "$OUTPUT_DIR/js/endpoints.txt"
        "$OUTPUT_DIR/js/api_endpoints.txt"
        "$OUTPUT_DIR/httpx/alive.txt"
    )

    for src in "${sources[@]}"; do
        if [[ -s "$src" ]]; then
            cat "$src" >> "$url_pool"
        fi
    done

    sort -u -o "$url_pool" "$url_pool"
    local pool_size
    pool_size=$(count "$url_pool")
    info "URL pool: ${GREEN}${pool_size}${RESET} unique URLs to scan"

    if [[ $pool_size -eq 0 ]]; then
        warn "No URLs collected. Skipping passive dorking."
    else
        local all_passive="$dorks_dir/passive_all.txt"
        > "$all_passive"

        for category in "${!DORK_PATTERNS[@]}"; do
            local pattern="${DORK_PATTERNS[$category]}"
            local outfile="$dorks_dir/passive_${category}.txt"

            grep -iE "$pattern" "$url_pool" 2>/dev/null \
                | sort -u > "$outfile" || true

            local hit_count
            hit_count=$(count "$outfile")
            if [[ $hit_count -gt 0 ]]; then
                success "  ${category}: ${GREEN}${hit_count}${RESET} matches"
                cat "$outfile" >> "$all_passive"
            else
                rm -f "$outfile"  # no hits, remove empty file
            fi
        done

        sort -u -o "$all_passive" "$all_passive"
        report_count "$all_passive" "Total passive dork matches"
    fi

    # ── Phase 2: Active Sensitive Path Probing ───────────────────────────
    header "Phase 2: Active Sensitive Path Probing"

    local alive_file="$OUTPUT_DIR/httpx/alive.txt"
    if [[ ! -s "$alive_file" ]]; then
        warn "No alive URLs. Skipping active probing."
    elif ! require_tool "httpx"; then
        warn "httpx not available. Skipping active probing."
    else
        # Build probe URL list: each alive base URL × each sensitive path
        step "Building probe URL list"
        local probe_list="$dorks_dir/.probe_urls.tmp"
        > "$probe_list"

        while IFS= read -r base_url; do
            # Normalize: strip trailing slash
            base_url="${base_url%/}"
            for path in "${SENSITIVE_PATHS[@]}"; do
                echo "${base_url}/${path}" >> "$probe_list"
            done
        done < "$alive_file"

        local probe_count
        probe_count=$(wc -l < "$probe_list")
        info "Probing ${GREEN}${probe_count}${RESET} URLs (${#SENSITIVE_PATHS[@]} paths × $(count "$alive_file") hosts)"

        # Probe with httpx — only keep 200 and 403 responses
        step "Running httpx probe (threads: $DORK_THREADS)"
        local active_raw="$dorks_dir/active_raw.json"

        run_safe "httpx dork probe" \
            "httpx -l '$probe_list' \
                -sc -title -cl -server \
                -t $DORK_THREADS -timeout $HTTPX_TIMEOUT \
                -mc 200,403 \
                -json -o '$active_raw' 2>>'$LOG_FILE'"

        # Parse results into categorized output
        if [[ -s "$active_raw" ]]; then
            # All active hits (human-readable)
            jq -r '"\(.url) [\(.status_code)] [\(.title // "N/A")] [len:\(.content_length // 0)]"' \
                "$active_raw" 2>/dev/null \
                | sort -u > "$dorks_dir/active_hits.txt" || true

            # Separate 200s (confirmed accessible) from 403s (exists but forbidden)
            jq -r 'select(.status_code == 200) | "\(.url) [\(.title // "N/A")] [len:\(.content_length // 0)]"' \
                "$active_raw" 2>/dev/null \
                | sort -u > "$dorks_dir/active_200.txt" || true

            jq -r 'select(.status_code == 403) | .url' \
                "$active_raw" 2>/dev/null \
                | sort -u > "$dorks_dir/active_403.txt" || true

            # Filter out false positives: 200 responses with tiny/empty body are likely custom 404s
            # Keep responses with content_length > 0 (actual content)
            jq -r 'select(.status_code == 200 and (.content_length // 0) > 0) | "\(.url) [\(.title // "N/A")] [len:\(.content_length // 0)]"' \
                "$active_raw" 2>/dev/null \
                | sort -u > "$dorks_dir/active_confirmed.txt" || true

            report_count "$dorks_dir/active_confirmed.txt" "Confirmed accessible sensitive files (200 + content)"
            report_count "$dorks_dir/active_403.txt" "Forbidden but existing paths (403)"
            report_count "$dorks_dir/active_hits.txt" "Total active probe hits"
        else
            info "No responsive sensitive paths found."
        fi

        # Cleanup temp files
        rm -f "$probe_list"
    fi

    # ── Merge all findings ───────────────────────────────────────────────
    step "Merging all dork findings"
    local all_findings="$dorks_dir/all_findings.txt"
    > "$all_findings"

    # Add passive findings
    [[ -s "$dorks_dir/passive_all.txt" ]] && cat "$dorks_dir/passive_all.txt" >> "$all_findings"

    # Add active confirmed hits (URLs only)
    if [[ -s "$dorks_dir/active_confirmed.txt" ]]; then
        awk '{print $1}' "$dorks_dir/active_confirmed.txt" >> "$all_findings"
    fi

    sort -u -o "$all_findings" "$all_findings"
    report_count "$all_findings" "Total unique dork findings"

    # Cleanup temp pool
    rm -f "$dorks_dir/.url_pool.tmp"

    success "Dork-style sensitive file discovery complete."
}
