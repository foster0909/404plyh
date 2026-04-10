#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# RECON ENGINE — Dependency Checker
# ─────────────────────────────────────────────────────────────────────────────

check_tool() {
    local tool="$1"
    local required="${2:-false}"

    if command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}✓${RESET} ${tool}"
        return 0
    else
        if [[ "$required" == "true" ]]; then
            echo -e "  ${RED}✗${RESET} ${tool} ${RED}(REQUIRED)${RESET}"
        else
            echo -e "  ${YELLOW}○${RESET} ${tool} ${YELLOW}(optional — module will be skipped)${RESET}"
        fi
        return 1
    fi
}

check_py_tool() {
    local path="$1"
    local label="$2"

    if [[ -f "$path" ]]; then
        echo -e "  ${GREEN}✓${RESET} ${label} ${GRAY}(${path})${RESET}"
        return 0
    elif command -v "$path" &>/dev/null; then
        echo -e "  ${GREEN}✓${RESET} ${label} ${GRAY}(in PATH)${RESET}"
        return 0
    else
        echo -e "  ${YELLOW}○${RESET} ${label} ${YELLOW}(not found — set ${label%%.*}_PATH or place in working dir)${RESET}"
        return 1
    fi
}

check_dependencies() {
    header "Dependency Check"

    local missing_critical=0
    local missing_optional=0

    echo -e "${WHITE}Core Tools:${RESET}"
    check_tool "curl"    "true" || ((missing_critical++))
    check_tool "jq"      "true" || ((missing_critical++))
    check_tool "sort"    "true" || ((missing_critical++))
    check_tool "grep"    "true" || ((missing_critical++))
    check_tool "awk"     "true" || ((missing_critical++))
    check_tool "sed"     "true" || ((missing_critical++))

    echo ""
    echo -e "${WHITE}Subdomain Discovery:${RESET}"
    check_tool "subfinder"   || ((missing_optional++))
    check_tool "amass"       || ((missing_optional++))
    check_tool "assetfinder" || ((missing_optional++))
    check_tool "chaos"       || ((missing_optional++))

    echo ""
    echo -e "${WHITE}DNS Resolution:${RESET}"
    check_tool "puredns" || ((missing_optional++))

    echo ""
    echo -e "${WHITE}HTTP Probing:${RESET}"
    check_tool "httpx" || ((missing_optional++))

    echo ""
    echo -e "${WHITE}Screenshots:${RESET}"
    check_tool "gowitness" || ((missing_optional++))

    echo ""
    echo -e "${WHITE}Port Scanning:${RESET}"
    check_tool "naabu" || ((missing_optional++))
    check_tool "nmap"  || ((missing_optional++))

    echo ""
    echo -e "${WHITE}JavaScript Analysis:${RESET}"
    check_tool "python3"      || ((missing_optional++))
    check_py_tool "$LINKFINDER_PATH" "linkfinder.py"   || ((missing_optional++))
    check_py_tool "$SECRETFINDER_PATH" "SecretFinder.py" || ((missing_optional++))

    echo ""
    echo -e "${WHITE}Historical URLs:${RESET}"
    check_tool "gau"         || ((missing_optional++))
    check_tool "waybackurls" || ((missing_optional++))

    echo ""
    echo -e "${WHITE}Crawling & Endpoints:${RESET}"
    check_tool "katana"    || ((missing_optional++))
    check_tool "hakrawler" || ((missing_optional++))

    echo ""
    echo -e "${WHITE}Dorking (Sensitive File Discovery):${RESET}"
    check_tool "httpx" || ((missing_optional++))  # reused from HTTP probing

    echo ""
    echo -e "${WHITE}Infrastructure:${RESET}"
    check_tool "whois" || ((missing_optional++))

    echo ""

    if [[ $missing_critical -gt 0 ]]; then
        error "Missing $missing_critical critical tool(s). Cannot proceed."
        return 1
    fi

    if [[ $missing_optional -gt 0 ]]; then
        warn "Missing $missing_optional optional tool(s). Some modules will be skipped."
    else
        success "All tools available."
    fi

    return 0
}
