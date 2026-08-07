#!/usr/bin/env python3
import sys
import os
import re
import json

# Regex definitions for secrets
SECRET_PATTERNS = {
    "AWS Access Key": r'\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b',
    "AWS Secret Key": r'\b[a-zA-Z0-9+/]{40}\b', # Checked via context or length, let's keep it specific in JS
    "Google API Key": r'\bAIza[yA-Z0-9_-]{35}\b',
    "Firebase URL": r'https://[a-zA-Z0-9-]+\.firebaseio\.com',
    "Slack Webhook": r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
    "GitHub Token": r'\b(gh[psour]_[a-zA-Z0-9]{36,40})\b',
    "Stripe API Key": r'\b(sk|rk)_(live|test)_[0-9a-zA-Z]{24,34}\b',
    "Discord Webhook": r'https://discord\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+',
    "Facebook OAuth": r'\b[fF]acebook|[fF][bB]_?[aA]pp_?[iI]d\b.*?\b[0-9a-f]{32}\b',
    "JWT Token": r'\beyJhbGciOi[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\b',
    "Mailgun API Key": r'\bkey-[a-f0-9]{32}\b',
    "API Key (Generic)": r"(?i)\b(api_key|apikey|secret_key|secretkey|auth_token|authtoken|access_token|accesstoken|session_token|sessiontoken)\s*[:=]\s*[\"']([a-zA-Z0-9_-]{16,64})[\"']",
    "Private Key": r'-----BEGIN[ A-Z0-9_-]+PRIVATE KEY-----',
}

# Regex for internal IPs & Dev domains
INTERNAL_IP_PATTERN = r'\b(127\.0\.0\.1|localhost|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'
DEV_DOMAIN_PATTERN = r'\b([a-zA-Z0-9_-]+\.(?:local|internal|dev|test|staging|localhost))\b'

# Regex for relative endpoints in JS strings
ENDPOINT_PATTERN = r'["\x27](/[a-zA-Z0-9_\-\.\:\/\{\}]+)["\x27]'

# Regex for developer comments
# Matches // comments and /* ... */ comments
COMMENT_PATTERN = r'(//.*|/\*.*?\*/)'
INTERESTING_COMMENT_KEYWORDS = r'(?i)\b(todo|fixme|bug|hack|password|username|creds|credential|secret|key|deprecated|remove|temp|bypass|debug)\b'

def scan_file(file_path, base_dir):
    rel_path = os.path.relpath(file_path, base_dir)
    results = {
        "endpoints": set(),
        "secrets": [],
        "leakage": set(),
        "comments": []
    }

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        return results

    # Line-by-line scanning (for secrets, leakage, comments with line numbers)
    lines = content.split('\n')
    for line_num, line in enumerate(lines, 1):
        line_strip = line.strip()
        if not line_strip:
            continue

        # 1. Secrets check
        for name, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, line)
            for m in matches:
                # If group match, extract the correct match string
                match_str = m[1] if isinstance(m, tuple) else m
                # Simple heuristic to exclude obvious false positives for AWS Secret Key
                if name == "AWS Secret Key" and (match_str.upper() == match_str or match_str.lower() == match_str):
                    continue
                results["secrets"].append({
                    "file": rel_path,
                    "line": line_num,
                    "type": name,
                    "match": match_str
                })

        # 2. Leakage check (IPs / Dev domains)
        ip_matches = re.findall(INTERNAL_IP_PATTERN, line)
        for ip in ip_matches:
            if isinstance(ip, tuple):
                ip = ip[0]
            results["leakage"].add(ip)

        dev_matches = re.findall(DEV_DOMAIN_PATTERN, line)
        for dev in dev_matches:
            if isinstance(dev, tuple):
                dev = dev[0]
            results["leakage"].add(dev)

        # 3. Comments check
        comment_matches = re.findall(COMMENT_PATTERN, line)
        for comment in comment_matches:
            if re.search(INTERESTING_COMMENT_KEYWORDS, comment):
                results["comments"].append({
                    "file": rel_path,
                    "line": line_num,
                    "comment": comment[:200].strip() # Truncate long comments
                })

    # 4. Global endpoint extraction (across multiple lines / entire content)
    # Finding relative endpoints
    endpoint_matches = re.findall(ENDPOINT_PATTERN, content)
    for ep in endpoint_matches:
        # Basic validation: ensure it's a path, not just a slash, and doesn't look like file extension metadata or HTML tags
        if len(ep) > 1 and not ep.startswith('//') and not ep.startswith('/<') and not ep.endswith('/') and not ep.endswith('.css') and not ep.endswith('.png') and not ep.endswith('.jpg') and not ep.endswith('.jpeg') and not ep.endswith('.gif'):
            results["endpoints"].add(ep)

    return results

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 js_scanner.py <input_dir> <output_dir>")
        sys.exit(1)

    input_dir = sys.argv[1]
    output_dir = sys.argv[2]

    if not os.path.exists(input_dir):
        print(f"[-] Input directory not found: {input_dir}")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    endpoints_all = set()
    secrets_all = []
    leakage_all = set()
    comments_all = []

    # Recurse and scan
    for root, _, files in os.walk(input_dir):
        for f in files:
            if f.endswith('.js') or f.endswith('.txt') or f.endswith('.json'):
                file_path = os.path.join(root, f)
                res = scan_file(file_path, input_dir)
                endpoints_all.update(res["endpoints"])
                secrets_all.extend(res["secrets"])
                leakage_all.update(res["leakage"])
                comments_all.extend(res["comments"])

    # Write endpoints
    with open(os.path.join(output_dir, "endpoints.txt"), "w") as f:
        for ep in sorted(endpoints_all):
            f.write(ep + "\n")

    # Write secrets (structured output)
    with open(os.path.join(output_dir, "secrets.txt"), "w") as f:
        for s in secrets_all:
            f.write(f"[{s['file']}:{s['line']}] [{s['type']}] {s['match']}\n")

    # Write leakage
    with open(os.path.join(output_dir, "leakage.txt"), "w") as f:
        for leak in sorted(leakage_all):
            f.write(leak + "\n")

    # Write comments
    with open(os.path.join(output_dir, "comments.txt"), "w") as f:
        for c in comments_all:
            f.write(f"[{c['file']}:{c['line']}] {c['comment']}\n")

    print(f"[+] JS Scanner complete: {len(endpoints_all)} endpoints, {len(secrets_all)} secrets, {len(leakage_all)} leakage, {len(comments_all)} comments found.")

if __name__ == '__main__':
    main()
