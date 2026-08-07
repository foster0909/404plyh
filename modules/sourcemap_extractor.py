#!/usr/bin/env python3
import sys
import json
import os
import re

def clean_filename(name):
    # Strip protocol and query params
    name = re.sub(r'^(webpack:///|https?://)', '', name)
    name = name.split('?')[0]
    # Remove leading dots or slashes to avoid path traversal
    name = name.lstrip('./\\')
    # Replace dangerous characters
    name = re.sub(r'[<>:"|?*]', '_', name)
    return name

def extract_sourcemap(map_path, output_dir):
    try:
        with open(map_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
    except Exception as e:
        print(f"[-] Error parsing source map JSON {map_path}: {e}")
        return False

    sources = data.get('sources', [])
    contents = data.get('sourcesContent', [])

    if not sources:
        print(f"[-] No sources found in {map_path}")
        return False

    if not contents:
        print(f"[-] No sourcesContent found in {map_path}")
        return False

    extracted_count = 0
    for idx, source_name in enumerate(sources):
        if idx >= len(contents) or not contents[idx]:
            continue

        cleaned = clean_filename(source_name)
        target_path = os.path.join(output_dir, cleaned)

        # Ensure parent directories exist
        os.makedirs(os.path.dirname(target_path), exist_ok=True)

        try:
            with open(target_path, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(contents[idx])
            extracted_count += 1
        except Exception as e:
            print(f"[-] Error writing {target_path}: {e}")

    print(f"[+] Reconstructed {extracted_count} original source files from {map_path}")
    return extracted_count > 0

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python3 sourcemap_extractor.py <map_file_path> <output_dir>")
        sys.exit(1)

    map_file = sys.argv[1]
    out_dir = sys.argv[2]

    if not os.path.exists(map_file):
        print(f"[-] File not found: {map_file}")
        sys.exit(1)

    os.makedirs(out_dir, exist_ok=True)
    extract_sourcemap(map_file, out_dir)
