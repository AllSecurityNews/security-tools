#!/usr/bin/env python3
"""
IOC Extractor - Pull indicators of compromise from any text

Extracts IPs, domains, URLs, email addresses, file hashes (MD5/SHA1/SHA256),
and CVE IDs from text files, log files, reports, or stdin.

Usage:
    python ioc_extractor.py report.txt
    python ioc_extractor.py --json report.txt
    cat access.log | python ioc_extractor.py -
    python ioc_extractor.py *.txt

Part of AllSecurityNews.com open source security tools
https://github.com/AllSecurityNews/security-tools
"""

import re
import sys
import json
import argparse
from collections import defaultdict

# Patterns
PATTERNS = {
    'ipv4': re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ),
    'ipv6': re.compile(
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
        r'\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b'
    ),
    'domain': re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
        r'+(?:com|net|org|io|gov|edu|mil|co|us|uk|de|fr|ru|cn|info|biz|xyz|top|'
        r'online|site|club|app|dev|security|tech|cloud|pro)\b',
        re.IGNORECASE
    ),
    'url': re.compile(
        r'https?://[^\s<>"\')\]]+',
        re.IGNORECASE
    ),
    'email': re.compile(
        r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    ),
    'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
    'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
    'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
    'cve': re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE),
}

# IPs to skip (internal, loopback, broadcast)
SKIP_IPS = {
    '0.0.0.0', '127.0.0.1', '255.255.255.255',
    '10.0.0.0', '172.16.0.0', '192.168.0.0',
}

# Domains to skip (common false positives)
SKIP_DOMAINS = {
    'example.com', 'example.org', 'example.net',
    'localhost', 'schema.org', 'w3.org',
    'schemas.microsoft.com', 'purl.org',
}


def extract_iocs(text):
    """Extract all IOC types from text. Returns dict of type -> sorted unique values."""
    results = defaultdict(set)

    for ioc_type, pattern in PATTERNS.items():
        for match in pattern.findall(text):
            value = match.strip().rstrip('.,;:)')

            # Filter noise
            if ioc_type == 'ipv4' and value in SKIP_IPS:
                continue
            if ioc_type == 'ipv4' and value.startswith(('10.', '192.168.', '127.')):
                continue
            if ioc_type == 'domain' and value.lower() in SKIP_DOMAINS:
                continue
            if ioc_type == 'md5' and len(set(value)) < 4:
                continue  # Skip low-entropy hex (likely not a real hash)

            results[ioc_type].add(value)

    # Remove hashes that are substrings of longer hashes
    if results['sha256']:
        sha256_set = results['sha256']
        results['sha1'] -= {h for h in results['sha1'] if any(h in s for s in sha256_set)}
        results['md5'] -= {h for h in results['md5'] if any(h in s for s in sha256_set)}
    if results['sha1']:
        sha1_set = results['sha1']
        results['md5'] -= {h for h in results['md5'] if any(h in s for s in sha1_set)}

    return {k: sorted(v) for k, v in results.items() if v}


def print_results(results, output_json=False):
    """Print extracted IOCs."""
    if output_json:
        print(json.dumps(results, indent=2))
        return

    total = sum(len(v) for v in results.values())
    if total == 0:
        print("No IOCs found.")
        return

    print(f"\nExtracted {total} indicators of compromise:\n")

    labels = {
        'ipv4': 'IPv4 Addresses',
        'ipv6': 'IPv6 Addresses',
        'domain': 'Domains',
        'url': 'URLs',
        'email': 'Email Addresses',
        'md5': 'MD5 Hashes',
        'sha1': 'SHA-1 Hashes',
        'sha256': 'SHA-256 Hashes',
        'cve': 'CVE IDs',
    }

    for ioc_type in ['cve', 'ipv4', 'ipv6', 'domain', 'url', 'email', 'sha256', 'sha1', 'md5']:
        values = results.get(ioc_type, [])
        if not values:
            continue
        print(f"  {labels.get(ioc_type, ioc_type)} ({len(values)}):")
        for v in values[:20]:
            print(f"    {v}")
        if len(values) > 20:
            print(f"    ... and {len(values) - 20} more")
        print()


def main():
    parser = argparse.ArgumentParser(
        description='Extract IOCs (IPs, domains, hashes, CVEs) from text files',
        epilog='Part of AllSecurityNews.com security tools'
    )
    parser.add_argument('files', nargs='+', help='Files to scan (use - for stdin)')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    args = parser.parse_args()

    all_text = ''
    for filepath in args.files:
        try:
            if filepath == '-':
                all_text += sys.stdin.read()
            else:
                with open(filepath, 'r', errors='ignore') as f:
                    all_text += f.read()
        except FileNotFoundError:
            print(f"Error: File not found: {filepath}", file=sys.stderr)
            sys.exit(1)

    results = extract_iocs(all_text)
    print_results(results, output_json=args.json)


if __name__ == '__main__':
    main()
