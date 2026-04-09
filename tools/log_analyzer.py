#!/usr/bin/env python3
"""
Security Log Analyzer - Flag suspicious patterns in web server logs

Parses Apache/nginx access logs and flags:
- Brute force attempts (repeated 401s from same IP)
- Directory traversal attempts (../ patterns)
- SQL injection probes (union, select, etc. in URLs)
- Scanner/bot activity (common scanner user agents)
- Suspicious HTTP methods (PUT, DELETE, TRACE, etc.)
- High request rates from single IPs

Usage:
    python log_analyzer.py /var/log/nginx/access.log
    python log_analyzer.py --top 20 access.log
    cat access.log | python log_analyzer.py -

Part of AllSecurityNews.com open source security tools
https://github.com/AllSecurityNews/security-tools
"""

import re
import sys
import argparse
from collections import Counter, defaultdict
from datetime import datetime

# Common log format regex (handles both Apache and nginx default formats)
LOG_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+'
    r'(?:\S+\s+){1,2}'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)")?'
    r'(?:\s+"(?P<useragent>[^"]*)")?'
)

# Suspicious patterns
SQLI_PATTERNS = re.compile(
    r'(?:union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|'
    r'or\s+1\s*=\s*1|and\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|'
    r'load_file|into\s+outfile|information_schema)',
    re.IGNORECASE
)

TRAVERSAL_PATTERNS = re.compile(r'\.\./|\.\.\\|%2e%2e|%252e')

XSS_PATTERNS = re.compile(
    r'<script|javascript:|onerror\s*=|onload\s*=|alert\s*\(|eval\s*\(',
    re.IGNORECASE
)

SCANNER_AGENTS = re.compile(
    r'nikto|sqlmap|nmap|masscan|dirbuster|gobuster|wfuzz|ffuf|nuclei|'
    r'acunetix|nessus|openvas|burpsuite|zaproxy|w3af|arachni',
    re.IGNORECASE
)

SUSPICIOUS_PATHS = re.compile(
    r'/wp-admin|/wp-login\.php|/xmlrpc\.php|/phpmyadmin|/admin|'
    r'/\.env|/\.git|/config\.php|/wp-config|/etc/passwd|/proc/self|'
    r'/shell|/cmd\.php|/eval-stdin|/console|/actuator',
    re.IGNORECASE
)

SUSPICIOUS_METHODS = {'PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH'}


def parse_log(lines):
    """Parse log lines and return structured entries."""
    entries = []
    for line in lines:
        match = LOG_PATTERN.search(line)
        if match:
            entries.append(match.groupdict())
    return entries


def analyze(entries, top_n=10):
    """Analyze log entries for suspicious activity."""
    findings = []
    ip_requests = Counter()
    ip_errors = defaultdict(int)
    ip_methods = defaultdict(set)

    for entry in entries:
        ip = entry['ip']
        path = entry.get('path', '')
        status = entry.get('status', '')
        method = entry.get('method', '')
        ua = entry.get('useragent', '') or ''

        ip_requests[ip] += 1

        # Track error codes per IP
        if status.startswith('4'):
            ip_errors[ip] += 1

        # Suspicious methods
        if method.upper() in SUSPICIOUS_METHODS:
            ip_methods[ip].add(method)

        # SQL injection attempts
        if SQLI_PATTERNS.search(path):
            findings.append(('SQLI', 'HIGH', ip, f'{method} {path[:100]}'))

        # Directory traversal
        if TRAVERSAL_PATTERNS.search(path):
            findings.append(('TRAVERSAL', 'HIGH', ip, f'{method} {path[:100]}'))

        # XSS attempts
        if XSS_PATTERNS.search(path):
            findings.append(('XSS', 'MEDIUM', ip, f'{method} {path[:100]}'))

        # Scanner detection
        if SCANNER_AGENTS.search(ua):
            findings.append(('SCANNER', 'MEDIUM', ip, f'User-Agent: {ua[:80]}'))

        # Suspicious paths
        if SUSPICIOUS_PATHS.search(path):
            findings.append(('RECON', 'LOW', ip, f'{method} {path[:100]}'))

    # Brute force detection (IPs with many 4xx errors)
    for ip, error_count in ip_errors.items():
        total = ip_requests[ip]
        if error_count >= 10 and error_count / total > 0.5:
            findings.append(('BRUTE_FORCE', 'HIGH', ip, f'{error_count} errors out of {total} requests'))

    # High volume detection
    for ip, count in ip_requests.most_common(top_n):
        if count >= 100:
            findings.append(('HIGH_VOLUME', 'MEDIUM', ip, f'{count} total requests'))

    # Suspicious methods
    for ip, methods in ip_methods.items():
        findings.append(('SUS_METHOD', 'LOW', ip, f'Used methods: {", ".join(methods)}'))

    return findings, ip_requests


def print_report(findings, ip_requests, top_n=10):
    """Print the analysis report."""
    print(f"\nSecurity Log Analysis Report")
    print(f"{'=' * 60}")
    print(f"Total entries parsed: {sum(ip_requests.values())}")
    print(f"Unique IPs: {len(ip_requests)}")
    print(f"Findings: {len(findings)}")
    print()

    # Group findings by severity
    by_severity = defaultdict(list)
    for finding_type, severity, ip, detail in findings:
        by_severity[severity].append((finding_type, ip, detail))

    for severity in ['HIGH', 'MEDIUM', 'LOW']:
        items = by_severity.get(severity, [])
        if not items:
            continue

        # Deduplicate by (type, ip)
        seen = set()
        unique = []
        for finding_type, ip, detail in items:
            key = (finding_type, ip)
            if key not in seen:
                seen.add(key)
                unique.append((finding_type, ip, detail))

        print(f"[{severity}] ({len(unique)} findings)")
        for finding_type, ip, detail in unique[:20]:
            print(f"  {finding_type:12s}  {ip:16s}  {detail}")
        if len(unique) > 20:
            print(f"  ... and {len(unique) - 20} more")
        print()

    # Top talkers
    print(f"Top {top_n} IPs by request volume:")
    for ip, count in ip_requests.most_common(top_n):
        print(f"  {ip:16s}  {count:6d} requests")

    print(f"\nLearn more: https://allsecuritynews.com/hub/tools")


def main():
    parser = argparse.ArgumentParser(
        description='Analyze web server logs for suspicious activity',
        epilog='Part of AllSecurityNews.com security tools'
    )
    parser.add_argument('files', nargs='+', help='Log files to analyze (use - for stdin)')
    parser.add_argument('--top', type=int, default=10, help='Number of top IPs to show (default: 10)')
    parser.add_argument('--json', action='store_true', help='Output findings as JSON')
    args = parser.parse_args()

    lines = []
    for filepath in args.files:
        try:
            if filepath == '-':
                lines.extend(sys.stdin.readlines())
            else:
                with open(filepath, 'r', errors='ignore') as f:
                    lines.extend(f.readlines())
        except FileNotFoundError:
            print(f"Error: File not found: {filepath}", file=sys.stderr)
            sys.exit(1)

    if not lines:
        print("No log data to analyze.")
        sys.exit(1)

    entries = parse_log(lines)
    if not entries:
        print(f"Could not parse any entries. Expected Apache/nginx common log format.")
        sys.exit(1)

    print(f"Parsed {len(entries)} of {len(lines)} lines...")

    findings, ip_requests = analyze(entries, top_n=args.top)

    if args.json:
        import json
        output = {
            'total_entries': len(entries),
            'unique_ips': len(ip_requests),
            'findings': [
                {'type': t, 'severity': s, 'ip': ip, 'detail': d}
                for t, s, ip, d in findings
            ],
            'top_ips': [
                {'ip': ip, 'requests': count}
                for ip, count in ip_requests.most_common(args.top)
            ],
        }
        print(json.dumps(output, indent=2))
    else:
        print_report(findings, ip_requests, top_n=args.top)


if __name__ == '__main__':
    main()
