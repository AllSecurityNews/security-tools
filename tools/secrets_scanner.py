#!/usr/bin/env python3
"""
Secrets Scanner - Find leaked credentials in files and directories

Scans files for accidentally committed secrets: API keys, tokens,
private keys, connection strings, and other sensitive values.

Usage:
    python secrets_scanner.py /path/to/project
    python secrets_scanner.py --json src/
    python secrets_scanner.py config.py .env docker-compose.yml

Part of AllSecurityNews.com open source security tools
https://github.com/AllSecurityNews/security-tools
"""

import re
import os
import sys
import json
import argparse
from pathlib import Path

# File extensions to skip (binary, media, dependencies)
SKIP_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2',
    '.ttf', '.eot', '.mp3', '.mp4', '.avi', '.mov', '.pdf', '.zip',
    '.tar', '.gz', '.bz2', '.7z', '.exe', '.dll', '.so', '.dylib',
    '.pyc', '.pyo', '.class', '.jar', '.war', '.min.js', '.min.css',
    '.map', '.lock', '.sum',
}

# Directories to skip
SKIP_DIRS = {
    '.git', 'node_modules', '__pycache__', '.venv', 'venv', 'vendor',
    'dist', 'build', '.next', '.nuxt', 'target', 'bin', 'obj',
    '.terraform', '.serverless',
}

# Detection patterns: (name, regex, severity, description)
PATTERNS = [
    # AWS
    ('AWS Access Key', r'(?:^|[^A-Z0-9])(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?:[^A-Z0-9]|$)', 'CRITICAL', 'AWS IAM access key ID'),
    ('AWS Secret Key', r'(?i)(?:aws_secret|secret_access_key|aws_secret_key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', 'CRITICAL', 'AWS secret access key'),

    # GCP
    ('GCP Service Account', r'"type"\s*:\s*"service_account"', 'CRITICAL', 'GCP service account JSON key file'),
    ('GCP API Key', r'AIza[0-9A-Za-z_-]{35}', 'HIGH', 'Google API key'),

    # Azure
    ('Azure Connection String', r'(?i)(?:DefaultEndpointsProtocol|AccountKey)\s*=\s*[^\s;]{20,}', 'CRITICAL', 'Azure storage connection string'),

    # Generic API keys and tokens
    ('Generic API Key', r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', 'HIGH', 'API key assignment'),
    ('Generic Secret', r'(?i)(?:secret|token|auth|credential|passwd|password)\s*[=:]\s*["\']([^\s"\']{8,})["\']', 'HIGH', 'Secret or credential assignment'),
    ('Bearer Token', r'(?i)bearer\s+[A-Za-z0-9_\-.]{20,}', 'HIGH', 'Bearer authentication token'),

    # Private keys
    ('Private Key', r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----', 'CRITICAL', 'Private key file'),
    ('PGP Private Key', r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'CRITICAL', 'PGP private key'),

    # Database connection strings
    ('Database URL', r'(?i)(?:mysql|postgres|postgresql|mongodb|redis|amqp):\/\/[^\s"\']+:[^\s"\']+@[^\s"\']+', 'CRITICAL', 'Database connection string with credentials'),

    # Stripe
    ('Stripe Secret Key', r'sk_live_[0-9a-zA-Z]{24,}', 'CRITICAL', 'Stripe live secret key'),
    ('Stripe Publishable', r'pk_live_[0-9a-zA-Z]{24,}', 'MEDIUM', 'Stripe live publishable key'),

    # GitHub
    ('GitHub Token', r'ghp_[A-Za-z0-9]{36}', 'CRITICAL', 'GitHub personal access token'),
    ('GitHub OAuth', r'gho_[A-Za-z0-9]{36}', 'CRITICAL', 'GitHub OAuth access token'),

    # Slack
    ('Slack Token', r'xox[bprs]-[0-9]{10,}-[A-Za-z0-9-]+', 'CRITICAL', 'Slack bot/user/app token'),
    ('Slack Webhook', r'https://hooks\.slack\.com/services/[A-Za-z0-9/]+', 'HIGH', 'Slack incoming webhook URL'),

    # JWT
    ('JWT Token', r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', 'MEDIUM', 'JSON Web Token'),

    # SendGrid
    ('SendGrid Key', r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}', 'CRITICAL', 'SendGrid API key'),

    # Twilio
    ('Twilio Key', r'SK[0-9a-fA-F]{32}', 'HIGH', 'Twilio API key'),

    # Generic high-entropy strings in assignments
    ('High-Entropy Secret', r'(?i)(?:password|passwd|pwd|secret|token)\s*[=:]\s*["\']([A-Za-z0-9!@#$%^&*()_+\-=]{16,})["\']', 'MEDIUM', 'Possible hardcoded password or secret'),
]

# Known false positive values
FALSE_POSITIVES = {
    'your-api-key-here', 'xxxxxxxxxxxx', 'placeholder',
    'example', 'changeme', 'password', 'secret', 'test',
    'TODO', 'FIXME', 'none', 'null', 'undefined',
    'process.env', 'os.environ', 'os.getenv',
}


def should_skip_file(filepath):
    """Check if a file should be skipped based on extension or path."""
    path = Path(filepath)

    # Skip by extension
    if path.suffix.lower() in SKIP_EXTENSIONS:
        return True

    # Skip by directory
    for part in path.parts:
        if part in SKIP_DIRS:
            return True

    # Skip very large files (>1MB)
    try:
        if path.stat().st_size > 1_000_000:
            return True
    except OSError:
        return True

    return False


def is_false_positive(value):
    """Check if a matched value is a known false positive."""
    clean = value.strip().lower().strip('"\'')
    if clean in FALSE_POSITIVES:
        return True
    if len(set(clean)) < 4:  # Low entropy
        return True
    if clean.startswith('${') or clean.startswith('{{'):  # Template variables
        return True
    return False


def scan_file(filepath):
    """Scan a single file for secrets. Returns list of findings."""
    findings = []
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
    except (PermissionError, OSError):
        return findings

    for line_num, line in enumerate(content.split('\n'), 1):
        for name, pattern, severity, description in PATTERNS:
            for match in re.finditer(pattern, line):
                value = match.group(0)[:80]
                if is_false_positive(value):
                    continue
                findings.append({
                    'file': str(filepath),
                    'line': line_num,
                    'type': name,
                    'severity': severity,
                    'description': description,
                    'match': value[:60] + ('...' if len(value) > 60 else ''),
                })

    return findings


def scan_directory(path):
    """Recursively scan a directory for secrets."""
    all_findings = []
    files_scanned = 0

    if os.path.isfile(path):
        if not should_skip_file(path):
            all_findings.extend(scan_file(path))
            files_scanned = 1
        return all_findings, files_scanned

    for root, dirs, files in os.walk(path):
        # Remove skip dirs from traversal
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for filename in files:
            filepath = os.path.join(root, filename)
            if should_skip_file(filepath):
                continue
            findings = scan_file(filepath)
            all_findings.extend(findings)
            files_scanned += 1

    return all_findings, files_scanned


def print_findings(findings, files_scanned, output_json=False):
    """Print scan results."""
    if output_json:
        print(json.dumps({
            'files_scanned': files_scanned,
            'total_findings': len(findings),
            'findings': findings,
        }, indent=2))
        return

    if not findings:
        print(f"\nScanned {files_scanned} files. No secrets found.")
        return

    # Group by severity
    by_severity = {}
    for f in findings:
        by_severity.setdefault(f['severity'], []).append(f)

    print(f"\nScanned {files_scanned} files. Found {len(findings)} potential secrets:\n")

    for severity in ['CRITICAL', 'HIGH', 'MEDIUM']:
        items = by_severity.get(severity, [])
        if not items:
            continue

        print(f"  [{severity}] ({len(items)} findings)")
        for f in items[:15]:
            rel_path = os.path.relpath(f['file'])
            print(f"    {rel_path}:{f['line']}  {f['type']}")
            print(f"      {f['match']}")
        if len(items) > 15:
            print(f"    ... and {len(items) - 15} more")
        print()

    print("Recommended actions:")
    if by_severity.get('CRITICAL'):
        print("  1. Rotate all CRITICAL secrets immediately")
        print("  2. Check git history for exposure duration")
    print("  3. Move secrets to environment variables or a vault")
    print("  4. Add patterns to your .gitignore and pre-commit hooks")
    print(f"\nLearn more: https://allsecuritynews.com/hub/tools")


def main():
    parser = argparse.ArgumentParser(
        description='Scan files and directories for leaked secrets',
        epilog='Part of AllSecurityNews.com security tools'
    )
    parser.add_argument('paths', nargs='+', help='Files or directories to scan')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    args = parser.parse_args()

    all_findings = []
    total_files = 0

    for path in args.paths:
        if not os.path.exists(path):
            print(f"Error: Path not found: {path}", file=sys.stderr)
            sys.exit(1)
        findings, count = scan_directory(path)
        all_findings.extend(findings)
        total_files += count

    print_findings(all_findings, total_files, output_json=args.json)

    # Exit with non-zero if critical findings
    if any(f['severity'] == 'CRITICAL' for f in all_findings):
        sys.exit(2)
    elif all_findings:
        sys.exit(1)


if __name__ == '__main__':
    main()
