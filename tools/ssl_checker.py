#!/usr/bin/env python3
"""
SSL/TLS Certificate Checker

Part of AllSecurityNews.com

Checks the SSL/TLS configuration of any domain and reports:
- Certificate subject, issuer, validity dates, SANs
- Key size and signature algorithm
- Supported protocol versions
- Warnings for weak configurations

Exit codes:
  0 = All checks passed
  1 = Warnings (expiring soon, etc.)
  2 = Critical issues (expired, weak key, self-signed, etc.)

Usage:
  python ssl_checker.py example.com
  python ssl_checker.py example.com --port 8443
  python ssl_checker.py example.com --json
"""

import argparse
import json
import socket
import ssl
import sys
from datetime import datetime, timezone


def get_certificate(hostname, port=443, timeout=10):
    """Connect to the host and retrieve the SSL certificate."""
    context = ssl.create_default_context()
    # We still want to fetch the cert even if verification fails,
    # so we do two passes: one strict, one permissive.
    cert_info = {}

    # First pass: try with verification to detect trust issues
    verification_error = None
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_info["peer_cert"] = ssock.getpeercert()
                cert_info["cipher"] = ssock.cipher()
                cert_info["version"] = ssock.version()
                cert_info["verified"] = True
    except ssl.SSLCertVerificationError as e:
        verification_error = str(e)
        cert_info["verified"] = False
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        print(f"ERROR: Could not connect to {hostname}:{port} -- {e}", file=sys.stderr)
        sys.exit(2)

    # Second pass: if verification failed, connect without verification to get cert details
    if not cert_info.get("peer_cert"):
        try:
            no_verify_ctx = ssl.create_default_context()
            no_verify_ctx.check_hostname = False
            no_verify_ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with no_verify_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # getpeercert() returns empty dict when CERT_NONE, use binary form
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_info["peer_cert"] = ssl.DER_cert_to_PEM_cert(cert_der)
                    cert_info["cipher"] = ssock.cipher()
                    cert_info["version"] = ssock.version()
                    cert_info["binary_cert"] = cert_der
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
            print(f"ERROR: Could not connect to {hostname}:{port} -- {e}", file=sys.stderr)
            sys.exit(2)

    cert_info["verification_error"] = verification_error
    return cert_info


def parse_cert_date(date_str):
    """Parse certificate date string to datetime."""
    # Format: 'Mon DD HH:MM:SS YYYY GMT'
    return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def get_san_list(cert):
    """Extract Subject Alternative Names from certificate."""
    sans = []
    for entry in cert.get("subjectAltName", []):
        sans.append(f"{entry[0]}:{entry[1]}")
    return sans


def get_subject_field(cert, field_name):
    """Extract a field from the certificate subject."""
    for rdn in cert.get("subject", ()):
        for attr_type, attr_value in rdn:
            if attr_type == field_name:
                return attr_value
    return None


def get_issuer_field(cert, field_name):
    """Extract a field from the certificate issuer."""
    for rdn in cert.get("issuer", ()):
        for attr_type, attr_value in rdn:
            if attr_type == field_name:
                return attr_value
    return None


def check_protocol_support(hostname, port=443, timeout=5):
    """Check which TLS protocol versions the server supports."""
    protocols = {}

    # Map of protocol names to ssl module attributes
    protocol_checks = {
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    }

    for name, version in protocol_checks.items():
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    protocols[name] = True
        except (ssl.SSLError, socket.timeout, OSError):
            protocols[name] = False

    # Check for old/insecure protocols by trying to force them
    # TLSv1.0 and TLSv1.1 are deprecated
    for name, version in [("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    protocols[name] = True
        except (ssl.SSLError, socket.timeout, OSError, ValueError):
            protocols[name] = False

    return protocols


def analyze_cert(hostname, port, cert_info):
    """Analyze the certificate and return findings."""
    findings = {
        "hostname": hostname,
        "port": port,
        "warnings": [],
        "critical": [],
    }

    cert = cert_info.get("peer_cert")

    # If cert is a PEM string (from unverified connection), we have limited info
    if isinstance(cert, str):
        findings["critical"].append("Certificate could not be parsed in detail (verification failed)")
        if cert_info.get("verification_error"):
            findings["critical"].append(f"Verification error: {cert_info['verification_error']}")
        findings["subject"] = "Unknown (verification failed)"
        findings["issuer"] = "Unknown (verification failed)"
        if cert_info.get("cipher"):
            findings["cipher_name"] = cert_info["cipher"][0]
            findings["cipher_protocol"] = cert_info["cipher"][1]
            findings["cipher_bits"] = cert_info["cipher"][2]
        if cert_info.get("version"):
            findings["negotiated_protocol"] = cert_info["version"]
        return findings

    # Subject
    cn = get_subject_field(cert, "commonName")
    org = get_subject_field(cert, "organizationName")
    findings["subject_cn"] = cn or "N/A"
    findings["subject_org"] = org or "N/A"

    # Issuer
    issuer_cn = get_issuer_field(cert, "commonName")
    issuer_org = get_issuer_field(cert, "organizationName")
    findings["issuer_cn"] = issuer_cn or "N/A"
    findings["issuer_org"] = issuer_org or "N/A"

    # Self-signed check
    subject_cn = get_subject_field(cert, "commonName")
    if subject_cn and issuer_cn and subject_cn == issuer_cn:
        # Compare full subject and issuer tuples for a more accurate check
        if cert.get("subject") == cert.get("issuer"):
            findings["critical"].append("Certificate is self-signed")
            findings["self_signed"] = True
        else:
            findings["self_signed"] = False
    else:
        findings["self_signed"] = False

    # Validity dates
    not_before_str = cert.get("notBefore")
    not_after_str = cert.get("notAfter")
    now = datetime.now(timezone.utc)

    if not_before_str:
        not_before = parse_cert_date(not_before_str)
        findings["valid_from"] = not_before.isoformat()
    if not_after_str:
        not_after = parse_cert_date(not_after_str)
        findings["valid_until"] = not_after.isoformat()
        days_remaining = (not_after - now).days
        findings["days_remaining"] = days_remaining

        if days_remaining < 0:
            findings["critical"].append(f"Certificate EXPIRED {abs(days_remaining)} days ago")
        elif days_remaining <= 7:
            findings["critical"].append(f"Certificate expires in {days_remaining} days")
        elif days_remaining <= 30:
            findings["warnings"].append(f"Certificate expires in {days_remaining} days")

    # SANs
    sans = get_san_list(cert)
    findings["sans"] = sans
    findings["san_count"] = len(sans)

    # Check if hostname matches any SAN
    dns_sans = [s.split(":", 1)[1] for s in sans if s.startswith("DNS:")]
    hostname_matched = False
    for san in dns_sans:
        if san == hostname:
            hostname_matched = True
            break
        # Wildcard matching
        if san.startswith("*.") and hostname.endswith(san[1:]):
            hostname_matched = True
            break
    if not hostname_matched and cn != hostname:
        findings["warnings"].append(f"Hostname '{hostname}' does not match certificate CN '{cn}' or any SAN")

    # Serial number
    findings["serial_number"] = cert.get("serialNumber", "N/A")

    # Cipher info
    if cert_info.get("cipher"):
        cipher_name, cipher_protocol, cipher_bits = cert_info["cipher"]
        findings["cipher_name"] = cipher_name
        findings["cipher_protocol"] = cipher_protocol
        findings["cipher_bits"] = cipher_bits

        if cipher_bits and cipher_bits < 128:
            findings["critical"].append(f"Weak cipher: {cipher_name} ({cipher_bits} bits)")
        elif cipher_bits and cipher_bits < 256:
            findings["warnings"].append(f"Consider upgrading cipher: {cipher_name} ({cipher_bits} bits)")

    # Negotiated protocol
    if cert_info.get("version"):
        findings["negotiated_protocol"] = cert_info["version"]

    # Verification status
    findings["verified"] = cert_info.get("verified", False)
    if not findings["verified"]:
        if cert_info.get("verification_error"):
            findings["critical"].append(f"Certificate verification failed: {cert_info['verification_error']}")
        else:
            findings["critical"].append("Certificate verification failed")

    return findings


def print_report(findings, protocols):
    """Print a human-readable report."""
    print()
    print("=" * 60)
    print(f"  SSL/TLS Report for {findings['hostname']}:{findings['port']}")
    print("=" * 60)
    print()

    # Certificate Details
    print("CERTIFICATE DETAILS")
    print("-" * 40)
    print(f"  Subject CN:     {findings.get('subject_cn', 'N/A')}")
    print(f"  Subject Org:    {findings.get('subject_org', 'N/A')}")
    print(f"  Issuer CN:      {findings.get('issuer_cn', 'N/A')}")
    print(f"  Issuer Org:     {findings.get('issuer_org', 'N/A')}")
    print(f"  Serial Number:  {findings.get('serial_number', 'N/A')}")
    print(f"  Self-Signed:    {'Yes' if findings.get('self_signed') else 'No'}")
    print()

    # Validity
    print("VALIDITY")
    print("-" * 40)
    print(f"  Valid From:     {findings.get('valid_from', 'N/A')}")
    print(f"  Valid Until:    {findings.get('valid_until', 'N/A')}")
    days = findings.get("days_remaining")
    if days is not None:
        if days < 0:
            status = f"EXPIRED ({abs(days)} days ago)"
        elif days <= 30:
            status = f"{days} days (EXPIRING SOON)"
        else:
            status = f"{days} days"
        print(f"  Days Remaining: {status}")
    print()

    # SANs
    print("SUBJECT ALTERNATIVE NAMES")
    print("-" * 40)
    sans = findings.get("sans", [])
    if sans:
        for san in sans[:20]:  # Limit display to 20
            print(f"  {san}")
        if len(sans) > 20:
            print(f"  ... and {len(sans) - 20} more")
    else:
        print("  None")
    print()

    # Connection Details
    print("CONNECTION DETAILS")
    print("-" * 40)
    print(f"  Negotiated Protocol: {findings.get('negotiated_protocol', 'N/A')}")
    print(f"  Cipher:              {findings.get('cipher_name', 'N/A')}")
    print(f"  Cipher Bits:         {findings.get('cipher_bits', 'N/A')}")
    print(f"  Verified:            {'Yes' if findings.get('verified') else 'No'}")
    print()

    # Protocol Support
    print("PROTOCOL SUPPORT")
    print("-" * 40)
    for proto, supported in sorted(protocols.items()):
        marker = "Supported" if supported else "Not supported"
        flag = ""
        if supported and proto in ("TLSv1.0", "TLSv1.1"):
            flag = " [INSECURE - should be disabled]"
        elif supported and proto == "TLSv1.3":
            flag = " [recommended]"
        print(f"  {proto:10s} {marker}{flag}")
    print()

    # Warnings
    if findings["warnings"]:
        print("WARNINGS")
        print("-" * 40)
        for w in findings["warnings"]:
            print(f"  [!] {w}")
        print()

    # Critical Issues
    if findings["critical"]:
        print("CRITICAL ISSUES")
        print("-" * 40)
        for c in findings["critical"]:
            print(f"  [X] {c}")
        print()

    # Add protocol warnings
    if protocols.get("TLSv1.0"):
        print("  [X] TLSv1.0 is enabled (deprecated, insecure)")
    if protocols.get("TLSv1.1"):
        print("  [X] TLSv1.1 is enabled (deprecated, insecure)")
    if not protocols.get("TLSv1.3"):
        print("  [!] TLSv1.3 is not supported (recommended)")

    # Summary
    print()
    if findings["critical"]:
        print("RESULT: CRITICAL ISSUES FOUND")
    elif findings["warnings"]:
        print("RESULT: WARNINGS FOUND")
    else:
        print("RESULT: ALL CHECKS PASSED")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Check SSL/TLS certificate and configuration for a domain.",
        epilog="Part of AllSecurityNews.com",
    )
    parser.add_argument("domain", help="Domain name to check (e.g., example.com)")
    parser.add_argument("--port", type=int, default=443, help="Port number (default: 443)")
    parser.add_argument("--timeout", type=int, default=10, help="Connection timeout in seconds (default: 10)")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output results as JSON")
    parser.add_argument("--no-protocols", action="store_true", help="Skip protocol version checks (faster)")
    args = parser.parse_args()

    # Strip protocol prefix if someone pastes a URL
    hostname = args.domain.replace("https://", "").replace("http://", "").strip("/")

    # Get certificate
    cert_info = get_certificate(hostname, args.port, args.timeout)

    # Analyze
    findings = analyze_cert(hostname, args.port, cert_info)

    # Check protocol support
    if args.no_protocols:
        protocols = {}
    else:
        protocols = check_protocol_support(hostname, args.port, args.timeout)

    # Add protocol issues to findings
    if protocols.get("TLSv1.0"):
        findings["critical"].append("TLSv1.0 is enabled (deprecated, insecure)")
    if protocols.get("TLSv1.1"):
        findings["critical"].append("TLSv1.1 is enabled (deprecated, insecure)")
    if protocols and not protocols.get("TLSv1.3"):
        findings["warnings"].append("TLSv1.3 is not supported (recommended)")

    findings["protocols"] = protocols

    # Output
    if args.json_output:
        print(json.dumps(findings, indent=2, default=str))
    else:
        print_report(findings, protocols)

    # Exit code
    if findings["critical"]:
        sys.exit(2)
    elif findings["warnings"]:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
