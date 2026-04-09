#!/usr/bin/env python3
"""
DNS Record Enumerator

Part of AllSecurityNews.com

Enumerates DNS records for a domain and checks email security configuration.

Queries: A, AAAA, MX, TXT, NS, SOA, CNAME
Checks: SPF, DKIM, DMARC records with security assessment

Uses only Python stdlib (subprocess calling dig/nslookup). No dnspython required.

Usage:
  python dns_enum.py example.com
  python dns_enum.py example.com --json
  python dns_enum.py example.com --dkim-selector google
  python dns_enum.py example.com --dkim-selector default --dkim-selector k1

Exit codes:
  0 = All checks passed
  1 = Missing email security records (SPF/DMARC)
"""

import argparse
import json
import re
import shutil
import subprocess
import sys


def find_dns_tool():
    """Find an available DNS query tool (dig preferred, nslookup as fallback)."""
    if shutil.which("dig"):
        return "dig"
    if shutil.which("nslookup"):
        return "nslookup"
    print("ERROR: Neither 'dig' nor 'nslookup' found in PATH.", file=sys.stderr)
    print("Install dig (part of bind-utils or dnsutils package) or ensure nslookup is available.", file=sys.stderr)
    sys.exit(2)


def query_dig(domain, record_type, timeout=5):
    """Query DNS records using dig."""
    try:
        result = subprocess.run(
            ["dig", "+short", "+time=" + str(timeout), "+tries=2", domain, record_type],
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
        output = result.stdout.strip()
        if not output:
            return []
        # Split by newlines and clean up
        records = [line.strip() for line in output.split("\n") if line.strip()]
        return records
    except subprocess.TimeoutExpired:
        return [f"ERROR: Query timed out for {record_type}"]
    except FileNotFoundError:
        return [f"ERROR: dig not found"]


def query_nslookup(domain, record_type, timeout=5):
    """Query DNS records using nslookup."""
    try:
        result = subprocess.run(
            ["nslookup", f"-type={record_type}", domain],
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
        output = result.stdout

        records = []
        # Parse nslookup output based on record type
        if record_type == "A":
            for line in output.split("\n"):
                if "Address:" in line and not line.strip().startswith("Server:"):
                    # Skip the server address line (usually the second "Address:" line is the answer)
                    addr = line.split("Address:")[-1].strip().split("#")[0].strip()
                    if addr and not addr.startswith("127.") and addr != "":
                        records.append(addr)
            # Sometimes nslookup puts the answer differently
            for line in output.split("\n"):
                match = re.search(r"address\s*=?\s*([\d.]+)", line, re.IGNORECASE)
                if match:
                    addr = match.group(1)
                    if addr not in records:
                        records.append(addr)

        elif record_type == "AAAA":
            for line in output.split("\n"):
                match = re.search(r"address\s*=?\s*([0-9a-fA-F:]+)", line, re.IGNORECASE)
                if match:
                    records.append(match.group(1))

        elif record_type == "MX":
            for line in output.split("\n"):
                match = re.search(r"mail exchanger\s*=\s*(\d+\s+\S+)", line, re.IGNORECASE)
                if match:
                    records.append(match.group(1).strip().rstrip("."))

        elif record_type == "TXT":
            for line in output.split("\n"):
                match = re.search(r'text\s*=\s*"(.+)"', line, re.IGNORECASE)
                if match:
                    records.append(match.group(1))

        elif record_type == "NS":
            for line in output.split("\n"):
                match = re.search(r"nameserver\s*=\s*(\S+)", line, re.IGNORECASE)
                if match:
                    records.append(match.group(1).rstrip("."))

        elif record_type == "SOA":
            for line in output.split("\n"):
                if "origin" in line.lower() or "serial" in line.lower() or "primary" in line.lower():
                    records.append(line.strip())

        elif record_type == "CNAME":
            for line in output.split("\n"):
                match = re.search(r"canonical name\s*=\s*(\S+)", line, re.IGNORECASE)
                if match:
                    records.append(match.group(1).rstrip("."))

        return records
    except subprocess.TimeoutExpired:
        return [f"ERROR: Query timed out for {record_type}"]
    except FileNotFoundError:
        return [f"ERROR: nslookup not found"]


def query_dns(domain, record_type, tool, timeout=5):
    """Query DNS records using the available tool."""
    if tool == "dig":
        return query_dig(domain, record_type, timeout)
    else:
        return query_nslookup(domain, record_type, timeout)


def enumerate_records(domain, tool, timeout=5):
    """Enumerate all standard DNS record types for a domain."""
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"]
    results = {}

    for rtype in record_types:
        records = query_dns(domain, rtype, tool, timeout)
        results[rtype] = records

    return results


def check_spf(txt_records):
    """Check for SPF record and assess its strength."""
    spf_records = [r for r in txt_records if r.startswith("v=spf1")]

    result = {
        "found": len(spf_records) > 0,
        "records": spf_records,
        "warnings": [],
    }

    if not spf_records:
        result["warnings"].append("No SPF record found. Email spoofing is possible.")
        return result

    if len(spf_records) > 1:
        result["warnings"].append(f"Multiple SPF records found ({len(spf_records)}). Only one is allowed per RFC 7208. This can cause delivery issues.")

    for spf in spf_records:
        # Check for overly permissive SPF
        if "+all" in spf:
            result["warnings"].append("SPF uses '+all' which allows any server to send email. This defeats the purpose of SPF.")
        elif "?all" in spf:
            result["warnings"].append("SPF uses '?all' (neutral). Consider using '~all' (softfail) or '-all' (hardfail) for better protection.")
        elif "~all" in spf:
            result["warnings"].append("SPF uses '~all' (softfail). Consider '-all' (hardfail) for stricter enforcement once you have confirmed all legitimate senders.")

        # Check for too many DNS lookups (limit is 10)
        lookup_mechanisms = re.findall(r'\b(include:|a:|mx:|ptr:|redirect=)', spf)
        if len(lookup_mechanisms) > 8:
            result["warnings"].append(f"SPF record has {len(lookup_mechanisms)} lookup mechanisms. The limit is 10. Close to exceeding the limit.")

    return result


def check_dmarc(domain, tool, timeout=5):
    """Check for DMARC record and assess its policy."""
    dmarc_domain = f"_dmarc.{domain}"
    records = query_dns(dmarc_domain, "TXT", tool, timeout)
    dmarc_records = [r for r in records if r.startswith("v=DMARC1")]

    result = {
        "found": len(dmarc_records) > 0,
        "records": dmarc_records,
        "warnings": [],
    }

    if not dmarc_records:
        result["warnings"].append("No DMARC record found. Email spoofing protection is incomplete without DMARC.")
        return result

    for dmarc in dmarc_records:
        # Parse policy
        policy_match = re.search(r'p\s*=\s*(\w+)', dmarc)
        if policy_match:
            policy = policy_match.group(1).lower()
            result["policy"] = policy
            if policy == "none":
                result["warnings"].append("DMARC policy is 'none' (monitoring only). No emails will be rejected. Consider 'quarantine' or 'reject' after monitoring.")
            elif policy == "quarantine":
                result["warnings"].append("DMARC policy is 'quarantine'. Failing emails go to spam. Consider upgrading to 'reject' once confident.")
            # 'reject' is the strongest setting

        # Check for reporting
        if "rua=" not in dmarc:
            result["warnings"].append("DMARC record has no aggregate report URI (rua=). You will not receive reports on email authentication results.")

        # Check subdomain policy
        sp_match = re.search(r'sp\s*=\s*(\w+)', dmarc)
        if sp_match:
            result["subdomain_policy"] = sp_match.group(1).lower()
        else:
            result["warnings"].append("No subdomain policy (sp=) set. Subdomains inherit the main policy. Consider setting sp=reject if subdomains do not send email.")

        # Check percentage
        pct_match = re.search(r'pct\s*=\s*(\d+)', dmarc)
        if pct_match:
            pct = int(pct_match.group(1))
            result["percentage"] = pct
            if pct < 100:
                result["warnings"].append(f"DMARC percentage is {pct}%. Only {pct}% of failing emails are subject to the policy. Set pct=100 for full enforcement.")

    return result


def check_dkim(domain, selectors, tool, timeout=5):
    """Check for DKIM records with given selectors."""
    if not selectors:
        # Try common selectors
        selectors = ["default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim", "s1", "s2"]

    result = {
        "found": False,
        "selectors_checked": selectors,
        "records": {},
        "warnings": [],
    }

    for selector in selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        records = query_dns(dkim_domain, "TXT", tool, timeout)
        # Filter for DKIM records
        dkim_records = [r for r in records if "DKIM" in r.upper() or "v=DKIM1" in r or "p=" in r]
        if dkim_records:
            result["found"] = True
            result["records"][selector] = dkim_records

    if not result["found"]:
        result["warnings"].append(
            f"No DKIM records found for selectors: {', '.join(selectors)}. "
            "DKIM may be configured with a different selector. Use --dkim-selector to specify."
        )

    return result


def print_report(domain, records, spf_result, dmarc_result, dkim_result):
    """Print a human-readable report."""
    print()
    print("=" * 60)
    print(f"  DNS Enumeration Report for {domain}")
    print("=" * 60)
    print()

    # Standard records
    for rtype in ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]:
        recs = records.get(rtype, [])
        print(f"{rtype} RECORDS ({len(recs)})")
        print("-" * 40)
        if recs:
            for r in recs:
                print(f"  {r}")
        else:
            print("  (none)")
        print()

    # Email Security
    print("=" * 60)
    print("  EMAIL SECURITY ASSESSMENT")
    print("=" * 60)
    print()

    # SPF
    print("SPF (Sender Policy Framework)")
    print("-" * 40)
    if spf_result["found"]:
        print(f"  Status: Found")
        for r in spf_result["records"]:
            print(f"  Record: {r}")
    else:
        print(f"  Status: NOT FOUND")
    for w in spf_result["warnings"]:
        print(f"  [!] {w}")
    print()

    # DMARC
    print("DMARC (Domain-based Message Authentication)")
    print("-" * 40)
    if dmarc_result["found"]:
        print(f"  Status: Found")
        for r in dmarc_result["records"]:
            print(f"  Record: {r}")
        if "policy" in dmarc_result:
            print(f"  Policy: {dmarc_result['policy']}")
        if "subdomain_policy" in dmarc_result:
            print(f"  Subdomain Policy: {dmarc_result['subdomain_policy']}")
        if "percentage" in dmarc_result:
            print(f"  Percentage: {dmarc_result['percentage']}%")
    else:
        print(f"  Status: NOT FOUND")
    for w in dmarc_result["warnings"]:
        print(f"  [!] {w}")
    print()

    # DKIM
    print("DKIM (DomainKeys Identified Mail)")
    print("-" * 40)
    if dkim_result["found"]:
        print(f"  Status: Found")
        for selector, recs in dkim_result["records"].items():
            print(f"  Selector: {selector}")
            for r in recs:
                # Truncate long DKIM records for display
                display = r if len(r) <= 80 else r[:77] + "..."
                print(f"    {display}")
    else:
        print(f"  Status: Not found (checked: {', '.join(dkim_result['selectors_checked'])})")
    for w in dkim_result["warnings"]:
        print(f"  [!] {w}")
    print()

    # Summary
    print("=" * 60)
    print("  SUMMARY")
    print("=" * 60)

    issues = []
    if not spf_result["found"]:
        issues.append("Missing SPF record")
    if not dmarc_result["found"]:
        issues.append("Missing DMARC record")
    if not dkim_result["found"]:
        issues.append("No DKIM records found (may use non-standard selector)")
    if spf_result["warnings"]:
        issues.extend([f"SPF: {w}" for w in spf_result["warnings"] if "No SPF" not in w])
    if dmarc_result["warnings"]:
        issues.extend([f"DMARC: {w}" for w in dmarc_result["warnings"] if "No DMARC" not in w])

    print()
    if issues:
        print(f"  {len(issues)} issue(s) found:")
        for issue in issues:
            print(f"    [!] {issue}")
    else:
        print("  No issues found. SPF, DMARC, and DKIM are all configured.")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Enumerate DNS records and check email security for a domain.",
        epilog="Part of AllSecurityNews.com",
    )
    parser.add_argument("domain", help="Domain name to enumerate (e.g., example.com)")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output results as JSON")
    parser.add_argument("--timeout", type=int, default=5, help="DNS query timeout in seconds (default: 5)")
    parser.add_argument(
        "--dkim-selector",
        action="append",
        dest="dkim_selectors",
        metavar="SELECTOR",
        help="DKIM selector to check (can be specified multiple times). Default: checks common selectors.",
    )
    parser.add_argument("--no-dkim", action="store_true", help="Skip DKIM checks")
    args = parser.parse_args()

    # Strip protocol prefix if someone pastes a URL
    domain = args.domain.replace("https://", "").replace("http://", "").strip("/").split("/")[0]

    # Find DNS tool
    tool = find_dns_tool()

    # Enumerate standard records
    records = enumerate_records(domain, tool, args.timeout)

    # Check email security
    spf_result = check_spf(records.get("TXT", []))
    dmarc_result = check_dmarc(domain, tool, args.timeout)

    if args.no_dkim:
        dkim_result = {"found": False, "selectors_checked": [], "records": {}, "warnings": ["DKIM check skipped"]}
    else:
        dkim_result = check_dkim(domain, args.dkim_selectors, tool, args.timeout)

    # Output
    if args.json_output:
        output = {
            "domain": domain,
            "dns_tool": tool,
            "records": records,
            "email_security": {
                "spf": spf_result,
                "dmarc": dmarc_result,
                "dkim": dkim_result,
            },
            "issues": [],
        }
        if not spf_result["found"]:
            output["issues"].append("Missing SPF record")
        if not dmarc_result["found"]:
            output["issues"].append("Missing DMARC record")
        if not dkim_result["found"]:
            output["issues"].append("No DKIM records found")
        output["issues"].extend(spf_result["warnings"])
        output["issues"].extend(dmarc_result["warnings"])
        output["issues"].extend(dkim_result["warnings"])

        print(json.dumps(output, indent=2, default=str))
    else:
        print_report(domain, records, spf_result, dmarc_result, dkim_result)

    # Exit code
    has_critical_missing = not spf_result["found"] or not dmarc_result["found"]
    if has_critical_missing:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
