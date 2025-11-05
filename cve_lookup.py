#!/usr/bin/env python3
"""
CVE Lookup Tool - Query NIST NVD for CVE details
Part of AllSecurityNews.com open source security tools

Usage: python cve_lookup.py CVE-2024-1234
"""

import sys
import json
import requests
from datetime import datetime

def lookup_cve(cve_id):
    """
    Query NVD API 2.0 for CVE details
    API documentation: https://nvd.nist.gov/developers/vulnerabilities
    """
    # Validate CVE format
    if not cve_id.upper().startswith('CVE-'):
        print(f"Error: Invalid CVE format. Expected format: CVE-YYYY-NNNN")
        return None

    # NVD API 2.0 endpoint
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {'cveId': cve_id.upper()}

    print(f"Querying NVD for {cve_id.upper()}...")

    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        if data.get('totalResults', 0) == 0:
            print(f"No results found for {cve_id}")
            return None

        return data['vulnerabilities'][0]['cve']

    except requests.exceptions.RequestException as e:
        print(f"Error querying NVD API: {e}")
        return None
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        print(f"Error parsing API response: {e}")
        return None

def display_cve_details(cve_data):
    """Display CVE details in a readable format"""

    cve_id = cve_data.get('id', 'Unknown')
    print(f"\n{'='*70}")
    print(f"CVE ID: {cve_id}")
    print(f"{'='*70}\n")

    # Published and modified dates
    published = cve_data.get('published', 'N/A')
    modified = cve_data.get('lastModified', 'N/A')

    if published != 'N/A':
        try:
            pub_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
            print(f"Published: {pub_date.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        except:
            print(f"Published: {published}")

    if modified != 'N/A':
        try:
            mod_date = datetime.fromisoformat(modified.replace('Z', '+00:00'))
            print(f"Modified:  {mod_date.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        except:
            print(f"Modified:  {modified}")

    # Description
    descriptions = cve_data.get('descriptions', [])
    for desc in descriptions:
        if desc.get('lang') == 'en':
            print(f"\nDescription:")
            print(f"{desc.get('value', 'N/A')}")
            break

    # CVSS Metrics
    metrics = cve_data.get('metrics', {})

    # CVSS v3.x
    cvss_v3_data = metrics.get('cvssMetricV31', []) or metrics.get('cvssMetricV30', [])
    if cvss_v3_data:
        cvss = cvss_v3_data[0].get('cvssData', {})
        print(f"\nCVSS v3.x Score: {cvss.get('baseScore', 'N/A')} ({cvss.get('baseSeverity', 'N/A')})")
        print(f"  Vector: {cvss.get('vectorString', 'N/A')}")
        print(f"  Attack Vector: {cvss.get('attackVector', 'N/A')}")
        print(f"  Attack Complexity: {cvss.get('attackComplexity', 'N/A')}")
        print(f"  Privileges Required: {cvss.get('privilegesRequired', 'N/A')}")
        print(f"  User Interaction: {cvss.get('userInteraction', 'N/A')}")
        print(f"  Scope: {cvss.get('scope', 'N/A')}")
        print(f"  Confidentiality Impact: {cvss.get('confidentialityImpact', 'N/A')}")
        print(f"  Integrity Impact: {cvss.get('integrityImpact', 'N/A')}")
        print(f"  Availability Impact: {cvss.get('availabilityImpact', 'N/A')}")

    # CVSS v2
    cvss_v2_data = metrics.get('cvssMetricV2', [])
    if cvss_v2_data:
        cvss = cvss_v2_data[0].get('cvssData', {})
        print(f"\nCVSS v2.0 Score: {cvss.get('baseScore', 'N/A')}")
        print(f"  Vector: {cvss.get('vectorString', 'N/A')}")

    # CWE (Weakness)
    weaknesses = cve_data.get('weaknesses', [])
    if weaknesses:
        print(f"\nCWE (Common Weakness Enumeration):")
        for weakness in weaknesses:
            for desc in weakness.get('description', []):
                if desc.get('lang') == 'en':
                    print(f"  - {desc.get('value', 'N/A')}")

    # References
    references = cve_data.get('references', [])
    if references:
        print(f"\nReferences ({len(references)}):")
        for i, ref in enumerate(references[:5], 1):  # Show first 5
            print(f"  {i}. {ref.get('url', 'N/A')}")
            tags = ref.get('tags', [])
            if tags:
                print(f"     Tags: {', '.join(tags)}")

        if len(references) > 5:
            print(f"  ... and {len(references) - 5} more")

    # Configurations (affected products)
    configurations = cve_data.get('configurations', [])
    if configurations:
        print(f"\nAffected Products:")
        node_count = 0
        for config in configurations:
            for node in config.get('nodes', []):
                cpe_matches = node.get('cpeMatch', [])
                for cpe in cpe_matches[:3]:  # Show first 3
                    if cpe.get('vulnerable'):
                        cpe_name = cpe.get('criteria', 'N/A')
                        print(f"  - {cpe_name}")
                        node_count += 1
                        if node_count >= 5:
                            break
                if node_count >= 5:
                    break
            if node_count >= 5:
                print(f"  ... and more")
                break

    print(f"\n{'='*70}\n")

def main():
    if len(sys.argv) != 2:
        print("Usage: python cve_lookup.py CVE-YYYY-NNNN")
        print("Example: python cve_lookup.py CVE-2024-1234")
        sys.exit(1)

    cve_id = sys.argv[1]
    cve_data = lookup_cve(cve_id)

    if cve_data:
        display_cve_details(cve_data)
        print(f"For more details, visit: https://nvd.nist.gov/vuln/detail/{cve_id.upper()}")
    else:
        sys.exit(1)

if __name__ == '__main__':
    main()
