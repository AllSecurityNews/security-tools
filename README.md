# AllSecurityNews Security Hub

Free, open-source security tools and guides from [AllSecurityNews.com](https://allsecuritynews.com).

Practical resources for security professionals. No fluff, no paywalls.

## Tools

Command-line utilities for daily security work. No dependencies beyond Python 3 and bash.

| Tool | Description | Usage |
|------|-------------|-------|
| [IOC Extractor](tools/ioc_extractor.py) | Extract IPs, domains, hashes, URLs, emails, and CVE IDs from any text | `python tools/ioc_extractor.py report.txt` |
| [Security Header Audit](tools/header_audit.sh) | Check HTTP security headers for any domain | `./tools/header_audit.sh example.com` |
| [Log Analyzer](tools/log_analyzer.py) | Flag suspicious patterns in Apache/nginx access logs | `python tools/log_analyzer.py access.log` |
| [CVE Lookup](tools/cve_lookup.py) | Query NVD for CVE details, CVSS scores, and references | `python tools/cve_lookup.py CVE-2024-1234` |

### IOC Extractor

Pull indicators of compromise from threat reports, log files, emails, or any text. Extracts IPv4/IPv6 addresses, domains, URLs, email addresses, MD5/SHA1/SHA256 hashes, and CVE IDs. Filters out internal IPs, common false positives, and low-entropy hex strings.

```bash
python tools/ioc_extractor.py threat_report.pdf.txt
python tools/ioc_extractor.py --json suspicious_email.eml
cat access.log | python tools/ioc_extractor.py -
```

### Security Header Audit

Check any website for security headers in seconds. Reports on HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, and flags information disclosure via Server and X-Powered-By headers.

```bash
./tools/header_audit.sh allsecuritynews.com
./tools/header_audit.sh https://example.com
```

### Log Analyzer

Feed it your web server logs and it flags brute force attempts, SQL injection probes, directory traversal, scanner activity, suspicious HTTP methods, and high-volume IPs. Supports Apache and nginx common log format.

```bash
python tools/log_analyzer.py /var/log/nginx/access.log
python tools/log_analyzer.py --top 20 --json access.log
```

## Guides

Practical how-to guides. Written for people who need to get things done, not study for an exam.

| Guide | Description |
|-------|-------------|
| [Incident Response Checklist](guides/incident-response-checklist.md) | Step-by-step checklist from detection through lessons learned |
| [Linux Server Hardening](guides/linux-server-hardening.md) | Practical hardening guide with commands you can run today |
| [Threat Hunting 101](guides/threat-hunting-101.md) | Getting started with proactive threat hunting using basic tools |

## Resources

| Resource | Description |
|----------|-------------|
| [Security Glossary](SECURITY_GLOSSARY.md) | 200+ cybersecurity terms and acronyms |

## Interactive Tools

We also have browser-based security tools on our site that require no installation:

- [Hash Generator](https://allsecuritynews.com/hub/tools/hash) - SHA-1, SHA-256, SHA-384, SHA-512
- [Encoder/Decoder](https://allsecuritynews.com/hub/tools/encoder) - Base64, URL, Hex, HTML
- [JWT Decoder](https://allsecuritynews.com/hub/tools/jwt) - Decode tokens, check expiry
- [CIDR Calculator](https://allsecuritynews.com/hub/tools/cidr) - Subnet calculations
- [Regex Tester](https://allsecuritynews.com/hub/tools/regex) - Test patterns for SIEM rules
- [IP Analyzer](https://allsecuritynews.com/hub/tools/ip) - Classify and convert IP addresses

Visit [allsecuritynews.com/hub](https://allsecuritynews.com/hub) for the full Security Hub.

## Requirements

- Python 3.7+
- `requests` library (for CVE lookup only)
- bash (for header audit)

```bash
pip install requests
```

## Contributing

We accept pull requests for:
- New tools that solve real security problems
- Improvements to existing tools
- New guides or corrections to existing ones
- Bug fixes

Open an [issue](https://github.com/AllSecurityNews/security-tools/issues) to discuss larger changes before submitting a PR.

## License

MIT License. See [LICENSE](LICENSE) for details.

## About

[AllSecurityNews.com](https://allsecuritynews.com) aggregates security news from 400+ sources with AI-powered threat analysis. Free to use.

## Disclaimer

These tools are for authorized security testing and educational purposes only. Always get written permission before testing systems you do not own.
