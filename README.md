# AllSecurityNews Security Hub

Free, open-source security tools and guides from [AllSecurityNews.com](https://allsecuritynews.com).

Practical resources for security professionals. No fluff, no paywalls.

## Tools

Command-line utilities you can use today. Python 3 and bash, no other dependencies.

| Tool | Description | Usage |
|------|-------------|-------|
| [IOC Extractor](tools/ioc_extractor.py) | Extract IPs, domains, hashes, URLs, emails, and CVE IDs from any text | `python tools/ioc_extractor.py report.txt` |
| [Secrets Scanner](tools/secrets_scanner.py) | Find leaked API keys, tokens, and credentials in files and repos | `python tools/secrets_scanner.py /path/to/project` |
| [Security Header Audit](tools/header_audit.sh) | Check HTTP security headers for any domain | `./tools/header_audit.sh example.com` |
| [Log Analyzer](tools/log_analyzer.py) | Flag brute force, SQLi, scanners, and traversal in web server logs | `python tools/log_analyzer.py access.log` |
| [CVE Lookup](tools/cve_lookup.py) | Query NVD for CVE details, CVSS scores, and affected products | `python tools/cve_lookup.py CVE-2024-1234` |
| [SSL/TLS Checker](tools/ssl_checker.py) | Check cert expiry, key strength, protocol, and misconfigs | `python tools/ssl_checker.py example.com` |
| [DNS Enumeration](tools/dns_enum.py) | Enumerate DNS records and check SPF/DKIM/DMARC | `python tools/dns_enum.py example.com` |

### IOC Extractor

Pull indicators of compromise from threat reports, log files, emails, or any text. Extracts IPv4/IPv6 addresses, domains, URLs, email addresses, MD5/SHA1/SHA256 hashes, and CVE IDs. Filters out internal IPs, common false positives, and low-entropy strings. Supports JSON output for piping into other tools.

```bash
python tools/ioc_extractor.py threat_report.txt
python tools/ioc_extractor.py --json suspicious_email.eml
cat access.log | python tools/ioc_extractor.py -
```

### Secrets Scanner

Scan files and directories for accidentally committed secrets. Detects AWS keys, GCP service accounts, Azure connection strings, Stripe keys, GitHub tokens, Slack tokens, private keys, database connection strings, and generic API keys. Skips binary files and dependency directories automatically. Use it as a pre-commit check or CI/CD gate.

```bash
python tools/secrets_scanner.py src/
python tools/secrets_scanner.py --json .
python tools/secrets_scanner.py config.py .env docker-compose.yml
```

Exit codes: 0 = clean, 1 = findings, 2 = critical findings.

### Security Header Audit

Check any website for security-critical HTTP headers. Color-coded pass/fail output for HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and Permissions-Policy. Also flags information disclosure via Server and X-Powered-By headers.

```bash
./tools/header_audit.sh allsecuritynews.com
./tools/header_audit.sh https://example.com
```

### Log Analyzer

Feed it your web server access logs and it flags suspicious activity: brute force attempts (repeated 401s), SQL injection probes, directory traversal, XSS attempts, known scanner user agents, unusual HTTP methods, and high-volume IPs. Supports Apache and nginx common log format.

```bash
python tools/log_analyzer.py /var/log/nginx/access.log
python tools/log_analyzer.py --top 20 --json access.log
zcat /var/log/nginx/access.log.*.gz | python tools/log_analyzer.py -
```

## Guides

Practical how-to guides written for people who need to get things done.

| Guide | What it covers |
|-------|----------------|
| [Incident Response Checklist](guides/incident-response-checklist.md) | Full IR checklist: detection, containment, investigation, eradication, recovery, lessons learned |
| [Linux Server Hardening](guides/linux-server-hardening.md) | SSH lockdown, firewall, auto-updates, fail2ban, kernel hardening, audit commands |
| [Threat Hunting 101](guides/threat-hunting-101.md) | 5 starter hunts with real commands: DNS, lateral movement, persistence, exfil, account anomalies |
| [Defending Against AI Phishing](guides/defending-against-ai-phishing.md) | AI-generated phishing, voice deepfakes, DMARC hardening, MFA bypass defenses, helpdesk protection |
| [Kubernetes Security Hardening](guides/kubernetes-security-hardening.md) | RBAC, Pod Security Standards, network policies, secrets, image security, audit logging |
| [Securing LLM Applications](guides/securing-llm-applications.md) | Prompt injection, RAG security, tool use controls, data leakage prevention, deployment checklist |
| [Cloud IAM Least Privilege](guides/cloud-iam-least-privilege.md) | AWS/Azure/GCP IAM auditing, finding overprivileged identities, managed identities, key rotation |
| [Supply Chain Security](guides/supply-chain-security.md) | SBOMs, SLSA provenance, dependency scanning, artifact signing, lock file strategies |
| [Ransomware Resilience](guides/ransomware-resilience.md) | Immutable backups, network segmentation, ESXi hardening, recovery playbooks |
| [Securing CI/CD Pipelines](guides/securing-cicd-pipelines.md) | GitHub Actions hardening, OIDC, secrets management, artifact signing, common attacks |
| [API Security Testing](guides/api-security-testing.md) | BOLA testing, auth bypass, rate limits, SSRF, API discovery, OWASP API Top 10 |
| [Detection Engineering](guides/detection-engineering.md) | Writing Sigma rules, Atomic Red Team testing, detection-as-code, ATT&CK coverage |

## Resources

| Resource | Description |
|----------|-------------|
| [Security Glossary](SECURITY_GLOSSARY.md) | 200+ cybersecurity terms and acronyms |

## Interactive Tools

Browser-based security tools on our site (no installation needed):

- [Hash Generator](https://allsecuritynews.com/hub/tools/hash) - SHA-1/256/384/512
- [Encoder/Decoder](https://allsecuritynews.com/hub/tools/encoder) - Base64, URL, Hex, HTML
- [JWT Decoder](https://allsecuritynews.com/hub/tools/jwt) - Decode tokens, check expiry
- [CIDR Calculator](https://allsecuritynews.com/hub/tools/cidr) - Subnet calculations
- [Regex Tester](https://allsecuritynews.com/hub/tools/regex) - Test patterns for SIEM rules
- [IP Analyzer](https://allsecuritynews.com/hub/tools/ip) - Classify and convert IP addresses
- [Timestamp Converter](https://allsecuritynews.com/hub/tools/timestamp) - Unix epoch conversion
- [User Agent Parser](https://allsecuritynews.com/hub/tools/useragent) - Identify browsers, bots, devices
- [Security Headers](https://allsecuritynews.com/hub/tools/headers) - Check HTTP security headers
- [Text Diff](https://allsecuritynews.com/hub/tools/diff) - Compare configs and baselines

Browse the [Security Glossary](https://allsecuritynews.com/hub/glossary) with 150+ searchable terms.

Visit [allsecuritynews.com/hub](https://allsecuritynews.com/hub) for the full Security Hub.

## Requirements

- Python 3.7+
- `requests` library (for CVE lookup only)
- bash (for header audit)

```bash
pip install requests
```

## Contributing

Pull requests welcome for:
- New tools that solve real problems
- New guides on current security topics
- Improvements or corrections to existing content
- Bug fixes

Open an [issue](https://github.com/AllSecurityNews/security-tools/issues) for larger changes.

## License

MIT License. See [LICENSE](LICENSE).

## About

[AllSecurityNews.com](https://allsecuritynews.com) aggregates security news from 400+ sources with AI-powered threat analysis. Free to use.

## Disclaimer

These tools are for authorized security testing and educational purposes only. Get written permission before testing systems you do not own.
