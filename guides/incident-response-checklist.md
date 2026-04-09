# Incident Response Checklist

A practical, step-by-step checklist for responding to a security incident. Designed for small to mid-size teams that may not have a dedicated SOC.

## Before an Incident

- [ ] Identify your critical assets and data
- [ ] Document your network topology and data flows
- [ ] Establish an incident response team with clear roles
- [ ] Set up out-of-band communication (Signal group, dedicated phone bridge)
- [ ] Prepare a contact list: legal counsel, insurance, law enforcement, PR
- [ ] Ensure logging is enabled on all critical systems
- [ ] Test your backup restoration process
- [ ] Have clean OS images ready for reimaging compromised systems

## Phase 1: Detection and Triage

When you suspect an incident:

- [ ] Record the date, time, and how the incident was detected
- [ ] Assign an incident lead who will coordinate the response
- [ ] Open a dedicated incident channel for communications
- [ ] Determine the scope: what systems, data, and users are affected?
- [ ] Classify the severity:
  - **Critical**: Active data exfiltration, ransomware spreading, business operations halted
  - **High**: Confirmed compromise, attacker has access but not yet spreading
  - **Medium**: Suspicious activity, possible compromise, needs investigation
  - **Low**: Phishing attempt blocked, scanner activity, no confirmed impact
- [ ] Notify management based on severity (Critical/High = immediate)
- [ ] Start a written timeline log of all actions taken

## Phase 2: Containment

Stop the bleeding without destroying evidence:

**Short-term containment (first hour):**
- [ ] Isolate affected systems from the network (disable switch port, VLAN change, or pull cable)
- [ ] Do NOT power off systems yet (volatile memory contains evidence)
- [ ] Block known malicious IPs and domains at the firewall
- [ ] Disable compromised user accounts
- [ ] Change credentials for service accounts on affected systems
- [ ] If ransomware: disconnect file shares immediately

**Long-term containment (first day):**
- [ ] Set up a clean VLAN for investigation work
- [ ] Capture memory dumps from affected systems before any changes
- [ ] Capture disk images of affected systems
- [ ] Review and preserve relevant logs (firewall, proxy, DNS, auth, endpoint)
- [ ] Check for lateral movement to other systems
- [ ] Monitor for attacker re-entry attempts

## Phase 3: Investigation

Understand what happened:

- [ ] Build a timeline of the attack using log data
- [ ] Identify the initial entry point (phishing email, exposed service, compromised credential)
- [ ] Determine what the attacker accessed and for how long
- [ ] Identify all compromised accounts and systems
- [ ] Check for persistence mechanisms:
  - Scheduled tasks / cron jobs
  - New user accounts
  - Modified startup scripts
  - Web shells
  - Registry run keys (Windows)
  - SSH authorized_keys modifications
- [ ] Collect and document indicators of compromise (IOCs):
  - IP addresses
  - Domain names
  - File hashes
  - Email addresses
  - Malware samples

## Phase 4: Eradication

Remove the attacker's access:

- [ ] Remove all identified malware and backdoors
- [ ] Close the initial entry point (patch the vulnerability, remove the phishing infrastructure)
- [ ] Remove unauthorized accounts and SSH keys
- [ ] Reset all credentials on compromised systems (local and domain)
- [ ] Rebuild compromised systems from clean images if possible
- [ ] Update firewall rules and block all identified IOCs
- [ ] Verify no persistence mechanisms remain
- [ ] Scan all systems with updated antivirus/EDR signatures

## Phase 5: Recovery

Restore normal operations:

- [ ] Restore systems from clean backups (verify backup integrity first)
- [ ] Bring systems back online one at a time, monitoring for reinfection
- [ ] Verify that business processes are functioning correctly
- [ ] Enable enhanced monitoring on recovered systems for 30+ days
- [ ] Communicate status to stakeholders and affected users
- [ ] If customer data was compromised: begin breach notification process

## Phase 6: Lessons Learned

Improve for next time:

- [ ] Hold a post-incident review within 1-2 weeks
- [ ] Document the complete timeline with all findings
- [ ] Identify what worked well and what needs improvement
- [ ] Update IR procedures based on what was learned
- [ ] Address the root cause (not just symptoms)
- [ ] Share sanitized IOCs with the security community (ISACs, threat intel feeds)
- [ ] Update detection rules based on observed TTPs
- [ ] Schedule follow-up checks at 30 and 90 days

## Quick Reference: Evidence Collection Priority

Collect in this order (most volatile first):

1. **Memory** - RAM contents, running processes, network connections
2. **Network state** - Active connections, ARP cache, routing tables
3. **Running processes** - Process list, open files, loaded modules
4. **Disk** - File system, logs, registry, temporary files
5. **External logs** - Firewall, proxy, DNS, email gateway, cloud audit logs

## Quick Reference: Communication Template

Use this when notifying leadership:

```
INCIDENT NOTIFICATION

Severity: [Critical/High/Medium/Low]
Detected: [Date/Time]
Affected: [Systems/Users/Data]

What we know:
- [Brief description]

What we're doing:
- [Current containment actions]

What we need:
- [Resources, decisions, approvals]

Next update: [Time]
```

---

From [AllSecurityNews.com](https://allsecuritynews.com) - Your hub for cybersecurity intelligence.
