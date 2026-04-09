# Threat Hunting 101

A beginner-friendly guide to proactive threat hunting. No expensive tools required. Just logs, a hypothesis, and curiosity.

## What Is Threat Hunting?

Threat hunting is the practice of proactively searching your environment for threats that have evaded existing security controls. Instead of waiting for an alert, you go looking.

The key difference from incident response: you start *before* something triggers an alert. You assume you are compromised and try to prove it.

## The Hunting Loop

Every hunt follows the same basic loop:

1. **Form a hypothesis** - "Attackers may be using PowerShell to download malware"
2. **Collect data** - Gather relevant logs and telemetry
3. **Analyze** - Search for patterns that match the hypothesis
4. **Investigate** - Dig into anything suspicious
5. **Respond or document** - Escalate findings or record that the hypothesis was not confirmed
6. **Refine** - Turn successful hunts into automated detection rules

## Getting Started: What You Need

You do not need a threat hunting platform. You need:

- **Log access**: authentication logs, DNS logs, proxy/firewall logs, endpoint logs
- **A way to search**: grep, awk, jq, Elastic, Splunk, or even Excel
- **MITRE ATT&CK**: The technique reference that tells you what to look for
- **Time**: Even 2 hours a week of hunting is valuable

## Five Starter Hunts

These hunts work with common log sources and catch real threats.

### Hunt 1: Unusual Outbound DNS

**Hypothesis**: An attacker is using DNS for command and control or data exfiltration.

**What to look for**:
- DNS queries to domains with unusually long names (>50 chars)
- High volume of DNS queries to a single domain from one host
- DNS queries to recently registered domains (if you have domain age data)
- TXT record queries (often used for C2 channels)

**Where to look**: DNS server logs, proxy logs, firewall DNS inspection

**Example search** (grep):
```bash
# Find unusually long DNS queries
awk '{print length($1), $1}' dns_queries.log | sort -rn | head -20

# Find hosts making excessive queries to one domain
awk '{print $2, $1}' dns_queries.log | sort | uniq -c | sort -rn | head -20
```

### Hunt 2: Lateral Movement via RDP/SSH

**Hypothesis**: An attacker has compromised one system and is moving laterally using remote access protocols.

**What to look for**:
- RDP or SSH connections between workstations (workstation-to-workstation is rare)
- Connections from servers to workstations (usually goes the other direction)
- Remote access at unusual hours
- A single account authenticating to many systems in a short period

**Where to look**: Windows Event Logs (4624 type 10 for RDP), auth.log for SSH, firewall logs

**Example search** (Windows):
```powershell
# Find RDP logins in the last 24 hours
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4624
    StartTime=(Get-Date).AddDays(-1)
} | Where-Object {
    $_.Properties[8].Value -eq 10
} | Select-Object TimeCreated,
    @{N='User';E={$_.Properties[5].Value}},
    @{N='SourceIP';E={$_.Properties[18].Value}}
```

### Hunt 3: Persistence Mechanisms

**Hypothesis**: An attacker has established persistence on a system that will survive a reboot.

**What to look for**:
- New scheduled tasks or cron jobs created recently
- New services installed
- Modified startup scripts or registry run keys
- New entries in authorized_keys files
- Web shells in web-accessible directories

**Linux**:
```bash
# Recently modified cron jobs
find /etc/cron* /var/spool/cron -mtime -7 -ls 2>/dev/null

# Recently added SSH keys
find /home -name "authorized_keys" -mtime -7 -ls 2>/dev/null
find /root -name "authorized_keys" -mtime -7 -ls 2>/dev/null

# Recently modified systemd services
find /etc/systemd/system -mtime -7 -name "*.service" -ls 2>/dev/null

# Web shells (PHP files in web directories modified recently)
find /var/www -name "*.php" -mtime -7 -ls 2>/dev/null
```

**Windows**:
```powershell
# New scheduled tasks
Get-ScheduledTask | Where-Object {$_.Date -gt (Get-Date).AddDays(-7)}

# New services
Get-WmiObject Win32_Service | Where-Object {
    $_.InstallDate -gt (Get-Date).AddDays(-7).ToString("yyyyMMdd")
}

# Registry run keys
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

### Hunt 4: Data Exfiltration Signs

**Hypothesis**: An attacker is exfiltrating data from the network.

**What to look for**:
- Unusually large outbound transfers (especially to cloud storage, paste sites, or unknown IPs)
- Connections to known file sharing services from servers that should not use them
- Spikes in encrypted traffic volume to external IPs
- Use of archive tools (zip, rar, 7z, tar) on sensitive file shares

**Where to look**: Proxy logs, firewall logs, DLP alerts, endpoint logs

**Example search** (firewall/proxy log):
```bash
# Find large outbound transfers (over 100MB)
awk '$10 > 100000000 {print $1, $3, $7, $10}' proxy_access.log | sort -t' ' -k4 -rn | head -20

# Connections to paste/file sharing sites
grep -iE 'pastebin|mega\.nz|dropbox|sendspace|wetransfer|file\.io' proxy_access.log
```

### Hunt 5: Account Anomalies

**Hypothesis**: An attacker is using compromised credentials.

**What to look for**:
- Accounts logging in from new or unusual locations
- Accounts active outside normal working hours
- Accounts authenticating to systems they have never accessed before
- Multiple failed logins followed by a success (credential stuffing)
- Admin accounts used interactively (these should only be used for administration)

**Where to look**: Authentication logs, VPN logs, cloud identity logs (Azure AD, Okta)

**Example search**:
```bash
# Failed then successful login from same IP
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -10

# Logins outside business hours (assuming UTC, business = 08-18)
grep "Accepted" /var/log/auth.log | awk '{
    split($3,t,":");
    hour=t[1];
    if (hour < 8 || hour > 18) print $0
}'
```

## Building a Hunt Program

If you want to do this regularly:

1. **Start small**: One hunt per week, 1-2 hours each
2. **Use MITRE ATT&CK**: Pick one technique per hunt from the matrix
3. **Document everything**: Even hunts that find nothing are valuable (they prove coverage)
4. **Automate successes**: If a hunt finds something, turn the search into a detection rule
5. **Track metrics**: Number of hunts, findings, rules created, coverage of ATT&CK techniques

## Recommended Reading

- MITRE ATT&CK Matrix: https://attack.mitre.org
- Sqrrl Threat Hunting Framework (archived): search for "sqrrl threat hunting reference"
- SANS Threat Hunting Summit talks (free on YouTube)

---

From [AllSecurityNews.com](https://allsecuritynews.com) - Your hub for cybersecurity intelligence.
