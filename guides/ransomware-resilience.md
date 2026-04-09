# Ransomware Resilience

A practical guide to preparing for, containing, and recovering from ransomware attacks. This covers backup architecture, network segmentation, hypervisor hardening, detection, recovery playbooks, and tabletop exercises.

---

## Table of Contents

1. [Immutable Backup Architecture](#immutable-backup-architecture)
2. [Network Segmentation for Containment](#network-segmentation-for-containment)
3. [ESXi and Hypervisor Hardening](#esxi-and-hypervisor-hardening)
4. [Endpoint Detection and Response Basics](#endpoint-detection-and-response-basics)
5. [Recovery Playbook](#recovery-playbook)
6. [Tabletop Exercise Template](#tabletop-exercise-template)
7. [Backup Verification Commands](#backup-verification-commands)

---

## Immutable Backup Architecture

Ransomware operators know that backups are the one thing standing between them and a payout. Modern ransomware actively hunts for backup infrastructure. Your backup system must be designed to survive a total domain compromise.

### The 3-2-1-1 Rule

| Component | What It Means |
|-----------|--------------|
| **3** copies | Three copies of your data (production + two backups) |
| **2** media types | Store backups on at least two different media (disk + tape, disk + cloud) |
| **1** offsite | At least one copy physically offsite or in a different cloud region |
| **1** immutable/offline | At least one copy that cannot be modified or deleted, even by an admin with root |

### Making Backups Immutable

**AWS S3 Object Lock:**

```bash
# Create a bucket with object lock enabled
aws s3api create-bucket \
  --bucket mycompany-immutable-backups \
  --region us-east-1 \
  --object-lock-enabled-for-bucket

# Set a default retention policy (governance mode allows override with special permission)
aws s3api put-object-lock-configuration \
  --bucket mycompany-immutable-backups \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "COMPLIANCE",
        "Days": 30
      }
    }
  }'

# Upload a backup with compliance-mode retention (nobody can delete it for 30 days)
aws s3api put-object \
  --bucket mycompany-immutable-backups \
  --key backups/2025-12-01/full-backup.tar.gz.enc \
  --body full-backup.tar.gz.enc \
  --object-lock-mode COMPLIANCE \
  --object-lock-retain-until-date "2026-01-01T00:00:00Z"
```

> Compliance mode means even the root AWS account cannot delete the object before the retention date. Governance mode allows deletion with `s3:BypassGovernanceRetention` permission. Use compliance mode for ransomware protection.

**Azure Immutable Blob Storage:**

```bash
# Set immutability policy on a container
az storage container immutability-policy create \
  --resource-group mygroup \
  --account-name mystorageaccount \
  --container-name backups \
  --period 30

# Lock the policy (irreversible)
az storage container immutability-policy lock \
  --resource-group mygroup \
  --account-name mystorageaccount \
  --container-name backups
```

**Linux filesystem-level immutability (local backups):**

```bash
# Make a backup file immutable on ext4/xfs
chattr +i /backups/2025-12-01/full-backup.tar.gz.enc

# Verify
lsattr /backups/2025-12-01/full-backup.tar.gz.enc
# Output: ----i----------- /backups/2025-12-01/full-backup.tar.gz.enc

# Remove immutable flag (requires root, ransomware with root could do this)
chattr -i /backups/2025-12-01/full-backup.tar.gz.enc
```

> `chattr +i` is useful but not ransomware-proof on its own. A root-level attacker can remove the flag. Use it as one layer, not the only layer.

### Air-Gapped Backup Strategy

For the highest assurance:

1. Use a dedicated backup server on a separate network segment.
2. Allow only inbound backup traffic (backup client pushes to server). No outbound access.
3. Use a separate authentication domain (not joined to Active Directory).
4. Pull backups to an offline tape/disk weekly.
5. Test restores monthly.

### Backup Encryption

Always encrypt backups at rest. If an attacker exfiltrates your backup, they should get ciphertext.

```bash
# Encrypt a backup with GPG (symmetric)
gpg --symmetric --cipher-algo AES256 --output backup.tar.gz.gpg backup.tar.gz

# Encrypt with OpenSSL
openssl enc -aes-256-cbc -salt -pbkdf2 -in backup.tar.gz -out backup.tar.gz.enc

# Store the encryption key separately from the backup (offline, in a safe, etc.)
```

---

## Network Segmentation for Containment

Flat networks are a ransomware operator's best friend. Once they compromise one host, they move laterally to everything. Segmentation limits blast radius.

### Segmentation Tiers

| Zone | Contains | Access Rules |
|------|---------|-------------|
| **DMZ** | Web servers, reverse proxies | Internet-facing. No direct DB access. |
| **Application** | App servers, APIs | Talks to DB zone on specific ports only. |
| **Database** | Database servers | No internet access. Accepts connections only from app zone. |
| **Management** | Jump boxes, monitoring, backup | Isolated. Accessed via VPN or bastion only. |
| **User** | Workstations | Cannot reach server zones directly. Goes through proxies/load balancers. |
| **OT/IoT** | Industrial systems, cameras | Air-gapped or heavily firewalled. |

### Implementation with iptables/nftables

```bash
# Example: Database server allows MySQL only from app subnet
iptables -A INPUT -s 10.10.20.0/24 -p tcp --dport 3306 -j ACCEPT
iptables -A INPUT -p tcp --dport 3306 -j DROP

# Block SMB between user segments (SMB is a primary lateral movement vector)
iptables -A FORWARD -s 10.10.10.0/24 -d 10.10.10.0/24 -p tcp --dport 445 -j DROP
iptables -A FORWARD -s 10.10.10.0/24 -d 10.10.10.0/24 -p tcp --dport 139 -j DROP
```

### VLANs Are Not Enough

VLANs separate broadcast domains but do nothing to restrict traffic between VLANs unless you add ACLs on the switch or firewall. Always pair VLANs with firewall rules.

### Quick Wins for Lateral Movement Prevention

```bash
# Disable SMBv1 on Windows (PowerShell)
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Disable unnecessary RDP
# Group Policy: Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services
# Or via registry:
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f

# Block LLMNR and NetBIOS (used for credential theft)
# Group Policy: Computer Configuration > Administrative Templates > Network > DNS Client
# Turn off multicast name resolution: Enabled
```

---

## ESXi and Hypervisor Hardening

Ransomware groups (Royal, Black Basta, LockBit, ESXiArgs) now routinely target VMware ESXi. Encrypting the hypervisor takes down every VM at once.

### ESXi Lockdown Checklist

```bash
# 1. Enable lockdown mode (restricts management to vCenter only)
vim-cmd hostsvc/advopt/update UserVars.ESXiShellInteractiveTimeOut long 900
vim-cmd hostsvc/advopt/update UserVars.ESXiShellTimeOut long 900

# 2. Disable SSH when not in use
vim-cmd hostsvc/disable_ssh

# 3. Disable the ESXi shell
vim-cmd hostsvc/disable_esx_shell

# 4. Set a strong root password and use Active Directory/LDAP
esxcli system account set -i root -p 'NewStrongPassword123!'

# 5. Enable UEFI Secure Boot (must be set in BIOS)
# Verify current status:
esxcli system settings encryption get

# 6. Restrict management network access
esxcli network firewall ruleset set --enabled true --ruleset-id sshServer
esxcli network firewall ruleset allowedip add --ruleset-id sshServer --ip-address 10.10.99.0/24

# 7. Disable unused services
esxcli network firewall ruleset set --enabled false --ruleset-id CIMSLP
esxcli network firewall ruleset set --enabled false --ruleset-id snmp

# 8. Check for open ports
esxcli network ip connection list | grep LISTEN

# 9. Verify NTP (time skew breaks authentication)
esxcli system ntp get

# 10. Enable audit logging
esxcli system syslog config set --loghost=tcp://10.10.99.50:514
```

### ESXi Patching

```bash
# List installed VIBs (packages)
esxcli software vib list

# Check for updates
esxcli software sources profile list --depot=https://hostupdate.vmware.com/software/VUM/PRODUCTION/main/vmw-depot-index.xml

# Install a patch bundle
esxcli software vib install --depot=/vmfs/volumes/datastore1/patches/ESXi-patch.zip
```

### VMware-Specific Ransomware Defenses

1. **Do not expose ESXi management (port 443) to the internet.** This is how ESXiArgs spread.
2. **Disable OpenSLP** (CVE-2021-21974, the ESXiArgs entry point):
   ```bash
   /etc/init.d/slpd stop
   esxcli network firewall ruleset set --enabled false --ruleset-id CIMSLP
   chkconfig slpd off
   ```
3. **Snapshot-based backups** should be stored outside the hypervisor. Do not rely on VMDK snapshots that live on the same datastore.
4. **Use vSphere Trust Authority** for encrypted VM isolation if you run vSphere 7+.

---

## Endpoint Detection and Response Basics

EDR is the primary tool for detecting ransomware execution and lateral movement. It goes beyond traditional antivirus by monitoring process behavior, file system changes, network connections, and registry modifications in real time.

### What EDR Should Detect

| Activity | Why It Matters |
|----------|---------------|
| Mass file renaming/encryption | Direct ransomware execution |
| Shadow copy deletion | `vssadmin delete shadows /all /quiet` |
| Credential dumping | Mimikatz, LSASS access |
| Lateral movement | PsExec, WMI, RDP brute force |
| Persistence mechanisms | Scheduled tasks, services, registry run keys |
| Defense evasion | AV tampering, log clearing |

### Canary Files

Deploy canary files (decoy files) in common locations. No legitimate user or process touches these. Any read/write to a canary triggers an alert.

```bash
# Create canary files across file shares
for dir in /shares/*/; do
  echo "CANARY-$(uuidgen)-DO-NOT-TOUCH" > "${dir}.important_backup.xlsx"
  chmod 444 "${dir}.important_backup.xlsx"
done

# Monitor with inotifywait (Linux)
inotifywait -m -r --format '%T %e %w%f' --timefmt '%Y-%m-%d %H:%M:%S' \
  -e access,modify,delete /shares/*/.important_backup.xlsx
```

On Windows, use FSRM (File Server Resource Manager) file screens to alert on known ransomware extensions:

```powershell
# Block known ransomware extensions via FSRM
New-FsrmFileGroup -Name "Ransomware_Extensions" -IncludePattern @("*.locky","*.cerber","*.crypt","*.encrypted","*.wnry","*.wcry","*.wncry")

New-FsrmFileScreen -Path "D:\Shares" -Description "Block Ransomware" -IncludeGroup "Ransomware_Extensions" -Notification @(
  New-FsrmAction -Type Email -MailTo "secops@company.com" -Subject "Ransomware Activity Detected" -Body "Ransomware file extension detected on [Source Io Owner] at [File Screen Path]"
)
```

### Key EDR Capabilities to Configure

1. **Process tree monitoring**: See the full chain (phishing email > Word macro > PowerShell > Cobalt Strike > lateral movement).
2. **File integrity monitoring**: Alert on bulk file changes.
3. **Network telemetry**: Detect C2 beaconing patterns.
4. **Isolation capability**: One-click host isolation that cuts network access while maintaining EDR management.

---

## Recovery Playbook

This is a step-by-step response plan. Adapt it to your organization.

### Phase 1: Detection and Scoping (Hours 0-4)

| Step | Action | Owner |
|------|--------|-------|
| 1 | Confirm ransomware (not a test, not a false positive) | SOC |
| 2 | Identify the ransomware variant (check ransom note, file extensions, ID Ransomware) | IR Lead |
| 3 | Determine scope: how many hosts, which segments, which data | IR Lead |
| 4 | Check if backups are intact (verify immutable copies first) | Backup Admin |
| 5 | Activate incident response team and notify leadership | CISO |
| 6 | Preserve evidence (do not wipe infected systems yet) | Forensics |

```bash
# Quick scope check: find recently modified files with ransomware extensions
find / -name "*.encrypted" -o -name "*.locked" -o -name "*.crypt" -mtime -1 2>/dev/null | head -50

# Check for ransom notes
find / -name "README_DECRYPT*" -o -name "HOW_TO_RECOVER*" -o -name "RESTORE_FILES*" 2>/dev/null

# List running suspicious processes
ps aux | grep -iE 'encrypt|ransom|crypt|lock' | grep -v grep
```

### Phase 2: Containment (Hours 1-8)

| Step | Action | Owner |
|------|--------|-------|
| 1 | Isolate infected hosts (EDR isolation or network disconnect) | IT/SOC |
| 2 | Block attacker's known IPs/domains at the firewall | Network |
| 3 | Disable compromised accounts | IAM |
| 4 | Shut down affected servers if encryption is still running | IT |
| 5 | Isolate backup infrastructure (verify it is clean before reconnecting) | Backup Admin |
| 6 | Preserve at least one infected machine for forensics (snapshot, memory dump) | Forensics |

```bash
# Network isolation (Linux): drop all traffic except management
iptables -F
iptables -A INPUT -s 10.10.99.0/24 -j ACCEPT   # Management subnet only
iptables -A OUTPUT -d 10.10.99.0/24 -j ACCEPT
iptables -A INPUT -j DROP
iptables -A OUTPUT -j DROP

# Capture memory for forensics (using LiME on Linux)
insmod /path/to/lime.ko "path=/evidence/memory.lime format=lime"

# Capture memory on Windows (using winpmem)
winpmem_mini_x64.exe memory.raw
```

### Phase 3: Eradication (Hours 4-48)

| Step | Action | Owner |
|------|--------|-------|
| 1 | Identify the initial access vector (phishing, RDP, VPN exploit, etc.) | Forensics |
| 2 | Close the entry point | IT |
| 3 | Reset all passwords (start with admin/service accounts) | IAM |
| 4 | Revoke and reissue certificates if CA was compromised | IAM |
| 5 | Scan all systems with updated signatures | SOC |
| 6 | Remove persistence mechanisms | IR Team |

### Phase 4: Recovery (Hours 24-168)

| Step | Action | Owner |
|------|--------|-------|
| 1 | Prioritize systems for restoration (revenue-critical first) | Business |
| 2 | Restore from verified clean backups | IT/Backup |
| 3 | Rebuild compromised systems from known-good images | IT |
| 4 | Validate restored data integrity | QA |
| 5 | Gradually reconnect segments (monitor for reinfection) | Network/SOC |
| 6 | Conduct post-recovery vulnerability scan | Security |

```bash
# Verify backup integrity before restoring
sha256sum /backups/2025-12-01/full-backup.tar.gz.enc
# Compare against stored checksum

# Decrypt and extract
gpg --decrypt backup.tar.gz.gpg | tar xzf - -C /restore/

# Verify restored database
mysql -u admin -p -e "SELECT COUNT(*) FROM critical_table;" mydb
```

### Phase 5: Post-Incident (Week 2+)

- Write an incident report with timeline, root cause, and lessons learned
- Update detection rules based on TTPs observed
- Conduct a tabletop exercise based on the actual incident
- Review and improve backup and segmentation architecture
- File regulatory notifications if required (GDPR 72-hour rule, SEC 4-day rule, etc.)

---

## Tabletop Exercise Template

Run this exercise quarterly. It takes 2-3 hours. No computers needed for participants.

### Setup

| Item | Detail |
|------|--------|
| **Duration** | 2-3 hours |
| **Participants** | IT, Security, Legal, Comms, Executive Leadership, HR |
| **Facilitator** | CISO or external consultant |
| **Materials** | Scenario printout, inject cards, evaluation rubric |
| **Rules** | No blame. Focus on process gaps. Everything discussed stays in the room. |

### Scenario: "Operation Midnight Lock"

> It is Tuesday at 2:47 AM. Your SOC receives alerts from the EDR platform showing bulk file encryption on 14 servers in the finance segment. By 3:15 AM, the helpdesk starts receiving calls from the Singapore office: "All our files have a .locked extension and there is a text file demanding 40 Bitcoin."
>
> The ransom note claims the attackers have exfiltrated 2TB of data including PII, financial records, and board meeting minutes. They threaten to publish in 72 hours.
>
> Initial investigation shows the attackers entered through a compromised VPN account (no MFA) two weeks ago and have been living in the network since.

### Inject Cards

Deal these out at 20-minute intervals to simulate the incident evolving.

**Inject 1 (20 min):**
> The backup team reports that the primary Veeam backup server was encrypted. Weekly offsite tapes from last Sunday appear intact but have not been tested in 6 months.

*Discussion: How do we verify tape integrity? What is our RTO without the primary backup server? Who authorizes bare-metal restore?*

**Inject 2 (40 min):**
> A reporter from a major news outlet emails your PR team: "We have been contacted by a group claiming to have your customer data. Can you confirm a breach?" Simultaneously, a tweet goes viral: "Looks like [Company] got ransomwared."

*Discussion: Who speaks publicly? What is our holding statement? When do we notify customers? What are our regulatory obligations?*

**Inject 3 (60 min):**
> The forensics team identifies that the attacker moved laterally using a service account with Domain Admin privileges. This account was also used by the backup system. There is evidence the attacker accessed the backup management console.

*Discussion: Are our offline/immutable backups actually safe? Do we need to assume all backups are compromised? What is the rebuild strategy if we cannot trust any backup?*

**Inject 4 (80 min):**
> Law enforcement contacts you: "The group behind this attack is sanctioned by OFAC. Paying the ransom may violate federal law." Your cyber insurance carrier says they will not cover a ransom payment to a sanctioned entity.

*Discussion: What is our no-pay recovery plan? How does this change our timeline? Do we have the technical capability to rebuild without backups?*

**Inject 5 (100 min):**
> The attacker emails your CEO directly: "We have your board meeting recordings. Pay in 48 hours or we release everything." The board chair calls the CEO demanding answers.

*Discussion: How do we manage executive pressure? Who makes the final call on ransom payment? How do we communicate with the board during an active incident?*

### Evaluation Rubric

Score each area 1-5 after the exercise.

| Area | Score | Notes |
|------|-------|-------|
| Detection speed | /5 | |
| Communication (internal) | /5 | |
| Communication (external/legal) | /5 | |
| Containment effectiveness | /5 | |
| Backup readiness | /5 | |
| Decision-making clarity | /5 | |
| Regulatory compliance awareness | /5 | |
| Technical recovery capability | /5 | |

### Action Items Template

| Finding | Action | Owner | Deadline |
|---------|--------|-------|----------|
| Example: Backup restoration not tested | Schedule monthly restore tests | Backup Admin | 30 days |
| | | | |
| | | | |

---

## Backup Verification Commands

Testing backups regularly is as important as having them. An untested backup is a hope, not a plan.

### Verify Backup File Integrity

```bash
# Generate checksum at backup time
sha256sum /backups/full-backup-2025-12-01.tar.gz > /backups/full-backup-2025-12-01.sha256

# Verify checksum later
sha256sum -c /backups/full-backup-2025-12-01.sha256
# Output: /backups/full-backup-2025-12-01.tar.gz: OK

# Verify a tar archive is not corrupted
tar -tzf /backups/full-backup-2025-12-01.tar.gz > /dev/null && echo "Archive OK" || echo "Archive CORRUPTED"
```

### Test Database Restore

```bash
# MySQL: restore to a test instance
mysql -h test-db-server -u admin -p test_restore < /backups/mysql-dump-2025-12-01.sql

# Verify row counts match production
mysql -h test-db-server -u admin -p -e "
  SELECT 'users' as tbl, COUNT(*) as cnt FROM test_restore.users
  UNION ALL
  SELECT 'orders', COUNT(*) FROM test_restore.orders
  UNION ALL
  SELECT 'transactions', COUNT(*) FROM test_restore.transactions;
"

# PostgreSQL: restore to a test database
pg_restore -h test-db-server -U admin -d test_restore /backups/pg-dump-2025-12-01.custom
```

### VM Snapshot Verification

```bash
# VMware: verify snapshot integrity
vmkfstools -e /vmfs/volumes/datastore1/vm-backups/server01/server01-flat.vmdk
# Output: "Disk is valid" or error

# Test boot a VM from backup in isolated network
# Use a VLAN with no routing to production
qemu-system-x86_64 -m 4096 -hda /backups/server01-backup.qcow2 -net none
```

### Automated Backup Verification Script

```bash
#!/bin/bash
# backup_verify.sh - Run weekly via cron
# Verifies backup integrity and sends alerts on failure

BACKUP_DIR="/backups/latest"
LOG_FILE="/var/log/backup-verify.log"
ALERT_EMAIL="secops@company.com"
FAILURES=0

echo "=== Backup Verification $(date) ===" >> "$LOG_FILE"

# Check all checksums
for checksum_file in "$BACKUP_DIR"/*.sha256; do
  if ! sha256sum -c "$checksum_file" >> "$LOG_FILE" 2>&1; then
    echo "FAIL: $checksum_file" >> "$LOG_FILE"
    FAILURES=$((FAILURES + 1))
  fi
done

# Check archive integrity
for archive in "$BACKUP_DIR"/*.tar.gz; do
  if ! tar -tzf "$archive" > /dev/null 2>&1; then
    echo "FAIL: $archive is corrupted" >> "$LOG_FILE"
    FAILURES=$((FAILURES + 1))
  fi
done

# Check backup age (alert if older than 48 hours)
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +2 | while read -r old_file; do
  echo "WARNING: $old_file is older than 48 hours" >> "$LOG_FILE"
  FAILURES=$((FAILURES + 1))
done

# Send alert if failures
if [ "$FAILURES" -gt 0 ]; then
  mail -s "BACKUP VERIFICATION FAILED ($FAILURES issues)" "$ALERT_EMAIL" < "$LOG_FILE"
  exit 1
fi

echo "All backups verified successfully." >> "$LOG_FILE"
exit 0
```

### Cron Setup for Verification

```bash
# Run backup verification every Sunday at 6 AM
echo "0 6 * * 0 /usr/local/bin/backup_verify.sh" | crontab -
```

---

## Quick Reference: Ransomware Resilience Checklist

- [ ] 3-2-1-1 backup architecture implemented
- [ ] At least one immutable backup copy (S3 Object Lock, tape, etc.)
- [ ] Backups encrypted at rest
- [ ] Backup restoration tested monthly
- [ ] Network segmented (no flat network)
- [ ] SMBv1 disabled everywhere
- [ ] ESXi management not exposed to internet
- [ ] OpenSLP disabled on ESXi hosts
- [ ] EDR deployed on all endpoints and servers
- [ ] Canary files deployed on file shares
- [ ] Incident response playbook documented and printed
- [ ] Tabletop exercise conducted quarterly
- [ ] Cyber insurance reviewed and current
- [ ] Regulatory notification requirements documented

---

*From [AllSecurityNews.com](https://allsecuritynews.com)*
