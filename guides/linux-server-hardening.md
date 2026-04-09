# Linux Server Hardening Guide

A practical guide to securing a Linux server. Covers the essentials that every server should have, without overcomplicating things. Based on CIS benchmarks and real-world best practices.

## 1. User and Access Management

### Disable root login over SSH

Edit `/etc/ssh/sshd_config`:
```
PermitRootLogin no
```

Create a regular user with sudo access instead:
```bash
adduser deployer
usermod -aG sudo deployer
```

### Use SSH keys, disable password auth

Generate a key pair on your local machine:
```bash
ssh-keygen -t ed25519 -C "your-email@example.com"
```

Copy it to the server:
```bash
ssh-copy-id deployer@your-server
```

Then disable password authentication in `/etc/ssh/sshd_config`:
```
PasswordAuthentication no
PubkeyAuthentication yes
```

Restart SSH:
```bash
sudo systemctl restart sshd
```

### Change the default SSH port (optional but reduces noise)

In `/etc/ssh/sshd_config`:
```
Port 2222
```

### Remove unused user accounts

List all users with login shells:
```bash
grep -v '/nologin\|/false' /etc/passwd
```

Lock any accounts that should not log in:
```bash
sudo usermod -L unused_account
sudo usermod -s /usr/sbin/nologin unused_account
```

## 2. Firewall Configuration

### UFW (Ubuntu/Debian)

```bash
# Start with deny-all incoming
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (use your custom port if changed)
sudo ufw allow 2222/tcp

# Allow web traffic
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Enable
sudo ufw enable
sudo ufw status verbose
```

### firewalld (RHEL/CentOS)

```bash
sudo firewall-cmd --set-default-zone=drop
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

## 3. System Updates

### Enable automatic security updates

**Ubuntu/Debian:**
```bash
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

**RHEL/CentOS:**
```bash
sudo dnf install dnf-automatic
sudo systemctl enable --now dnf-automatic-install.timer
```

### Check for updates regularly

```bash
# Debian/Ubuntu
sudo apt update && sudo apt list --upgradable

# RHEL/CentOS
sudo dnf check-update
```

## 4. Service Hardening

### Disable unnecessary services

List running services:
```bash
sudo systemctl list-units --type=service --state=running
```

Disable anything you do not need:
```bash
sudo systemctl disable --now cups        # printing
sudo systemctl disable --now avahi-daemon # mDNS
sudo systemctl disable --now bluetooth   # bluetooth
```

### Set restrictive file permissions

```bash
# SSH config
sudo chmod 600 /etc/ssh/sshd_config
sudo chmod 700 ~/.ssh
sudo chmod 600 ~/.ssh/authorized_keys

# Cron
sudo chmod 600 /etc/crontab
sudo chmod 700 /etc/cron.d

# Password files
sudo chmod 640 /etc/shadow
```

## 5. Logging and Monitoring

### Ensure critical logs are enabled

Check that these exist and are being written to:
```bash
ls -la /var/log/auth.log     # authentication events
ls -la /var/log/syslog       # system events
ls -la /var/log/kern.log     # kernel messages
ls -la /var/log/fail2ban.log # brute force blocking (if installed)
```

### Install fail2ban

Automatically bans IPs after repeated failed login attempts:

```bash
sudo apt install fail2ban
```

Create `/etc/fail2ban/jail.local`:
```ini
[sshd]
enabled = true
port = 2222
maxretry = 5
bantime = 3600
findtime = 600
```

```bash
sudo systemctl enable --now fail2ban
```

Check status:
```bash
sudo fail2ban-client status sshd
```

### Set up log rotation

Ensure logs do not fill your disk. Check `/etc/logrotate.d/` for service-specific configs.

## 6. Kernel and Network Hardening

Add to `/etc/sysctl.d/99-security.conf`:

```ini
# Disable IP forwarding (unless this is a router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Ignore source-routed packets
net.ipv4.conf.all.accept_source_route = 0

# Enable SYN flood protection
net.ipv4.tcp_syncookies = 1

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1

# Disable SUID core dumps
fs.suid_dumpable = 0

# Restrict kernel pointer exposure
kernel.kptr_restrict = 2

# Restrict dmesg access
kernel.dmesg_restrict = 1
```

Apply:
```bash
sudo sysctl -p /etc/sysctl.d/99-security.conf
```

## 7. File Integrity Monitoring

### AIDE (Advanced Intrusion Detection Environment)

```bash
sudo apt install aide
sudo aideinit
```

Run a check:
```bash
sudo aide --check
```

Schedule a daily check via cron:
```bash
0 3 * * * /usr/bin/aide --check | mail -s "AIDE Report" admin@example.com
```

## 8. TLS and Encryption

### Force TLS 1.2+ in nginx

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers on;
```

### Encrypt disks at rest

For new servers, enable LUKS during installation. For existing servers:
```bash
sudo apt install cryptsetup
```

At minimum, encrypt sensitive data directories.

## 9. Quick Audit Checklist

Run these commands to check your current state:

```bash
# Open ports
sudo ss -tlnp

# Users with login shells
grep -v 'nologin\|false' /etc/passwd

# World-writable files (should be minimal)
find / -xdev -type f -perm -0002 -ls 2>/dev/null | head -20

# SUID binaries (review for unexpected entries)
find / -xdev -type f -perm -4000 -ls 2>/dev/null

# Failed SSH logins (last 24h)
grep "Failed password" /var/log/auth.log | tail -20

# Listening services
sudo netstat -tlnp 2>/dev/null || sudo ss -tlnp

# Pending security updates
apt list --upgradable 2>/dev/null | grep -i securi
```

## 10. What to Do Next

This guide covers the basics. For production systems, also consider:

- **Intrusion Detection**: Deploy OSSEC or Wazuh for host-based monitoring
- **Centralized Logging**: Ship logs to a SIEM (Elastic, Wazuh, Grafana Loki)
- **Vulnerability Scanning**: Run OpenVAS or Trivy regularly
- **Backup Strategy**: Automate backups with verification and off-site copies
- **CIS Benchmarks**: Run `cis-cat` for a thorough compliance check against your OS

---

From [AllSecurityNews.com](https://allsecuritynews.com) - Your hub for cybersecurity intelligence.
