# Defending Against AI-Powered Phishing

Attackers are using large language models to generate phishing emails that are grammatically perfect, contextually relevant, and personalized at scale. Voice deepfakes are targeting helpdesks and executives. This guide covers what's changed, what to look for, and what actually works.

## What's Different About AI-Generated Phishing

Traditional phishing had tells: broken English, generic greetings, obvious urgency. AI-generated phishing has none of these. Here's what you're up against:

- **Perfect grammar and tone**: LLMs produce emails that read like a native speaker wrote them
- **Context-aware content**: Attackers scrape LinkedIn, company websites, and press releases to personalize attacks
- **Voice cloning**: A 30-second audio clip is enough to clone someone's voice for phone-based attacks
- **Scale**: What used to require a human writing individual emails can now be automated for thousands of targets
- **Multilingual**: AI easily generates phishing in any language, removing the "foreign origin" tell
- **Thread hijacking**: AI can generate contextually appropriate replies to ongoing email threads

## Red Flags That Still Work

Despite the improvement in quality, some indicators still hold:

**Email indicators:**
- Sender domain is slightly off (microsoftt.com, go0gle.com)
- Reply-to address differs from the From address
- Links point to domains registered in the last 30 days
- Embedded links use URL shorteners or redirectors
- Unexpected attachments, especially .html, .iso, .img, or password-protected zips
- Request for credentials, MFA codes, or financial action via email
- Urgency that bypasses normal approval workflows

**Voice/video deepfake indicators:**
- Unusual call timing (after hours, when the real person is known to be traveling)
- Request to bypass normal procedures
- Audio quality inconsistencies or unnatural pauses
- Refusal to switch to video or meet in person
- Requests for wire transfers, credential resets, or MFA bypasses over the phone

## Technical Controls

### Email Security

**DMARC, DKIM, and SPF (non-negotiable baseline):**
```
# DNS TXT records for your domain

# SPF - specify which servers can send email for your domain
v=spf1 include:_spf.google.com include:sendgrid.net -all

# DMARC - tell receivers what to do with unauthenticated email
_dmarc.yourdomain.com  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com; pct=100"
```

Set DMARC policy to `p=reject` (not `p=none` or `p=quarantine`). If you're still on `p=none`, you're not actually preventing spoofing.

**Check your current DMARC status:**
```bash
dig TXT _dmarc.yourdomain.com +short
```

**Additional email controls:**
- Enable external email tagging (banner on emails from outside the org)
- Block .html, .iso, .img, .vhd attachments at the email gateway
- Strip macros from Office documents or block macro-enabled formats entirely
- Implement link rewriting/sandboxing for URLs in emails
- Enable impersonation protection for executive names and display names

### MFA Hardening

AI phishing often targets MFA. Harden against MFA bypass:

- Deploy phishing-resistant MFA (FIDO2/WebAuthn hardware keys) for privileged accounts
- Disable SMS and voice call as MFA methods (vulnerable to SIM swap and social engineering)
- Implement number matching for push notification MFA (prevents MFA fatigue attacks)
- Monitor for MFA bypass techniques: adversary-in-the-middle proxies (EvilGinx-style attacks)

### Helpdesk Protection

Voice deepfakes target helpdesks for credential resets and MFA bypasses:

- Require a callback to a known phone number before processing any reset request
- Implement a verification code system: user requests reset via self-service portal, receives code via secondary channel, provides code to helpdesk
- Never reset MFA or credentials based solely on a phone call, regardless of who the caller claims to be
- Log all helpdesk reset requests and review for anomalies weekly

## Detection and Monitoring

### What to Monitor

```
# Email gateway logs - look for:
- High volumes from newly registered domains (domain age < 30 days)
- Spikes in blocked emails from a single domain
- Pattern: multiple similar emails hitting different users within minutes

# Authentication logs - look for:
- Successful login shortly after a phishing email was delivered
- Login from a new location/device within hours of phishing delivery
- MFA registration of a new device after a phishing email

# Web proxy logs - look for:
- Connections to recently registered domains
- Connections to known phishing infrastructure (check against threat intel feeds)
- POST requests to external login pages from internal users
```

### Phishing-Specific Detection Rules

Sigma rule concept for detecting credential phishing access:
```yaml
title: Potential Credential Phishing - Login to Suspicious Domain
description: Detects when a user accesses a login page on a recently registered or suspicious domain shortly after receiving an email
detection:
  selection_proxy:
    url|contains:
      - '/login'
      - '/signin'
      - '/auth'
      - '/verify'
  filter_known:
    url|contains:
      - 'microsoft.com'
      - 'google.com'
      - 'okta.com'
      - 'your-company.com'
  condition: selection_proxy and not filter_known
```

## Incident Response: When Someone Clicks

1. **Credential compromise assumed**: Immediately reset the user's password and revoke all sessions
2. **Check for MFA changes**: Did the attacker register a new MFA device?
3. **Review mailbox activity**: Check for forwarding rules, delegate access, or sent items
4. **Check OAuth app grants**: Attackers often install persistent OAuth apps during the session
5. **Review downstream access**: What systems did the user's credentials have access to?
6. **Block the phishing domain**: Add to your blocklist and report it

```bash
# Quick check for OAuth app grants (Microsoft 365)
# Use Graph API or Azure AD portal to review
# Enterprise Applications > All Applications > Filter by recent consent grants

# Check mailbox rules (Exchange Online)
Get-InboxRule -Mailbox user@company.com | Where-Object {$_.ForwardTo -or $_.RedirectTo -or $_.ForwardAsAttachmentTo}
```

## Employee Training That Works

Traditional phishing training is becoming less effective against AI-generated content. Update your approach:

**What to train on:**
- "When in doubt, verify through a separate channel" (call them, walk to their desk, use Slack)
- Never enter credentials after clicking an email link. Navigate to the site directly.
- Report suspicious emails even if you're not sure. False positives are better than missed phish.
- For phone calls requesting credential resets or wire transfers: hang up and call back on a known number

**What to stop doing:**
- Gotcha-style phishing simulations that shame employees (destroys trust, reduces reporting)
- Training that relies on spotting typos (AI phishing has none)
- Annual checkbox training (too infrequent to change behavior)

**What to start doing:**
- Monthly 5-minute micro-trainings with real-world examples
- Celebrate employees who report phishing attempts
- Share anonymized examples of actual phishing attempts that targeted your organization
- Run tabletop exercises for deepfake voice attacks on your helpdesk

---

From [AllSecurityNews.com](https://allsecuritynews.com) - Your hub for cybersecurity intelligence.
