# Suspicious Scheduled Task Persistence Detection

## Overview

Scheduled Tasks are a legitimate Windows feature commonly used for automation and system maintenance. However, attackers frequently abuse Scheduled Tasks to establish persistence, execute payloads, maintain access, and evade detection.

This detection identifies suspicious Scheduled Task creation and modification activity by analyzing process execution patterns, command-line arguments, parent-child process relationships, and persistence-related indicators.

The query uses a risk-scoring approach to prioritize high-fidelity events for investigation.

---

## Detection Objective

Identify potentially malicious Scheduled Task creation or modification attempts that may indicate:

- Persistence mechanisms
- Malware execution
- Privilege escalation attempts
- Living-off-the-Land (LotL) activity
- Post-exploitation actions
- Defense evasion techniques

---

## Data Source

**Microsoft Defender XDR**

Table:

```text
DeviceProcessEvents
```

---

## Detection Logic

This query monitors:

### Scheduled Task Activity

- schtasks.exe
- PowerShell Scheduled Task cmdlets
- Command Prompt task creation commands

Examples:

```cmd
schtasks /create
schtasks /change
```

```powershell
Register-ScheduledTask
New-ScheduledTask
```

---

### Obfuscation Indicators

The query looks for:

- Encoded PowerShell commands
- Base64 payloads
- Invoke-Expression (IEX)
- PowerShell execution bypasses

Examples:

```powershell
-EncodedCommand
FromBase64String()
IEX
```

---

### Hidden Execution Techniques

Indicators include:

- Hidden PowerShell windows
- NoProfile execution
- Non-interactive execution

Examples:

```powershell
-WindowStyle Hidden
-W Hidden
-NoProfile
-NoP
```

---

### Privileged Task Creation

The query identifies tasks configured to run:

- As SYSTEM
- With highest privileges
- At logon
- On recurring schedules

Examples:

```cmd
/RU SYSTEM
/RL HIGHEST
/SC ONLOGON
```

---

### Suspicious Parent Processes

The query increases risk when Scheduled Tasks are created from unusual parent processes such as:

- winword.exe
- excel.exe
- powerpnt.exe
- outlook.exe
- mshta.exe
- wscript.exe
- cscript.exe

These parent-child relationships are commonly observed during phishing and malware execution chains.

---

### Suspicious File Locations

The query flags execution paths associated with attacker-controlled payloads:

- AppData
- Temp
- Public
- ProgramData

Examples:

```text
C:\Users\User\AppData\
C:\Users\Public\
C:\Windows\Temp\
```

---

## Risk Scoring Methodology

| Indicator | Score |
|------------|--------|
| Scheduled Task Creation/Modification | +30 |
| Encoded or Obfuscated Commands | +30 |
| Hidden Execution Techniques | +20 |
| SYSTEM or High Privilege Execution | +20 |
| Suspicious Parent Process | +20 |
| Suspicious File Location | +20 |

---

## Risk Levels

| Score | Severity |
|---------|---------|
| 70+ | High |
| 40-69 | Medium |
| 1-39 | Low |
| 0 | Informational |

---

## MITRE ATT&CK Mapping

| Technique ID | Technique |
|-------------|------------|
| T1053.005 | Scheduled Task/Job: Scheduled Task |
| T1059 | Command and Scripting Interpreter |
| T1059.001 | PowerShell |
| T1027 | Obfuscated Files or Information |
| T1547 | Boot or Logon Autostart Execution |
| T1543 | Create or Modify System Process |
| T1105 | Ingress Tool Transfer |

---

## Investigation Guide

### 1. Review the Scheduled Task Command

Identify:

- Task name
- Execution path
- Trigger conditions
- User context

Questions:

- What executable is being launched?
- Is the task expected?

---

### 2. Analyze the Parent Process

Review:

- InitiatingProcessFileName
- InitiatingProcessCommandLine

High-risk examples include:

- winword.exe
- excel.exe
- powerpnt.exe
- mshta.exe
- wscript.exe

---

### 3. Review Command-Line Arguments

Look for:

- Encoded payloads
- Download activity
- Obfuscation
- Hidden execution

Examples:

```powershell
-EncodedCommand
Invoke-WebRequest
IEX
```

---

### 4. Investigate the Executable Path

Review whether the payload resides in:

- AppData
- Temp
- Downloads
- Public
- ProgramData

User-writable locations often indicate malicious persistence.

---

### 5. Review Network Activity

Determine whether the process:

- Downloaded files
- Contacted external IPs
- Connected to suspicious domains

---

### 6. Validate User Activity

Confirm:

- Was the task intentionally created?
- Was software being installed?
- Was an administrator performing maintenance?

---

### 7. Determine Impact

Classify the activity as:

- Legitimate administration
- Software deployment
- Security testing
- Malware persistence
- Confirmed compromise

---

## False Positive Considerations

The following activities may generate legitimate alerts:

- Enterprise software deployment
- SCCM or Intune task creation
- Backup software
- Monitoring agents
- IT automation scripts
- Security testing activities

Environment-specific tuning is recommended.

---

## Detection Strategy

This detection combines:

- Persistence hunting
- Behavioral analytics
- Parent-child process analysis
- Command-line inspection
- Risk scoring

Rather than relying on a single indicator, multiple suspicious characteristics are combined to improve detection fidelity and reduce noise.

---

## Author

**Harsh Kethwas**

SOC Analyst | Microsoft Defender XDR | KQL | Threat Hunting | Detection Engineering
