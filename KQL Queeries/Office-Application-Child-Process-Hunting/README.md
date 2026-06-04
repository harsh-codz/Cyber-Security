# Office Application Child Process Hunting

## Overview

Microsoft Office applications are frequently targeted by attackers as an initial access vector. Malicious documents, embedded macros, phishing attachments, and weaponized Office files can be used to spawn suspicious child processes, download payloads, or establish persistence.

This project contains two Microsoft Defender XDR KQL detections focused on identifying potentially malicious child processes launched from Office applications.

The detections combine both signature-based and anomaly-based hunting techniques.

---

## Data Source

**Microsoft Defender XDR**

Table:

```text
DeviceProcessEvents
```

---

# Detection 1: Suspicious Child Processes Spawned by Office Applications

## Objective

Detect known suspicious executables launched directly by Microsoft Office applications.

Attackers commonly abuse Office applications to launch:

- PowerShell
- Command Prompt
- Windows Script Host
- LOLBins (Living-off-the-Land Binaries)
- Download utilities
- Persistence mechanisms

This detection focuses on identifying these known attack patterns.

---

## Office Parent Processes Monitored

- winword.exe
- excel.exe
- powerpnt.exe
- outlook.exe
- onenote.exe
- msaccess.exe
- publisher.exe

---

## Suspicious Child Processes Monitored

- cmd.exe
- powershell.exe
- pwsh.exe
- wscript.exe
- cscript.exe
- mshta.exe
- rundll32.exe
- regsvr32.exe
- certutil.exe
- bitsadmin.exe
- wmic.exe
- schtasks.exe
- msbuild.exe
- installutil.exe

---

## Detection Logic

The query identifies Office applications spawning known suspicious child processes and performs additional command-line analysis to detect:

- Encoded PowerShell payloads
- Base64 decoding activity
- Download cradles
- Script execution abuse
- Hidden execution techniques

---

## MITRE ATT&CK Mapping

| Technique ID | Technique |
|-------------|------------|
| T1204 | User Execution |
| T1566 | Phishing |
| T1059 | Command and Scripting Interpreter |
| T1059.001 | PowerShell |
| T1218 | System Binary Proxy Execution |
| T1105 | Ingress Tool Transfer |

---

# Detection 2: Uncommon Child Processes Spawned by Office Applications

## Objective

Identify unusual or previously unseen child processes launched by Microsoft Office applications.

Instead of looking for known malicious executables, this detection excludes commonly observed child processes and highlights everything else for investigation.

This approach is useful for discovering:

- Novel attack techniques
- New LOLBins
- Malware execution chains
- Environment-specific anomalies
- Custom attacker tooling

---

## Common Child Processes Excluded

Examples include:

- msedge.exe
- chrome.exe
- firefox.exe
- teams.exe
- ms-teams.exe
- outlook.exe
- splwow64.exe
- protocolhandler.exe
- filecoauth.exe
- adobe.exe
- acrobat.exe
- microsoft.mashup.container.loader.exe

These are commonly observed and often legitimate in enterprise environments.

---

## Detection Logic

The query:

1. Identifies Office applications acting as parent processes.
2. Excludes known and expected child processes.
3. Reviews remaining child processes.
4. Applies risk scoring based on suspicious indicators.

---

## Risk Scoring Methodology

### Network-Based Indicators (+30)

- http://
- https://
- invoke-webrequest
- download
- webclient

### Obfuscation Indicators (+30)

- -enc
- -encodedcommand
- frombase64string
- iex

### Suspicious Execution Locations (+20)

- AppData
- Temp
- Public
- Downloads

### High-Risk LOLBins (+20)

- mshta.exe
- rundll32.exe
- regsvr32.exe
- certutil.exe
- bitsadmin.exe

---

## Risk Levels

| Score | Severity |
|---------|---------|
| 70+ | High |
| 40-69 | Medium |
| 1-39 | Low |
| 0 | Review |

---

## MITRE ATT&CK Mapping

| Technique ID | Technique |
|-------------|------------|
| T1204 | User Execution |
| T1055 | Process Injection |
| T1218 | System Binary Proxy Execution |
| T1036 | Masquerading |
| T1059 | Command and Scripting Interpreter |

---

## Investigation Guide

### 1. Review the Parent Office Process

Determine:

- Which Office application launched the child process
- Whether a document was recently opened
- Whether the activity aligns with expected user behavior

---

### 2. Examine the Child Process

Review:

- File name
- Command line
- Execution path
- Digital signature

Look for:

- PowerShell execution
- LOLBins
- Encoded commands
- Download activity

---

### 3. Analyze Command-Line Arguments

Indicators of concern include:

- Encoded payloads
- Base64 strings
- Download commands
- Hidden execution
- Obfuscation techniques

---

### 4. Investigate Network Activity

Determine whether the process:

- Downloaded files
- Connected to external IPs
- Communicated with suspicious domains

---

### 5. Review File Activity

Check for:

- Newly created files
- Persistence mechanisms
- Dropped executables
- Scheduled tasks

---

### 6. Validate User Intent

Determine whether the behavior was:

- Legitimate business activity
- Administrative activity
- Security testing
- Malicious execution

---

## False Positive Considerations

Legitimate activity may include:

- Internal automation scripts
- Software deployment tools
- Office add-ins
- Enterprise applications
- Remote support tools
- Business workflows
- Security testing activities

Environment-specific tuning is recommended.

---

## Detection Strategy

This project uses two complementary approaches:

### Detection 1 – Signature-Based Hunting

Focuses on known suspicious child processes commonly used by attackers.

### Detection 2 – Anomaly-Based Hunting

Focuses on uncommon child processes and behavioral anomalies that may reveal previously unknown attack techniques.

Using both detections together provides broader visibility into Office-based attack chains.

---

## Author

**Harsh Kethwas**

SOC Analyst | Microsoft Defender XDR | KQL | Threat Hunting | Detection Engineering
