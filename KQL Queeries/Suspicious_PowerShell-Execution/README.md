# Suspicious PowerShell Execution Detection

## Overview

This KQL query is designed to detect potentially suspicious PowerShell activity that may indicate malicious behavior, post-exploitation activity, or abuse of legitimate system tools.

The detection focuses on command-line arguments commonly associated with:

- Encoded PowerShell execution
- Download cradles
- Script obfuscation
- Defense evasion techniques
- Living-off-the-Land (LotL) activity

---

## Detection Objective

Identify PowerShell processes executing potentially malicious commands by monitoring for suspicious parameters and execution patterns.

Examples include:

- Encoded commands (`-EncodedCommand`)
- PowerShell download functions (`DownloadString`, `Invoke-WebRequest`)
- Hidden execution (`-WindowStyle Hidden`)
- Execution policy bypass attempts
- Obfuscation and payload decoding

---

## MITRE ATT&CK Mapping

| Technique ID | Technique |
|-------------|-----------|
| T1059.001 | PowerShell |
| T1027 | Obfuscated Files or Information |
| T1105 | Ingress Tool Transfer |
| T1140 | Deobfuscate/Decode Files or Information |

---

## Detection Logic

This query monitors PowerShell-related processes and searches for suspicious command-line arguments commonly observed in attacker tradecraft.

### Indicators Monitored

- `-enc`
- `-encodedcommand`
- `iex`
- `invoke-expression`
- `downloadstring`
- `downloadfile`
- `invoke-webrequest`
- `iwr`
- `wget`
- `curl`
- `frombase64string`
- `-executionpolicy`
- `-ep`
- `hidden`
- `-w hidden`
- `-nop`
- `-noprofile`

Additionally, built-in system accounts are excluded to reduce noise and focus on user-initiated activity.

---

## KQL Query

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe","pwsh.exe","powershell_ise.exe")
| extend CmdLine = tolower(ProcessCommandLine)
| where CmdLine has_any (
    "-enc",
    "-encodedcommand",
    "iex",
    "-executionpolicy",
    "invoke-expression",
    "-ep",
    "downloadstring",
    "downloadfile",
    "invoke-webrequest",
    "iwr",
    "wget",
    "curl",
    "frombase64string",
    "hidden",
    "-w hidden",
    "-nop",
    "-noprofile"
)
| where AccountSid !in (
    "S-1-5-18",
    "S-1-5-19",
    "S-1-5-20",
    "S-1-5-15"
)
| summarize
      FirstSeen = min(Timestamp),
      LastSeen = max(Timestamp),
      EventCount = count()
      by DeviceName,
         AccountName,
         AccountSid,
         FileName,
         ProcessCommandLine,
         InitiatingProcessFileName,
         InitiatingProcessCommandLine
| sort by EventCount desc, LastSeen desc
```

---

## Investigation Guide

When this detection triggers:

### 1. Review the Command Line

- Identify suspicious parameters.
- Look for encoded or obfuscated content.
- Check for download or execution functionality.

### 2. Analyze the Parent Process

Review:

- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`

Suspicious parent processes may include:

- `winword.exe`
- `excel.exe`
- `outlook.exe`
- `wscript.exe`
- `mshta.exe`
- `cmd.exe`

### 3. Check for Encoded Payloads

If the command contains:

```powershell
-EncodedCommand
```

Decode the Base64 content and determine its purpose.

### 4. Review Network Activity

Investigate:

- External connections
- File downloads
- Connections to unknown domains or IPs

### 5. Validate User Activity

Determine:

- Whether the execution was expected
- If the user was performing administrative tasks
- Whether the activity aligns with business operations

### 6. Determine Impact

Assess whether the activity represents:

- Legitimate administration
- Security testing
- Malware execution
- Post-compromise attacker activity

---

## False Positive Considerations

Legitimate activity may trigger this detection, including:

- Administrative PowerShell scripts
- Software deployment platforms
- Endpoint management tools
- Automation frameworks
- Security tooling and testing activities

Environment-specific tuning may be required to reduce false positives.

---

## Data Source

**Microsoft Defender XDR**

Table:

```text
DeviceProcessEvents
```

---

## Author

**Harsh Kethwas**
