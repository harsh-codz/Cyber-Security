# Office Application Child Process Hunting

## Overview

Microsoft Office applications are frequently abused by attackers to execute malicious code, download payloads, establish persistence, or launch post-exploitation tools.

This project contains two KQL detections designed to identify suspicious child processes spawned from Office applications.

The detections are intended for threat hunting and investigation within Microsoft Defender XDR.

---

# Detection 1: Suspicious Child Processes Spawned by Office Applications

## Objective

Identify known suspicious executables launched directly from Microsoft Office applications.

Attackers commonly use Office documents containing:

- Malicious macros
- Embedded objects
- Exploits
- Social engineering payloads

to spawn command interpreters, scripting engines, or LOLBins.

---

## Detection Logic

Monitor Office applications acting as parent processes and identify child processes frequently associated with malicious activity.

### Office Parent Processes

- winword.exe
- excel.exe
- powerpnt.exe
- outlook.exe
- onenote.exe
- msaccess.exe
- publisher.exe

### Suspicious Child Processes

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
- schtasks.exe
- wmic.exe
- installutil.exe
- msbuild.exe

---

## MITRE ATT&CK Mapping

| Technique | Description |
|------------|------------|
| T1204 | User Execution |
| T1566 | Phishing |
| T1059 | Command and Scripting Interpreter |
| T1059.001 | PowerShell |
| T1218 | System Binary Proxy Execution |
| T1105 | Ingress Tool Transfer |

---

## Investigation Steps

1. Review the Office document involved.
2. Identify the parent Office process.
3. Examine the spawned child process.
4. Review command-line arguments.
5. Check downloaded files.
6. Investigate network connections.
7. Determine whether the activity is legitimate.

---

# Detection 2: Uncommon Child Processes Spawned by Office Applications

## Objective

Identify unusual or previously unseen child processes launched by Office applications.

Instead of looking for known bad processes, this detection excludes common and expected child processes and highlights everything else for analyst review.

This approach helps uncover:

- Novel attacker techniques
- New LOLBins
- Malware execution chains
- Environment-specific anomalies

---

## Detection Logic

Monitor Office applications as parent processes.

Exclude commonly observed child processes such as:

- chrome.exe
- msedge.exe
- teams.exe
- outlook.exe
- splwow64.exe
- protocolhandler.exe
- filecoauth.exe
- adobe.exe
- acrobat.exe
- microsoft.mashup.container.loader.exe

Any remaining child process should be reviewed for legitimacy.

---

## MITRE ATT&CK Mapping

| Technique | Description |
|------------|------------|
| T1204 | User Execution |
| T1055 | Process Injection |
| T1218 | System Binary Proxy Execution |
| T1036 | Masquerading |
| T1059 | Command and Scripting Interpreter |

---

## Risk Scoring Methodology

This detection assigns a risk score based on suspicious indicators found in the process command line.

### Network Activity Indicators

- http://
- https://
- download
- invoke-webrequest
- webclient

Score: +30

### Obfuscation Indicators

- -enc
- -encodedcommand
- frombase64string
- iex

Score: +30

### Suspicious File Locations

- temp
- appdata
- public
- downloads

Score: +20

### High-Risk LOLBins

- mshta.exe
- rundll32.exe
- regsvr32.exe
- certutil.exe
- bitsadmin.exe

Score: +20

---

## Risk Levels

| Score | Severity |
|---------|---------|
| 70+ | High |
| 40-69 | Medium |
| 1-39 | Low |
| 0 | Review |

---

## Data Source

Microsoft Defender XDR

```text
DeviceProcessEvents
```

---

## False Positives

### Detection 1

- Administrative scripts
- Internal automation
- Software deployment tools
- IT support activity

### Detection 2

- Newly installed software
- Office add-ins
- Business applications
- Custom enterprise tooling

Environment-specific tuning is recommended.

---

## Analyst Notes

Detection 1 focuses on identifying known malicious behaviors.

Detection 2 focuses on anomaly hunting by identifying uncommon child processes that may indicate new attack techniques.

Using both detections together provides broader visibility into Office-based attack chains.

---

## Author

Harsh Kethwas

SOC Analyst | Threat Hunting | Microsoft Defender XDR | KQL | Detection Engineering
