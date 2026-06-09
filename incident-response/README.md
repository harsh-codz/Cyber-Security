# Incident Name

## Incident Summary

Provide a brief overview of the incident.

**Example:**
A Microsoft Defender alert identified suspicious PowerShell execution on a workstation. The investigation revealed the execution of an encoded PowerShell command attempting to download content from an external domain.

---

## Alert Information

| Field          | Value |
| -------------- | ----- |
| Alert Name     |       |
| Alert Source   |       |
| Severity       |       |
| Detection Time |       |
| Affected Host  |       |
| User Account   |       |
| Status         |       |

---

## Investigation Scope

### Systems Affected

* Hostname(s)
* IP Address(es)
* Operating System

### Accounts Involved

* User Accounts
* Service Accounts

### Time Range

* Start Time
* End Time

---

## Investigation Timeline

| Time  | Event                   |
| ----- | ----------------------- |
| 00:00 | Alert Generated         |
| 00:05 | Initial Triage          |
| 00:10 | Evidence Collection     |
| 00:20 | IOC Analysis            |
| 00:30 | Containment Action      |
| 00:45 | Investigation Completed |

---

## Evidence Collected

### Process Activity

```text
Process Name:
Command Line:
Parent Process:
Process ID:
```

### Network Activity

```text
Source IP:
Destination IP:
Destination Domain:
Protocol:
Port:
```

### File Activity

```text
File Name:
File Path:
SHA256:
Detection Result:
```

---

## Indicators of Compromise (IOCs)

### IP Addresses

```text
x.x.x.x
x.x.x.x
```

### Domains

```text
example.com
malicious-domain.com
```

### File Hashes

```text
SHA256:
MD5:
```

---

## MITRE ATT&CK Mapping

| Tactic              | Technique | ID |
| ------------------- | --------- | -- |
| Initial Access      |           |    |
| Execution           |           |    |
| Persistence         |           |    |
| Defense Evasion     |           |    |
| Credential Access   |           |    |
| Discovery           |           |    |
| Command and Control |           |    |

---

## Analysis Findings

### What Happened?

Describe the observed activity and findings.

### Impact Assessment

* Systems affected
* Users affected
* Data exposure risk
* Business impact

### Root Cause

Explain how the incident occurred.

---

## Response Actions

### Containment

* [ ] Host isolated
* [ ] Account disabled
* [ ] IP blocked
* [ ] Domain blocked

### Eradication

* [ ] Malware removed
* [ ] Persistence removed
* [ ] Vulnerability remediated

### Recovery

* [ ] System restored
* [ ] Monitoring enabled
* [ ] Validation completed

---

## Detection Opportunities

### Existing Detection

Describe which detection identified the incident.

### Recommended Improvements

* Additional monitoring rules
* New KQL detections
* Threat hunting opportunities
* Security control enhancements

---

## Lessons Learned

* Key findings
* Detection gaps
* Process improvements
* Future recommendations

---

## Conclusion

Provide a final summary of the investigation, outcome, and remediation actions.

---

## References

* Microsoft Documentation
* MITRE ATT&CK
* Vendor Security Advisories
* Threat Intelligence Sources

---

## Analyst Notes

**Investigator:** Harsh Kethwas

**Role:** SOC Analyst

**Investigation Date:** YYYY-MM-DD
