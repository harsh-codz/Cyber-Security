# Brute Force and Password Spray Detection

## Overview

This KQL query detects repeated failed authentication attempts within Microsoft Entra ID (Azure AD).

The detection is designed to identify:

- Brute force attacks against user accounts
- Password spraying activity
- Credential stuffing attempts
- Unauthorized access attempts
- Account enumeration behavior

By monitoring failed sign-in events, security analysts can identify suspicious authentication patterns before successful account compromise occurs.

---

## Detection Objective

Identify users or source IP addresses generating an excessive number of failed sign-in attempts within a defined period.

This helps detect:

- Automated password guessing
- Password spraying campaigns
- Stolen credential usage
- Malicious authentication activity

---

## MITRE ATT&CK Mapping

| Technique ID | Technique |
|-------------|-----------|
| T1110 | Brute Force |
| T1110.001 | Password Guessing |
| T1110.003 | Password Spraying |
| T1078 | Valid Accounts |

---

## Detection Logic

The query searches Microsoft Entra ID sign-in logs for:

- Failed authentication attempts
- Interactive sign-in events
- Multiple failures originating from the same IP address
- Multiple failed attempts against the same account

The detection triggers when the number of failed login attempts exceeds the configured threshold.

---

## KQL Query

```kql
EntraIdSignInEvents
| where Timestamp > ago(1d)
| where LogonType == "interactive"
| where ErrorCode != 0
| summarize FailedAttempts = count()
    by AccountDisplayName,
       AccountUpn,
       IPAddress
| where FailedAttempts > 5
| order by FailedAttempts desc
```

---

## Investigation Guide

### 1. Review Affected Account

Validate:

- User identity
- Account sensitivity
- Administrative privileges

Determine whether the account belongs to:

- Standard user
- Administrator
- Service account
- Privileged account

---

### 2. Analyze Source IP Address

Investigate:

- Geolocation
- Reputation
- ASN ownership
- Historical activity

Questions to ask:

- Is the IP known?
- Is the location expected?
- Has the IP targeted multiple accounts?

---

### 3. Check for Password Spray Indicators

Look for:

- One IP targeting many users
- Similar failure counts across accounts
- Broad authentication attempts

Example:

```text
IP A → User1
IP A → User2
IP A → User3
IP A → User4
```

This behavior may indicate password spraying.

---

### 4. Check for Successful Authentication

Review subsequent sign-in events to determine whether:

- Authentication eventually succeeded
- MFA was triggered
- Conditional Access blocked access

A successful login following multiple failures increases the severity of the investigation.

---

### 5. Review Additional Activity

Investigate:

- Device activity
- Endpoint alerts
- Mailbox access
- File access
- Privileged actions

Look for signs of account compromise.

---

### 6. Determine Impact

Classify the activity as:

- User password mistake
- Password spray attempt
- Brute force attack
- Credential stuffing
- Confirmed account compromise

---

## False Positive Considerations

The following scenarios may generate legitimate failed sign-in attempts:

- Users entering incorrect passwords
- Cached credentials on devices
- Mobile applications using old passwords
- Service account password changes
- VPN authentication failures
- Misconfigured applications

Environment-specific tuning may be required.

---

## Data Source

Microsoft Defender XDR

Table:

```text
EntraIdSignInEvents
```

---

## Detection Severity

**Medium**

Increase to **High** if:

- A successful login follows the failed attempts
- Multiple accounts are targeted
- Privileged accounts are involved
- Suspicious geolocation is observed

---

## Author

Harsh Kethwas
