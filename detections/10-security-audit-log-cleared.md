# Detection 10 — Windows Security Audit Log Cleared

## Overview

This detection monitors Windows Security Event ID **1102** to identify when the Windows Security audit log has been cleared.

Clearing the Security audit log can remove valuable forensic evidence from a Windows system. Because of this, Event ID 1102 is a high-value security monitoring event and should receive immediate attention when detected.

---

# Detection Objective

Detect activity indicating that the Windows Security audit log has been cleared.

The detection provides SOC analysts with visibility into:

- When the Security log was cleared
- Which host was affected
- Which account performed the action
- The account domain associated with the activity

---

# Windows Event ID

| Event ID | Description |
|---|---|
| 1102 | The audit log was cleared |

---

# Data Source

**Log Source:**

```text
Windows Security Event Log
```

**Splunk Index:**

```text
security_lab
```

---

# Detection Query

The primary SPL detection query is:

```spl
index=security_lab EventCode=1102
| table _time host EventCode Account_Name Account_Domain
| sort - _time
```

---

# Query Explanation

## Event Filtering

```spl
EventCode=1102
```

This restricts the search to Windows Security audit-log-clearing events.

---

## Field Selection

```spl
| table _time host EventCode Account_Name Account_Domain
```

The query displays the primary investigation fields:

- `_time` — Time of the event
- `host` — Affected Windows host
- `EventCode` — Windows event identifier
- `Account_Name` — Account associated with the event
- `Account_Domain` — Domain associated with the account

---

## Sorting

```spl
| sort - _time
```

The newest events are displayed first.

---

# Alert Configuration

| Configuration | Value |
|---|---|
| Alert Name | Windows - Security Audit Log Cleared |
| Alert Type | Scheduled |
| Schedule | Every 5 minutes |
| Time Range | Last 5 minutes |
| Trigger Condition | Number of Results > 0 |
| Trigger Behavior | Once |
| Action | Add to Triggered Alerts |
| Severity | High |

---

# Validation Approach

Unlike several other detections in this project, the Security Audit Log Cleared detection was **not intentionally triggered**.

Intentionally clearing the Windows Security log would remove existing security telemetry and could negatively affect the integrity of the lab dataset.

Instead, validation focused on:

1. Confirming that Event ID 1102 was not already present.
2. Confirming that the Splunk detection query was correctly configured.
3. Confirming that the scheduled alert was configured.
4. Confirming that the dashboard could monitor the event count.

This provides a safer method of validating the detection without deliberately destroying security evidence.

---

# Windows Event Check

The Windows Security log was checked for Event ID 1102 using:

```powershell
Get-WinEvent -LogName Security -MaxEvents 100 |
Where-Object {$_.Id -eq 1102} |
Select-Object TimeCreated, Id, Message |
Format-List
```

The command returned no output.

This indicated that no Event ID 1102 event was present within the checked Security log entries.

---

# Splunk Validation

The detection was also verified using:

```spl
index=security_lab EventCode=1102
| table _time host EventCode Account_Name Account_Domain
| sort - _time
```

No Event ID 1102 events were available in the current lab dataset.

This was expected because the Windows Security log was not intentionally cleared during testing.

---

# Dashboard Monitoring

The detection was incorporated into the SOC Dashboard as a dedicated Security Audit Log Clears panel.

The dashboard uses:

```spl
index=security_lab EventCode=1102 earliest=-7d latest=now
| stats count as Security_Log_Cleared
```

This provides a single-value count representing the number of detected Security audit-log-clearing events during the selected period.

During the lab validation period, the value was:

```text
0
```

This indicates that no Event ID 1102 events were observed during the selected monitoring period.

---

# Why the Detection Was Not Destructively Triggered

The purpose of the detection is to identify an event that can potentially represent the destruction of forensic evidence.

Generating the event by intentionally clearing the Security log would itself destroy existing Windows Security telemetry.

For this reason, the project used a non-destructive validation approach.

The detection was therefore documented as:

```text
Configured / Not Triggered During Testing
```

This distinction is important because it prevents the portfolio from incorrectly claiming that Event ID 1102 was actually generated during the lab.

---

# Security Relevance

Security audit-log clearing can be significant because Windows Security logs may contain evidence relating to:

- Authentication
- Account management
- Privilege use
- Process execution
- Security configuration
- Other security-relevant activity

An unexpected Event ID 1102 should therefore be treated as a potentially high-priority investigation signal.

---

# SOC Investigation Procedure

If this alert triggers, the analyst should immediately investigate the event.

## 1. Identify the Host

Review:

```text
host
```

Determine which Windows system experienced the log-clearing event.

---

## 2. Identify the Account

Review:

```text
Account_Name
Account_Domain
```

Determine which account performed the action.

---

## 3. Review Authentication Activity

Search for authentication events immediately before the log-clearing event.

Useful events include:

```text
4624 — Successful Logon
4625 — Failed Logon
4672 — Special Privileges Assigned
```

---

## 4. Review Process Creation

Investigate Event ID 4688 around the same timestamp.

Example:

```spl
index=security_lab EventCode=4688 earliest=-15m latest=+15m
| table _time host Account_Name New_Process_Name Process_Command_Line
| sort - _time
```

This can help identify processes executed before or after the log-clearing activity.

---

## 5. Investigate Privilege Activity

Review Event ID 4672:

```spl
index=security_lab EventCode=4672 earliest=-15m latest=+15m
| table _time host Account_Name Account_Domain Logon_ID PrivilegeList
| sort - _time
```

Determine whether the account had elevated privileges.

---

## 6. Review Account Changes

Investigate account-management events around the same period:

```text
4720 — Account Created
4722 — Account Enabled
4725 — Account Disabled
4726 — Account Deleted
4732 — Group Membership Changed
```

---

# Example Correlation Timeline

A suspicious sequence could look like:

```text
4624 Successful Logon
        ↓
4672 Privileged Activity
        ↓
4688 Suspicious Process Creation
        ↓
1102 Security Audit Log Cleared
```

Such a sequence would warrant immediate investigation because it could indicate privileged activity followed by an attempt to remove security evidence.

The presence of Event ID 1102 alone does not prove compromise.

---

# False Positives

Legitimate administrative activity can potentially generate this event.

Possible legitimate scenarios include:

- Authorized security log maintenance
- System administration
- Troubleshooting
- Security configuration activities
- Approved incident-response procedures

However, because clearing the Security log can remove forensic evidence, even potentially legitimate occurrences should be reviewed.

---

# Severity Assessment

**Severity: High**

Event ID 1102 is classified as High because clearing the Security audit log can affect forensic visibility and may be associated with attempts to conceal activity.

The final severity should be determined based on the surrounding context.

Risk is significantly higher when the event occurs alongside:

- Privileged account activity
- Suspicious process creation
- Failed or successful authentication anomalies
- Account manipulation
- Privilege escalation
- Other indicators of compromise

---

# MITRE ATT&CK Relevance

Security log clearing can support investigations involving **Indicator Removal** activity.

A relevant ATT&CK technique is:

```text
T1070 — Indicator Removal
```

The Event ID itself does not prove malicious activity or successful use of an ATT&CK technique. It provides telemetry that can support investigation and correlation.

---

# Evidence

The following evidence was captured:

```text
evidence/screenshots/E-16-security-audit-logs-alert.png
```

The evidence demonstrates the configured Security Audit Log Cleared monitoring and associated Splunk alert configuration.

The evidence does **not** represent a confirmed Event ID 1102 occurrence.

---

# Dashboard Evidence

The SOC Dashboard also contains a dedicated panel for Security Audit Log Clears.

The dashboard uses:

```spl
index=security_lab EventCode=1102 earliest=-7d latest=now
| stats count as Security_Log_Cleared
```

The observed value during validation was:

```text
0
```

This confirms that no Security Audit Log Cleared events were observed during the selected monitoring period.

---

# Validation Summary

The detection successfully demonstrated:

- Windows Security Event ID 1102 identification
- SPL detection logic
- Scheduled alert configuration
- Non-destructive validation
- SOC Dashboard integration
- Security audit-log monitoring
- Investigation and correlation procedures

The event itself was **not intentionally generated**.

---

# Detection Status

**Status: Configured / Not Triggered During Testing**

This status accurately reflects the validation performed during the lab.

The alert is configured and ready to detect Event ID 1102 if it occurs.

No destructive Security log-clearing action was performed solely for testing purposes.

---

# Conclusion

Windows Event ID 1102 is a high-value security monitoring event because clearing the Security audit log can reduce forensic visibility.

The detection was successfully configured in Splunk and incorporated into the SOC Dashboard.

Rather than intentionally clearing the Security log, the project used a non-destructive validation approach to preserve the integrity of the Windows security telemetry.

The resulting detection provides the SOC with an important capability for identifying potential attempts to remove or disrupt security evidence.