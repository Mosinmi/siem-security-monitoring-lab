# Evidence Log

## SIEM Security Monitoring Lab

This evidence log maps the screenshots collected during the SIEM Security Monitoring Lab to the corresponding detection, test activity, and security objective.

---

# Evidence Summary

| Evidence ID | Detection / Activity | Evidence File | Purpose |
|---|---|---|---|
| E-01 | Repeated Failed Logons | `E-01-repeated-failed-logon-alert.png` | Demonstrates failed-logon detection and alerting |
| E-02 | PowerShell Script Block Logging | `E-02-powershell-script-block-logging.png` | Demonstrates Event ID 4104 telemetry |
| E-03 | Suspicious PowerShell | `E-03-powershell-suspicious-script-block.png` | Demonstrates suspicious PowerShell detection |
| E-04 | PowerShell Alert | `E-04-powershell-alert-triggered.png` | Demonstrates alert triggering |
| E-05 | Group Enumeration | `E-05-windows-group-enumeration-detection.png` | Demonstrates Event ID 4799 detection |
| E-06 | Group Enumeration Alert | `E-06-group-enumeration-alert-triggered.png` | Demonstrates alert triggering |
| E-07 | Privileged Account Activity | `E-07-privileged-account-activity.png` | Demonstrates Event ID 4672 monitoring |
| E-08 | Privileged Account Alert | `E-08-privileged-account-alert-triggered.png` | Demonstrates alert triggering |
| E-09 | User Account Creation | `E-09-user-account-creation-alert.png` | Demonstrates Event ID 4720 monitoring |
| E-10 | Privileged Group Membership | `E-10-privileged-group-membership-change.png` | Demonstrates Event ID 4732 activity |
| E-11 | Privileged Group Membership | `E-11-privileged-group-membership-change.png` | Additional evidence for Event ID 4732 |
| E-12 | Account Disabled/Enabled | `E-12-account-disabled-enabled.png` | Demonstrates Events 4725/4722 |
| E-13 | Account Disabled/Enabled Alert | `E-13-account-disabled-enabled-alert.png` | Demonstrates alert triggering |
| E-14 | Process Creation | `E-14-process-creation-alert.png` | Demonstrates Event ID 4688 monitoring |
| E-15 | User Account Deletion | `E-15-user-account-deletion-alert.png` | Demonstrates Event ID 4726 monitoring |
| E-16 | Security Audit Log Cleared | `E-16-security-audit-logs-alert.png` | Demonstrates Event ID 1102 alert configuration |
| — | SOC Dashboard | `soc-dashboard.png` | Demonstrates centralized monitoring |

---

# E-01 — Repeated Failed Logons

**Detection:** Windows - Repeated Failed Logons

**Event ID:**

```text
4625
```

**Evidence:**

```text
E-01-repeated-failed-logon-alert.png
```

**Purpose:**

Demonstrates the Splunk detection and alerting workflow for repeated Windows failed logon activity.

**Validation:**

A controlled failed authentication test was performed using the temporary SIEM testing environment.

---

# E-02 — PowerShell Script Block Logging

**Detection:** PowerShell Script Block Logging

**Event ID:**

```text
4104
```

**Evidence:**

```text
E-02-powershell-script-block-logging.png
```

**Purpose:**

Demonstrates that Windows PowerShell Script Block Logging was active and that Event ID 4104 telemetry was available for ingestion into Splunk.

---

# E-03 — Suspicious PowerShell Script Block

**Detection:** PowerShell - Suspicious Script Block Activity

**Event ID:**

```text
4104
```

**Evidence:**

```text
E-03-powershell-suspicious-script-block.png
```

**Purpose:**

Demonstrates the detection of potentially suspicious PowerShell indicators within Event ID 4104.

**Controlled Test Indicator:**

```text
Invoke-WebRequest
```

The test was intentionally harmless and did not perform an actual web request.

---

# E-04 — PowerShell Alert Triggered

**Detection:** PowerShell - Suspicious Script Block Activity

**Evidence:**

```text
E-04-powershell-alert-triggered.png
```

**Purpose:**

Demonstrates successful Splunk alert triggering after the suspicious PowerShell detection identified the controlled test activity.

---

# E-05 — Windows Group Enumeration Detection

**Detection:** Windows - Repeated Group Enumeration

**Event ID:**

```text
4799
```

**Evidence:**

```text
E-05-windows-group-enumeration-detection.png
```

**Purpose:**

Demonstrates detection of repeated enumeration of security-enabled local group membership.

**Controlled Activity:**

```powershell
Get-LocalGroup
```

---

# E-06 — Group Enumeration Alert

**Detection:** Windows - Repeated Group Enumeration

**Evidence:**

```text
E-06-group-enumeration-alert-triggered.png
```

**Purpose:**

Demonstrates that the configured scheduled alert successfully triggered after the group-enumeration threshold was reached.

---

# E-07 — Privileged Account Activity

**Detection:** Windows - Privileged Account Activity

**Event ID:**

```text
4672
```

**Evidence:**

```text
E-07-privileged-account-activity.png
```

**Purpose:**

Demonstrates monitoring of privileged Windows account activity while filtering expected `SYSTEM` activity.

---

# E-08 — Privileged Account Alert

**Detection:** Windows - Privileged Account Activity

**Evidence:**

```text
E-08-privileged-account-alert-triggered.png
```

**Purpose:**

Demonstrates successful alert triggering for non-SYSTEM privileged account activity.

---

# E-09 — User Account Creation

**Detection:** Windows - User Account Creation

**Event ID:**

```text
4720
```

**Evidence:**

```text
E-09-user-account-creation-alert.png
```

**Purpose:**

Demonstrates detection of a newly created Windows user account.

**Controlled Test Account:**

```text
SIEM_TEST_USER_05
```

**Creation Command:**

```powershell
net user SIEM_TEST_USER_05 "TempPass!2026" /add
```

---

# E-10 — Privileged Group Membership Change

**Detection:** Windows - Privileged Group Membership Change

**Event ID:**

```text
4732
```

**Evidence:**

```text
E-10-privileged-group-membership-change.png
```

**Purpose:**

Demonstrates detection of an account being added to a security-enabled local group.

**Controlled Test:**

```powershell
Add-LocalGroupMember -Group "Administrators" -Member "SIEM_TEST_USER_05"
```

---

# E-11 — Privileged Group Membership Alert

**Detection:** Windows - Privileged Group Membership Change

**Event ID:**

```text
4732
```

**Evidence:**

```text
E-11-privileged-group-membership-change.png
```

**Purpose:**

Provides additional evidence of the privileged group membership detection and alerting workflow.

---

# E-12 — Account Disabled/Enabled

**Detection:** Windows - Account Disabled or Enabled

**Event IDs:**

```text
4725 — Account Disabled
4722 — Account Enabled
```

**Evidence:**

```text
E-12-account-disabled-enabled.png
```

**Purpose:**

Demonstrates monitoring of Windows account state changes.

**Controlled Test:**

```powershell
Disable-LocalUser -Name "SIEM_TEST_USER_05"
```

and:

```powershell
Enable-LocalUser -Name "SIEM_TEST_USER_05"
```

---

# E-13 — Account Disabled/Enabled Alert

**Detection:** Windows - Account Disabled or Enabled

**Evidence:**

```text
E-13-account-disabled-enabled-alert.png
```

**Purpose:**

Demonstrates successful alerting for Windows account state changes.

---

# E-14 — Process Creation

**Detection:** Windows - Process Creation Monitoring

**Event ID:**

```text
4688
```

**Evidence:**

```text
E-14-process-creation-alert.png
```

**Purpose:**

Demonstrates Windows process creation monitoring.

**Controlled Test:**

```powershell
Start-Process notepad.exe
```

Process Creation auditing was enabled using:

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
```

---

# E-15 — User Account Deletion

**Detection:** Windows - User Account Deletion

**Event ID:**

```text
4726
```

**Evidence:**

```text
E-15-user-account-deletion-alert.png
```

**Purpose:**

Demonstrates detection of Windows user account deletion.

**Controlled Test:**

```powershell
Remove-LocalUser -Name "SIEM_TEST_USER_05"
```

The event identified the deletion of the temporary test account.

---

# E-16 — Security Audit Log Cleared

**Detection:** Windows - Security Audit Log Cleared

**Event ID:**

```text
1102
```

**Evidence:**

```text
E-16-security-audit-logs-alert.png
```

**Purpose:**

Demonstrates the configured Event ID 1102 detection and alerting capability.

**Important Validation Note:**

The Windows Security audit log was **not intentionally cleared** during testing.

The evidence demonstrates the alert configuration rather than a confirmed Event ID 1102 occurrence.

The detection status is therefore:

```text
Configured / Not Triggered During Testing
```

---

# SOC Dashboard Evidence

**Dashboard:**

```text
SOC Dashboard
```

**Evidence:**

```text
soc-dashboard.png
```

**Purpose:**

Demonstrates centralized visualization of Windows security telemetry and detection activity.

The dashboard contains monitoring panels for:

- Failed Logons
- PowerShell Script Block Activity
- Local Group Enumeration
- Privileged Account Activity
- Windows Account and Privilege Changes
- Process Creation
- Security Audit Log Clears

---

# Evidence Handling

All screenshots were captured from the local Splunk and Windows security-monitoring environment.

The evidence was retained as part of the project repository to demonstrate:

```text
Telemetry
   ↓
Detection
   ↓
Alert
   ↓
Investigation
   ↓
Response
```

The evidence is intended for portfolio and laboratory documentation rather than as forensic evidence from a production incident.

---

# Evidence Integrity

The screenshots document controlled testing performed within the local cybersecurity laboratory.

No real-world victim, production system, or unauthorized external target was used during the detection validation process.

---

# Evidence Summary

The evidence set demonstrates the implementation of a complete Windows-focused SIEM monitoring workflow using Splunk:

```text
Windows Security Logs
        ↓
PowerShell Logs
        ↓
Splunk Ingestion
        ↓
SPL Detection Rules
        ↓
Scheduled Alerts
        ↓
SOC Dashboard
        ↓
Investigation
        ↓
Remediation
```

The evidence collection therefore supports the project's objective of demonstrating practical SIEM monitoring and SOC detection engineering capabilities.