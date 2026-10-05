# Detection Engineering Report

## SIEM Security Monitoring Lab

**Platform:** Splunk Enterprise  
**Operating System:** Windows 10 Pro  
**Primary Data Source:** Windows Security Event Log  
**Additional Data Source:** Windows PowerShell Operational Log  
**Splunk Index:** `security_lab`  
**Detection Count:** 10  
**Project:** SIEM & Security Monitoring Lab

---

# 1. Executive Summary

This report documents the detection engineering activities performed as part of the SIEM Security Monitoring Lab.

The project involved deploying Splunk Enterprise as a local Security Information and Event Management (SIEM) platform, ingesting Windows security telemetry, developing detection logic using Splunk Search Processing Language (SPL), configuring scheduled alerts, validating detections using controlled local activity, and creating a SOC monitoring dashboard.

The detection engineering process focused on Windows authentication activity, PowerShell execution, reconnaissance, privileged account activity, account lifecycle changes, privilege changes, process creation, and security audit events.

The project produced ten detection use cases covering Windows Security Event IDs:

- 4625 — Failed Logon
- 4104 — PowerShell Script Block Logging
- 4799 — Security-Enabled Local Group Membership Enumeration
- 4672 — Special Privileges Assigned to New Logon
- 4720 — User Account Created
- 4732 — Member Added to Security-Enabled Local Group
- 4725 — User Account Disabled
- 4722 — User Account Enabled
- 4688 — Process Creation
- 4726 — User Account Deleted
- 1102 — Security Audit Log Cleared

Controlled testing was used where appropriate to verify telemetry ingestion and detection behavior.

The Security Audit Log Cleared detection was configured and documented without intentionally clearing the Windows Security log. This avoided destructive testing while still demonstrating the intended detection logic.

---

# 2. Project Objectives

The primary objectives of the detection engineering phase were to:

1. Establish Windows security telemetry collection in Splunk.
2. Validate that security events were being ingested into the `security_lab` index.
3. Develop practical SOC detection rules using SPL.
4. Configure scheduled Splunk alerts.
5. Validate detection logic using controlled local activity.
6. Capture evidence of detection and alert behavior.
7. Develop analyst response guidance for each detection.
8. Build a centralized SOC monitoring dashboard.

---

# 3. SIEM Environment

## 3.1 Technology Stack

| Component | Technology |
|---|---|
| SIEM | Splunk Enterprise 10.6.0.5 |
| Operating System | Windows 10 Pro |
| Security Telemetry | Windows Security Event Log |
| PowerShell Telemetry | PowerShell Operational Log |
| Query Language | Splunk SPL |
| Primary Index | `security_lab` |
| Dashboard | Splunk Classic Dashboard |
| Testing Environment | Local Windows lab |

---

# 4. Telemetry Collection

## 4.1 Windows Security Log

Windows Security events were configured to be ingested into the Splunk index:

```text
security_lab
```

The collected telemetry included authentication, privilege, account management, process creation, group enumeration, and security audit events.

Initial telemetry verification demonstrated that Windows Security events were successfully being indexed by Splunk.

---

## 4.2 PowerShell Operational Log

PowerShell Operational logging was configured using:

```ini
[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = security_lab
```

This provided visibility into PowerShell Script Block Logging events, including Event ID 4104.

---

# 5. Detection Summary

| ID | Detection | Event ID | Severity | Status |
|---|---|---:|---|---|
| DET-01 | Repeated Failed Logons | 4625 | Medium | Validated |
| DET-02 | Suspicious PowerShell Script Block Activity | 4104 | High | Validated |
| DET-03 | Repeated Group Enumeration | 4799 | Medium | Validated |
| DET-04 | Privileged Account Activity | 4672 | Medium | Validated |
| DET-05 | User Account Creation | 4720 | High | Validated |
| DET-06 | Privileged Group Membership Change | 4732 | High | Validated |
| DET-07 | Account Disabled/Enabled | 4725/4722 | Medium | Validated |
| DET-08 | Process Creation | 4688 | Informational/Monitoring | Validated |
| DET-09 | User Account Deletion | 4726 | High | Validated |
| DET-10 | Security Audit Log Cleared | 1102 | High | Configured / Not Triggered |

---

# 6. Detection 01 — Repeated Failed Logons

## Objective

Identify repeated Windows authentication failures that may indicate password guessing, brute-force activity, credential misuse, or unauthorized access attempts.

## Event

```text
Event ID: 4625
```

## Detection Logic

The detection groups failed logon events into five-minute windows and identifies three or more failures from the same workstation.

```spl
index=security_lab EventCode=4625
| bin _time span=5m
| stats count as failed_logons values(Account_Name) as accounts values(Failure_Reason) as failure_reasons by _time Workstation_Name
| where failed_logons >= 3
| sort - _time
```

## Alert Configuration

| Setting | Value |
|---|---|
| Alert Name | Windows - Repeated Failed Logons |
| Type | Scheduled |
| Schedule | Every 5 minutes |
| Trigger | Number of Results > 0 |
| Trigger Behavior | Once |
| Action | Add to Triggered Alerts |

## Validation

A controlled failed authentication test was performed using:

```powershell
net use \\127.0.0.1\IPC$ /user:.\SIEM_TEST_NOTREAL WrongPassword123!
```

The command was executed three times.

The resulting telemetry included:

```text
Event ID: 4625
Account: SIEM_TEST_NOTREAL
Failure Reason: Unknown user name or bad password.
Workstation: MODUPE
```

The Splunk detection identified the three failed logons within the five-minute threshold.

The scheduled alert successfully triggered.

## Analyst Response

An analyst should:

1. Identify the source workstation.
2. Identify the targeted account.
3. Review the authentication failure reason.
4. Check for successful logons around the same time.
5. Review source IP information where available.
6. Determine whether the activity is legitimate.
7. Correlate with other security events.
8. Escalate suspicious authentication activity.

## Evidence

```text
evidence/screenshots/E-01-repeated-failed-logon-alert.png
```

## Status

**Validated**

---

# 7. Detection 02 — Suspicious PowerShell Script Block Activity

## Objective

Identify potentially suspicious PowerShell activity using Script Block Logging.

## Event

```text
Event ID: 4104
```

## Detection Logic

```spl
index=security_lab EventCode=4104 earliest=-5m latest=now
| eval suspicious=if(match(Message,"(?i)(invoke-expression|invoke-webrequest|downloadstring|frombase64string|encodedcommand|net\.webclient|start-bitstransfer|\biex\b)"),1,0)
| where suspicious=1
| table _time host EventCode Message
| sort - _time
```

## Indicators

The detection searches for indicators including:

- `Invoke-Expression`
- `Invoke-WebRequest`
- `DownloadString`
- `FromBase64String`
- `EncodedCommand`
- `Net.WebClient`
- `Start-BitsTransfer`
- `IEX`

These indicators are treated as investigation signals rather than automatic proof of malicious activity.

## Alert Configuration

| Setting | Value |
|---|---|
| Alert Name | PowerShell - Suspicious Script Block Activity |
| Type | Scheduled |
| Schedule | Every 5 minutes |
| Severity | High |
| Trigger | Number of Results > 0 |
| Trigger Behavior | Once |
| Action | Add to Triggered Alerts |

## Validation

A harmless controlled PowerShell test generated Event ID 4104 telemetry containing:

```powershell
Write-Output "SIEM-LAB-4104-TEST Invoke-WebRequest"
```

The specific event was verified in Splunk using:

```spl
index=security_lab EventCode=4104 "SIEM-LAB-4104-TEST"
```

The suspicious PowerShell detection identified the event because of the `Invoke-WebRequest` indicator.

The scheduled alert successfully triggered.

## Analyst Response

An analyst should:

1. Review the complete Event 4104 script block.
2. Identify the user and host.
3. Determine whether the execution was expected.
4. Investigate download and execution indicators.
5. Correlate with Event 4688.
6. Review authentication and privilege activity.
7. Determine whether the activity is legitimate or suspicious.
8. Escalate confirmed malicious activity.

## Evidence

```text
evidence/screenshots/E-02-powershell-script-block-logging.png
evidence/screenshots/E-03-powershell-suspicious-script-block.png
evidence/screenshots/E-04-powershell-alert-triggered.png
```

## Status

**Validated**

---

# 8. Detection 03 — Repeated Group Enumeration

## Objective

Identify repeated enumeration of security-enabled local group membership.

## Event

```text
Event ID: 4799
```

## Detection Logic

```spl
index=security_lab EventCode=4799 earliest=-5m latest=now
| bin _time span=5m
| stats count as group_enumerations values(Process_Name) as processes values(Account_Name) as accounts by _time host
| where group_enumerations >= 5
| sort - _time
```

## Threshold

Five or more Event ID 4799 events within a five-minute window.

## Alert Configuration

| Setting | Value |
|---|---|
| Alert Name | Windows - Repeated Group Enumeration |
| Type | Scheduled |
| Schedule | Every 5 minutes |
| Severity | Medium |
| Trigger | Number of Results > 0 |
| Trigger Behavior | Once |
| Action | Add to Triggered Alerts |

## Validation

Repeated local group enumeration was generated using:

```powershell
Get-LocalGroup
```

The activity generated Event ID 4799 events.

The Windows telemetry included:

```text
Event ID: 4799
Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Subject Account: OBAFEFMI-MOSES
Domain: MODUPE
```

The Splunk detection identified the burst of repeated enumeration activity.

The scheduled alert successfully triggered.

## Analyst Response

An analyst should:

1. Identify the host.
2. Identify the user responsible.
3. Review the process performing the enumeration.
4. Determine whether the activity was expected.
5. Correlate with Event 4688.
6. Review privilege-related events.
7. Investigate additional reconnaissance activity.

## Evidence

```text
evidence/screenshots/E-05-windows-group-enumeration-detection.png
evidence/screenshots/E-06-group-enumeration-alert-triggered.png
```

## Status

**Validated**

---

# 9. Detection 04 — Privileged Account Activity

## Objective

Identify privileged Windows logon activity involving accounts other than `SYSTEM`.

## Event

```text
Event ID: 4672
```

## Detection Logic

```spl
index=security_lab EventCode=4672 earliest=-5m latest=now
| where Account_Name!="SYSTEM"
| table _time host EventCode Account_Name Account_Domain Logon_ID SubjectUserName SubjectDomainName PrivilegeList
| sort - _time
```

## Alert Configuration

| Setting | Value |
|---|---|
| Alert Name | Windows - Privileged Account Activity |
| Type | Scheduled |
| Schedule | Every 5 minutes |
| Severity | Medium |
| Trigger | Number of Results > 0 |
| Trigger Behavior | Once |
| Action | Add to Triggered Alerts |

## Validation

Analysis of Event 4672 showed a large volume of expected `SYSTEM` activity.

The detection was refined to exclude:

```text
Account_Name="SYSTEM"
```

A non-SYSTEM event associated with the interactive account was identified:

```text
Account: OBAFEFMI-MOSES
Domain: MODUPE
Logon ID: 0xB806C80
```

The Splunk alert successfully triggered on the non-SYSTEM activity.

## Analyst Response

An analyst should:

1. Identify the privileged account.
2. Determine whether the account should have elevated privileges.
3. Review the Logon ID.
4. Review the privilege list.
5. Correlate with process creation.
6. Review account and group changes.
7. Investigate unexplained privileged activity.

## Evidence

```text
evidence/screenshots/E-07-privileged-account-activity.png
evidence/screenshots/E-08-privileged-account-alert-triggered.png
```

## Status

**Validated**

---

# 10. Detection 05 — User Account Creation

## Objective

Detect the creation of new Windows user accounts.

## Event

```text
Event ID: 4720
```

## Detection Logic

```spl
index=security_lab EventCode=4720 earliest=-10m latest=now
| table _time host EventCode Account_Name TargetUserName TargetDomainName
| sort - _time
```

## Alert Configuration

| Setting | Value |
|---|---|
| Alert Name | Windows - User Account Creation |
| Type | Scheduled |
| Schedule | Every 5 minutes |
| Severity | High |
| Trigger | Number of Results > 0 |
| Trigger Behavior | Once |
| Action | Add to Triggered Alerts |

## Validation

A controlled temporary account was created:

```powershell
net user SIEM_TEST_USER_05 "TempPass!2026" /add
```

Windows generated Event ID 4720.

The event identified:

```text
Target Account: SIEM_TEST_USER_05
Created By: OBAFEFMI-MOSES
Host/Domain: MODUPE
```

Splunk successfully ingested and identified the event.

The scheduled alert successfully triggered.

## Analyst Response

An analyst should:

1. Identify the new account.
2. Identify who created it.
3. Determine whether the creation was authorized.
4. Review group memberships.
5. Check whether administrative privileges were assigned.
6. Review authentication activity.
7. Correlate with Event 4732.
8. Escalate unauthorized account creation.

## Evidence

```text
evidence/screenshots/E-09-user-account-creation-alert.png
```

## Status

**Validated**

---

# 11. Detection 06 — Privileged Group Membership Change

## Objective

Detect additions to security-enabled local groups, particularly privileged groups such as Administrators.

## Event

```text
Event ID: 4732
```

## Detection Logic

```spl
index=security_lab EventCode=4732
| table _time host EventCode Account_Name MemberName TargetUserName TargetDomainName
| sort - _time
```

## Alert Configuration

| Setting | Value |
|---|---|
| Alert Name | Windows - Privileged Group Membership Change |
| Type | Scheduled |
| Schedule | Every 5 minutes |
| Severity | High |
| Trigger | Number of Results > 0 |
| Trigger Behavior | Once |
| Action | Add to Triggered Alerts |

## Validation

The controlled test account was added to the local Administrators group:

```powershell
Add-LocalGroupMember -Group "Administrators" -Member "SIEM_TEST_USER_05"
```

Windows generated Event ID 4732.

The event indicated:

```text
Event ID: 4732
Target Group: Administrators
Subject: OBAFEFMI-MOSES
```

Splunk successfully identified the event and the scheduled alert triggered.

## Cleanup

The temporary account was removed from the Administrators group after validation:

```powershell
Remove-LocalGroupMember -Group "Administrators" -Member "SIEM_TEST_USER_05"
```

## Analyst Response

An analyst should:

1. Identify the account added.
2. Identify the affected group.
3. Identify who performed the change.
4. Determine whether the change was authorized.
5. Review subsequent privileged activity.
6. Correlate with Event 4672.
7. Review Event 4688 for suspicious process execution.
8. Escalate unexplained privilege changes.

## Evidence

```text
evidence/screenshots/E-10-privileged-group-membership-change.png
evidence/screenshots/E-11-privileged-group-membership-change.png
```

## Status

**Validated**

---

# 12. Detection 07 — Account Disabled or Enabled

## Objective

Detect Windows user account state changes.

## Events

```text
Event ID 4725 — User Account Disabled
Event ID 4722 — User Account Enabled
```

## Detection Logic

```spl
index=security_lab (EventCode=4725 OR EventCode=4722)
| table _time host EventCode Account_Name TargetUserName TargetDomainName
| sort - _time
```

## Alert Configuration

| Setting | Value |
|---|---|
| Alert Name | Windows - Account Disabled or Enabled |
| Type | Scheduled |
| Schedule | Every 5 minutes |
| Severity | Medium |
| Trigger | Number of Results > 0 |
| Trigger Behavior | Once |
| Action | Add to Triggered Alerts |

## Validation

The controlled test account was disabled using:

```powershell
Disable-LocalUser -Name "SIEM_TEST_USER_05"
```

Windows generated Event ID 4725.

The account was subsequently enabled during testing using:

```powershell
Enable-LocalUser -Name "SIEM_TEST_USER_05"
```

The resulting telemetry included both Event IDs 4725 and 4722.

Splunk successfully identified the account state changes and the scheduled alert triggered.

## Analyst Response

An analyst should:

1. Identify the affected account.
2. Identify who performed the change.
3. Determine whether the state change was authorized.
4. Review surrounding authentication events.
5. Check whether the account is privileged.
6. Investigate unexpected disabling or enabling activity.

## Evidence

```text
evidence/screenshots/E-12-account-disabled-enabled.png
evidence/screenshots/E-13-account-disabled-enabled-alert.png
```

## Status

**Validated**

---

# 13. Detection 08 — Process Creation Monitoring

## Objective

Monitor Windows process creation activity and provide visibility into executable execution on the host.

## Event

```text
Event ID: 4688
```

## Telemetry Configuration

Windows Process Creation auditing was enabled using:

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
```

The configuration was verified using:

```powershell
auditpol /get /subcategory:"Process Creation"
```

## Detection Logic

```spl
index=security_lab EventCode=4688
| table _time host EventCode Account_Name New_Process_Name Process_Command_Line
| sort - _time
```

## Controlled Validation

A harmless process was launched:

```powershell
Start-Process notepad.exe
```

This generated Windows Event ID 4688 telemetry.

The resulting Splunk search identified the process:

```spl
index=security_lab EventCode=4688
| search New_Process_Name="*\\notepad.exe"
| table _time host EventCode Account_Name New_Process_Name Process_Command_Line
| sort - _time
```

The event demonstrated successful process creation telemetry and Splunk ingestion.

## Alert Configuration

| Setting | Value |
|---|---|
| Alert Name | Windows - Process Creation Monitoring |
| Type | Scheduled |
| Schedule | Every 5 minutes |
| Time Range | Last 5 minutes |
| Trigger | Number of Results > 0 |
| Trigger Behavior | Once |
| Action | Add to Triggered Alerts |

## Analyst Response

Process creation events should be investigated in context.

An analyst should review:

1. Process name.
2. Parent process where available.
3. Command line.
4. Executing account.
5. Host.
6. Process timing.
7. Related PowerShell activity.
8. Related authentication events.

## Evidence

```text
evidence/screenshots/E-14-process-creation-alert.png
```

## Status

**Validated**

---

# 14. Detection 09 — User Account Deletion

## Objective

Detect deletion of Windows user accounts.

## Event

```text
Event ID: 4726
```

## Detection Logic

```spl
index=security_lab EventCode=4726
| table _time host EventCode Account_Name TargetUserName TargetDomainName
| sort - _time
```

## Alert Configuration

| Setting | Value |
|---|---|
| Alert Name | Windows - User Account Deletion |
| Type | Scheduled |
| Schedule | Every 5 minutes |
| Time Range | Last 5 minutes |
| Trigger | Number of Results > 0 |
| Trigger Behavior | Once |
| Action | Add to Triggered Alerts |

## Validation

The temporary SIEM test account was deleted after the account lifecycle testing:

```powershell
Remove-LocalUser -Name "SIEM_TEST_USER_05"
```

Windows generated Event ID 4726.

The event recorded:

```text
Event ID: 4726
Target Account: SIEM_TEST_USER_05
Subject: OBAFEFMI-MOSES
```

Splunk successfully identified the account deletion event.

## Analyst Response

An analyst should:

1. Identify the deleted account.
2. Identify who performed the deletion.
3. Determine whether deletion was authorized.
4. Review the account's previous activity.
5. Check whether the account was privileged.
6. Correlate the deletion with account creation and group membership events.

## Evidence

```text
evidence/screenshots/E-15-user-account-deletion-alert.png
```

## Status

**Validated**

---

# 15. Detection 10 — Security Audit Log Cleared

## Objective

Detect attempts to clear the Windows Security audit log.

## Event

```text
Event ID: 1102
```

## Security Importance

Clearing the Windows Security audit log can remove forensic evidence and may be associated with attempts to conceal malicious activity.

Event ID 1102 therefore represents a high-value security monitoring event.

## Detection Logic

```spl
index=security_lab EventCode=1102
| table _time host EventCode Account_Name Account_Domain
| sort - _time
```

## Alert Configuration

| Setting | Value |
|---|---|
| Alert Name | Windows - Security Audit Log Cleared |
| Type | Scheduled |
| Schedule | Every 5 minutes |
| Severity | High |
| Time Range | Last 5 minutes |
| Trigger | Number of Results > 0 |
| Trigger Behavior | Once |
| Action | Add to Triggered Alerts |

## Validation Method

The Windows Security log was checked for Event ID 1102 using:

```powershell
Get-WinEvent -LogName Security -MaxEvents 100 |
Where-Object {$_.Id -eq 1102} |
Select-Object TimeCreated, Id, Message |
Format-List
```

No Event ID 1102 event was present in the checked Security log entries.

The Security audit log was **not intentionally cleared** solely to generate a test event.

This decision prevented the destruction of existing Windows Security telemetry and preserved the integrity of the lab dataset.

## Detection Status

The detection was successfully configured in Splunk.

However, because no Event ID 1102 occurred during testing, the detection should not be represented as an actively triggered detection.

The appropriate status is:

**Configured — Not Triggered During Testing**

## Analyst Response

If Event ID 1102 is detected, an analyst should immediately investigate:

1. Which account cleared the log.
2. The affected host.
3. The timestamp.
4. Authentication activity before the event.
5. Process creation around the event.
6. Privilege changes.
7. Other indicators of compromise.
8. Whether the action was authorized administrative maintenance.

The event should be treated as a potentially high-priority investigation signal.

## Evidence

```text
evidence/screenshots/E-16-security-audit-logs-alert.png
```

## Status

**Configured / Not Triggered**

---

# 16. Detection Engineering Methodology

The project followed a repeatable detection engineering workflow:

```text
Telemetry Source
      ↓
Event Identification
      ↓
SPL Detection Logic
      ↓
Threshold / Filtering
      ↓
Scheduled Alert
      ↓
Controlled Validation
      ↓
Evidence Capture
      ↓
Analyst Response Guidance
```

This workflow was applied across authentication, PowerShell, reconnaissance, privilege, account management, process creation, and audit events.

---

# 17. Validation Approach

Controlled testing was performed locally to generate representative Windows security telemetry.

Testing included:

- Controlled failed authentication attempts
- Harmless PowerShell Script Block activity
- Local group enumeration
- Privileged account telemetry analysis
- Temporary user account creation
- Temporary privileged group membership
- Account disabling and enabling
- Harmless process execution
- Temporary account deletion

Destructive actions were avoided where they were unnecessary.

In particular, the Windows Security audit log was not intentionally cleared to generate Event ID 1102.

---

# 18. Detection Engineering Considerations

## False Positives

Several detections can legitimately occur during normal Windows administration.

Examples include:

- Failed logons caused by incorrect credentials
- PowerShell commands used by administrators
- Local group enumeration performed by security tools
- Privileged account activity
- Authorized account creation
- Approved group membership changes
- Legitimate process execution

Therefore, the detections should be treated as **investigation signals** rather than automatic proof of compromise.

---

## Correlation

Individual events become more useful when correlated with additional telemetry.

For example:

```text
4625 Failed Logon
        +
4624 Successful Logon
        +
4672 Privileged Activity
        +
4688 Process Creation
```

may provide significantly more useful investigative context than any single event alone.

Similarly:

```text
4720 Account Created
        +
4732 Group Membership Changed
        +
4672 Privileged Activity
```

could represent a potentially important account and privilege escalation sequence.

---

# 19. Evidence Register

| Evidence | Filename | Purpose |
|---|---|---|
| E-01 | `E-01-repeated-failed-logon-alert.png` | Failed logon detection/alert |
| E-02 | `E-02-powershell-script-block-logging.png` | PowerShell 4104 telemetry |
| E-03 | `E-03-powershell-suspicious-script-block.png` | Suspicious PowerShell detection |
| E-04 | `E-04-powershell-alert-triggered.png` | PowerShell alert trigger |
| E-05 | `E-05-windows-group-enumeration-detection.png` | Group enumeration detection |
| E-06 | `E-06-group-enumeration-alert-triggered.png` | Group enumeration alert |
| E-07 | `E-07-privileged-account-activity.png` | Privileged account detection |
| E-08 | `E-08-privileged-account-alert-triggered.png` | Privileged account alert |
| E-09 | `E-09-user-account-creation-alert.png` | User account creation |
| E-10 | `E-10-privileged-group-membership-change.png` | Privileged group membership |
| E-11 | `E-11-privileged-group-membership-change.png` | Privileged group membership evidence |
| E-12 | `E-12-account-disabled-enabled.png` | Account state change detection |
| E-13 | `E-13-account-disabled-enabled-alert.png` | Account state change alert |
| E-14 | `E-14-process-creation-alert.png` | Process creation |
| E-15 | `E-15-user-account-deletion-alert.png` | User account deletion |
| E-16 | `E-16-security-audit-logs-alert.png` | Security log clearing detection |
| — | `soc-dashboard.png` | SOC dashboard |

---

# 20. Overall Detection Status

The project successfully implemented a collection of Windows-focused SIEM detections covering:

- Authentication monitoring
- PowerShell monitoring
- Host reconnaissance
- Privileged account activity
- Account lifecycle monitoring
- Privilege escalation indicators
- Process creation
- Security audit monitoring

Nine detections were validated through controlled lab activity.

The Security Audit Log Cleared detection was configured and documented but was not intentionally triggered because doing so would require clearing the Windows Security log and potentially destroying existing telemetry.

---

# 21. Conclusion

The SIEM Security Monitoring Lab demonstrates the practical implementation of a Windows-focused detection engineering workflow using Splunk Enterprise.

The project progressed beyond basic SIEM installation by incorporating:

- Windows telemetry collection
- SPL-based detection engineering
- Threshold-based behavioral detection
- Scheduled alerting
- Controlled validation
- Evidence collection
- SOC analyst response procedures
- False-positive considerations
- Detection limitations
- Centralized dashboard monitoring

The resulting detection set provides a practical foundation for a Security Operations Center monitoring workflow and demonstrates hands-on experience with SIEM operations, Windows security telemetry, SPL, alert engineering, and security investigation.