# SIEM Security Monitoring & Detection Engineering Lab

## Overview

This project demonstrates the design and implementation of a **Security Information and Event Management (SIEM)** monitoring environment using **Splunk Enterprise** on a Windows workstation.

The lab was designed to simulate core activities performed by a **Security Operations Center (SOC) analyst**, including security telemetry collection, detection engineering, alert configuration, investigation, incident response, remediation, and security monitoring through a centralized dashboard.

The project uses Windows Security and PowerShell telemetry to develop and validate **10 security detections** covering authentication activity, PowerShell execution, account and privilege changes, process creation, group enumeration, and security audit log manipulation.

All suspicious activity used for validation was **deliberately generated in a controlled local laboratory environment**. No real compromise or malicious activity was involved.

---

## Objectives

The primary objectives of this project were to:

- Deploy and configure Splunk Enterprise as a local SIEM.
- Collect Windows security telemetry into a dedicated Splunk index.
- Develop practical security detections using SPL.
- Configure scheduled alerts and trigger conditions.
- Generate controlled security events to validate detections.
- Investigate security events using Splunk searches.
- Build a SOC monitoring dashboard.
- Document incident response procedures.
- Develop remediation and containment procedures.
- Maintain structured evidence for every detection.
- Demonstrate practical SOC analyst and detection engineering skills.

---

## Lab Architecture

```text
                         ┌──────────────────────────┐
                         │      Windows Host        │
                         │                          │
                         │  Windows Security Logs   │
                         │  PowerShell Logs         │
                         │  Process Creation        │
                         │  Account Activity        |
                         └────────────┬─────────────┘
                                      │
                                      │ Windows Event Logs
                                      ▼
                         ┌──────────────────────────┐
                         │     Splunk Enterprise    │
                         │        Version 10.6      │
                         │                          │
                         │     Index: security_lab  │
                         └────────────┬─────────────┘
                                      │
                         ┌────────────┴─────────────┐
                         │                          │
                         ▼                          ▼
                ┌─────────────────┐       ┌──────────────────┐
                │ Detection       │       │ SOC Dashboard    │
                │ Engineering     │       │                  │
                │                 │       │ Event Trends     │
                │ SPL Rules       │       │ Account Activity │
                │ Scheduled Alerts│       │ PowerShell       │
                └────────┬────────┘       │ Process Creation │
                         │                └──────────────────┘
                         ▼
                ┌─────────────────┐
                │ Alert & Incident│
                │ Investigation   │
                │                 │
                │ Triage          │
                │ Containment     │
                │ Remediation     │
                └─────────────────┘
```

---

## Environment

| Component | Configuration |
|---|---|
| Operating System | Windows 10 Pro 22H2 |
| SIEM | Splunk Enterprise 10.6.0.5 |
| SIEM Index | `security_lab` |
| Host | Local Windows workstation |
| PowerShell | Windows PowerShell |
| Event Sources | Windows Security / PowerShell Operational |
| Dashboard | Splunk Classic Dashboard |
| Virtualization | WSL2 / Docker environment available |
| Test Environment | Local isolated laboratory |

The Splunk installation used a local trial license with a **500 MB daily ingestion limit**.

---

## Technologies & Tools

- **Splunk Enterprise**
- **Splunk Search Processing Language (SPL)**
- **Windows Event Viewer**
- **Windows Security Event Logs**
- **PowerShell**
- **Windows Audit Policy**
- **Windows Event IDs**
- **Scheduled SIEM Alerts**
- **Splunk Classic Dashboards**
- **Windows command-line utilities**

---

# Telemetry Sources

The lab collected and analyzed Windows security telemetry associated with several security-relevant activities.

### Windows Security Events

The following Windows Event IDs were used throughout the project:

| Event ID | Activity |
|---:|---|
| 4625 | Failed Logon |
| 4672 | Special Privileges Assigned to New Logon |
| 4688 | Process Creation |
| 4720 | User Account Created |
| 4722 | User Account Enabled |
| 4725 | User Account Disabled |
| 4726 | User Account Deleted |
| 4732 | Member Added to Security-Enabled Local Group |
| 4799 | Security-Enabled Local Group Membership Enumeration |
| 1102 | Security Audit Log Cleared |

### PowerShell Telemetry

PowerShell **Event ID 4104** was monitored to identify potentially suspicious PowerShell Script Block activity.

Script Block Logging was verified on the host and ingested into the `security_lab` Splunk index.

---

# Detection Engineering

A total of **10 security detections** were developed and validated.

Each detection was implemented using SPL and, where appropriate, configured as a scheduled Splunk alert.

## Detection Summary

| # | Detection | Event ID | Severity | Validation |
|---:|---|---:|---|---|
| 01 | Repeated Failed Logons | 4625 | Medium | Validated |
| 02 | Suspicious PowerShell Script Block | 4104 | High | Validated |
| 03 | Repeated Group Enumeration | 4799 | Medium | Validated |
| 04 | Privileged Account Activity | 4672 | Medium | Validated |
| 05 | User Account Creation | 4720 | High | Validated |
| 06 | Privileged Group Membership Change | 4732 | High | Validated |
| 07 | Account Disabled or Enabled | 4725 / 4722 | Medium | Validated |
| 08 | Process Creation Monitoring | 4688 | — | Validated |
| 09 | User Account Deletion | 4726 | — | Validated |
| 10 | Security Audit Log Cleared | 1102 | High | Configured |

> Severity ratings represent the context assigned to the lab detections and should be tuned according to organizational environment, asset criticality, user context, and additional telemetry.

---

# Detection 01 — Repeated Failed Logons

**Event ID:** 4625

This detection identifies multiple failed Windows logon attempts from the same workstation within a five-minute window.

```spl
index=security_lab EventCode=4625
| bin _time span=5m
| stats count as failed_logons values(Account_Name) as accounts values(Failure_Reason) as failure_reasons by _time Workstation_Name
| where failed_logons >= 3
| sort - _time
```

A controlled authentication test was used to generate multiple failed logon events.

The detection successfully identified a three-event burst involving the controlled test account.

---

# Detection 02 — Suspicious PowerShell Script Block Activity

**Event ID:** 4104

This detection monitors PowerShell Script Block Logging for indicators associated with potentially suspicious execution, downloading, encoding, or payload activity.

```spl
index=security_lab EventCode=4104 earliest=-5m latest=now
| eval suspicious=if(match(Message,"(?i)(invoke-expression|invoke-webrequest|downloadstring|frombase64string|encodedcommand|net\.webclient|start-bitstransfer|\biex\b)"),1,0)
| where suspicious=1
| table _time host EventCode Message
| sort - _time
```

A controlled PowerShell test was used to validate Script Block Logging and the detection logic.

The corresponding Splunk alert was successfully triggered during validation.

---

# Detection 03 — Repeated Windows Group Enumeration

**Event ID:** 4799

This detection identifies repeated enumeration of security-enabled local group membership.

```spl
index=security_lab EventCode=4799 earliest=-5m latest=now
| bin _time span=5m
| stats count as group_enumerations values(Process_Name) as processes values(Account_Name) as accounts by _time host
| where group_enumerations >= 5
| sort - _time
```

A controlled PowerShell test using `Get-LocalGroup` generated repeated group enumeration events.

The resulting event burst was successfully identified by Splunk.

---

# Detection 04 — Privileged Account Activity

**Event ID:** 4672

This detection monitors Windows special privilege assignments while excluding the normal `SYSTEM` account activity.

```spl
index=security_lab EventCode=4672 earliest=-5m latest=now
| where Account_Name!="SYSTEM"
| table _time host EventCode Account_Name Account_Domain Logon_ID SubjectUserName SubjectDomainName PrivilegeList
| sort - _time
```

The detection successfully identified non-SYSTEM privileged account activity generated during the lab.

---

# Detection 05 — Windows User Account Creation

**Event ID:** 4720

This detection identifies the creation of new Windows user accounts.

```spl
index=security_lab EventCode=4720 earliest=-10m latest=now
| table _time host EventCode Account_Name TargetUserName TargetDomainName
| sort - _time
```

A temporary test account named `SIEM_TEST_USER_05` was created specifically for detection validation.

The resulting Event ID 4720 was successfully ingested and detected by Splunk.

---

# Detection 06 — Privileged Group Membership Change

**Event ID:** 4732

This detection identifies accounts being added to security-enabled local groups.

```spl
index=security_lab EventCode=4732
| table _time host EventCode Account_Name MemberName TargetUserName TargetDomainName
| sort - _time
```

The controlled test account was temporarily added to the local `Administrators` group.

The resulting Windows Event ID 4732 was successfully detected.

The test account was subsequently removed from the privileged group.

---

# Detection 07 — Account Disabled or Enabled

**Event IDs:** 4725 / 4722

This detection monitors account state changes involving user accounts being disabled or enabled.

```spl
index=security_lab (EventCode=4725 OR EventCode=4722)
| table _time host EventCode Account_Name TargetUserName TargetDomainName
| sort - _time
```

The controlled test account was disabled and subsequently re-enabled to generate both event types.

The resulting events were successfully ingested and detected.

---

# Detection 08 — Windows Process Creation

**Event ID:** 4688

Process Creation auditing was enabled on the Windows host to provide process execution telemetry.

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
```

Detection query:

```spl
index=security_lab EventCode=4688
| table _time host EventCode Account_Name New_Process_Name Process_Command_Line
| sort - _time
```

A controlled `notepad.exe` process launch was used to validate Event ID 4688 collection.

The resulting process creation event was successfully observed in Splunk.

---

# Detection 09 — Windows User Account Deletion

**Event ID:** 4726

This detection identifies Windows user account deletion activity.

```spl
index=security_lab EventCode=4726
| table _time host EventCode Account_Name TargetUserName TargetDomainName
| sort - _time
```

The temporary test account was deleted after the account lifecycle testing was completed.

The resulting Event ID 4726 was successfully ingested and detected.

---

# Detection 10 — Security Audit Log Cleared

**Event ID:** 1102

This detection identifies activity indicating that the Windows Security audit log was cleared.

```spl
index=security_lab EventCode=1102
| table _time host EventCode Account_Name Account_Domain
| sort - _time
```

No destructive Security log-clearing action was performed during validation.

The detection and alert were configured so that future Event ID 1102 activity would be surfaced immediately.

---

# Alert Engineering

The validated detections were implemented as scheduled Splunk alerts.

Common alert configuration included:

- Scheduled execution
- Five-minute evaluation interval
- Result-based triggering
- Trigger once per scheduled execution
- Add to Triggered Alerts
- Severity assignment based on detection context

The alerts were designed to demonstrate the complete workflow from:

```text
Telemetry
    ↓
SPL Detection
    ↓
Scheduled Search
    ↓
Trigger Condition
    ↓
Alert
    ↓
SOC Investigation
```

---

# SOC Dashboard

A Splunk Classic Dashboard titled **SOC Dashboard** was created to provide centralized visibility into the security telemetry collected during the lab.

The dashboard contains seven monitoring panels:

1. **Failed Logon Activity**
2. **PowerShell Script Block Activity**
3. **Local Group Enumeration**
4. **Privileged Account Activity**
5. **Windows Account & Privilege Changes**
6. **Process Creation Activity**
7. **Security Audit Log Clears**

Example dashboard query:

```spl
index=security_lab EventCode=4625 earliest=-7d latest=now
| timechart span=1h count as Failed_Logons
```

Security audit log monitoring:

```spl
index=security_lab EventCode=1102 earliest=-7d latest=now
| stats count as Security_Log_Cleared
```

The dashboard provides a centralized view of authentication activity, PowerShell execution, privilege changes, account lifecycle events, process creation, and potential audit log tampering.

---

# Incident Response

A controlled suspicious PowerShell scenario was investigated using the SIEM environment.

The incident response workflow followed a simplified SOC methodology:

```text
Alert
  ↓
Initial Triage
  ↓
Event Investigation
  ↓
Context Analysis
  ↓
Containment
  ↓
Remediation
  ↓
Recovery
  ↓
Evidence Documentation
```

The investigation focused on PowerShell Event ID 4104 activity containing indicators associated with potentially suspicious PowerShell execution.

The activity was confirmed as a **controlled laboratory test rather than a real compromise**.

The complete investigation is documented in:

```text
docs/incident-response-report.md
```

---

# Remediation & Cleanup

The lab also included controlled remediation activities following the detection tests.

Actions included:

- Removing the temporary test account from the `Administrators` group.
- Disabling and re-enabling the test account during account lifecycle testing.
- Deleting the temporary test account after testing.
- Cleaning up the temporary PowerShell test script.
- Closing controlled process creation testing.
- Preserving detection evidence.
- Avoiding destructive Security Event Log clearing.

The remediation documentation is available in:

```text
remediation/remediation-plan.md
remediation/remediation-report.md
```

---

# Evidence & Validation

Each detection was supported by evidence collected during the lab.

The evidence repository contains:

- Detection results
- Alert trigger screenshots
- PowerShell telemetry
- Windows security events
- SOC dashboard screenshots
- Controlled test results

## Evidence Index

| Evidence | Description |
|---|---|
| E-01 | Repeated Failed Logon Alert |
| E-02 | PowerShell Script Block Logging |
| E-03 | Suspicious PowerShell Script Block |
| E-04 | PowerShell Alert Triggered |
| E-05 | Windows Group Enumeration Detection |
| E-06 | Group Enumeration Alert Triggered |
| E-07 | Privileged Account Activity |
| E-08 | Privileged Account Alert Triggered |
| E-09 | User Account Creation Alert |
| E-10 | Privileged Group Membership Change |
| E-11 | Privileged Group Membership Change Alert |
| E-12 | Account Disabled/Enabled Activity |
| E-13 | Account Disabled/Enabled Alert |
| E-14 | Process Creation Alert |
| E-15 | User Account Deletion Alert |
| E-16 | Security Audit Log Detection |
| Dashboard | SOC Dashboard |

Detailed evidence mapping is maintained in:

```text
evidence/evidence-log.md
```

---

# Detection Engineering Report

The complete detection engineering documentation covers:

- Detection objectives
- Data sources
- Event IDs
- SPL logic
- Validation methodology
- Controlled test procedures
- Alert configuration
- Evidence
- Detection limitations
- Tuning considerations

Location:

```text
docs/detection-engineering-report.md
```

---

# Repository Structure

```text
siem-security-monitoring-lab/
│
├── README.md
│
├── detections/
│   ├── 01-repeated-failed-logons.md
│   ├── 02-suspicious-powershell.md
│   ├── 03-group-enumeration.md
│   ├── 04-privileged-account-activity.md
│   ├── 05-user-account-creation.md
│   ├── 06-privileged-group-membership.md
│   ├── 07-account-disabled-enabled.md
│   ├── 08-process-creation.md
│   ├── 09-user-account-deletion.md
│   └── 10-security-audit-log-cleared.md
│
├── docs/
│   ├── detection-engineering-report.md
│   └── incident-response-report.md
│
├── evidence/
│   ├── evidence-log.md
│   └── screenshots/
│       ├── E-01-repeated-failed-logon-alert.png
│       ├── E-02-powershell-script-block-logging.png
│       ├── E-03-powershell-suspicious-script-block.png
│       ├── E-04-powershell-alert-triggered.png
│       ├── E-05-windows-group-enumeration-detection.png
│       ├── E-06-group-enumeration-alert-triggered.png
│       ├── E-07-privileged-account-activity.png
│       ├── E-08-privileged-account-alert-triggered.png
│       ├── E-09-user-account-creation-alert.png
│       ├── E-10-privileged-group-membership-change.png
│       ├── E-11-privileged-group-membership-change-alert.png
│       ├── E-12-account-disabled-enabled.png
│       ├── E-13-account-disabled-enabled-alert.png
│       ├── E-14-process-creation-alert.png
│       ├── E-15-user-account-deletion-alert.png
│       ├── E-16-security-audit-logs-alert.png
│       └── soc-dashboard.png
│
├── remediation/
│   ├── remediation-plan.md
│   └── remediation-report.md
│
└── spl/
    ├── 01-repeated-failed-logons.spl
    ├── 02-suspicious-powershell.spl
    ├── 03-group-enumeration.spl
    ├── 04-privileged-account-activity.spl
    ├── 05-user-account-creation.spl
    ├── 06-privileged-group-membership.spl
    ├── 07-account-disabled-enabled.spl
    ├── 08-process-creation.spl
    ├── 09-user-account-deletion.spl
    └── 10-security-audit-log-cleared.spl
```

---

# Key Skills Demonstrated

## SIEM

- Splunk Enterprise deployment
- Windows event ingestion
- Index management
- SPL searching
- Scheduled searches
- Alert configuration
- Trigger conditions
- Dashboard development

## Detection Engineering

- Windows Event ID analysis
- Detection logic development
- Threshold-based detection
- Time-window correlation
- Suspicious PowerShell detection
- Account and privilege monitoring
- Process monitoring
- Detection validation
- Evidence-driven tuning

## SOC Operations

- Alert triage
- Security event investigation
- Incident analysis
- Evidence preservation
- Containment
- Remediation
- Recovery
- Incident documentation

## Windows Security

- Windows Security Event Logs
- PowerShell Script Block Logging
- Process Creation auditing
- User account monitoring
- Local group monitoring
- Privileged activity monitoring
- Security audit monitoring

---

# Limitations

This project was intentionally designed as a local laboratory environment.

The following limitations apply:

- Telemetry was generated primarily from a single Windows workstation.
- The environment did not represent a distributed enterprise network.
- No real production security incidents were investigated.
- Controlled test activity was used to validate detections.
- The Splunk installation used a local trial license.
- Detection thresholds would require tuning in a production environment.
- Additional telemetry such as Sysmon, EDR, DNS, firewall, proxy, authentication infrastructure, and network flow data was not included.
- The project did not attempt to demonstrate complete attack-chain coverage.

These limitations are important when interpreting the detections and their operational value.

---

# Future Improvements

Future versions of the lab could include:

- Sysmon telemetry integration
- Windows Defender telemetry
- Network traffic ingestion
- DNS monitoring
- Authentication correlation
- MITRE ATT&CK technique mapping
- Risk-based alert prioritization
- Automated enrichment
- Threat intelligence integration
- SOAR-style automated response
- Detection-as-code workflows
- Automated testing of detection rules
- Additional dashboards and executive reporting
- Multi-host Windows telemetry
- Linux telemetry integration

---

# Project Outcome

This project demonstrates an end-to-end SIEM workflow:

```text
Windows Telemetry
       ↓
Data Collection
       ↓
Splunk Indexing
       ↓
SPL Detection Engineering
       ↓
Scheduled Alerts
       ↓
SOC Investigation
       ↓
Incident Response
       ↓
Remediation
       ↓
Evidence & Reporting
```

The lab resulted in **10 implemented security detections**, a centralized **SOC monitoring dashboard**, controlled detection validation, documented incident response procedures, and structured remediation documentation.

The project demonstrates practical experience with **SIEM administration, SPL, Windows security monitoring, detection engineering, SOC operations, incident response, and security documentation**.

---

# Disclaimer

This project was conducted in a controlled local laboratory environment for cybersecurity education and portfolio development.

All security testing and simulated suspicious activity were performed against systems under the author's control.

No unauthorized systems, accounts, networks, or production environments were targeted.

---

## OBAFEMI-MOSES MOSINMI


Focus areas:

`SOC Operations` · `SIEM` · `Detection Engineering` · `Incident Response` · `Windows Security` · `Security Monitoring`