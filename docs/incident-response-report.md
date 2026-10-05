# SOC Incident Response Report

## Suspicious PowerShell Script Block Activity

**Project:** SIEM & Security Monitoring Lab  
**SIEM:** Splunk Enterprise 10.6.0.5  
**Operating System:** Windows 10 Pro  
**Log Source:** Microsoft-Windows-PowerShell/Operational  
**Event ID:** 4104  
**Splunk Index:** `security_lab`  
**Incident Type:** Suspicious PowerShell Activity  
**Environment:** Controlled Local Security Lab

---

# 1. Executive Summary

This report documents the investigation of a suspicious PowerShell Script Block Logging event detected by the Splunk SIEM.

The investigation was performed as part of a controlled cybersecurity laboratory environment. A harmless PowerShell test was deliberately generated to validate the detection capability for potentially suspicious PowerShell activity.

The detection identified Windows Event ID **4104** containing an indicator associated with PowerShell web-request functionality:

```text
Invoke-WebRequest
```

The event was successfully ingested into Splunk and identified by the suspicious PowerShell detection rule.

No evidence of an actual compromise, unauthorized access, malware execution, or successful external communication was established during this controlled test.

The activity was therefore classified as a **controlled security-testing event**.

---

# 2. Incident Overview

## Incident Description

A PowerShell Script Block Logging event containing a potentially suspicious PowerShell indicator triggered the Splunk detection:

```text
PowerShell - Suspicious Script Block Activity
```

The detection searches Event ID 4104 for indicators commonly associated with PowerShell execution, downloading, encoding, or payload activity.

---

## Detection Trigger

The detection uses the following SPL:

```spl
index=security_lab EventCode=4104 earliest=-5m latest=now
| eval suspicious=if(match(Message,"(?i)(invoke-expression|invoke-webrequest|downloadstring|frombase64string|encodedcommand|net\.webclient|start-bitstransfer|\biex\b)"),1,0)
| where suspicious=1
| table _time host EventCode Message
| sort - _time
```

---

# 3. Detection Details

| Field | Value |
|---|---|
| Detection Name | PowerShell - Suspicious Script Block Activity |
| Event ID | 4104 |
| Log Source | PowerShell Operational |
| Index | `security_lab` |
| Severity | High |
| Alert Type | Scheduled |
| Schedule | Every 5 minutes |
| Trigger | Number of Results > 0 |
| Action | Add to Triggered Alerts |

---

# 4. Initial Detection

The Windows PowerShell Operational log was inspected to verify the availability of Event ID 4104 telemetry.

A PowerShell Script Block Logging event was observed containing:

```text
Creating Scriptblock text (1 of 1)
```

This confirmed that PowerShell Script Block Logging was active on the Windows system.

Splunk subsequently received the PowerShell telemetry in:

```text
security_lab
```

---

# 5. Controlled Test Activity

A harmless test was created specifically to validate the SIEM detection.

The PowerShell process was configured to execute:

```powershell
Write-Output "SIEM-LAB-4104-TEST Invoke-WebRequest"
```

The test script was created using:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

@'
Write-Output "SIEM-LAB-4104-TEST Invoke-WebRequest"
'@ | Set-Content "$env:TEMP\siem-4104-test.ps1"

& "$env:TEMP\siem-4104-test.ps1"
```

The purpose of the test was not to perform an actual web request.

The string:

```text
Invoke-WebRequest
```

was included specifically to test whether the detection logic could identify a known suspicious PowerShell indicator.

---

# 6. Windows Event Validation

The resulting Windows event was verified in the PowerShell Operational log.

Relevant information included:

```text
Event ID: 4104
```

The Script Block message contained:

```text
Write-Output "SIEM-LAB-4104-TEST Invoke-WebRequest"
```

The event demonstrated that the PowerShell activity was successfully recorded by Windows Script Block Logging.

---

# 7. Splunk Investigation

The specific test event was located in Splunk using:

```spl
index=security_lab EventCode=4104 "SIEM-LAB-4104-TEST"
```

The search successfully returned the controlled event.

This confirmed the following telemetry pipeline:

```text
PowerShell Activity
        ↓
Windows Event ID 4104
        ↓
PowerShell Operational Log
        ↓
Splunk
        ↓
security_lab Index
        ↓
Detection Rule
        ↓
SOC Alert
```

---

# 8. Detection Match

The suspicious PowerShell detection matched the controlled event because it contained:

```text
Invoke-WebRequest
```

The detection therefore classified the event as potentially suspicious.

The detection does not automatically determine that the PowerShell activity is malicious.

Instead, the indicator should cause an analyst to investigate the event and its surrounding context.

---

# 9. Alert Investigation

The Splunk alert was configured as:

```text
PowerShell - Suspicious Script Block Activity
```

The alert was configured with:

```text
Severity: High
Schedule: Every 5 minutes
Trigger: Number of Results > 0
Action: Add to Triggered Alerts
```

The alert successfully triggered during validation.

---

# 10. Initial SOC Triage

A SOC analyst receiving this alert should begin by answering:

### What happened?

A PowerShell Script Block event contained a potentially suspicious indicator.

### Where did it happen?

The event identifies the affected Windows host.

### Who executed it?

The analyst should review the available user/account information associated with the event.

### What was executed?

The analyst should review the complete Event ID 4104 Script Block message.

### Was the activity expected?

The analyst should determine whether the activity was part of:

- Administrative work
- Security testing
- Software installation
- Automation
- System maintenance
- User activity
- Potentially malicious execution

---

# 11. Investigation Queries

## 11.1 Review the Full Script Block

```spl
index=security_lab EventCode=4104
| table _time host EventCode Message
| sort - _time
```

---

## 11.2 Search for Suspicious PowerShell Indicators

```spl
index=security_lab EventCode=4104
| eval suspicious=if(match(Message,"(?i)(invoke-expression|invoke-webrequest|downloadstring|frombase64string|encodedcommand|net\.webclient|start-bitstransfer|\biex\b)"),1,0)
| where suspicious=1
| table _time host EventCode Message
| sort - _time
```

---

## 11.3 Search for Process Creation

PowerShell activity can be correlated with Windows Event ID 4688:

```spl
index=security_lab EventCode=4688
| search New_Process_Name="*\\powershell.exe"
| table _time host Account_Name New_Process_Name Process_Command_Line
| sort - _time
```

This helps determine when PowerShell was launched and, where available, how it was executed.

---

## 11.4 Search for Authentication Activity

```spl
index=security_lab (EventCode=4624 OR EventCode=4625)
| table _time host EventCode Account_Name Workstation_Name Failure_Reason
| sort - _time
```

This can help establish whether the PowerShell activity occurred around suspicious authentication activity.

---

## 11.5 Search for Privileged Activity

```spl
index=security_lab EventCode=4672
| where Account_Name!="SYSTEM"
| table _time host EventCode Account_Name Account_Domain Logon_ID PrivilegeList
| sort - _time
```

This can determine whether the activity was associated with a privileged account.

---

# 12. Correlation Analysis

PowerShell Script Block activity becomes more significant when correlated with other security events.

A potentially suspicious sequence could look like:

```text
4624 Successful Logon
        ↓
4672 Privileged Activity
        ↓
4688 powershell.exe
        ↓
4104 Suspicious Script Block
        ↓
Network Activity
```

The controlled laboratory event did not establish this type of malicious sequence.

The test only demonstrated that the SIEM could identify the suspicious PowerShell indicator.

---

# 13. Investigation Findings

## Finding 1 — PowerShell Script Block Logging Was Active

Windows Event ID 4104 telemetry was available from:

```text
Microsoft-Windows-PowerShell/Operational
```

This confirmed that Script Block Logging was providing useful PowerShell visibility.

---

## Finding 2 — Splunk Successfully Ingested Event ID 4104

The event was successfully indexed in:

```text
security_lab
```

This confirmed that the PowerShell telemetry pipeline was operational.

---

## Finding 3 — Suspicious Indicator Was Detected

The controlled event contained:

```text
Invoke-WebRequest
```

The detection rule successfully identified the indicator.

---

## Finding 4 — No Malicious Activity Was Demonstrated

The controlled test used:

```powershell
Write-Output
```

and did not perform an actual web request or download.

Therefore, the event should not be classified as a confirmed malicious PowerShell execution.

---

# 14. Incident Classification

## Classification

```text
Controlled Security Test
```

## Severity

```text
High Detection Severity
```

The alert itself is configured as High because suspicious PowerShell activity can be associated with significant attack behavior.

However, the specific event investigated during this laboratory exercise was benign and intentionally generated.

---

# 15. Containment

No containment action was required.

The activity was generated intentionally within the controlled laboratory environment.

No evidence indicated:

- Unauthorized access
- Malware execution
- Persistence
- Credential compromise
- Data exfiltration
- Successful external download

Therefore, isolating the host or terminating processes was unnecessary.

---

# 16. Eradication

No eradication action was required because the event was generated by a controlled test.

The temporary test script was created under:

```text
%TEMP%\siem-4104-test.ps1
```

The test artifact can be removed using:

```powershell
Remove-Item "$env:TEMP\siem-4104-test.ps1" -Force
```

---

# 17. Recovery

No system recovery action was required.

The test was performed locally and did not intentionally modify the system beyond the temporary test artifact and the process-level PowerShell execution-policy setting.

The execution policy was configured with:

```text
-Scope Process
```

meaning the change applied only to the current PowerShell process.

---

# 18. Lessons Learned

The investigation demonstrated several important SOC concepts.

### 1. Detection Does Not Equal Compromise

A suspicious indicator should initiate investigation rather than automatically being classified as malicious.

### 2. Context Matters

The same PowerShell command may be legitimate in one environment and suspicious in another.

### 3. Event Correlation Improves Detection

Event ID 4104 becomes more useful when correlated with:

```text
4624
4625
4672
4688
```

and other relevant telemetry.

### 4. Script Block Logging Provides Valuable Visibility

PowerShell Script Block Logging gives analysts visibility into PowerShell content that may otherwise be difficult to investigate.

### 5. Detection Rules Require Tuning

Indicators such as:

```text
Invoke-WebRequest
```

can appear in legitimate administrative or automation workflows.

Production deployments therefore require allowlisting, contextual filtering, and additional correlation.

---

# 19. Recommended SOC Improvements

The following improvements could make the detection more effective in a production environment:

## User Context

Include the executing user account in the alert output where available.

## Host Context

Include hostname and asset criticality.

## Process Context

Correlate Event ID 4104 with Event ID 4688.

## Network Context

Correlate suspicious PowerShell activity with outbound network connections.

## Command-Line Analysis

Inspect encoded commands, download URLs, suspicious paths, and execution parameters.

## Threat Intelligence

Compare suspicious domains, URLs, hashes, or indicators against approved threat-intelligence sources where available.

## Alert Suppression

Suppress known administrative automation where appropriate to reduce false positives.

---

# 20. Evidence

The following evidence was collected during the investigation:

```text
evidence/screenshots/E-02-powershell-script-block-logging.png
evidence/screenshots/E-03-powershell-suspicious-script-block.png
evidence/screenshots/E-04-powershell-alert-triggered.png
```

### E-02

Demonstrates PowerShell Script Block Logging and Event ID 4104 telemetry.

### E-03

Demonstrates the suspicious PowerShell detection query identifying the controlled test activity.

### E-04

Demonstrates the Splunk alert triggering on the detection.

---

# 21. Incident Timeline

| Stage | Activity |
|---|---|
| 1 | PowerShell Script Block Logging verified |
| 2 | Event ID 4104 telemetry confirmed |
| 3 | Controlled PowerShell test created |
| 4 | Test script executed |
| 5 | Windows generated Event ID 4104 |
| 6 | Splunk ingested the event |
| 7 | Suspicious PowerShell detection matched `Invoke-WebRequest` |
| 8 | Splunk scheduled alert triggered |
| 9 | Event investigated and classified as controlled testing |
| 10 | No containment or eradication required |

---

# 22. Final Assessment

The investigation successfully demonstrated the complete detection-to-investigation workflow:

```text
PowerShell Activity
        ↓
Windows Event 4104
        ↓
Splunk Ingestion
        ↓
Detection Rule
        ↓
Alert
        ↓
SOC Triage
        ↓
Correlation
        ↓
Classification
        ↓
Response Decision
```

The activity was determined to be a **controlled security testing event** rather than a confirmed security incident.

The detection nevertheless demonstrated that the SIEM can identify potentially suspicious PowerShell behavior and provide analysts with the telemetry required for further investigation.

---

# 23. Incident Status

```text
Status: Closed
Classification: Controlled Security Test
Compromise Confirmed: No
Containment Required: No
Eradication Required: No
Recovery Required: No
Detection Validated: Yes
```

---

# 24. Conclusion

This investigation demonstrates the practical use of Splunk as a SIEM for detecting and investigating potentially suspicious PowerShell activity.

The exercise moved beyond simply creating an alert by demonstrating the SOC workflow of:

- Alert detection
- Initial triage
- Event analysis
- Correlation
- Classification
- Containment assessment
- Eradication assessment
- Recovery assessment
- Evidence collection
- Incident closure

The investigation also demonstrates an important SOC principle: **a detection is an investigation starting point, not automatic proof of compromise.**

In this controlled laboratory scenario, the PowerShell activity was intentionally generated to validate the detection and was therefore classified as a benign security test.