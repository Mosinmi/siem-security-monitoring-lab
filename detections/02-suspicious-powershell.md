# Detection 02 — Suspicious PowerShell Script Block Activity

## Overview

This detection identifies potentially suspicious PowerShell activity using Windows PowerShell Script Block Logging and Event ID **4104**.

The detection searches PowerShell script block content for indicators commonly associated with command execution, remote content retrieval, encoded commands, and payload-related activity.

---

## Detection Metadata

| Field | Value |
|---|---|
| Detection ID | DET-02 |
| Detection Name | PowerShell - Suspicious Script Block Activity |
| Data Source | PowerShell Operational Log |
| Event ID | 4104 |
| Severity | High |
| Detection Type | Scheduled Search |
| Frequency | Every 5 minutes |
| Trigger Condition | Number of Results > 0 |
| SIEM | Splunk Enterprise |
| Index | `security_lab` |

---

## Security Objective

PowerShell is a legitimate Windows administration tool, but it is also frequently used in malicious activity.

This detection provides visibility into PowerShell Script Block activity and identifies script content containing indicators associated with:

- PowerShell execution
- Remote content retrieval
- Download activity
- Encoded content
- In-memory execution
- Payload-related commands

The detection is intended to identify suspicious activity for analyst investigation rather than classify every matching event as malicious.

---

## Detection Logic

The following SPL searches Event ID 4104 for common PowerShell execution and payload indicators:

```spl
index=security_lab EventCode=4104 earliest=-5m latest=now
| eval suspicious=if(match(Message,"(?i)(invoke-expression|invoke-webrequest|downloadstring|frombase64string|encodedcommand|net\.webclient|start-bitstransfer|\biex\b)"),1,0)
| where suspicious=1
| table _time host EventCode Message
| sort - _time

Detection Indicators
The detection looks for indicators including:
Indicator	Purpose
Invoke-Expression	Dynamic command execution
Invoke-WebRequest	Web/remote content retrieval
DownloadString	Retrieval of remote content
FromBase64String	Base64 decoding
EncodedCommand	Encoded PowerShell execution
Net.WebClient	Web-based content retrieval
Start-BitsTransfer	File transfer activity
IEX	Common alias for Invoke-Expression


These indicators should be investigated in context because legitimate administrative scripts may contain some of them.
Telemetry Configuration
PowerShell Operational logging was configured in Splunk using:
[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = security_lab

Splunk was restarted after the input configuration was added.
A verification search confirmed Event ID 4104 telemetry was being ingested:
index=security_lab EventCode=4104

The search returned PowerShell Script Block Logging events, confirming successful telemetry ingestion.
Controlled Validation
A harmless PowerShell test was created to generate a Script Block Logging event containing a detection indicator.
The test script contained:
Write-Output "SIEM-LAB-4104-TEST Invoke-WebRequest"

The test was executed locally and generated Windows PowerShell Event ID 4104 telemetry.
The Windows event showed:
Event ID:
4104

Test Indicator:
SIEM-LAB-4104-TEST Invoke-WebRequest

The test was intentionally designed to be harmless. It did not download or execute external content.
Splunk Validation
The specific test event was confirmed in Splunk using:
index=security_lab EventCode=4104 "SIEM-LAB-4104-TEST"

The suspicious PowerShell detection query then identified the event because the message contained the Invoke-WebRequest indicator.
This demonstrated the complete telemetry and detection path:

PowerShell Test
      ↓
Windows Event ID 4104
      ↓
Splunk Ingestion
      ↓
SPL Indicator Matching
      ↓
Suspicious PowerShell Result

Alert Configuration

The Splunk alert was configured as follows:
Setting	Value
Alert Name	PowerShell - Suspicious Script Block Activity
Alert Type	Scheduled
Schedule	Every 5 minutes
Severity	High
Trigger Condition	Number of Results > 0
Trigger	Once
Action	Add to Triggered Alerts


The scheduled alert successfully triggered during validation.
Alert Validation
The Splunk alert trigger history recorded successful alert executions after the controlled PowerShell test.
This confirmed that the detection was not only returning results but was also connected to the Splunk alerting mechanism.
SOC Analyst Response
When this detection fires, an analyst should:

1. Review the complete Event ID 4104 script block.
2. Identify the user associated with the PowerShell execution.
3. Identify the affected host.
4. Determine whether the PowerShell activity was expected.
5. Investigate URLs, download operations, encoded content, and execution functions.
6. Correlate the event with Windows Event ID 4688 process creation telemetry.
7. Review authentication and privilege-related activity around the same timestamp.
8. Determine whether the activity represents legitimate administration or potentially malicious execution.
9. Escalate the event when malicious behavior is confirmed or strongly suspected.
Detection Limitations
This is an indicator-based detection and may generate false positives.
For example, legitimate administrators or security tools may use:
Invoke-WebRequest
Start-BitsTransfer
Base64 decoding

Therefore, the presence of one indicator should not automatically be treated as evidence of compromise.
The detection should be correlated with:
- User identity
- Host identity
- Process creation
- Command-line activity
- Network activity
- Authentication events
- Other security detections
Evidence
The following evidence supports this detection:

E-02 — PowerShell Script Block Logging
evidence/screenshots/E-02-powershell-script-block-logging.png

Demonstrates successful PowerShell Event ID 4104 telemetry.
E-03 — Suspicious PowerShell Script Block Detection
evidence/screenshots/E-03-powershell-suspicious-script-block.png

Demonstrates the suspicious PowerShell detection identifying the controlled test event.
E-04 — PowerShell Alert Trigger

evidence/screenshots/E-04-powershell-alert-triggered.png

Demonstrates successful Splunk alert triggering.