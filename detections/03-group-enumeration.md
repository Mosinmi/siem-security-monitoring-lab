# Detection 03 — Repeated Windows Group Enumeration

## Overview

This detection identifies repeated enumeration of security-enabled local group membership on a Windows host.

The detection monitors Windows Security Event ID **4799**, which is generated when the membership of a security-enabled local group is enumerated.

Repeated group enumeration can provide an attacker with information about local privileges, administrative groups, and accounts that may be useful during reconnaissance and privilege escalation.

---

## Detection Metadata

| Field | Value |
|---|---|
| Detection ID | DET-03 |
| Detection Name | Windows - Repeated Group Enumeration |
| Data Source | Windows Security Event Log |
| Event ID | 4799 |
| Severity | Medium |
| Detection Type | Scheduled Search |
| Frequency | Every 5 minutes |
| Threshold | 5 or more group enumeration events |
| Time Window | 5 minutes |
| SIEM | Splunk Enterprise |
| Index | `security_lab` |

---

## Security Objective

Detect repeated local group membership enumeration that may indicate host reconnaissance.

The detection is intended to identify activity such as:

- Enumeration of local security groups
- Discovery of privileged groups
- Reconnaissance before privilege escalation
- Repeated security group discovery by scripts or tools

A single Event ID 4799 does not necessarily indicate malicious activity. The detection therefore focuses on repeated activity within a short time window.

---

## Detection Logic

The detection groups Event ID 4799 events into five-minute windows and counts the number of group enumeration events observed on the host.

An alert is generated when five or more events occur within the same five-minute window.

### SPL Query

```spl
index=security_lab EventCode=4799 earliest=-5m latest=now
| bin _time span=5m
| stats count as group_enumerations values(Process_Name) as processes values(Account_Name) as accounts by _time host
| where group_enumerations >= 5
| sort - _time

## Alert Configuration

Setting	Value
Alert Name	Windows - Repeated Group Enumeration
Alert Type	Scheduled
Schedule	Every 5 minutes
Severity	Medium
Time Range	Last 5 minutes
Trigger Condition	Number of Results > 0
Trigger	Once
Action	Add to Triggered Alerts


## Controlled Validation
A controlled local test was performed using PowerShell to generate repeated local group enumeration activity.
The following command was executed repeatedly:
Get-LocalGroup

The activity generated Windows Security Event ID 4799 events.
A representative Windows event contained:
Event ID:
4799

Description:
A security-enabled local group membership was enumerated.

Process:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

Subject Account:
OBAFEFMI-MOSES

Domain:
MODUPE

The test was performed locally and was intended only to generate security telemetry for the SIEM lab.

## Detection Validation
Splunk successfully ingested Event ID 4799 telemetry into the security_lab index.
The detection query identified a burst of repeated group enumeration activity within the five-minute threshold.
The qualifying activity exceeded the configured threshold of five events.
The resulting detection provided information including:
- Number of group enumeration events
- Host
- Account associated with the activity
- Process associated with the activity
This demonstrated that the detection could identify repeated local group enumeration rather than simply individual events.

## Alert Validation
The scheduled Splunk alert successfully triggered after the controlled group enumeration activity exceeded the configured threshold.
This confirmed the complete detection workflow:
PowerShell Group Enumeration
          ↓
Windows Event ID 4799
          ↓
Splunk Ingestion
          ↓
Five-Minute Aggregation
          ↓
Threshold ≥ 5 Events
          ↓
Scheduled Alert
          ↓
Triggered Alert

## SOC Analyst Response
When this alert fires, an analyst should:
1. Identify the host generating the enumeration activity.
2. Identify the user account responsible for the activity.
3. Review the process responsible for the enumeration.
4. Determine whether the activity was performed by an administrator, security tool, or expected script.
5. Review nearby process creation events such as Event ID 4688.
6. Look for other reconnaissance activity.
7. Investigate privilege-related events such as Event IDs 4672 and 4732.
8. Correlate the activity with authentication events.
9. Escalate when the enumeration is associated with other suspicious behavior.


## Detection Limitations
Group enumeration is not inherently malicious.
Legitimate software, administrators, security tools, and system processes may enumerate local groups.
The threshold-based approach reduces noise but does not eliminate false positives.
Additional context should therefore be considered, including:

- User identity
- Host identity
- Process name
- Command-line activity
- Frequency of enumeration
- Other security events occurring around the same time

## Evidence
The following evidence supports this detection.
E-05 — Group Enumeration Detection
evidence/screenshots/E-05-windows-group-enumeration-detection.png

Demonstrates the Splunk detection identifying repeated Windows Event ID 4799 activity.
E-06 — Group Enumeration Alert
evidence/screenshots/E-06-group-enumeration-alert-triggered.png

Demonstrates successful triggering of the scheduled Splunk alert.

# Status
## Validated
The controlled PowerShell group enumeration activity generated Windows Event ID 4799 telemetry, Splunk successfully detected the repeated activity using the five-minute threshold, and the scheduled alert successfully triggered.

