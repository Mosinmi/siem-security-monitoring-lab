# Detection 01 — Repeated Failed Logons

## Overview

This detection identifies repeated Windows authentication failures that may indicate password guessing, brute-force activity, credential misuse, or an attempted unauthorized login.

The detection monitors Windows Security Event ID **4625** and triggers when three or more failed logon events are observed from the same workstation within a five-minute window.

---

## Detection Metadata

| Field | Value |
|---|---|
| Detection ID | DET-01 |
| Detection Name | Windows - Repeated Failed Logons |
| Data Source | Windows Security Event Log |
| Event ID | 4625 |
| Severity | Medium |
| Detection Type | Scheduled Search |
| Frequency | Every 5 minutes |
| Threshold | 3 or more failed logons |
| Time Window | 5 minutes |
| SIEM | Splunk Enterprise |
| Index | `security_lab` |

---

## Security Objective

Detect repeated authentication failures that could represent:

- Password guessing
- Brute-force authentication attempts
- Credential misuse
- Unauthorized access attempts
- Misconfigured applications repeatedly submitting invalid credentials

The detection is designed to provide an early warning signal rather than automatically classify every failed login as malicious.

---

## Detection Logic

The detection groups Windows Event ID 4625 events into five-minute windows and counts failed authentication attempts by workstation.

An alert is generated when the number of failures reaches or exceeds three.

### SPL Query

```spl
index=security_lab EventCode=4625
| bin _time span=5m
| stats count as failed_logons values(Account_Name) as accounts values(Failure_Reason) as failure_reasons by _time Workstation_Name
| where failed_logons >= 3
| sort - _time

Alert Configuration
The Splunk alert was configured with the following settings:
Alert Name:
Windows - Repeated Failed Logons

Description:
Detects three or more Windows failed logon events (Event ID 4625)
from the same workstation within a five-minute window.

Alert Type:
Scheduled

Schedule:
*/5 * * * *

Trigger Condition:
Number of Results > 0

Trigger:
Once

Action:
Add to Triggered Alerts

Controlled Validation
A controlled failed-authentication test was performed locally using a deliberately invalid test account.
The following command was executed three times:
net use \\127.0.0.1\IPC$ /user:.\SIEM_TEST_NOTREAL WrongPassword123!

The test generated Windows Security Event ID 4625 events.
The resulting telemetry contained:
Event ID:
4625

Failure Reason:
Unknown user name or bad password.

Account:
SIEM_TEST_NOTREAL

Workstation:
MODUPE

The Splunk detection subsequently identified the three failed logons within the five-minute threshold.
Detection Result
The detection successfully returned a qualifying event group:
Failed Logons:
3

Account:
SIEM_TEST_NOTREAL

Workstation:
MODUPE

Failure Reason:
Unknown user name or bad password.

The scheduled Splunk alert also successfully triggered.
The alert trigger history recorded a successful trigger at approximately:
2026-10-03 13:15:02

This confirmed both the detection logic and the alerting workflow.
Security Interpretation
Repeated failed authentication attempts are not automatically malicious. Legitimate causes can include:
- Incorrectly stored credentials
- Expired passwords
- User input errors
- Misconfigured services
- Network applications repeatedly attempting authentication
However, repeated failures from the same source within a short period can indicate password-guessing or brute-force behavior and therefore warrant investigation.
SOC Analyst Response
When this alert fires, an analyst should:
1. Identify the source workstation.
2. Identify the targeted account or accounts.
3. Review the failure reason and authentication type.
4. Check for successful logons around the same time.
5. Review the source IP address where available.
6. Determine whether the activity is associated with a legitimate user or service.
7. Investigate for additional suspicious Windows events.
8. Escalate if the activity appears malicious.
Useful related events include:
- 4624 — Successful Logon
- 4625 — Failed Logon
- 4672 — Special Privileges Assigned
- 4688 — Process Creation
Evidence
Associated evidence:
evidence/screenshots/E-01-repeated-failed-logon-alert.png

The screenshot demonstrates the configured Splunk alert and its successful trigger history
