# Detection 05 — Windows User Account Creation

## Overview

This detection identifies the creation of new Windows user accounts using Security Event ID **4720**.

Unexpected account creation can indicate unauthorized account provisioning, persistence, privilege escalation preparation, or administrative activity that requires investigation.

The detection monitors the Windows Security event stream and alerts whenever a new user account is created.

---

## Detection Metadata

| Field | Value |
|---|---|
| Detection ID | DET-05 |
| Detection Name | Windows - User Account Creation |
| Data Source | Windows Security Event Log |
| Event ID | 4720 |
| Severity | High |
| Detection Type | Scheduled Search |
| Frequency | Every 5 minutes |
| Trigger Condition | Number of Results > 0 |
| SIEM | Splunk Enterprise |
| Index | `security_lab` |

---

## Security Objective

Detect the creation of new Windows user accounts that may require security investigation.

Unexpected account creation can be associated with:

- Persistence
- Unauthorized access
- Privilege escalation preparation
- Insider activity
- Malware or attacker activity
- Unauthorized administrative changes

The detection provides an early warning signal that can be correlated with subsequent privilege or authentication events.

---

## Detection Logic

The detection searches for Windows Security Event ID 4720.

### SPL Query

```spl
index=security_lab EventCode=4720 earliest=-10m latest=now
| table _time host EventCode Account_Name TargetUserName TargetDomainName
| sort - _time

The query displays the time of account creation, host, account responsible for the action, and the newly created account.
## Alert Configuration
Setting	Value
Alert Name	Windows - User Account Creation
Alert Type	Scheduled
Schedule	Every 5 minutes
Severity	High
Time Range	Last 5 minutes
Trigger Condition	Number of Results > 0
Trigger	Once
Action	Add to Triggered Alerts


## Initial Telemetry Check
Before validation, the Splunk search for Event ID 4720 returned no results.
This established that there was no previously observed account-creation telemetry available for the detection test.
A controlled test account was therefore created locally.
## Controlled Validation
The following temporary Windows account was created specifically for SIEM testing:
```net user SIEM_TEST_USER_05 "TempPass!2026" /add

Windows generated Security Event ID 4720 as a result of the account creation.
The event recorded information including:
Event ID:
4720

Target Account:
SIEM_TEST_USER_05

Created By:
OBAFEFMI-MOSES

Host / Domain:
MODUPE

The created account was a temporary lab account and was used only to generate security telemetry.
Splunk Validation
The following search confirmed that the Windows Event ID 4720 event was successfully ingested:
index=security_lab EventCode=4720 earliest=-10m latest=now
| table _time host EventCode Account_Name TargetUserName TargetDomainName
| sort - _time

The search returned the controlled account creation event.
The detection therefore confirmed the complete telemetry path:
Local Account Creation
        ↓
Windows Event ID 4720
        ↓
Splunk Ingestion
        ↓
SPL Detection
        ↓
Alert

## Alert Validation
The scheduled Splunk alert successfully triggered after the controlled account creation event was ingested.
The alert trigger history recorded successful triggers during validation.
This confirmed that the detection was capable of identifying and alerting on Windows user account creation activity.

## SOC Analyst Response
When this detection fires, an analyst should:
1. Identify the newly created account.
2. Identify the account responsible for creating it.
3. Determine whether the creation was authorized.
4. Review the account's group memberships.
5. Determine whether administrative privileges were assigned.
6. Check whether the account was subsequently enabled or disabled.
7. Review authentication activity involving the account.
8. Correlate with Event ID 4732 for privileged group membership changes.
9. Investigate further if the account cannot be attributed to legitimate administrative activity.
Useful related events include:
- 4720 — User Account Created
- 4722 — User Account Enabled
- 4725 — User Account Disabled
- 4726 — User Account Deleted
- 4732 — Member Added to Security-Enabled Local Group
- 4672 — Special Privileges Assigned

## Detection Limitations
User account creation is not inherently malicious.
Legitimate administrators and applications may create accounts as part of normal system administration.
The detection should therefore be correlated with:
- Account creator
- New account name
- Group membership
- Privilege assignments
- Authentication activity
- Change-management records
- Host context

## Evidence
The following evidence supports this detection:
E-09 — User Account Creation Alert
evidence/screenshots/E-09-user-account-creation-alert.png

This evidence demonstrates the configured Splunk alert associated with Windows Event ID 4720 account creation activity.

# Status
## Validated
A controlled Windows user account was created, Event ID 4720 was successfully generated and ingested by Splunk, the detection identified the event, and the corresponding scheduled alert successfully triggered.