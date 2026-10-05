# Detection 04 — Privileged Account Activity

## Overview

This detection identifies Windows Security Event ID **4672**, which indicates that special privileges were assigned to a new logon session.

Event 4672 can provide useful visibility into privileged account activity. Because Windows commonly generates this event for system and service accounts, this detection focuses on **non-SYSTEM accounts** to reduce expected background activity and highlight potentially significant privileged sessions.

---

## Detection Metadata

| Field | Value |
|---|---|
| Detection ID | DET-04 |
| Detection Name | Windows - Privileged Account Activity |
| Data Source | Windows Security Event Log |
| Event ID | 4672 |
| Severity | Medium |
| Detection Type | Scheduled Search |
| Frequency | Every 5 minutes |
| Filter | Non-SYSTEM accounts |
| SIEM | Splunk Enterprise |
| Index | `security_lab` |

---

## Security Objective

Identify privileged Windows logon activity involving accounts other than the expected `SYSTEM` account.

Privileged account activity is important to monitor because compromised or unexpectedly privileged accounts can be used to:

- Execute administrative actions
- Modify security controls
- Access protected resources
- Establish persistence
- Perform privilege escalation
- Conduct further system-level activity

Event 4672 is therefore useful as a correlation signal within a broader SOC detection strategy.

---

## Detection Logic

The detection searches for Event ID 4672 and excludes events associated with the `SYSTEM` account.

### SPL Query

```spl
index=security_lab EventCode=4672 earliest=-5m latest=now
| where Account_Name!="SYSTEM"
| table _time host EventCode Account_Name Account_Domain Logon_ID SubjectUserName SubjectDomainName PrivilegeList
| sort - _time

The query exposes the account, domain, logon identifier, subject information, and privilege list for analyst investigation.

## Alert Configuration
Setting	Value
Alert Name	Windows - Privileged Account Activity
Alert Type	Scheduled
Schedule	Every 5 minutes
Severity	Medium
Trigger Condition	Number of Results > 0
Trigger	Once
Action	Add to Triggered Alerts


## Telemetry Analysis
Initial analysis of Event ID 4672 showed that many events were associated with the Windows SYSTEM account.
Because this represents expected operating-system activity in the lab environment, the detection was refined to exclude:
```Account_Name="SYSTEM"

The remaining telemetry included privileged activity associated with the interactive user account:
Account:

OBAFEMI-MOSES

Domain:
MODUPE

This provided a more useful signal for SOC monitoring.

## Detection Validation
A non-SYSTEM Event ID 4672 event was identified in Splunk.
The event included:
Event ID:
4672

Account:
OBAFEFMI-MOSES

Domain:
MODUPE

Logon ID:
0xB806C80

The detection query successfully returned the non-SYSTEM privileged account event.
This demonstrated that the filtering logic could separate potentially relevant privileged account activity from the high-volume SYSTEM events.

## Alert Validation
The Splunk alert was configured to monitor the refined detection query.
During validation, the alert successfully triggered on the non-SYSTEM Event ID 4672 activity.
The trigger history recorded a successful alert at approximately:
```2026-10-04 14:15:02

This confirmed that the detection and alerting workflow were functioning as intended.

## SOC Analyst Response
When this detection fires, an analyst should:
1. Identify the account associated with the privileged logon.
2. Determine whether the account is expected to have administrative privileges.
3. Review the logon session and Logon ID.
4. Review the privileges assigned to the session.
5. Correlate the event with process creation activity such as Event ID 4688.
6. Review account and group membership changes.
7. Check for authentication anomalies around the same timestamp.
8. Determine whether the privileged activity corresponds to an approved administrative action.
9. Escalate the event if the privileged activity cannot be explained.
Useful related events include:

- 4624 — Successful Logon
- 4625 — Failed Logon
- 4672 — Special Privileges Assigned
- 4688 — Process Creation
- 4720 — User Account Created
- 4732 — Member Added to Security-Enabled Local Group

## Detection Limitations
Event 4672 is not inherently malicious.
Windows generates privileged events for legitimate system, service, and administrative activity.
The exclusion of SYSTEM reduces some expected noise but does not eliminate false positives.
Additional context should therefore be considered, including:
- Account identity
- Logon type
- Logon ID
- Privilege list
- Host
- Process activity
- Account membership
- Time of activity
- Expected administrative activity

## Evidence
The following evidence supports this detection.
E-07 — Privileged Account Activity
evidence/screenshots/E-07-privileged-account-activity.png

Demonstrates the detection of non-SYSTEM Event ID 4672 activity.
## E-08 — Privileged Account Alert
evidence/screenshots/E-08-privileged-account-alert-triggered.png

Demonstrates successful triggering of the scheduled Splunk alert.
# Status
## Validated
The detection successfully identified non-SYSTEM Windows Event ID 4672 activity after filtering expected SYSTEM events. The corresponding Splunk scheduled alert successfully triggered during validation.