# Detection 06 — Privileged Group Membership Change

## Overview

This detection identifies changes to security-enabled local group membership using Windows Security Event ID **4732**.

Event 4732 is generated when a member is added to a security-enabled local group. Changes to privileged groups such as the local **Administrators** group are particularly important because unauthorized membership changes can provide an account with elevated privileges.

---

## Detection Metadata

| Field | Value |
|---|---|
| Detection ID | DET-06 |
| Detection Name | Windows - Privileged Group Membership Change |
| Data Source | Windows Security Event Log |
| Event ID | 4732 |
| Severity | High |
| Detection Type | Scheduled Search |
| Frequency | Every 5 minutes |
| Trigger Condition | Number of Results > 0 |
| SIEM | Splunk Enterprise |
| Index | `security_lab` |

---

## Security Objective

Detect additions to security-enabled local groups that could result in unauthorized privilege assignment.

This detection is particularly relevant for monitoring:

- Local Administrators membership
- Privilege escalation
- Unauthorized account changes
- Persistence mechanisms
- Post-compromise privilege assignment
- Suspicious administrative activity

---

## Detection Logic

The detection searches the Windows Security event stream for Event ID 4732.

### SPL Query

```spl
index=security_lab EventCode=4732
| table _time host EventCode Account_Name MemberName TargetUserName TargetDomainName
| sort - _time

The query displays the event time, host, account responsible for the change, and available member/group information.

## Alert Configuration
Setting	Value
Alert Name	Windows - Privileged Group Membership Change
Alert Type	Scheduled
Schedule	Every 5 minutes
Severity	High
Time Range	Last 5 minutes
Trigger Condition	Number of Results > 0
Trigger	Once
Action	Add to Triggered Alerts


## Controlled Validation
A temporary test account was used to generate a controlled group membership change.
The account:
```SIEM_TEST_USER_05

was added to the local Administrators group using:
```Add-LocalGroupMember -Group "Administrators" -Member "SIEM_TEST_USER_05"

The membership change generated Windows Security Event ID 4732.
The Windows event indicated:

Event ID:
4732

Description:
A member was added to a security-enabled local group.

Subject:
OBAFEFMI-MOSES

Target Group:
Administrators

The event was generated locally as part of the controlled SIEM testing process.

## Splunk Validation
The following SPL query was used to verify the event:
index=security_lab EventCode=4732
| table _time host EventCode Account_Name MemberName TargetUserName TargetDomainName
| sort - _time

Splunk successfully returned the controlled Event ID 4732 activity.

This confirmed that the Windows Security event was successfully ingested into the security_lab index and could be queried by the detection.

## Alert Validation
The scheduled Splunk alert successfully triggered after the controlled group membership change.
The alert trigger history recorded a successful trigger during validation.
This demonstrated the complete detection workflow:
Account Added to Administrators
          ↓
Windows Event ID 4732
          ↓
Splunk Ingestion
          ↓
SPL Detection
          ↓
Scheduled Alert
          ↓
Triggered Alert

## SOC Analyst Response
When this detection fires, an analyst should:
1. Identify the account added to the group.
2. Identify the group affected by the change.
3. Identify the account that performed the modification.
4. Determine whether the change was authorized.
5. Review whether the affected group provides administrative privileges.
6. Check for account creation or authentication events involving the account.
7. Review Event ID 4672 for subsequent privileged activity.
8. Review Event ID 4688 for suspicious processes executed after the privilege change.
9. Escalate when the modification cannot be attributed to legitimate administration.
Useful related events include:
- 4720 — User Account Created
- 4732 — Member Added to Security-Enabled Local Group
- 4672 — Special Privileges Assigned
- 4688 — Process Creation
- 4624 — Successful Logon

## Detection Limitations
Event 4732 is not inherently malicious.
Legitimate administrators may add accounts to local security groups as part of normal system administration.
The detection should therefore be correlated with:
- Account identity
- Group affected
- Change initiator
- Account creation activity
- Authentication activity
- Privileged activity
- Approved administrative changes

## Evidence
The following evidence supports this detection:
## E-10 — Privileged Group Membership Change
```evidence/screenshots/E-10-privileged-group-membership-change.png

## E-11 — Privileged Group Membership Change Alert
```evidence/screenshots/E-11-privileged-group-membership-change.png

These screenshots provide evidence of the controlled group membership detection and associated alerting activity.
Cleanup
After validation, the temporary test account was removed from the local Administrators group:
Remove-LocalGroupMember -Group "Administrators" -Member "SIEM_TEST_USER_05"

This ensured that the controlled privilege assignment did not remain active after testing.
# Status
## Validated
A controlled account was added to the local Administrators group, Windows generated Event ID 4732, Splunk successfully ingested and detected the event, and the scheduled alert successfully triggered.