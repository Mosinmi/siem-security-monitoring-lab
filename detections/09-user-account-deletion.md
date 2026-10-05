# Detection 09 — Windows User Account Deletion

## Overview

This detection monitors Windows Security Event ID **4726** to identify the deletion of user accounts.

Unexpected account deletion can indicate unauthorized administrative activity, account manipulation, attempts to remove persistence mechanisms, or efforts to alter the identity configuration of a Windows system.

---

## Detection Objective

Detect when a Windows user account is deleted and provide SOC analysts with visibility into:

- The account that was deleted
- The account responsible for the deletion
- The affected host
- The time of the deletion
- The target domain

---

## Windows Event ID

| Event ID | Description |
|---|---|
| 4726 | A user account was deleted |

---

## Data Source

**Log Source:**

```text
Windows Security Event Log
```

**Splunk Index:**

```text
security_lab
```

---

# Detection Query

The following SPL query searches for Windows user account deletion events:

```spl
index=security_lab EventCode=4726
| table _time host EventCode Account_Name TargetUserName TargetDomainName
| sort - _time
```

---

## Query Explanation

### Event Filtering

```spl
EventCode=4726
```

Restricts the search to Windows user account deletion events.

### Field Selection

```spl
| table _time host EventCode Account_Name TargetUserName TargetDomainName
```

The query displays the primary fields required for investigation:

- `_time` — Time of the event
- `host` — Windows host
- `EventCode` — Windows event identifier
- `Account_Name` — Account that performed the action
- `TargetUserName` — Account that was deleted
- `TargetDomainName` — Target account domain

### Sorting

```spl
| sort - _time
```

Displays the most recent deletion events first.

---

# Alert Configuration

| Configuration | Value |
|---|---|
| Alert Name | Windows - User Account Deletion |
| Alert Type | Scheduled |
| Schedule | Every 5 minutes |
| Time Range | Last 5 minutes |
| Trigger Condition | Number of Results > 0 |
| Trigger Behavior | Once |
| Action | Add to Triggered Alerts |
| Severity | High |

---

# Controlled Validation

A temporary Windows account was used for controlled SIEM testing:

```text
SIEM_TEST_USER_05
```

After the account lifecycle and privilege-change tests were completed, the account was deleted using:

```powershell
Remove-LocalUser -Name "SIEM_TEST_USER_05"
```

This generated Windows Security Event ID:

```text
4726
```

---

# Windows Event Validation

The generated Windows event contained information indicating:

```text
Event ID: 4726
Description: A user account was deleted.
Target Account: SIEM_TEST_USER_05
Subject Account: OBAFEFMI-MOSES
```

The event demonstrated that Windows successfully recorded the account deletion activity.

---

# Splunk Validation

The event was verified in Splunk using:

```spl
index=security_lab EventCode=4726
| table _time host EventCode Account_Name TargetUserName TargetDomainName
| sort - _time
```

The search successfully returned the controlled account deletion event.

The relevant account was:

```text
SIEM_TEST_USER_05
```

The event identified:

```text
Account responsible: OBAFEFMI-MOSES
```

This confirmed successful ingestion of Event ID 4726 into the `security_lab` index.

---

# Security Relevance

Account deletion can be a significant security event depending on the context.

An attacker with sufficient privileges could potentially delete accounts to:

- Remove legitimate users
- Disrupt access
- Alter system identity configuration
- Remove temporary accounts
- Modify persistence mechanisms
- Cover up previous account activity

However, account deletion is also a normal administrative operation.

The event therefore requires contextual investigation.

---

# SOC Investigation Procedure

When this detection triggers, the analyst should perform the following steps.

## 1. Identify the Deleted Account

Review:

```text
TargetUserName
```

Determine which account was deleted.

---

## 2. Identify Who Performed the Deletion

Review:

```text
Account_Name
```

Determine which account initiated the deletion.

---

## 3. Validate Authorization

Determine whether the deletion was:

- Authorized
- Part of employee offboarding
- Part of account cleanup
- Requested by IT/security
- Performed by an approved administrator

---

## 4. Determine Whether the Account Was Privileged

Investigate whether the deleted account previously belonged to:

```text
Administrators
```

or another privileged group.

Correlate with Event ID 4732 and other group membership events where available.

---

## 5. Review Previous Account Activity

Search for activity involving the deleted account before deletion.

Example:

```spl
index=security_lab "SIEM_TEST_USER_05"
| table _time host EventCode Account_Name TargetUserName TargetDomainName Message
| sort - _time
```

This can help establish the account's activity timeline before deletion.

---

## 6. Review Related Security Events

Useful events for correlation include:

```text
4624 — Successful Logon
4625 — Failed Logon
4672 — Special Privileges Assigned
4688 — Process Creation
4720 — Account Creation
4722 — Account Enabled
4725 — Account Disabled
4732 — Group Membership Change
4726 — Account Deleted
```

A sequence such as:

```text
4720 Account Created
      ↓
4732 Added to Administrators
      ↓
4672 Privileged Activity
      ↓
4726 Account Deleted
```

could warrant deeper investigation.

---

# Example Investigation Query

A broader investigation can search for account-management activity:

```spl
index=security_lab
(EventCode=4720 OR EventCode=4722 OR EventCode=4725 OR EventCode=4726 OR EventCode=4732)
| table _time host EventCode Account_Name TargetUserName TargetDomainName
| sort - _time
```

This provides a basic timeline of Windows account lifecycle and group membership events.

---

# False Positives

Potential legitimate sources include:

- Employee offboarding
- Temporary account cleanup
- IT administration
- Security administration
- Test account removal
- Account-management procedures
- Automated identity-management systems

The SOC should therefore verify the business justification before escalating the event.

---

# Severity Assessment

**Severity: High**

The detection is classified as High because unauthorized deletion of an account can affect access control and system identity management.

The severity should be evaluated in context.

Higher-risk situations include:

- Deletion of privileged accounts
- Deletion outside normal administrative hours
- Multiple accounts deleted rapidly
- Deletion following suspicious authentication
- Deletion following privilege escalation
- Deletion associated with a compromised administrator account

---

# MITRE ATT&CK Relevance

Account deletion activity can provide supporting telemetry for investigations involving account manipulation.

A relevant ATT&CK technique is:

```text
T1098 — Account Manipulation
```

The Event ID itself does not prove malicious activity or successful use of an ATT&CK technique. It provides telemetry that can support investigation and correlation.

---

# Evidence

The following evidence was captured during validation:

```text
evidence/screenshots/E-15-user-account-deletion-alert.png
```

The evidence demonstrates the user account deletion detection and associated Splunk monitoring activity.

---

# Detection Validation Summary

The detection successfully demonstrated:

- Windows Event ID 4726 generation
- User account deletion visibility
- Splunk ingestion of Event ID 4726
- Identification of the deleted account
- Identification of the account responsible for the deletion
- Scheduled alert configuration
- Supporting evidence capture

---

# Detection Status

**Status: Validated**

The detection was validated using the controlled deletion of:

```text
SIEM_TEST_USER_05
```

The resulting Event ID 4726 was successfully ingested into Splunk and identified by the detection query.

---

# Conclusion

Windows Event ID 4726 provides valuable visibility into user account deletion activity.

Although account deletion can be completely legitimate, unexpected deletion should be investigated because it may indicate unauthorized account manipulation or other suspicious administrative activity.

By correlating Event ID 4726 with account creation, privilege assignment, group membership, authentication, and process creation events, SOC analysts can build a more complete timeline of account-related activity.

The detection therefore provides an important component of Windows account lifecycle monitoring within the SIEM environment.