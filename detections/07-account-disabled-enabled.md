# Detection 07 — Windows Account Disabled or Enabled

## Overview

This detection monitors Windows Security Event IDs **4725** and **4722** to identify changes to the enabled state of user accounts.

Account state changes can be legitimate administrative activities, but unexpected disabling or enabling of an account may indicate unauthorized account manipulation, persistence activity, or attempts to disrupt access.

---

## Detection Objective

Detect when a Windows user account is:

- Disabled
- Enabled

The detection is designed to provide SOC analysts with visibility into account lifecycle changes and identify potentially unauthorized modifications.

---

## Windows Event IDs

| Event ID | Description |
|---|---|
| 4725 | A user account was disabled |
| 4722 | A user account was enabled |

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

## Detection Query

The following SPL query searches for both account-disabled and account-enabled events:

```spl
index=security_lab (EventCode=4725 OR EventCode=4722)
| table _time host EventCode Account_Name TargetUserName TargetDomainName
| sort - _time
```

---

## Query Explanation

### Event Filtering

```spl
(EventCode=4725 OR EventCode=4722)
```

The query searches for either:

- `4725` — Account disabled
- `4722` — Account enabled

### Field Selection

```spl
| table _time host EventCode Account_Name TargetUserName TargetDomainName
```

The detection displays the most relevant investigation fields:

- Event timestamp
- Host
- Event ID
- Account responsible for the change
- Target account
- Target domain

### Sorting

```spl
| sort - _time
```

Events are displayed with the newest activity first.

---

# Alert Configuration

| Configuration | Value |
|---|---|
| Alert Name | Windows - Account Disabled or Enabled |
| Alert Type | Scheduled |
| Schedule | Every 5 minutes |
| Trigger Condition | Number of Results > 0 |
| Trigger Behavior | Once |
| Action | Add to Triggered Alerts |
| Severity | Medium |

---

# Detection Validation

## Test Account

A temporary test account was used during validation:

```text
SIEM_TEST_USER_05
```

The account was previously created specifically for controlled SIEM testing.

---

## Account Disable Test

The account was disabled using PowerShell:

```powershell
Disable-LocalUser -Name "SIEM_TEST_USER_05"
```

This generated Windows Security Event ID:

```text
4725
```

The Windows event indicated:

```text
A user account was disabled.
```

The event identified:

```text
Target Account: SIEM_TEST_USER_05
Subject Account: OBAFEFMI-MOSES
```

---

## Account Enable Test

The account was subsequently enabled using:

```powershell
Enable-LocalUser -Name "SIEM_TEST_USER_05"
```

This generated Windows Security Event ID:

```text
4722
```

The resulting Windows Security telemetry demonstrated that both account state transitions could be monitored.

---

# Splunk Validation

The following SPL query was used to verify the events in Splunk:

```spl
index=security_lab (EventCode=4725 OR EventCode=4722)
| table _time host EventCode Account_Name TargetUserName TargetDomainName
| sort - _time
```

The search returned events associated with:

```text
SIEM_TEST_USER_05
```

The observed events included:

```text
4725 — Account Disabled
4722 — Account Enabled
```

This confirmed that the Windows account state-change telemetry was successfully ingested into Splunk.

---

# Alert Validation

The scheduled alert was configured to evaluate the detection query every five minutes.

The alert was successfully triggered during validation after the account state-change activity was generated.

The alert configuration provided the SOC with visibility into account enable/disable activity.

---

# Security Relevance

Unexpected account state changes can be important security indicators.

### Account Disabled

An attacker may disable an account to:

- Prevent legitimate users from accessing systems
- Disrupt administrative access
- Disable security or service accounts
- Modify account availability as part of persistence or lateral movement

### Account Enabled

An attacker may enable an account to:

- Reactivate a previously disabled account
- Restore access to a compromised account
- Establish persistence
- Bypass organizational account-management controls

However, these events can also occur during legitimate administrative operations.

---

# SOC Investigation Procedure

When this alert triggers, the analyst should investigate:

### 1. Identify the Target Account

Determine which account was affected:

```text
TargetUserName
```

### 2. Identify the Account Performing the Change

Review:

```text
Account_Name
```

Determine who performed the account state change.

### 3. Determine the Type of Change

Identify whether the event was:

```text
4725 → Account Disabled
4722 → Account Enabled
```

### 4. Validate Authorization

Determine whether the account change was:

- Requested
- Approved
- Performed by an authorized administrator
- Part of normal account lifecycle management

### 5. Review Related Activity

Search for other events involving the same account around the same time.

Useful events include:

```text
4624 — Successful Logon
4625 — Failed Logon
4672 — Special Privileges Assigned
4688 — Process Creation
4720 — Account Creation
4732 — Group Membership Change
4726 — Account Deletion
```

### 6. Investigate Suspicious Activity

Escalate the alert if the account change:

- Was unauthorized
- Involved a privileged account
- Occurred outside normal administrative activity
- Coincided with suspicious authentication
- Coincided with privilege escalation
- Was followed by suspicious process execution

---

# Example Investigation Query

To investigate activity involving the affected test account:

```spl
index=security_lab "SIEM_TEST_USER_05"
| table _time host EventCode Account_Name TargetUserName TargetDomainName Message
| sort - _time
```

This can help establish a timeline around account activity.

---

# False Positives

Potential legitimate sources of this alert include:

- IT administrators
- Employee onboarding
- Employee offboarding
- Account reactivation
- Temporary account suspension
- Security policy enforcement
- Help-desk operations
- Automated identity-management systems

The alert should therefore be investigated within the context of the user's role and the organization's account-management procedures.

---

# Severity Assessment

**Severity: Medium**

The severity is classified as Medium because account state changes are not inherently malicious.

The severity should be increased when the event involves:

- Privileged accounts
- Unexpected administrative activity
- Multiple accounts
- Suspicious authentication activity
- Other indicators of compromise

---

# MITRE ATT&CK Relevance

This detection can provide supporting telemetry for investigations involving account manipulation and persistence.

Relevant ATT&CK techniques may include:

```text
T1098 — Account Manipulation
```

The Event ID itself does not prove that an ATT&CK technique was successfully executed. It provides telemetry that can support investigation and correlation.

---

# Evidence

The following screenshots were captured during validation:

```text
evidence/screenshots/E-12-account-disabled-enabled.png
evidence/screenshots/E-13-account-disabled-enabled-alert.png
```

### E-12

Demonstrates the Windows account disabled/enabled detection activity and associated Splunk results.

### E-13

Demonstrates the configured Splunk alert and its triggered alert activity.

---

# Cleanup

The temporary SIEM testing account was used only for controlled security monitoring validation.

The account was later removed as part of lab cleanup:

```powershell
Remove-LocalUser -Name "SIEM_TEST_USER_05"
```

This prevented the temporary testing account from remaining unnecessarily on the Windows host.

---

# Detection Status

**Status: Validated**

The detection successfully:

- Ingested Windows Event IDs 4725 and 4722
- Identified account disable activity
- Identified account enable activity
- Displayed relevant investigation fields
- Triggered the scheduled Splunk alert
- Produced supporting evidence

---

# Conclusion

The Windows Account Disabled or Enabled detection provides visibility into changes to local Windows account states.

The detection was successfully validated using a controlled test account, with both Event ID 4725 and Event ID 4722 observed in Splunk.

This detection can help SOC analysts identify unauthorized account manipulation when correlated with authentication, privilege, process creation, and other account-management events.
