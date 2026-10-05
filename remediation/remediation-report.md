# SIEM Security Monitoring Lab — Remediation Report

## Overview

This report documents the remediation and cleanup activities performed during the SIEM Security Monitoring Lab.

The remediation phase focused on safely reversing temporary configuration changes and test activities created during detection validation.

The objective was to ensure that controlled testing did not leave unnecessary accounts, privileges, or temporary artifacts on the Windows system.

---

# 1. Remediation Objectives

The remediation phase was performed to:

- Remove temporary testing accounts
- Remove temporary elevated privileges
- Restore account state after testing
- Remove temporary test artifacts
- Verify that test activity did not leave unnecessary access
- Preserve the integrity of the SIEM environment
- Document actions performed during cleanup

---

# 2. Temporary Test Account

A temporary Windows account was created during detection testing:

```text
SIEM_TEST_USER_05
```

The account was used to validate several account-management detections, including:

```text
4720 — User Account Creation
4732 — Privileged Group Membership Change
4725 — User Account Disabled
4722 — User Account Enabled
4726 — User Account Deleted
```

The account was intentionally created as part of controlled SIEM testing.

---

# 3. Privileged Group Cleanup

During Detection 06, the temporary test account was added to the local Administrators group to generate Event ID 4732.

The test action was:

```powershell
Add-LocalGroupMember -Group "Administrators" -Member "SIEM_TEST_USER_05"
```

After validation, the temporary account was removed from the Administrators group:

```powershell
Remove-LocalGroupMember -Group "Administrators" -Member "SIEM_TEST_USER_05"
```

This ensured that the test account did not retain unnecessary administrative privileges.

---

# 4. Account State Restoration

During Detection 07, the temporary account was disabled to generate Event ID 4725:

```powershell
Disable-LocalUser -Name "SIEM_TEST_USER_05"
```

The account was subsequently re-enabled to validate Event ID 4722:

```powershell
Enable-LocalUser -Name "SIEM_TEST_USER_05"
```

The account was restored to an enabled state before the final account cleanup.

---

# 5. Temporary Account Deletion

After the account lifecycle and privilege-management detections were completed, the temporary test account was deleted.

The cleanup command was:

```powershell
Remove-LocalUser -Name "SIEM_TEST_USER_05"
```

This generated Event ID 4726, which was also captured as part of Detection 09.

The account was therefore removed from the Windows system after completing the required detection tests.

---

# 6. PowerShell Test Artifact Cleanup

During Detection 02, a temporary PowerShell script was created for Script Block Logging validation.

The test script was located at:

```text
%TEMP%\siem-4104-test.ps1
```

The script contained controlled test content designed to generate Event ID 4104.

After testing, the temporary file could be removed using:

```powershell
Remove-Item "$env:TEMP\siem-4104-test.ps1" -Force
```

The test was designed to avoid performing an actual web request or downloading external content.

---

# 7. PowerShell Execution Policy

The PowerShell test used:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

The `Process` scope was deliberately used so that the execution-policy change applied only to the current PowerShell process.

No permanent machine-wide execution policy change was required for the test.

---

# 8. Process Creation Test Cleanup

Detection 08 used:

```powershell
Start-Process notepad.exe
```

to generate Windows Event ID 4688.

The test process was a normal Windows application and was used only to demonstrate process creation telemetry.

No malicious executable was introduced into the environment.

---

# 9. Security Audit Log Handling

Detection 10 monitored:

```text
Event ID 1102 — Security Audit Log Cleared
```

The Windows Security audit log was **not intentionally cleared** during testing.

This was an intentional safety decision.

Clearing the Security log would have removed existing security telemetry and reduced the forensic integrity of the lab.

Instead, the detection was validated by:

- Confirming the Event ID
- Configuring the SPL detection
- Configuring the scheduled alert
- Adding the detection to the SOC Dashboard
- Verifying that no Event ID 1102 was currently present

The detection therefore remained:

```text
Configured / Not Triggered During Testing
```

---

# 10. Detection Cleanup Summary

| Detection | Test Activity | Remediation |
|---|---|---|
| 4625 | Failed authentication | No persistent system change |
| 4104 | Temporary PowerShell script | Temporary artifact removed |
| 4799 | Group enumeration | No persistent system change |
| 4672 | Privileged account telemetry | No persistent privilege retained |
| 4720 | Temporary account created | Account later deleted |
| 4732 | Test account added to Administrators | Membership removed |
| 4725/4722 | Account disabled/enabled | Account restored before deletion |
| 4688 | Notepad process execution | Normal test process terminated/closed |
| 4726 | Test account deletion | Temporary account removed |
| 1102 | No destructive test performed | No remediation required |

---

# 11. Security Verification

The remediation process was designed to ensure that temporary testing privileges were not left behind.

The important cleanup actions included:

```text
Administrators membership removed
        ↓
Temporary account restored
        ↓
Temporary account deleted
        ↓
Temporary test artifacts removed
```

This reduced the risk of leaving unnecessary access on the Windows host.

---

# 12. Evidence Preservation

Although the temporary test activity was cleaned up, the resulting Windows and Splunk telemetry remained useful for the project.

The following evidence captured the detection activity:

```text
evidence/screenshots/E-01-repeated-failed-logon-alert.png
evidence/screenshots/E-02-powershell-script-block-logging.png
evidence/screenshots/E-03-powershell-suspicious-script-block.png
evidence/screenshots/E-04-powershell-alert-triggered.png
evidence/screenshots/E-05-windows-group-enumeration-detection.png
evidence/screenshots/E-06-group-enumeration-alert-triggered.png
evidence/screenshots/E-07-privileged-account-activity.png
evidence/screenshots/E-08-privileged-account-alert-triggered.png
evidence/screenshots/E-09-user-account-creation-alert.png
evidence/screenshots/E-10-privileged-group-membership-change.png
evidence/screenshots/E-11-privileged-group-membership-change.png
evidence/screenshots/E-12-account-disabled-enabled.png
evidence/screenshots/E-13-account-disabled-enabled-alert.png
evidence/screenshots/E-14-process-creation-alert.png
evidence/screenshots/E-15-user-account-deletion-alert.png
evidence/screenshots/E-16-security-audit-logs-alert.png
```

---

# 13. Remediation Principles Demonstrated

The remediation phase demonstrated several practical SOC principles.

## Least Privilege

Temporary accounts should not retain unnecessary administrative privileges after testing.

## Controlled Testing

Security testing should be performed in a controlled environment to prevent unintended impact.

## Evidence Preservation

Security logs should not be unnecessarily destroyed during detection testing.

## Cleanup

Temporary accounts, privileges, scripts, and test artifacts should be removed after validation.

## Documentation

Remediation actions should be documented so that the state of the system after testing is clear.

---

# 14. Lab Limitations

This remediation exercise was conducted in a local security laboratory.

It did not involve:

- A production Windows domain
- Active Directory
- Enterprise endpoint management
- Production user accounts
- Real malicious activity
- Enterprise incident-management systems
- Production forensic collection

Therefore, the remediation actions documented here demonstrate practical laboratory procedures rather than a complete enterprise incident-response process.

---

# 15. Final Remediation Status

| Area | Status |
|---|---|
| Temporary test account | Removed |
| Temporary Administrators membership | Removed |
| Account state restored before deletion | Completed |
| Temporary PowerShell artifact | Cleanup performed/available |
| Process creation test | Completed |
| Security log clearing | Not performed |
| SIEM detections | Preserved |
| Detection evidence | Preserved |
| SOC Dashboard | Preserved |

---

# 16. Conclusion

The remediation phase successfully completed the cleanup of temporary security-testing activity created during the SIEM lab.

The most important remediation action was the removal of the temporary test account:

```text
SIEM_TEST_USER_05
```

The account was used to validate multiple Windows account-management and privilege-related detections before being removed from the system.

Temporary administrative membership was also removed, and the account was restored to an enabled state before final deletion.

The Security audit log was deliberately not cleared during testing to preserve the integrity of the Windows security telemetry.

The remediation process demonstrates the importance of completing the full SOC lifecycle:

```text
Detect
  ↓
Investigate
  ↓
Validate
  ↓
Remediate
  ↓
Verify
  ↓
Document
```

This ensures that security testing improves monitoring capabilities without unnecessarily leaving behind accounts, privileges, or system artifacts.