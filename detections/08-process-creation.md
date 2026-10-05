# Detection 08 — Windows Process Creation Monitoring

## Overview

This detection monitors Windows process creation activity using **Security Event ID 4688**.

Process creation telemetry provides visibility into programs and executables launched on a Windows system. This information can help SOC analysts investigate suspicious execution, command-line activity, malware execution, scripting activity, and potential post-compromise behavior.

---

## Detection Objective

Detect and monitor Windows process creation events and capture relevant information about:

- The process that was executed
- The account that launched the process
- The host where execution occurred
- The process command line
- The time of execution

The detection provides foundational endpoint telemetry that can be correlated with other security events.

---

## Windows Event ID

| Event ID | Description |
|---|---|
| 4688 | A new process has been created |

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

# Windows Audit Configuration

Initially, Event ID 4688 was not present in the Windows Security log.

Windows Process Creation auditing was therefore enabled using:

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
```

The configuration was verified using:

```powershell
auditpol /get /subcategory:"Process Creation"
```

This enabled Windows to generate successful process creation audit events.

---

# Detection Query

The primary SPL query used for process creation monitoring was:

```spl
index=security_lab EventCode=4688
| table _time host EventCode Account_Name New_Process_Name Process_Command_Line
| sort - _time
```

---

## Query Explanation

### Event Filtering

```spl
EventCode=4688
```

This restricts the search to Windows process creation events.

### Field Selection

```spl
| table _time host EventCode Account_Name New_Process_Name Process_Command_Line
```

The query displays important process execution information:

- `_time` — Time of execution
- `host` — Host where the event occurred
- `EventCode` — Windows event identifier
- `Account_Name` — Account associated with the activity
- `New_Process_Name` — Executable that was launched
- `Process_Command_Line` — Command-line information when available

### Sorting

```spl
| sort - _time
```

The newest process creation events are displayed first.

---

# Controlled Validation

A harmless Windows process was launched to generate a process creation event.

The following PowerShell command was used:

```powershell
Start-Process notepad.exe
```

This generated Windows Security Event ID:

```text
4688
```

The resulting event demonstrated that Windows was successfully recording process creation activity.

---

# Splunk Validation

The process creation telemetry was verified in Splunk using:

```spl
index=security_lab EventCode=4688
| table _time host EventCode Account_Name New_Process_Name Process_Command_Line
| sort - _time
```

The search returned Windows process creation events.

At one point, the Splunk index contained a substantial volume of Event ID 4688 telemetry, confirming that process creation auditing was successfully being collected.

---

# Controlled Notepad Validation

To specifically verify the controlled test process, the following SPL search was used:

```spl
index=security_lab EventCode=4688
| search New_Process_Name="*\\notepad.exe"
| table _time host EventCode Account_Name New_Process_Name Process_Command_Line
| sort - _time
```

The search successfully identified the controlled `notepad.exe` process creation activity.

This demonstrated that the detection could identify a specific executable within the Windows process creation telemetry.

---

# Alert Configuration

| Configuration | Value |
|---|---|
| Alert Name | Windows - Process Creation Monitoring |
| Alert Type | Scheduled |
| Schedule | Every 5 minutes |
| Time Range | Last 5 minutes |
| Trigger Condition | Number of Results > 0 |
| Trigger Behavior | Once |
| Action | Add to Triggered Alerts |

---

# Security Relevance

Process creation monitoring is valuable because attackers frequently execute programs after gaining access to a system.

Examples of potentially interesting process activity include:

```text
powershell.exe
cmd.exe
wscript.exe
cscript.exe
mshta.exe
rundll32.exe
regsvr32.exe
certutil.exe
```

However, the presence of a process alone does not establish malicious activity.

Many of these programs can be legitimately used by administrators, applications, installers, and operating-system components.

Process creation should therefore be investigated using additional context.

---

# SOC Investigation Procedure

When a process creation event is considered suspicious, an analyst should investigate the following information.

## 1. Process Name

Review:

```text
New_Process_Name
```

Determine what executable was launched.

---

## 2. Executing Account

Review:

```text
Account_Name
```

Determine which user or service account launched the process.

---

## 3. Command Line

Review:

```text
Process_Command_Line
```

Look for suspicious arguments, encoded commands, download locations, scripts, unusual paths, or unexpected parameters.

---

## 4. Host

Identify the affected system:

```text
host
```

Determine whether the host is a workstation, server, administrative system, or other critical asset.

---

## 5. Correlate With PowerShell

Process creation can be correlated with Event ID 4104.

For example:

```text
4688 — powershell.exe created
        ↓
4104 — suspicious PowerShell script block
```

This provides stronger investigative context than either event alone.

---

## 6. Correlate With Authentication

Review:

```text
4624 — Successful Logon
4625 — Failed Logon
4672 — Special Privileges Assigned
```

This can help determine whether suspicious process execution occurred shortly after authentication or privileged access.

---

# Example Investigation Query

A broader process investigation can be performed using:

```spl
index=security_lab EventCode=4688
| table _time host Account_Name New_Process_Name Process_Command_Line
| sort - _time
```

---

# Suspicious Process Investigation

A SOC analyst can search for commonly abused Windows interpreters and utilities:

```spl
index=security_lab EventCode=4688
| search New_Process_Name="*\\powershell.exe"
    OR New_Process_Name="*\\cmd.exe"
    OR New_Process_Name="*\\wscript.exe"
    OR New_Process_Name="*\\cscript.exe"
    OR New_Process_Name="*\\mshta.exe"
    OR New_Process_Name="*\\rundll32.exe"
    OR New_Process_Name="*\\regsvr32.exe"
    OR New_Process_Name="*\\certutil.exe"
| table _time host Account_Name New_Process_Name Process_Command_Line
| sort - _time
```

This should be treated as an investigation query rather than proof of malicious execution.

---

# False Positives

Process creation generates a large amount of legitimate Windows activity.

Potential sources include:

- Windows system processes
- Applications
- Software updates
- Installers
- Administrative tools
- Security software
- Background services
- User applications

For this reason, a simple:

```spl
EventCode=4688
```

search is more appropriate for **monitoring and investigation** than as a high-confidence standalone security alert.

---

# Detection Tuning Considerations

The initial process creation alert uses:

```spl
index=security_lab EventCode=4688
```

This provides broad visibility but can generate a significant number of results on an active Windows system.

For a production SOC environment, the detection should be tuned to focus on higher-risk process activity.

Possible tuning approaches include:

- Suspicious process names
- Unusual parent-child process relationships
- Suspicious command-line arguments
- Execution from temporary directories
- Execution from user-writable directories
- Encoded PowerShell commands
- Unusual administrative utilities
- Execution by unexpected accounts
- Correlation with authentication events
- Correlation with endpoint security alerts

The goal is to reduce alert fatigue while preserving useful endpoint visibility.

---

# Severity Assessment

**Severity: Monitoring / Informational**

The base process creation telemetry is not inherently malicious.

Severity should be increased when Event ID 4688 is correlated with additional suspicious indicators.

For example:

```text
4688 Process Creation
+
4104 Suspicious PowerShell
+
4624 Successful Logon
+
4672 Privileged Activity
```

could warrant a significantly higher-priority investigation.

---

# MITRE ATT&CK Relevance

Process creation telemetry can support investigation of multiple ATT&CK techniques depending on the process and command-line activity observed.

One relevant technique is:

```text
T1059 — Command and Scripting Interpreter
```

Specific sub-techniques may become relevant depending on the interpreter involved.

The Event ID itself does not prove that an ATT&CK technique was successfully executed.

---

# Evidence

The following evidence was captured during validation:

```text
evidence/screenshots/E-14-process-creation-alert.png
```

The evidence demonstrates the configured process creation monitoring alert and associated Splunk activity.

---

# Validation Summary

The detection successfully demonstrated:

- Windows Process Creation auditing
- Event ID 4688 generation
- Splunk ingestion of process creation telemetry
- Process execution visibility
- Identification of a controlled `notepad.exe` process
- Scheduled alert configuration
- SOC investigation fields

---

# Detection Status

**Status: Validated**

The detection was successfully validated using a controlled process execution test.

Windows generated Event ID 4688 after process creation auditing was enabled, and Splunk successfully ingested and displayed the resulting telemetry.

---

# Conclusion

Windows Event ID 4688 provides valuable endpoint visibility by recording the creation of new processes.

Although the raw event volume can be high, process creation telemetry becomes significantly more valuable when correlated with command-line information, PowerShell Script Block Logging, authentication events, privilege events, and other security telemetry.

The detection therefore serves as an important foundational component of the SIEM monitoring architecture while also demonstrating the need for proper detection tuning in a production SOC environment.