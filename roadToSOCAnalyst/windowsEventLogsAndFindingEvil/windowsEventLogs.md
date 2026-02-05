# Windows Event Logging and Analysis

## 1. Fundamentals of Windows Event Logs
Windows Event Logs are the primary mechanism for recording system, application, and security activities within the Windows Operating System. They provide a structured audit trail essential for diagnostic, administrative, and cybersecurity purposes.

### The .evtx Format

* **Structure:** Modern Windows versions (Vista and later) use the `.evtx` format. This is a binary XML format, which is more compact and faster to parse than plain text logs.
* **Storage Path:** Physical log files are located at `C:\Windows\System32\winevt\Logs\`.
* **Access Methods:** Logs are typically viewed through the GUI-based `eventvwr.msc` (Event Viewer) or via command-line tools like PowerShell using the `Get-WinEvent` cmdlet.


## 2. Core Log Categories
Logs are organized into channels based on their source and the nature of the information they contain:

| Log Channel | Description | Security Significance |
| :--- | :--- | :--- |
| **Security** | Records audit events such as logons, logoffs, and privilege usage. | **Critical**: Primary source for detecting unauthorized access and lateral movement. |
| **System** | Contains events logged by Windows system components (e.g., driver failures). | **High**: Detects system reboots, service crashes, and hardware tampering. |
| **Application** | Records events from installed software and third-party applications. | **Medium**: Useful for identifying application-level exploits or configuration errors. |
| **Forwarded** | Stores logs collected from remote computers across the network. | **High**: Enables centralized monitoring for enterprise-wide threat hunting. |


## 3. Event Anatomy and XML Structure
Every event entry consists of two main technical sections:

### A. The <System> Section (Metadata)
This section contains standard headers present in every event, regardless of its source:
* **Event ID:** A numeric identifier for the type of event (e.g., 4624 for Logon).
* **TimeCreated:** The precise timestamp of when the event was logged.
* **Level:** The severity rating (Information, Warning, Error, Critical).
* **Computer:** The hostname of the machine that generated the log.

### B. The <EventData> Section (Contextual Data)
This section contains variable fields specific to the Event ID. For a SOC analyst, these fields provide the evidence:
* **SubjectLogonId / TargetLogonId:** A unique hexadecimal identifier used to correlate all actions performed during a specific user session.
* **ProcessName:** The full path of the executable responsible for the event.
* **ObjectName:** The specific file, registry key, or object that was accessed or modified.
* **LogonType:** A numeric value defining the method of authentication (e.g., Type 2 for Interactive, Type 3 for Network).


## 4. Advanced Analysis via XPath Queries
When dealing with high-volume logs, standard filters are insufficient. Analysts use the XML/XPath query language to perform granular searches.

**Example: Correlating an Actor with an Action**
To find all instances where a specific session (identified by `SubjectLogonId`) modified a security policy (Event ID 4907):

```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4907)]] and 
      *[EventData[Data[@Name='SubjectLogonId']='0x3E7']]
    </Select>
  </Query>
</QueryList>
```




## 5. Critical Event IDs for Threat Detection

### Authentication and Access
* **4624 / 4625:** Successful vs. Failed Logon (Brute-force detection).
* **4672:** Special privileges assigned (Indicates high-privilege/admin login).
* **4648:** Logon using explicit credentials (Potential lateral movement indicator).

### Persistence and Tampering
* **4698:** A scheduled task was created (Common persistence mechanism).
* **7045:** A new service was installed (Malware persistence).
* **1102:** Audit log cleared (Indicator of anti-forensics activity).
* **4907 / 4719:** Changes to object SACLs or system audit policies (Attempts to hide future actions).

### Antivirus and Remediation
* **1116 / 1117:** Malware detection and remediation by Windows Defender.
* **5001:** Real-time protection configuration changed (Potential attempt to disable AV).


## 6. Investigation Methodology: Finding Evil
The analytical workflow follows a logical progression:
1. **Initial Trigger:** Identify an anomaly (e.g., a login at an unusual time via Event ID 4624).
2. **Identification:** Extract the **TargetLogonId** from the initial event.
3. **Correlation:** Filter all Security logs using that Logon ID to reconstruct the user's activity timeline.
4. **Verification:** Inspect the **ProcessName** to ensure the executing file is legitimate and not a renamed malicious binary.
5. **Impact Assessment:** Review **ObjectName** and **Privilege List** (via Event 4672) to determine the extent of the system modification.
