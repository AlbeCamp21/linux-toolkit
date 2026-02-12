# Technical Reference: Event ID Categorization for Behavioral Analysis

This guide outlines the critical Windows Event IDs (Standard and Sysmon) used to identify malicious patterns during log analysis. It focuses on the technical purpose of each ID and its representation in forensic investigations.

---

## 1. Process Telemetry (Execution & Lifecycle)
Tracking the creation and termination of processes is the baseline for identifying anomalies like **Living Off the Land (LotL)** or **Unmanaged Code Execution**.

### Event ID 1: Process Creation (Sysmon) / 4688 (Security Log)
Identifies when a new process is instantiated.
* **Analysis Focus:** `ParentImage`, `CommandLine`, and `Hashes`.
* **Security Insight:** Used to detect **PPID Spoofing** by comparing the `ParentImage` with the expected behavior of the child.
* **Representation Case:** If `lsass.exe` is the `ParentImage` for `cmd.exe`, it indicates a high-probability injection or spoofing event, as the Local Security Authority Subsystem does not natively spawn shells.

### Event ID 5: Process Terminated (Sysmon)
Identifies the end of a process lifecycle.
* **Analysis Focus:** `UtcTime` and `ProcessGuid`.
* **Security Insight:** Used to measure the duration of execution. Short-lived processes (e.g., `whoami.exe` running for <1 second) often indicate automated reconnaissance scripts.

---

## 2. Memory & Thread Injection (In-Memory Attacks)
These IDs are vital for detecting advanced evasion techniques where malicious code resides only in the memory space of legitimate processes.



### Event ID 8: CreateRemoteThread (Sysmon)
Detects when a process creates a thread in another process.
* **Analysis Focus:** `SourceImage`, `TargetImage`, and `StartAddress`.
* **Representation Case:** A `SourceImage` of `rundll32.exe` targeting `calculator.exe` with a `StartFunction` value of `-` (null) suggests the injection of raw shellcode into the target's memory space.

### Event ID 10: ProcessAccess (Sysmon)
Identifies when a process opens a handle to another process.
* **Analysis Focus:** `GrantedAccess` masks.
* **Representation Case:** An access mask of `0x1F1FFF` or `0x1410` against `lsass.exe` indicates a process is attempting to read the memory of the security subsystem, typically for credential dumping (e.g., via Mimikatz or ProcDump).

---

## 3. Network & Persistence Telemetry
Monitoring how processes interact with the file system and the network provides context on C2 (Command & Control) communications and staging.

### Event ID 3: Network Connection (Sysmon)
Records TCP/UDP connections initiated by a process.
* **Analysis Focus:** `DestinationIp`, `DestinationPort`, and `Initiated` (Boolean).
* **Representation Case:** Identifying `svchost.exe` (a system process) connecting to an external IP on port `4444` or `8080` often indicates a beaconing payload or a reverse shell.

### Event ID 11: FileCreate (Sysmon)
Records when a file is created or overwritten.
* **Analysis Focus:** `TargetFilename` and `ProcessGuid`.
* **Security Insight:** Critical for detecting **Staging**. For example, the creation of a `.dmp` file in `C:\Windows\Temp\` by a non-system process suggests a successful LSASS memory dump.

---

## 4. Module & Library Telemetry
Monitoring library loads is the primary method for detecting **DLL Hijacking** and **Unmanaged Code Loading**.



### Event ID 7: Image Loaded (Sysmon)
Identifies when a DLL or executable module is loaded into a process.
* **Analysis Focus:** `ImageLoaded`, `Hashes`, and `Signed` status.
* **Representation Case 1 (DLL Hijacking):** A legitimate process (`dism.exe`) loading `version.dll` from a user-writable directory (`C:\Users\Public\`) instead of `C:\Windows\System32\`.
* **Representation Case 2 (Unmanaged PowerShell):** A non-PowerShell process (e.g., `sqlserver.exe`) loading `System.Management.Automation.dll`.

---

## 5. Summary Matrix for Incident Response

| Security Event | Sysmon ID | Security ID | Primary Field to Inspect |
| :--- | :--- | :--- | :--- |
| **Process Spoofing** | 1 | 4688 | `ParentImage` / `CommandLine` |
| **Lateral Movement** | 3 | 4624 / 4625 | `DestinationIp` / `LogonType` |
| **Credential Dumping** | 10 | N/A | `TargetImage` (lsass.exe) / `GrantedAccess` |
| **Code Injection** | 8 | N/A | `SourceImage` / `StartAddress` |
| **DLL Hijacking** | 7 | N/A | `ImageLoaded` / `SignatureStatus` |

---

## 6. Pro-Tip: Correlating IDs (The "Pivot")
Forensic efficiency is achieved by pivoting via the `ProcessGuid` rather than the `ProcessId`. Since PIDs are recycled by Windows, the `ProcessGuid` remains a unique identifier for a specific execution instance. 

**Example Workflow:**
1.  Identify suspicious DLL load in **ID 7**.
2.  Filter all **ID 1** and **ID 3** events using that specific `ProcessGuid`.
3.  Reconstruct the timeline from process birth to network egress.
