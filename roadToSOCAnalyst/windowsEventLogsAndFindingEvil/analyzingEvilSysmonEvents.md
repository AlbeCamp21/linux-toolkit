# Analyzing Evil With Sysmon & Event Logs: Comprehensive Technical Guide

## 1. Introduction to Advanced Threat Detection
Cybersecurity professionals must identify and analyze malicious events. Benign events are normal system operations. Malicious activities are actions taken by an attacker to compromise a system. To move from observing normal behavior to identifying attacks, we must use specific tools and event identifiers.

### Standard Windows Limitations
The default Windows Event Log records basic information. For example:
* **Event ID 4624:** Records when a user logs on. It shows the username and the time.
* **Event ID 4688:** Records when a new process is created. It shows the name of the program that started.

However, these logs often lack deep context, such as network connections made by a process or the specific files (DLLs) a program loads into memory. To fill this information gap, we use Sysmon.

---

## 2. System Monitor (Sysmon) Deep Dive

### What is Sysmon?
System Monitor (Sysmon) is a Windows system service and a device driver. Once installed, it stays on the system even after reboots. Its sole purpose is to monitor system activity and write very detailed information into the Windows Event Log.

### The Three Components of Sysmon
1. **The Service:** A background process that manages the data collection logic.
2. **The Device Driver:** A low-level component that sits between the hardware and the Operating System (Kernel level) to capture activity as it happens in real-time.
3. **The Event Log:** A specific destination in the Event Viewer (`Applications and Services -> Microsoft -> Windows -> Sysmon -> Operational`) where the captured data is stored.

### Sysmon Event IDs
Sysmon uses its own numbering system to categorize actions:
* **Event ID 1: Process Creation.** Similar to 4688 but includes the file hash (MD5/SHA256) and the exact command line used.
* **Event ID 3: Network Connection.** Records when a program connects to an IP address.
* **Event ID 7: Image Loaded.** Records when a process loads a DLL file into memory.
* **Event ID 10: Process Access.** Records when one process tries to open or interact with another process (e.g., reading its memory).

### The Configuration File (XML)
Sysmon generates a lot of data. To prevent it from recording useless information (noise), we use an XML configuration file.
* **Include:** Tells Sysmon "Only record events that match these specific rules."
* **Exclude:** Tells Sysmon "Record everything EXCEPT events that match these rules."

If you set a rule to `exclude` and leave the rules blank, Sysmon will exclude nothing. This means it will record **every single action** of that type, which is useful for deep investigation but heavy on system resources.

---

## 3. Detailed Case Study 1: DLL Hijacking

### What is a DLL (Dynamic Link Library)?
A DLL is a file containing code and data that multiple programs can use at the same time. Programs like `calc.exe` (Calculator) do not contain all the code they need to run; they "call" or "load" DLLs to perform specific tasks, like connecting to the internet or drawing graphics.

### What is DLL Hijacking?
DLL Hijacking is an attack that exploits how Windows searches for these DLL files. When a program starts, it looks for its required DLLs in a specific order:
1. The directory from which the application loaded (the folder where the `.exe` is).
2. The system directory (`C:\Windows\System32`).
3. The 16-bit system directory.
4. The Windows directory.
5. The current working directory.
6. The directories that are listed in the PATH environment variable.

**The Attack Mechanism:**
If an attacker places a malicious DLL with a legitimate name (e.g., `WININET.dll`) in the same folder as a legitimate program (e.g., `calc.exe`), the program will find the malicious DLL first and execute its code instead of the real one located in `System32`.



### How to Detect it with Sysmon
We use **Sysmon Event ID 7 (Image Loaded)**.

**Technical Indicators of Compromise (IOCs):**
1. **Unusual Path:** `calc.exe` should always be in `C:\Windows\System32`. If Sysmon shows `calc.exe` running from `C:\Users\Public\Downloads`, it is highly suspicious.
2. **DLL Location:** `WININET.dll` is a system file. If Sysmon shows `calc.exe` loading `WININET.dll` from the Desktop instead of `System32`, it is a confirmed hijack.
3. **Signature Status:** Legitimate Microsoft DLLs are "Signed." This means they have a digital certificate proving they are authentic. Malicious hijacked DLLs are usually "Unsigned." Sysmon Event ID 7 explicitly shows if a loaded module is signed or not.



---

## 4. Detailed Case Study 2: Unmanaged PowerShell/C# Injection

### Managed vs. Unmanaged Code
* **Managed Code (C# / .NET):** This code runs inside a "container" called the Common Language Runtime (CLR). It does not talk directly to the hardware. `powershell.exe` is a managed process.
* **Unmanaged Code (C++ / C):** This code runs directly on the processor. Most Windows system processes (like `spoolsv.exe`, the print spooler) are unmanaged.

### The Attack: Unmanaged PowerShell Injection
Attackers want to run PowerShell code because it is powerful, but they want to hide it inside a normal, unmanaged process like the Print Spooler (`spoolsv.exe`).

**How it works:**
The attacker forces an unmanaged process to load the .NET Runtime DLLs (`clr.dll` and `clrjit.dll`). Once these DLLs are loaded into a process like `spoolsv.exe`, that process suddenly gains the ability to execute C# and PowerShell code.

### How to Detect it
1. **Process Hacker Observation:** In Process Hacker, managed processes are highlighted in green. If a system process like `spoolsv.exe` (which is normally unmanaged) turns green, it has been injected with .NET.
2. **Sysmon Event ID 7:** We look for the "Instance of Loading" (the specific moment the DLL enters memory).
   * **Indicator:** If Sysmon records `spoolsv.exe` loading `clr.dll` or `clrjit.dll`, this is an anomaly. The Print Spooler has no legitimate reason to load the .NET Runtime.



---

## 3. Detailed Case Study 3: Credential Dumping (Mimikatz)

### What is LSASS?
The Local Security Authority Subsystem Service (`lsass.exe`) is a critical Windows process. It manages user credentials, password hashes, and active login sessions. Because it holds passwords in memory, it is the primary target for attackers.

### What is Mimikatz?
Mimikatz is a tool used to extract (dump) these credentials from the memory of the `lsass.exe` process.

### The Attack: sekurlsa::logonpasswords
This specific Mimikatz command performs the following technical steps:
1. It requests **SeDebugPrivilege**. This is a high-level permission that allows a process to inspect the memory of another process (normally used for debugging software).
2. It opens a handle (a connection) to the `lsass.exe` process.
3. It reads the raw memory of `lsass.exe` to find password data.

### How to Detect it with Sysmon
We use **Sysmon Event ID 10 (Process Access)**.

**Technical Indicators of Compromise (IOCs):**
1. **Source Image:** If a process like `mimikatz.exe` or an unknown `Agent.exe` from the `Downloads` folder tries to access `lsass.exe`, it is a high-severity alert.
2. **Target Image:** The target is always `lsass.exe`.
3. **GrantedAccess:** Sysmon ID 10 shows the "Access Mask" (a hexadecimal code). Attackers need specific access rights (like `0x1010` or `0x1410`) to read memory.
4. **User Mismatch:** If the `SourceUser` is a regular user (e.g., `waldo`) but they are trying to access a process owned by `SYSTEM` (the OS itself), this is unauthorized behavior.



---

## 5. Summary Table of Detection Logic

| Attack Type | Target | Sysmon ID | Key Field to Watch |
| :--- | :--- | :--- | :--- |
| **DLL Hijacking** | Any `.exe` | 7 (Image Load) | `ImageLoaded` path (should be `System32`). |
| **C# Injection** | Unmanaged `.exe` | 7 (Image Load) | Loading of `clr.dll` in non-.NET processes. |
| **Credential Dumping** | `lsass.exe` | 10 (Process Access) | `SourceImage` (the program attacking LSASS). |

### Conclusion
To "find evil," you must compare what Sysmon tells you against the known "normal" state of Windows.
* **Where:** `Applications and Services Logs -> Microsoft -> Windows -> Sysmon`.
* **When:** Whenever a process starts, loads a module, or touches another process.
* **Why:** Because default logs do not show the relationship between processes and the files they load or the memory they access.
