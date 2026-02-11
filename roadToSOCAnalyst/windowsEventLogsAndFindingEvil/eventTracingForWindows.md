# Comprehensive Technical Guide: Event Tracing for Windows (ETW)

## 1. What is ETW? (Literal Definition)
**Event Tracing for Windows (ETW)** is a high-speed, general-purpose tracing facility provided by the Windows Operating System. It is implemented in the **Kernel** (the core of the OS).

It functions as a **data transport mechanism**. It does not analyze data; it simply moves information from the source where an event happens to the application that wants to see it. 



---

## 2. The Architecture: The Publish-Subscribe Model
ETW operates using three main components. This is called a "Publish-Subscribe" model because the source "publishes" data and the receiver "subscribes" to it.

### A. Providers (The Sensors)
* **What they are:** Software components that generate events. Windows has over 1,000 built-in providers.
* **What they do:** They sit inside applications or the kernel. When an action occurs (like a file being deleted), they "shout" a message.
* **Identifier:** Every provider has a unique **GUID** (Globally Unique Identifier), which is a long string of numbers and letters like `{A68CA8B7-004F-D7B6-A698-07E2DE0F1F5D}`.

### B. Controllers (The Management)
* **What they are:** Tools that start and stop tracing sessions.
* **Main Tool:** `logman.exe`.
* **Important Note:** Most sensors are turned **OFF** by default to save CPU power. A controller is needed to turn them **ON**.

### C. Consumers (The Listeners)
* **What they are:** Applications that catch the events and show them to the user.
* **Examples:** **Sysmon**, Event Viewer, and Performance Monitor.

---

## 3. Key Technical Components

* **Channels:** These are logical containers. For an ETW event to be visible in the **Event Viewer**, it must be sent through a "Channel." If there is no channel, the event exists in the system but remains invisible to standard log tools.
* **ETL Files (.etl):** This is the binary format used to save ETW data to the hard drive. 
    * **Why they matter:** In digital forensics, you can record a system's activity into an `.etl` file and analyze it later on a different computer.



---

## 4. Using Logman.exe to Audit the System
`Logman.exe` is the built-in command-line tool to interact with ETW.

* **Viewing Active Sessions:** `logman query -ets`
    * The `-ets` flag is mandatory to see sessions running in the live memory (RAM).
* **Finding Specific Sensors:** `logman query providers | findstr "Keyword"`
    * This allows you to search the list of 1,000+ providers for a specific one (e.g., "Network" or "Process").
* **Analyzing a Provider:** When you query a provider, you see its **Level** (how much data it sends) and its **Keywords** (specific filters for types of events).



---

## 5. Critical Providers for Security Analysis
Analysts use these specific sensors to find "evil" activity that standard logs might miss:

| Provider Name | Technical Use Case |
| :--- | :--- |
| **Microsoft-Windows-Kernel-Process** | Detects Process Injection and Process Hollowing. |
| **Microsoft-Windows-Kernel-File** | Detects Ransomware (unauthorized file encryption). |
| **Microsoft-Windows-Kernel-Network** | Detects data exfiltration and C2 (Command & Control) traffic. |
| **Microsoft-Windows-DotNETRuntime** | Detects malicious C# code execution (like PSInject). |
| **Microsoft-Windows-PowerShell** | Records hidden scripts and de-obfuscated commands. |

---

## 6. Restricted Providers and PPL
Some providers are **Restricted** because they record sensitive security data.

* **Microsoft-Windows-Threat-Intelligence:** This is the most powerful security sensor. It sees deep memory attacks that other tools miss.
* **Protected Process Light (PPL):** To listen to the Threat-Intelligence provider, a program must run as a "PPL." 
    * This requires a special digital signature from Microsoft. 
    * It prevents malware from reading the security data or stopping the sensor.

---

## 7. Summary for New Students
1. **The Action:** Something happens in Windows (e.g., a process starts).
2. **The Provider:** A sensor detects the action and creates a message.
3. **The Highway (ETW):** The message travels through the system.
4. **The Consumer:** A tool like **Sysmon** catches the message.
5. **The Result:** You see the event in the Event Viewer and can identify the attack.

---

## 8. Tapping Into ETW: Practical Detection Cases

In this section, we transition from theory to practice by "tapping into" the data stream of specific providers to detect advanced evasion techniques.

---

### Case A: Detecting Parent PID Spoofing (Kernel-Process)

**The Technique:** Attackers can lie to Windows about which process is their "parent." For example, a malicious `cmd.exe` can claim its parent is a legitimate system service like `spoolsv.exe` (Print Spooler) instead of the actual source (`powershell.exe`).

**The Limitation of Standard Tools:**
* **Sysmon (Event ID 1):** Often relies on the Process Environment Block (PEB). If an attacker spoofs the Parent PID, Sysmon may incorrectly log the fake parent as the real one.

**The ETW Solution:**
By using the **Microsoft-Windows-Kernel-Process** provider via tools like **SilkETW**, we can see the ground truth.
* **Why it works:** The Kernel-level provider sees the actual memory thread that requested the process creation.
* **Key Evidence:** In the generated `etw.json`, the `ParentProcessID` might show the spoofed parent, but internal fields like `CreatorProcessID` reveal the true culprit.

**Command Example:**
`SilkETW.exe -t user -pn Microsoft-Windows-Kernel-Process -ot file -p C:\temp\process_trace.json`

---

### Case B: Detecting Malicious .NET Assembly Loading (DotNETRuntime)

**The Strategy: Bring Your Own Land (BYOL)**
Instead of using native tools (LotL), attackers bring their own custom-built tools (like **Seatbelt** or **SharpHound**) written in C# (.NET) and load them directly into memory.

**Why attackers love .NET:**
1. **Fileless:** Assemblies can be loaded directly into RAM without touching the disk, bypassing traditional AV scans.
2. **Managed Nature:** The Common Language Runtime (CLR) handles execution, making it easier to hide inside legitimate processes (e.g., injecting C# code into `notepad.exe`).

**The Role of clr.dll and mscoree.dll:**
These are the "engines" of .NET. 
* `mscoree.dll`: The trigger that starts the .NET runtime.
* `clr.dll`: The actual engine (Common Language Runtime).
* **Detection Tip:** If a process that shouldn't use .NET (like `calc.exe`) suddenly loads `clr.dll`, it is a high-priority anomaly (Sysmon Event ID 7).

---

## 9. Advanced Filtering with Keywords (The 0x2038 Filter)

Capturing every .NET event creates too much "noise." To find malware like Seatbelt, we use specific **Keywords** to filter the **Microsoft-Windows-DotNETRuntime** provider.

**The 0x2038 Keyword Mask:**
This specific filter targets four critical areas:
1. **JitKeyword:** Captures "Just-In-Time" compilation (methods being converted to machine code in real-time).
2. **InteropKeyword:** Captures when managed code (.NET) calls unmanaged code (Native Windows APIs). This is where malicious actions often occur.
3. **LoaderKeyword:** Logs exactly which assemblies are being loaded into memory.
4. **NGenKeyword:** Monitors pre-compiled native images.

**Practical Command:**
`SilkETW.exe -t user -pn Microsoft-Windows-DotNETRuntime -uk 0x2038 -ot file -p C:\temp\dotnet_detection.json`

---

## 10. Deep Visibility: Method Names and Interop

The ultimate advantage of ETW over Sysmon is **granularity**. 

* **Sysmon** tells you: "A .NET engine was loaded."
* **ETW (DotNETRuntime)** tells you: "The assembly 'Seatbelt' was loaded, and it is calling the method `ManagedInteropMethodName: GetTokenInformation`."

By looking at the **method names** inside the ETW JSON output, an analyst can see the *intent* of the attacker. Even if the attacker renames `Seatbelt.exe` to `NormalFile.exe`, the ETW metadata will reveal the internal function names (e.g., methods starting with "G" and ending with "ion" like `GetTokenInformation`).

---

## 11. Summary: Why ETW is the "Gold Standard" for Hunting

| Feature | Sysmon / Event Logs | ETW (SilkETW/Kernel) |
| :--- | :--- | :--- |
| **Visibility** | High-level (Process Start, File Create) | Low-level (Method Calls, JIT, Interop) |
| **Evasion Resistance** | Vulnerable to Spoofing (PPID Spoofing) | Harder to spoof (Logs Kernel-level truth) |
| **Data Volume** | Manageable, but less detail | Massive, requires Keywords (0x2038) |
| **Memory Forensics** | Limited | Exceptional (Sees assemblies loaded in RAM) |

**Conclusion:** ETW allows analysts to move beyond "Who ran what?" and answer the much deeper question: **"What is this code actually doing in memory?"**
