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
