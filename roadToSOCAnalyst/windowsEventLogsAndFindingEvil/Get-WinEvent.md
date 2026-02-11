# Master Guide: Advanced Threat Hunting with PowerShell Get-WinEvent

In modern Windows environments, the **Event Viewer (GUI)** is a bottleneck. For professional Threat Hunting and Incident Response (IR), we use the **Get-WinEvent** engine. This guide breaks down not just the "how," but the "why" behind every command.

---

## 1. Understanding the Architecture
**Get-WinEvent** interacts directly with the **Windows Event Log service (eventlog.dll)**. It is designed to handle high-speed queries across local and remote systems, as well as offline binary files (`.evtx`).

### Why use it over `Get-EventLog`?
* **Legacy vs Modern:** `Get-EventLog` is legacy and only sees "Classic" logs (System, Security, Application).
* **Scope:** `Get-WinEvent` sees everything: Classic logs, **Operational logs** (like Sysmon or WinRM), and **ETW (Event Tracing for Windows)**.
* **Speed:** It supports server-side filtering (filtering data before it reaches your RAM).

---

## 2. Reconnaissance: Mapping the Logs
Before hunting, you must perform reconnaissance to see what telemetry is actually being recorded.

### Deep-Scan of Available Logs
```powershell
Get-WinEvent -ListLog * | Select-Object LogName, RecordCount, IsEnabled, LogMode, LogType | Format-Table -AutoSize
```
* **Explanation:**
    * **LogName:** The unique path to the log (e.g., `Microsoft-Windows-Sysmon/Operational`).
    * **RecordCount:** Essential for IR. If the count is 0, your sensors are broken. If it's extremely high, you might be under a "Log Flooding" attack.
    * **LogMode (Circular vs. Retain):** Tells you if the log overwrites itself when full.
    * **LogType:** **Administrative** (High level), **Operational** (Action-specific), or **Analytical** (Deep debugging).

### Finding the Evidence Source (Providers)
```powershell
Get-WinEvent -ListProvider *Network*
```
* **Explanation:** Every log entry is "shouted" by a **Provider**. If you are looking for hidden network activity but don't know the log name, searching the providers will reveal the exact source (e.g., `Microsoft-Windows-Kernel-Network`).

---

## 3. Forensic Analysis & Retrieval
In many cases, the attacker has already been kicked out, and you are analyzing a "dead" system or exported evidence.

### Reading Offline Evidence (.evtx)
```powershell
Get-WinEvent -Path 'C:\Forensics\Dump_Security.evtx' -MaxEvents 500
```
* **The Logic:** Using `-Path` is "Safe Analysis." It reads the file as a stream. It does **not** register the log in your local Event Viewer, ensuring you don't contaminate your own logs with malicious entries from the target.

### Determining the Timeline (Oldest vs Newest)
```powershell
Get-WinEvent -LogName 'Security' -Oldest -MaxEvents 1 | Select-Object TimeCreated
```
* **Explanation:** By default, PowerShell retrieves the **Newest** events first. The `-Oldest` flag is critical for determining the **Retention Period** (how far back in time your logs go) and identifying the very first moment an attacker gained persistence.

---

## 4. The "Hunter's Law": Filter at the Source
The most critical rule in log analysis: **Filter Left.** This means you should filter as much data as possible using the cmdlet parameters instead of the pipe (`|`).

### A. The FilterHashtable (Maximum Efficiency)
This method pushes the filter into the Windows Event Service itself.
```powershell
$TimeLimit = (Get-Date).AddHours(-12)
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Sysmon/Operational'; 
    ID        = 1, 3; 
    StartTime = $TimeLimit
}
```
* **Breaking it down:**
    * **LogName:** Directs the query to the specific database.
    * **ID:** Accepts an array. Here we look for **Process Create (1)** and **Network Connection (3)**.
    * **StartTime:** Only retrieves records from the last 12 hours.
* **Performance:** This is **50x faster** than using `Where-Object` because it only sends the matching results to PowerShell, rather than sending 1,000,000 logs and letting PowerShell sort them.



### B. FilterXPath (Surgical Precision)
XPath is a query language for XML. Since Windows logs are stored as XML, this allows you to look inside specific "Data" fields.
```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[EventData[Data[@Name='DestinationIp']='52.113.194.132']]"
```
* **Why use this?** A standard search for "52.113..." might find that IP in a text description. XPath ensures you only get events where that IP is specifically the **DestinationIp** in a network connection.

---

## 5. Advanced Technique: The Property Array & Indexing
Underneath the "Message" of an event lies the **EventData** array. Sysmon stores its most valuable data here in a specific order (indices).

### Detecting Obfuscated PowerShell (The Index [21] Trick)
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} | 
Where-Object { $_.Properties[21].Value -like "*-enc*" -or $_.Properties[21].Value -like "*FromBase64*" }
```
* **The Secret:** In a Sysmon **Event ID 1**, the index **21** is the `ParentCommandLine`. 
* **The Attack:** Attackers often launch a hidden PowerShell script from a "sacrificial" process. Even if they rename the malware, the **ParentCommandLine** (captured in index 21) will reveal the original malicious command used to start the chain.



---

## 6. Summary: Efficiency Comparison

| Feature | FilterHashtable | FilterXPath / FilterXml | Where-Object |
| :--- | :--- | :--- | :--- |
| **Filtering Location** | Service-Side (Windows) | Service-Side (Windows) | Client-Side (PowerShell) |
| **Speed** | Instant | Instant | Very Slow |
| **Complexity** | Simple | High (Requires XML knowledge) | High (Supports full PS Scripting) |
| **When to use?** | To narrow down logs, IDs, and Dates. | To find specific IPs, Users, or Registry Keys. | To perform complex string math or index checks. |

---

## 7. Pro-Tip: The "Pivot" Strategy
In a real investigation, you move from one clue to another. This is called **Pivoting**.

1. **The Lead:** You find a connection to a C2 IP in **Event ID 3**.
2. **The Pivot:** Copy the `ProcessGuid` from that event.
3. **The Discovery:** Run `Get-WinEvent` for **Event ID 1** using that specific `ProcessGuid`.
4. **The Result:** You now see the exact file that made the connection, the user who ran it, and the command-line arguments used, effectively unmasking the attacker's activity.

Would you like me to create a script that automates this "Pivot" logic for you?
