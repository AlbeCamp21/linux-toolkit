# Incident Case Study: Multi-Vector Compromise and Exfiltration (Insight Nexus)

## 1. Executive Summary
This report details the forensic analysis and incident response following a critical security breach at **Insight Nexus**. The investigation identified a dual-actor intrusion involving **Crimson Fox** (a sophisticated, state-sponsored threat actor) and **Silent Jackal** (an opportunistic criminal group). The breach resulted in the compromise of the organization's Active Directory environment, lateral movement to internal workstations, and the successful exfiltration of sensitive market forecasts and client data via malicious Group Policy Objects (GPOs).

---

## 2. Threat Actor Profiles

| Attribute | Crimson Fox (Primary) | Silent Jackal (Secondary) |
| :--- | :--- | :--- |
| **Origin/Affiliation** | Suspected state-backed; links to IT supply chain targeting | Loosely organized criminal group |
| **Specialization** | Credential theft and long-term data exfiltration | Opportunistic website defacement and PoC intrusions |
| **Skill Level** | High; capable and persistent | Low-skill web intruders |
| **Motivation** | Corporate intelligence and strategic espionage | Disruptive; signal presence |

---

## 3. Environment & Critical Assets
The Insight Nexus infrastructure consisted of a mix of internet-facing applications and an internal Windows-based domain.

### 3.1 External Assets
* **manage.insightnexus.com:** A web console running **ManageEngine ADManager Plus** on HTTPS (port 443) used for Active Directory management.
* **portal.insightnexus.com:** A PHP-based client reporting portal with file upload capabilities enabled.

### 3.2 Internal Infrastructure
* **Domain Controller (DC01.insight.local):** The central authentication authority.
* **File Server (FS01.insight.local):** Hosted sensitive project folders and market forecasts (`\\fs01\projects`).
* **Developer Fleet (DEV-001 to DEV-120):** Workstations, notably **DEV-021**, which had an RDP port (3389) misconfigured and exposed to the public internet.

---

## 4. Attack Timeline & Technical Analysis

### 4.1 Initial Access (2025-10-01)
The actor **Crimson Fox** achieved initial access through the ManageEngine portal. They successfully performed a targeted login using default credentials (`admin/admin`), which had not been changed following a system update. Furthermore, they exploited a Java-based unauthenticated Remote Code Execution (RCE) vulnerability within the product.

### 4.2 Command & Control (C2) Establishment
Upon exploitation, the actor established an outbound HTTPS C2 channel to an attacker-controlled host at `103.112.60.117`. This activity was logged by **Sysmon (Event ID 3)**, showing the `java.exe` process initiating the connection.

### 4.3 Privilege Escalation & Lateral Movement (2025-10-02 to 2025-10-04)
Using the ManageEngine foothold, the attackers enumerated domain users and created a new **Domain Administrator** account. During reconnaissance, they discovered the publicly exposed RDP port on **DEV-021**. 
On **2025-10-04**, the attackers used the `insight\svc_deployer` account to log into DEV-021 via RDP (**Windows Event ID 4624, Logon Type 10**) from the same external IP address.

### 4.4 Mass Malware Deployment via GPO
From the compromised workstation, the attackers executed PowerShell scripts to create a **Group Policy Object (GPO)**. This GPO was configured to push a malicious MSI package (`java-update.msi`) to every machine in the domain.
* **Sysmon Event ID 11:** Recorded the creation of the MSI file in `C:\Windows\Temp\`.
* **Sysmon Event ID 1:** Recorded the silent execution: `msiexec /i java-update.msi /quiet`.

### 4.5 Opportunistic Intrusion (Silent Jackal)
Simultaneously, **Silent Jackal** exploited a file upload vulnerability on the PHP portal. Their activity was limited to uploading a marker file, `checkme.txt`, in the web root. While less sophisticated, this "noisy" activity provided the SOC with the initial clue needed to investigate the wider breach.

---

## 5. Detection & Correlation Analysis
The breach was identified when a system administrator noticed unusual outbound connections during routine maintenance. The SOC team performed cross-platform correlation to confirm the full scope of the attack:

| Evidence Source | Finding |
| :--- | :--- |
| **ManageEngine Logs** | Successful admin logins from foreign IPs. |
| **Windows Event Logs** | Event ID 4624 (Logon Type 10) from an external IP to an internal host. |
| **Sysmon Logs** | Event ID 1 (msiexec execution) and Event ID 3 (C2 beaconing). |
| **File Server Logs** | Event ID 5140 (Network share object accessed) indicating mass file access. |
| **Network Logs** | Outbound HTTPS traffic to `103.112.60.117`. |

---

## 6. Containment & Remediation Actions
The SOC escalated the incident to **Critical** and managed the response via **TheHive**.

1.  **Network Isolation:** Blocked all traffic to/from `103.112.60.117` at the perimeter firewall.
2.  **Credential Hardening:** Disabled the compromised ManageEngine admin account and forced a rotation of all high-privilege service account passwords.
3.  **Host Containment:** Isolated `manage.insightnexus.com` and `DEV-021` for forensic imaging.
4.  **Persistence Removal:** Disabled the malicious GPO and suspended scheduled tasks created by the MSI package.
5.  **Access Control:** Restricted the ManageEngine console to internal access only and enforced Multi-Factor Authentication (MFA).

---

## 7. MITRE ATT&CK Mapping

* **Initial Access:** Valid Accounts (T1078.004), Exploit Public-Facing Application (T1190).
* **Persistence:** Scheduled Task (T1053), Domain Policy Modification (T1484).
* **Lateral Movement:** Remote Desktop Protocol (T1021.001).
* **C2:** Application Layer Protocol: Web Protocols (T1071.001).
* **Exfiltration:** Exfiltration Over C2 Channel (T1041), Archive Collected Data (T1560).

---

## 8. Lessons Learned
* **Default Credentials:** Critical infrastructure must never retain vendor default credentials; automated auditing is required.
* **Alert Fatigue:** The initial alert for `checkme.txt` was ignored due to high false-positive rates in the IDS, highlighting the need for better alert tuning.
* **Shadow IT:** The exposure of RDP on a developer machine (DEV-021) allowed for immediate lateral movement; egress/ingress filtering must be enforced at the host level.
* **Multi-Actor Environments:** Defenders must assume that one visible intruder may hide a more sophisticated, silent actor.
