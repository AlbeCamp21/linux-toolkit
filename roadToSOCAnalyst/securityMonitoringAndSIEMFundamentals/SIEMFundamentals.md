# SIEM Definition & Fundamentals

## 1. SIEM Definition
**SIEM** stands for *Security Information and Event Management*. It is a solution that merges two primary technologies:

* **SIM (Security Information Management):** Focused on long-term log collection, storage, and compliance reporting.
* **SEM (Security Event Management):** Focused on real-time analysis, event correlation, and immediate alerting.

> **Core Purpose:** To provide a holistic view of an organization's security, enabling the detection of attacks during or even before they occur.

---

## 2. How a SIEM Solution Works
The SIEM workflow is divided into four critical stages:

1. **Data Ingestion/Collection:** Gathers information from various sources (PCs, servers, firewalls, switches).
2. **Normalization & Aggregation:** * **Normalization:** Converts diverse log formats into a common standard (such as JSON).
    * **Aggregation:** Consolidates similar data to prevent redundancy and simplify analysis.
3. **Analysis & Correlation:** Security experts and correlation engines scrutinize data to identify patterns indicating threats (e.g., multiple failed logins followed by a successful one).
4. **Alerting:** Notifies SOC personnel via emails, console pop-ups, or SMS when a high-risk event is detected.



---

## 3. Business Requirements & Use Cases

### A. Visibility & Log Consolidation
* Enables the handling of terabytes of information from critical sources (databases, applications, network).
* Without consolidation, security incidents often remain hidden within data silos.

### B. Threat Contextualization
* **The Problem:** Excessive alerting leads to "alert fatigue" and frequent false positives.
* **The Solution:** Contextualization helps identify who is involved, which parts of the network are affected, and the timing, allowing teams to prioritize genuine threats.

### C. Compliance
* Assists in meeting international laws and standards (**PCI DSS, HIPAA, GDPR, ISO**).
* Provides automated reporting and auditing evidence for log retention and monitoring.

---

## 4. Benefits of Using a SIEM
* **Centralized Perspective:** A single dashboard for the entire IT infrastructure.
* **Incident Response Efficiency:** Identifies malicious attacks before they escalate into full-scale breaches.
* **Behavior-Based Detection:** Modern SIEMs use AI to detect anomalies that traditional rules might miss.
* **Cost Reduction:** Preventing a breach is significantly cheaper than remediating the financial and reputational damage of a successful attack.



---

## 5. Comparison with Other Tools
* **Vs. IDS/IPS:** SIEM does not replace IDS/IPS; it complements them by processing their logs alongside data from other sources for more accurate detection.
* **Vs. Case Management (TheHive):** A SIEM **detects** the threat; TheHive **manages** the investigation and resolution process by the analysts.

---

### Key Concepts for the SOC Analyst
* **Logs:** The raw material (records of events).
* **Parser:** The "translator" that reads raw log data.
* **Threshold:** A configured limit to trigger an alert (e.g., "more than 10 failed attempts").
* **False Positive:** An alert triggered by legitimate activity.

---

## 6. SIEM Use Case Development

### A. What is a SIEM Use Case?
A **Use Case** is a specific detection logic or scenario designed to identify potential security incidents. It acts as the "intelligence" of the SIEM, transforming raw log data into actionable alerts.

* **Purpose:** To illustrate specific situations (from simple brute force to complex ransomware) where the SIEM should notify the SOC team.
* **Core Logic:** "If [Condition A] occurs within [Timeframe X], then trigger [Alert Y] with [Priority Z]."

### B. Development Lifecycle
Creating effective use cases requires a structured approach to ensure accuracy and minimize noise:

1. **Requirements:** Define the threat or risk (e.g., "Detect unauthorized VPN access").
2. **Data Points:** Identify which sources generate the logs (Windows, Linux, Firewalls, Cloud).
3. **Log Validation:** Verify that logs contain essential fields (User, IP, Timestamp, Application).
4. **Design & Implementation:** Define the logic based on **Condition**, **Aggregation**, and **Priority**.
5. **Documentation (SOP):** Create Standard Operating Procedures for analysts to follow once the alert triggers.
6. **Onboarding:** Deploy in a development environment first to identify gaps and reduce **False Positives**.
7. **Fine-tuning:** Regularly refine rules based on analyst feedback and whitelisting legitimate activity.

---

### C. Practical Examples (Case Studies)

#### Example 1: MSBuild.exe Started by an Office Application
* **Risk:** Attackers use **LoLBins** (Living-off-the-Land Binaries) to bypass security. `MSBuild.exe` is a trusted Microsoft tool that can be used to compile and execute malicious payloads.
* **Scenario:** Microsoft Word or Excel initiates `MSBuild.exe`.
* **Severity:** **HIGH** (Office apps have no legitimate reason to call a development compiler).
* **MITRE Mapping:**
    * **Tactic:** Defense Evasion (TA0005) & Execution (TA0002).
    * **Technique:** Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001).
* **Analyst Action:** Investigate the Parent-Child process relationship and user activity +/- 2 days.

#### Example 2: MSBuild.exe Making Network Connections
* **Risk:** `MSBuild.exe` is being used to communicate with a remote Command & Control (C2) server.
* **Scenario:** The process `MsBuild.exe` initiates an outbound network connection.
* **Severity:** **MEDIUM** (It may be legitimate, such as Microsoft updates, leading to more False Positives).
* **Analyst Action:** Verify the **IP Reputation** and the action performed (`event.action`).

---

### D. Operational Performance Metrics (KPIs)
A well-designed use case allows the SOC to measure effectiveness through:

* **TTD (Time to Detection):** The speed at which the SIEM identifies an event after it occurs.
* **TTR (Time to Response):** The speed at which an analyst begins investigating the generated alert.

---

### Key Operational Documents
* **SOP (Standard Operating Procedure):** Step-by-step instructions for managing specific alerts.
* **IRP (Incident Response Plan):** The roadmap for addressing confirmed "True Positive" incidents.
* **SLA (Service Level Agreement):** The defined timeframes for handling alerts between different teams.
* **Knowledge Base:** Centralized documentation for case management updates and essential information.
