# Incident Handling Process: Detection & Analysis Stage

## 1. Overview of Detection and Analysis

The Detection and Analysis stage is the point where the organization identifies that a security event is occurring and determines its nature. This phase requires a combination of technical tools, defined processes, and skilled personnel to distinguish between normal activity and a real threat.

---

## 2. Sources and Levels of Detection

Incidents can be detected through various channels. A robust defense implements detection at multiple layers to ensure visibility across the entire infrastructure.

### Common Detection Sources
* **Automated Alerts:** Notifications from security tools like EDR (Endpoint Detection and Response), IDS (Intrusion Detection Systems), or SIEM (Security Information and Event Management).
* **Human Reporting:** Employees noticing unusual system behavior or suspicious emails.
* **Threat Hunting:** Proactive searches by security analysts to find hidden threats that automated tools might have missed.
* **Third-Party Notifications:** External entities (like law enforcement or partners) informing the organization of a potential breach.

### Logical Detection Levels
1. **Network Perimeter:** Monitoring traffic entering and leaving the organization via Firewalls and DMZs.
2. **Internal Network:** Analyzing traffic between internal systems to detect lateral movement.
3. **Endpoint Level:** Using antivirus and EDR to monitor processes and files on individual laptops and servers.
4. **Application Level:** Reviewing logs from specific software or services for unauthorized access or errors.

---

## 3. Initial Investigation and Context

When an alert is triggered, the team must conduct an initial investigation to establish context before declaring a full-scale incident.

### Key Information to Collect
* **The "Whos" and "Whens":** Who reported it, who is involved, and the exact timestamp of the activity.
* **Incident Nature:** Identifying if it is phishing, malware, system unavailability, or unauthorized access.
* **Impacted Systems:** Listing hostnames, IP addresses, and the physical location of affected devices.
* **Malware Details:** If malicious code is found, collecting file names, hashes (unique digital fingerprints), and copies for analysis.

### Incident Timeline
Analysts must build a chronological timeline of events. This helps organize the evidence and reveals the attacker's behavior. A standard timeline includes the **Date/Time**, **Hostname**, **Event Description**, and the **Data Source**.



---

## 4. Technical Analysis and Indicators of Compromise (IOC)

The investigation follows a cyclic process: creating indicators, identifying new leads, and analyzing data.

### Indicators of Compromise (IOC)
An IOC is a piece of digital evidence that indicates a system has been breached.
* **Common Examples:** IP addresses of known attack servers, specific file names, or unique file hashes (MD5/SHA-256).
* **Standard Formats:** Using languages like **STIX** or **YARA** allows security teams to share IOCs in a machine-readable format so that other systems can automatically search for them.

### Data Collection Approaches
* **Live Response:** Collecting data from a running system. This is the most common method as it preserves volatile data like **RAM memory**, which is lost if the computer is turned off.
* **Forensic Imaging:** Creating a bit-by-bit copy of a hard drive for deep analysis.
* **Chain of Custody:** A process that documents everyone who handled the evidence. This is vital to ensure the evidence is valid in a court of law.

---

## 5. The Role of Artificial Intelligence (AI)

Modern Detection and Analysis increasingly rely on AI to handle the massive volume of security data.

* **Automated Triage:** AI can prioritize alerts, highlighting the most dangerous ones and reducing "alert fatigue" for human analysts.
* **Attack Discovery:** Generative AI can group thousands of related alerts into a single "attack story," showing the relationship between different hosts and users.
* **Behavioral Profiling:** AI learns what "normal" looks like in a network and can detect anomalies much faster than manual review.

---

## 6. Determining Severity and Scope

To manage resources effectively, the team must answer critical questions:
* Is a business-critical system affected?
* How many systems are impacted in total?
* Does the threat have "worm-like" capabilities (can it spread automatically)?
* Is the exploit being used widely in the industry?

Answers to these questions determine if an incident needs to be escalated to senior management or legal departments.