# SOC Definition & Fundamentals

## 1. What is a SOC?
A **Security Operations Center (SOC)** is a centralized facility housing a team of security experts responsible for the continuous monitoring and assessment of an organization’s security posture.

* **Primary Objective:** To identify, investigate, and resolve cybersecurity incidents.
* **The Triad:** A SOC operates through a synergy of **Technology** (SIEM, EDR, IDS), **Processes** (Standard Operating Procedures), and **People** (Security Analysts).

---

## 2. How a SOC Works
Unlike security architects who design systems, the SOC focuses on the **ongoing operational aspect** of information security.

* **Core Workflow:** Detect → Assess → Respond → Report → Prevent.
* **Collaboration:** Working closely with Incident Response teams ensures that detected threats are contained and mitigated swiftly.
* **Advanced Capabilities:** Mature SOCs may include specialized labs for **Malware Analysis** and **Digital Forensics** to identify the root cause of complex attacks.

---

## 3. Roles Within a SOC
The SOC follows a tiered structure to manage the volume and complexity of alerts efficiently:

| Role | Responsibility |
| :--- | :--- |
| **Tier 1 Analyst** | "First Responders." Monitor alerts, perform initial triage, and escalate potential incidents. |
| **Tier 2 Analyst** | Deep analysis of escalated incidents. Develop mitigation strategies and perform tool tuning. |
| **Tier 3 Analyst** | Highly experienced. Lead complex investigations, perform proactive **Threat Hunting**, and forensic analysis. |
| **Detection Engineer**| Build and maintain detection rules/signatures for SIEM, EDR, and IDS tools. |
| **Incident Responder**| In charge of active breaches. Lead containment, remediation, and recovery efforts. |
| **Threat Intelligence Analyst**| Gather and analyze data on emerging threats to proactively defend the network. |
| **SOC Manager** | Oversees day-to-day operations, budget, staffing, and departmental alignment. |

---

## 4. The Evolution of SOC Stages

### SOC 1.0 (Reactive Generation)
* **Focus:** Network and perimeter security.
* **Weakness:** Siloed tools and lack of integration led to uncorrelated alerts and manual task buildup.

### SOC 2.0 (Intelligence-Driven)
* **Focus:** Situational awareness and multi-vector detection.
* **Key Features:** Integration of **Threat Intelligence**, network flow analysis, and **Layer-7 (Application)** inspection to catch "low and slow" attacks.

### Cognitive SOC (Next-Gen)
* **Focus:** Bridging the experience gap using **AI and Machine Learning**.
* **Key Features:** Standardized incident response procedures and rules tailored specifically to business processes and systems.

---

## 5. The Alert Triaging Process

### A. Definition
**Alert Triaging** is the systematic process performed by a SOC analyst to evaluate and prioritize security alerts. The goal is to determine the threat level and potential impact on the organization's systems and data to effectively allocate response resources.

### B. The Ideal Triaging Workflow
1.  **Initial Review:** Thoroughly analyze metadata, timestamps, IPs, and the triggering rule/signature.
2.  **Classification & Correlation:** Categorize the alert by severity and cross-reference it with other events or Threat Intelligence to identify patterns or IOCs.
3.  **Enrichment:** Gather additional context through network packet captures, memory dumps, or sandbox analysis of suspicious files/URLs.
4.  **Risk & Contextual Analysis:** Evaluate the criticality of the affected asset and check if security controls (Firewalls, EDR) failed or were evaded.
5.  **IT Consultation:** Coordinate with IT Operations to identify maintenance activities or configuration changes that might cause **False Positives**.
6.  **Response Execution:** Determine if the alert is a non-malicious event (close) or a true security concern (proceed to Incident Response).

### C. Escalation and De-escalation
* **Escalation:** The process of notifying higher-level teams (Tier 2/3), incident response teams, or management.
* **Triggers:** Escalation is mandatory when critical systems are compromised, attacks are ongoing, or sophisticated techniques are detected.
* **Communication:** The analyst must provide a comprehensive summary including severity, findings, and risk assessment.
* **De-escalation:** Occurs when the risk is mitigated, the incident is contained, and further high-level coordination is no longer necessary.

---

## 6. Summary of Incident Response Steps
1.  **Triage:** Initial categorization and prioritization of alerts.
2.  **Containment:** Limiting the scope and impact of an active threat.
3.  **Eradication:** Removing the threat from the environment.
4.  **Recovery:** Restoring systems to normal operation and analyzing lessons learned.
