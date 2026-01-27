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

## 5. Summary of Incident Response Steps
1.  **Triage:** Initial categorization and prioritization of alerts.
2.  **Containment:** Limiting the scope and impact of an active threat.
3.  **Eradication:** Removing the threat from the environment.
4.  **Recovery:** Restoring systems to normal operation and analyzing lessons learned.
