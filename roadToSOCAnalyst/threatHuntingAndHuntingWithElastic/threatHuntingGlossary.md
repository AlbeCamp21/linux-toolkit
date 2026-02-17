# Reference: Threat Hunting Glossary & Frameworks

This glossary covers the fundamental concepts, metrics, and models used in proactive threat detection and strategic intrusion analysis.

---

## 1. Core Definitions
* **Adversary:** An unauthorized entity (Cybercriminals, Insider Threats, Hacktivists, or State-sponsored groups) seeking to infiltrate an organization to fulfill collection requirements (financial, IP, etc.).
* **Threat:** A multifaceted concept consisting of three factors: **Intent** (Rationale), **Capability** (Tools/Resources), and **Opportunity** (Vulnerabilities/Timing).
* **Campaign:** A collection of incidents sharing similar TTPs and suspected to be driven by the same adversary over a period of time.
* **Indicator:** A combination of technical data and **context**. Without context, technical data has limited value for defenders.

---

## 2. TTPs: The Adversary's Signature
Borrowed from military doctrine, TTPs describe the operational patterns of a threat actor:
* **Tactics:** The strategic "Why" (e.g., Initial Access, Persistence).
* **Techniques:** The general "How" (e.g., Spear-phishing, DLL Search Order Hijacking).
* **Procedures:** The granular, step-by-step "Recipe" (e.g., the specific PowerShell command or registry path used).

---

## 3. The Pyramid of Pain
Developed by David Bianco, this model illustrates the relationship between the type of indicator and the "pain" caused to the adversary when it is denied.

| Level | Indicator Type | Difficulty for Hunter | Impact on Adversary |
| :--- | :--- | :--- | :--- |
| **Tough!** | **TTPs** | Very High | **Vast** (Forces a total rewrite of operations) |
| **Hard** | **Tools** | High | **High** (Requires developing/buying new tools) |
| **Challenging** | **Host/Network Artifacts** | Medium | **Medium** (Disrupts current campaign) |
| **Simple** | **Domain Names** | Low | **Low** (Attacker registers a new domain) |
| **Easy** | **IP Addresses** | Very Low | **Low** (Attacker changes VPN/Proxy) |
| **Trivial** | **Hash Values** | Automated | **None** (Polymorphism/adding a single byte) |

---

## 4. The Diamond Model of Intrusion Analysis
A framework to understand the dynamic relationships between four core vertices:

1.  **Adversary:** The threat actor responsible.
2.  **Capability:** The malware, exploits, and TTPs used.
3.  **Infrastructure:** The IPs, domains, and C2 servers used to facilitate the attack.
4.  **Victim:** The target organization or system.

**Comparison:**
* **Cyber Kill Chain:** Focuses on the *stages* of an attack (Sequence).
* **Diamond Model:** Focuses on the *interrelationships* between components (Holistic view).

---

## 5. Summary Table: APT Characteristics
| Concept | Description |
| :--- | :--- |
| **Advanced** | Refers to sophisticated strategic planning (not always tech-heavy). |
| **Persistent** | Refers to dogged persistence and long-term commitment of resources. |
| **Threat** | The organized group or nation-state entity behind the operation. |

---

> **Analyst Insight:** To become an effective Threat Hunter, focus on the top of the **Pyramid of Pain**. Detecting **TTPs** and **Artifacts** provides a more resilient defense than relying on fragile **IOCs** like IPs or Hashes.
