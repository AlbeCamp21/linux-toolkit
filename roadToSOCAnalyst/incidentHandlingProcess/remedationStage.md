# Incident Handling Process: Remediation Stage

## 1. Overview of Containment, Eradication, and Recovery

Once the investigation has clearly identified the type of incident and its impact, the team moves into the action phase. This stage focuses on stopping the damage, removing the threat, and restoring business operations. Success here depends on coordinated execution to avoid alerting the attacker prematurely.

---

## 2. Containment: Stopping the Damage

Containment is designed to prevent the incident from spreading. It is divided into two distinct strategic approaches.

### Short-Term Containment
The goal is to limit the immediate impact with minimal changes to the system. This allows the team to preserve evidence for forensic analysis (also known as the Backup Substage).
* **Isolation:** Moving compromised systems to a dedicated "Isolation VLAN" or physically disconnecting the network cable.
* **DNS Redirection:** Changing the attacker’s Command & Control (C2) DNS entries to point to a non-existent IP or a system controlled by the defenders.
* **Business Coordination:** If a system must be shut down, the business must be notified to manage the operational impact.

### Long-Term Containment
This involves persistent changes to the environment to maintain a secure state while preparing for the next steps.
* **Access Control:** Changing user passwords across the affected domain.
* **Network Filtering:** Applying new firewall rules to block malicious traffic.
* **Host Defense:** Installing Host Intrusion Detection Systems (HIDS) or applying urgent security patches.

---

## 3. Eradication: Removing the Threat

Eradication is the process of eliminating the root cause and all residues of the attack. It ensures the adversary no longer has any presence in the network.

### Key Activities
* **Malware Removal:** Identifying and deleting malicious files, scripts, and scheduled tasks.
* **System Rebuilding:** Often, the safest way to eradicate a threat is to wipe the affected systems and rebuild them from "Golden Images" or trusted backups.
* **Hardening:** Extending security measures beyond the affected systems to the rest of the network to prevent the same vulnerability from being exploited again.

---

## 4. Recovery: Restoring Normal Operations

In the recovery stage, systems are brought back into the production environment. This is often a phased approach, especially in large-scale incidents.

### Verification and Production
Before a system is considered "live," the business must verify that it is functional and that the data is intact. Once verified, the system returns to normal use.

### Enhanced Monitoring (Post-Recovery)
Restored systems are high-priority targets. Attackers often try to regain access quickly. Analysts must monitor for:
* **Unusual Logons:** Accounts logging into systems they have never accessed before.
* **Registry Changes:** Modifications in auto-start locations or security settings.
* **Suspicious Processes:** New or renamed executables running in the background.

---

## 5. Strategic Phases of Recovery

* **Initial Phases:** Focus on "Quick Wins" and eliminating "Low-Hanging Fruit" (obvious vulnerabilities) to increase immediate security.
* **Long-Term Phases:** Implement permanent structural changes to the infrastructure, which may take months to complete depending on the size of the organization.