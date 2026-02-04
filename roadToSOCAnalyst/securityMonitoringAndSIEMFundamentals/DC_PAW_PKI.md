# Infrastructure Security: DC, PAW, and PKI

## 1. Domain Controller (DC)

### Definition and Core Purpose
A **Domain Controller (DC)** is a server that manages security authentication requests within a computer domain. It is the central authority in a Microsoft Active Directory (AD) environment. Its primary purpose is to provide a centralized database for managing identities, including users, computers, and groups, ensuring that every entity in the network is verified before accessing resources.

### Functional Components
The DC operates using several critical protocols and services:
* **Active Directory Domain Services (AD DS):** The main service that stores directory data and handles user communication with the domain.
* **Kerberos:** The default authentication protocol used to verify user or host identities.
* **DNS (Domain Name System):** Used to locate the DC and other resources within the network.
* **NTDS.dit:** The physical database file where all domain data, including password hashes, is stored.

### How it Works (Technical Flow)
1. **Request:** When a user at "Company-A" enters credentials, the client machine sends a request to the DC.
2. **Authentication:** The DC verifies the username and password hash against its database.
3. **Authorization:** Once authenticated, the DC checks the user's group memberships (e.g., "Accounting" or "Admins").
4. **Token Issuance:** The DC issues a Ticket-Granting Ticket (TGT) via Kerberos, allowing the user to access specific network resources without re-entering passwords.



### Practical Implementation Example
In a global organization like "Enterprise-1," there may be two DCs (DC-01 and DC-02). If an employee in the HR department tries to access a restricted file server, the file server asks DC-01 if the employee is valid. DC-01 checks the database, confirms the identity, and tells the file server to grant access based on the employee's pre-defined permissions.

---

## 2. Privileged Admin Workstation (PAW)

### Definition and Core Purpose
A **Privileged Admin Workstation (PAW)** is a dedicated, hardened computing device used exclusively for sensitive administrative tasks. It is not a server; it is a highly restricted client machine designed to provide a "clean source" for managing critical infrastructure. The core objective is to isolate administrative credentials from common attack vectors like email, web browsing, and general-purpose applications.

### Technical Hardening and Constraints
A PAW is built following strict security baselines (such as CIS or Microsoft's Enterprise Access Model):
* **Network Isolation:** Internet access is typically blocked or restricted to specific update repositories.
* **No Productivity Tools:** Software like Microsoft Office, Outlook, or third-party browsers is prohibited to prevent phishing or drive-by download attacks.
* **Hardware Integrity:** Often utilizes Trusted Platform Modules (TPM) and Secure Boot to ensure the operating system has not been tampered with.
* **Local Admin Restriction:** Even the person using the PAW does not have permanent local administrative rights on the device to prevent local malware persistence.

### Operation Mode
Administrators use a "Normal PC" for daily tasks (email, chat) and switch to the "PAW" only when they need to log into a Domain Controller or a PKI server. This separation ensures that if the Normal PC is infected with a keylogger, the admin's high-privilege credentials remain safe because they were never typed on that compromised machine.

### Practical Implementation Example
At "Finance-Corp," the IT department issues each Senior SysAdmin two laptops. Laptop-A is for daily work. Laptop-B is the PAW. To change a global password policy on the Domain Controller, the Admin must physically switch to Laptop-B. Laptop-B has a fixed IP address that is the only IP allowed to connect to the Domain Controller's management interface.

---

## 3. Public Key Infrastructure (PKI)

### Definition and Core Purpose
**Public Key Infrastructure (PKI)** is a framework of hardware, software, and policies that manage digital identities through public-key cryptography. It is the system that issues, manages, and revokes **Digital Certificates**. Its purpose is to provide a "Root of Trust" for the entire organization, ensuring data integrity, encryption, and non-repudiation.

### Technical Components
* **Certificate Authority (CA):** The trusted server that validates identities and signs certificates.
* **Registration Authority (RA):** Verifies the identity of entities requesting certificates before the CA signs them.
* **Certificate Revocation List (CRL):** A list of certificates that are no longer valid (e.g., if a laptop is stolen).
* **Digital Certificates (X.509):** Files that link a public key to an identity (User, Server, or Device).

### How it Works (Technical Process)
1. **Key Generation:** A server generates a private key (kept secret) and a public key.
2. **CSR (Certificate Signing Request):** The server sends the public key and identity data to the PKI.
3. **Verification:** The PKI validates that the server belongs to the organization.
4. **Issuance:** The PKI signs a certificate. Now, any device in the network that trusts the PKI will automatically trust that server.



### Practical Implementation Example
"Retail-Global" wants to ensure that all internal web traffic between its web servers and its database is encrypted. The PKI issues a digital certificate to the Database Server. When the Web Server connects, it checks the certificate. Because the Web Server trusts the "Retail-Global PKI," it knows the Database Server is legitimate and establishes an encrypted (HTTPS/TLS) tunnel.

---

## 4. Integrated Connectivity: How They Work Together

The connection between these three elements creates a **Secure Management Loop**. They do not function as isolated silos; they are dependencies for one another.

### The Management Chain
* **PAW to DC/PKI:** The PAW acts as the **Secure Vehicle**. It is the only machine permitted by the network firewall to send management traffic to the DC and the PKI.
* **DC to PAW/PKI:** The DC acts as the **Identity Gatekeeper**. It verifies the administrator's account when they sit down at the PAW or try to access the PKI management console.
* **PKI to DC/PAW:** The PKI acts as the **Trust Provider**. It issues certificates to the DC and the PAW so they can prove their identity to each other and encrypt the communication between them.

### Attack Scenario and Defense Connection
If an attacker compromises a standard user account:
1. They cannot log into the **DC** because they lack permissions.
2. They cannot use a **PAW** because it is physically and logically isolated.
3. They cannot manipulate the **PKI** because the PKI only accepts connections from a verified PAW.

By connecting these three, the organization ensures that high-privilege actions (managed by the DC) are only performed from clean devices (the PAW) using encrypted and verified channels (managed by the PKI).
