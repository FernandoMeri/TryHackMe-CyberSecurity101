# TryHackMe - Cyber Security 101

## Module Completed: Search Skills

**Completion Date:** [2025/09/22]
**Module Objective:** Develop advanced search and information evaluation techniques for cybersecurity investigations.

### 📚 What I Learned / Skills Practiced

This module focused on research methodology, teaching how to efficiently find and validate critical information.

#### 1. **Evaluating Information Sources**
   - Criteria for determining the credibility and accuracy of an online source.
   - Differentiating between reliable information and noise.

#### 2. **Efficient Use of Search Engines**
   - Advanced search techniques with Boolean operators (`AND`, `OR`, `NOT`).
   - Use of quotation marks for exact searches and the `site:` operator to restrict searches to specific domains.

#### 3. **Specialized Search Engines**
   - **Shodan:** The “search engine for Internet-connected devices.” Ideal for finding exposed systems (cameras, routers, servers).
   - **Censys:** Similar to Shodan, for discovering and analyzing hosts and infrastructures.
   - **VirusTotal:** Analyzes suspicious files, URLs, IP addresses, and domains with multiple antivirus engines.
   - **Have I Been Pwned:** Checks if your email accounts or data have been compromised in public leaks.

#### 4. **Searching for Vulnerabilities and Exploits**
   - **CVE (Common Vulnerabilities and Exposures):** Standard identifiers for public vulnerabilities.
   - **Exploit Database (Exploit-DB):** Archive of verified exploits and vulnerabilities.
   - **GitHub:** Key platform for finding proof-of-concept (PoC) scripts, tools, and security research.

#### 5. **Reading Technical Documentation**
   - How to navigate and understand official documentation for:
     - **Linux (`man` pages):** Manuals integrated into Unix/Linux systems.
     - **Microsoft Windows:** Docs.microsoft.com for Windows technologies.
     - **Product Documentation:** Primary sources from manufacturers for configurations and solutions.

#### 6. **Using Social Media and News Outlets**
   - How to follow security researchers and stay up to date with the latest threats on platforms such as Twitter and Reddit.
   - Identifying reliable news sources to stay informed about cyber incidents.

### 🛠️ Why it's important
These skills are the foundation for critical tasks such as:
- Threat intelligence.
- Incident response.
- Vulnerability research.
- Malware analysis.

# TryHackMe - Cyber Security 101

## Module Completed: Active Directory Basics

**Completion Date:** [2022/09/22]
**Module Objective:** Understand the fundamentals of Active Directory (AD), the directory service used to manage Windows corporate networks, including users, computers, policies, and authentication methods.

### 📚 What I Learned / Skills Explored

This module provides a solid foundation on how Windows enterprise environments are structured and managed.

#### 1. **Fundamental Concepts**
   - **Windows Domains:** Administrative entities that centralize the management of users, computers, and policies.
   - **Active Directory Domain Services (AD DS):** The Microsoft service that implements network directory functionality.

#### 2. **Management Tools**
   - **Active Directory Users and Computers (ADUC):** The main administrative console for managing objects within the domain (users, groups, computers, OUs).

#### 3. **Structure and Organization**
   - **Organizational Units (OUs):** Containers used to organize users, computers, and other objects within a domain. They are mainly used to **apply policies (GPOs)** in a delegated manner.
   - **Security Groups:** Used to **assign permissions and access rights** to resources (such as files or printers) to sets of users.

#### 4. **Object Management**
   - **Managing Users in AD:** Creating, modifying, and deleting user accounts.
   - **Managing Computers in AD:** How computers join a domain and are managed by it.
   - **Deleting extra OUs and users:** Maintenance and cleanup of the AD structure.

#### 5. **Delegation and Policies**
   - **Delegation:** Assigning specific administrative permissions to users or groups to perform specific tasks (e.g., resetting passwords) without giving them full access.
   - **Group Policies (GPOs) & GPO Distribution:** Set of rules that control the working environment of users and computers. How these policies are applied and distributed across the domain.

#### 6. **Authentication Methods**
   - **Kerberos:** A modern and secure authentication protocol that uses tickets to verify the identity of users and services.
   - **NetNTLM:** A legacy challenge-response authentication protocol, maintained for compatibility but less secure.

#### 7. **Large-Scale Structures**
   - **Trees, Forests, and Trust Relationships:**
     - **Tree:** A set of one or more domains that share a contiguous namespace.
     - **Forest:** A set of one or more trees that share a global directory schema. This is the maximum security boundary.
- **Trust Relationships:** Links that allow users in one domain to authenticate and access resources in another domain.

### 🛠️ Why it matters
Understanding Active Directory is **CRITICAL** for almost any role in cybersecurity, as it is the backbone of most enterprise networks. It is essential for:
- **Blue Team:** Defending the network, monitoring suspicious activity, and responding to incidents.
- **Red Team / Pentesting:** Identifying and exploiting weak configurations to demonstrate vulnerabilities.
- **Systems Administration:** Securely and efficiently managing network resources.

**Note:** This module lays the conceptual foundation. Practical AD administration requires ongoing experience, but the essential principles are now understood.

