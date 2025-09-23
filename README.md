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

# TryHackMe - Cyber Security 101

## Module Completed: Windows Command Line

**Completion Date:** [2025/09/23]
**Module Objective:** Become familiar with essential Windows Command Prompt (CMD) commands for basic system administration, troubleshooting, and resource management.

### 📚 What I Learned / Commands Practiced

This module covers the fundamental operations that can be performed from the Windows command line (CMD).

#### 1. **Basic System Information**
   - **`systeminfo`**: Command that displays a detailed summary of the system configuration (OS, hardware, installed patches).
   - **`hostname`**: Displays the name of the current computer.

#### 2. **Network Troubleshooting**
   - **Network Configuration:**
     - **`ipconfig` / `ipconfig /all`**: Displays the current IP configuration (IP address, gateway, DNS servers). The `/all` option provides detailed information.
   - **Networking Commands:**
     - **`ping <IP/Domain>`**: Checks connectivity with another host on the network.
     - **`tracert <IP/Domain>`**: Displays the route (hops) that packets take to reach a destination, useful for diagnosing network problems.

#### 3. **File and Disk Management**
   - **Working with directories:**
     - **`cd <path>`**: Changes the current directory.
     - **`dir`**: Lists the contents of the current directory.
     - **`mkdir <folder_name>`**: Creates a new directory.
     - **`rmdir <folder_name>`**: Deletes a (empty) directory.
   - **Working with files:**
    - **`type <file>`**: Displays the contents of a text file in the console.
    - **`copy <source> <destination>`**: Copies files from one location to another.
    - **`del <file>`**: Deletes a file.

#### 4. **Task and Process Management**
   - **`tasklist`**: Displays a list of all processes running on the system (similar to Task Manager).
   - **`taskkill /PID <Process_ID> /F`**: Ends a specific process using its ID. The `/F` option forces shutdown.

### 🛠️ Why it's important
Although PowerShell is more powerful, Windows CMD is still ubiquitous. Knowing how to use these commands is crucial for:
- Performing quick system and network diagnostics.
- Automating tasks using batch scripts (.bat).
- Operating in restricted environments where PowerShell may be limited.
- Laying the foundation for learning PowerShell and advanced Windows administration.

# TryHackMe - Cyber Security 101

## Module Completed: Windows PowerShell

**Completion Date:** [2025/09/23]
**Module Objective:** Introduce the fundamental concepts of Windows PowerShell as a scripting and automation language, highlighting its structure, basic cmdlets, and critical application in cybersecurity.

### 📚 What I Learned / Concepts Explored

This module lays the foundation for understanding and using PowerShell, an indispensable tool in Windows environments.

#### 1. **PowerShell Basics**
   - **What is it?** It is not just a terminal; it is a **scripting language and administration shell** built on .NET. It is much more powerful than the traditional CMD.
   - **Philosophy:** It is designed for the **automation** of administrative tasks.

#### 2. **Basic Structure: Verb-Noun**
   - Commands (called **cmdlets**) follow a `Verb-Noun` convention (e.g., `Get-Process`, `Stop-Service`).
   - **Advantage:** This structure is intuitive and consistent. You know what a cmdlet does just by reading its name.
   - **Common Examples:**
     - `Get-`: Get information (Get-Service, Get-Process).
     - `Set-`: Configure or change something (Set-Service).
    - `Start-`/`Stop-`: Start or stop a service/process.
    - `Export-`/`Import-`: Export or import data.

#### 3. **Basic Cmdlets and Navigation**
   - **Navigation:** Commands similar to Linux (`Get-Location`, `Set-Location`, `Get-ChildItem`) but for Windows.
   - **File Management:** `Copy-Item`, `Remove-Item`, `Get-Content`.

#### 4. **Piping, Filtering, and Sorting Data (The Real Power)**
   - **Piping (|):** The ability to pass the output of one cmdlet as input to another. This is what allows you to create extremely powerful one-liners.
     - **Example:** `Get-Process | Where-Object {$_.CPU -gt 50} | Sort-Object CPU -Descending`
       - `Get-Process`: Gets all processes.
       - `| Where-Object {...}`: Filters and only shows processes that use more than 50% of the CPU.
       - `| Sort-Object CPU -Descending`: Sorts the result by CPU usage from highest to lowest.
   - **Filtering (`Where-Object`):** To filter results based on conditions.
   - **Sorting (`Sort-Object`):** To sort the results.

#### 5. **System, Network, and Real-Time Information**
   - **System Info:** Cmdlets such as `Get-ComputerInfo` for a complete system analysis.
   - **Network Info:** `Get-NetTCPConnection` to view active network connections (similar to `netstat`).
   - **Real-Time Analysis:** The ability to obtain system information instantly and continuously, crucial for monitoring.

#### 6. **Where to Find and Download Cmdlets**
   - **Modules:** PowerShell functionality is extended through **modules**.
   - **PowerShell Gallery:** A public repository where you can install modules with new cmdlets for specific tasks (e.g., Azure administration, AWS, security tools).
   - **Command:** `Install-Module -Name <ModuleName>`.

#### 7. **Scripting (The Next Level)**
   - **Concept:** The ability to save a series of cmdlets in a file (`.ps1`) to automate complex and repetitive tasks.
   - **Application in Cybersecurity:** Automation of data collection, log analysis, incident response, etc.

### 🛠️ **Why is it crucial in Cybersecurity?**

PowerShell is a **Swiss Army knife** for any professional:
- **Blue Team (Defense):** To monitor suspicious activity, analyze logs automatically, and deploy countermeasures.
- **Red Team (Attack):** It is a powerful offensive tool. Attackers use it to move laterally across a network, execute payloads, and evade detection, as it is a legitimate system tool.
- **Forensic Analysis:** Quickly extract and process large amounts of data from the system.

**Key Takeaway:** It's not about memorizing all the cmdlets, but about **understanding the logic and knowing how to find the solution** using `Get-Help` and `Get-Command`. This foundation will allow you to learn any specific cmdlet when you need it in the future.
