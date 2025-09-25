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

# TryHackMe - Cyber Security 101

## Completed Module: Linux Shells

**Completion Date:** [2025/09/23]
**Module Objective:** Introduce the fundamentals of interacting with the Linux command line (shell), including the types of shells available, basic commands, and the basics of scripting to automate tasks.

### 📚 What I Learned / Skills Explored

This module provides the essential foundation for working efficiently in Linux environments, which are the standard in servers and cybersecurity.

#### 1. **Interaction with Shells**
   - The **shell** is the command interpreter that allows the user to interact with the operating system through text.
   - It is the main interface for managing servers and performing ethical hacking and forensic tasks.

#### 2. **Types of Linux Shells**
   - **Bash (Bourne-Again SHell):** The most common and standard shell in most Linux distributions. It is the one you learn first.
   - **Zsh (Z Shell):** A powerful shell with enhanced features such as smarter autocompletion. Basis of the “Oh My Zsh” framework.
   - **Fish (Friendly Interactive SHell):** Designed to be user-friendly and interactive, with auto-suggestions and easy configuration.

#### 3. **Shell Scripting and Components**
   - A **shell script** is a file containing a series of commands that are executed sequentially, allowing tasks to be automated.
   - **Basic components of a script:**
     - **Variables:** For storing information (`name=“Fernando”`).
     - **Conditional structures (`if`, `else`):** To make decisions in the script based on conditions.
     - **Loops (`for`, `while`):** To repeat tasks multiple times.
     - **Comments (`#`):** To explain the code and make it more readable.

#### 4. **Practical Example: “The lockers script”**
   - A practical script was analyzed that probably simulated interaction with “lockers” or resources, demonstrating how the above components are applied in a specific case.
   - The objective was to understand the logic of a real script and how tasks are structured.

#### 5. **Practical Exercise**
   - Putting knowledge into practice to write or modify a simple script, consolidating learning.

### 🛠️ **Why it is important**
Mastering the Linux shell is **non-negotiable** in cybersecurity:
- **Server Administration:** Most web, database, and application servers run on Linux.
- **Forensic and Malware Analysis:** The most powerful tools are command line tools.
- **Pentesting and Ethical Hacking:** Security assessment tools (such as those in Kali Linux) are used from the terminal.
- **Automation:** Writing scripts allows you to perform complex tasks quickly, repetitively, and accurately.

**Conclusion:** This module lays the foundation for navigating, managing, and automating tasks in any Linux environment, a fundamental skill for any technical role in security.

# TryHackMe - Cyber Security 101

## Module Completed: Networking Concepts

**Completion Date:** [2025/09/25]
**Module Objective:** Understand fundamental networking models, IP addressing, key protocols, and the encapsulation process, which are the basis for understanding how any device communicates on the Internet.

### 📚 What I Learned / Key Concepts

This module explains the “backbone” of digital communications, a non-negotiable skill in cybersecurity.

#### 1. **Reference Models: OSI vs TCP/IP**
   - **OSI Model (7 layers):** A theoretical model that divides communication into 7 layers (Physical, Link, Network, Transport, Session, Presentation, Application). It is useful for learning and diagnosing problems.
   - **TCP/IP Model (4 layers):** The practical and real model on which the Internet is based (Link, Internet, Transport, Application).
   - We learned to **compare and contrast** both models, seeing how their layers relate to each other.

#### 2. **IP Addressing and Subnets**
   - **IP Addresses:** The unique identifiers of devices on a network (e.g., `192.168.1.1` for IPv4).
   - **Subnets:** How large networks are divided into smaller parts for better organization and security.

#### 3. **Transport Protocols: TCP vs UDP**
   - **TCP (Transmission Control Protocol):**
     - **Connection-oriented.** Establishes a channel before sending data.
     - **Reliable.** Ensures that packets arrive in order and without errors.
     - **Slower.** Used for web (HTTP/HTTPS), email (SMTP), file transfer (FTP).
   - **UDP (User Datagram Protocol):**
     - **Connectionless.** Sends data without establishing a channel first.
     - **Unreliable.** Does not guarantee delivery or order.
- **Faster.** Used for video/audio streaming, VoIP, DNS.

#### 4. **Encapsulation**
   - The process of **adding information from each layer (headers)** to application data as it travels “down” the protocol stack to be transmitted over the network.
   - At the destination, the process is reversed (“up”), removing each header until the original data is reached.

#### 5. **Hands-on Demonstration with Telnet**
   - The **`telnet`** command was used to “talk” directly to services (such as web servers) over TCP on a specific port.
   - This demonstrated in a tangible way how a connection is established at the application/transport level.

### 🛠️ **Why is this important?**
- **Fundamentals of Cybersecurity:** To defend, audit, or attack a network, **you must understand how it works.**
- **Traffic Analysis:** Tools such as Wireshark require this knowledge to analyze packets and detect malicious activity.
- **Troubleshooting:** It allows you to diagnose connectivity failures logically.
- **Ethical Hacking:** Understanding ports, protocols, and services is the first step in finding entry points.

> **Note:** This module lays the essential technical foundation for all subsequent rooms related to networking, pentesting, and forensics.

# TryHackMe - Cyber Security 101

## Module Completed: [Networking Essentials]

**Completion Date:** [2025/09/25]
**Module Objective:** Understand the functioning and importance of fundamental protocols that enable modern networks to operate, from automatic device configuration to global routing on the Internet.

### 📚 What I Learned / Protocols Explored

This module delves into the protocols that enable automatic and efficient network communication.

#### 1. **DHCP (Dynamic Host Configuration Protocol)**
   - **What does it do?** It automatically assigns IP addresses and other network parameters (such as the gateway and DNS server) to devices when they connect to a network.
   - **Analogy:** It is the “automatic rental” of IP addresses on a network.
   - **Importance in Cybersecurity:** A malicious DHCP server can trick devices into connecting to it, redirecting their traffic (“DHCP Spoofing” attack).

#### 2. **ARP (Address Resolution Protocol)**
   - **What does it do?** It finds the MAC (physical) address of a device when only its IP (logical) address is known within a local network.
   - **Fernando's diagram:** “Who has this IP? -> Tell me your MAC.”
   - **Importance in Cybersecurity:** Vulnerable to “ARP Spoofing” or “ARP Poisoning,” where an attacker can trick the network into sending traffic intended for someone else.

#### 3. **ICMP (Internet Control Message Protocol)**
   - **What does it do?** It is used to send control and error messages between network devices.
   - **Key Tools:**
     - **`Ping`:** Checks if a host is active and reachable on the network. (Uses ICMP Echo Request and Reply).
     - **`Traceroute`/`Tracert`:** Discovers the route that packets take to reach a destination, showing all intermediate routers.
   - **Importance in Cybersecurity:** Essential for network diagnostics. Attackers use it to “map” a network (discover active hosts). ICMP traffic is often blocked by firewalls to prevent this.

#### 4. **Routing Protocols**
   - **What do they do?** They are the “navigation systems” of routers. They allow them to share information with each other to find the best route to send packets across different networks.
   - **Main Protocols:**
     - **OSPF & EIGRP:** Used within large networks within the same organization (e.g., a company).
     - **BGP (Border Gateway Protocol):** The protocol that **connects the Internet**. It manages routing *between* large service providers (ISPs). It is the most critical protocol globally.
- **RIP:** An older and simpler protocol.
- **Importance in Cybersecurity:** An attack on BGP can redirect Internet traffic on a massive scale. Understanding routing is key to defending an organization's perimeter network.

#### 5. **NAT (Network Address Translation)**
   - **What does it do?** It translates private IP addresses (e.g., `192.168.1.10`) from a local network to a single public IP address to access the Internet. It allows many devices to share a single public IP.
   - **Analogy:** It is the “receptionist” of an office. All employees (private IPs) use the same office address (public IP) to send emails outside the office.
   - **Importance in Cybersecurity:** It hides the internal structure of a network from the Internet, acting as a first layer of defense (concealment). It is essential in any home router.

### 🛠️ **Practical Conclusion**
These protocols are the “invisible magic” that makes networks work. A system administrator or cybersecurity professional must understand them in order to:
-   **Diagnose problems** with connectivity effectively.
-   **Understand and exploit** common vulnerabilities such as ARP Spoofing.
-   **Secure the configuration** of routers and firewalls.
