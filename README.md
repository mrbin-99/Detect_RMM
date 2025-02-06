# Detect_RMM
RMM Tool Detection Script

This script is designed to detect the presence of Remote Monitoring and Management (RMM) tools and potential 
security threats on a Windows system. RMM tools are often used for legitimate system administration but can also 
be misused by attackers for unauthorized access, persistence, and lateral movement.

Key Features:
1. **Process Detection** – Scans currently running processes to identify active RMM tools.
2. **File System Search** – Checks common installation directories (Program Files, System32, AppData, etc.) 
   to find known RMM tool executables.
3. **Windows Registry Analysis** – Looks for traces of RMM tool installations in the Windows registry.
4. **Hash-Based Verification** – 
   - Computes **SHA-256 hashes** of detected executables.
   - Cross-checks with known malicious hashes from **Abuse.ch Malware Bazaar** and other open-source intelligence (OSINT) sources.
5. **Multi-Threaded Execution** – Uses Python’s `ThreadPoolExecutor` for faster scanning.
6. **Comprehensive Reporting** – Saves the results in a detailed report, listing detected tools and potential security risks.

Purpose & Use Cases:
- **Security Analysts & Incident Responders** – Helps in **identifying unauthorized or suspicious RMM tools** that could indicate compromise.
- **IT Administrators** – Assists in **monitoring and auditing installed remote access software** to prevent abuse.
- **Threat Hunting Teams** – Enhances **proactive defense** by comparing local file hashes against threat intelligence databases.
- **Red Teaming & Pentesting** – Used to **verify the presence of known RMM tools** in controlled environments.

How It Works:
1. The script loads a **list of known RMM tools** (e.g., AnyDesk, TeamViewer, MeshAgent, Atera).
2. It **scans running processes, file locations, and the registry** for signs of these tools.
3. If a tool is found, it **computes its hash** and checks against the **Abuse.ch Malware Bazaar API**.
4. The results are displayed **in a structured output**, indicating:
   - **Found** (with details like file path, hash, and registry presence)
   - **Not Found** (if no traces were detected)
5. The final report is saved as a **detailed log file** on the desktop.

Security Considerations:
- The script does **not modify or remove** any files.
- It is **safe to run on production environments** for auditing purposes.
- Network access is required for **hash lookups via Abuse.ch API**.

**Reference:**
This script is inspired by the **Ransomware Tool Matrix** project on GitHub: 
[https://github.com/BushidoUK/Ransomware-Tool-Matrix](https://github.com/BushidoUK/Ransomware-Tool-Matrix)

By using this script, security teams and administrators can **enhance endpoint monitoring** and **detect unauthorized 
use of remote access tools**, which is a common tactic in cyberattacks.
