import os
import psutil
import winreg
import requests
import hashlib
import logging
from concurrent.futures import ThreadPoolExecutor

"""
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
"""


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

TOOLS = [
    "Action1", "AnyDesk", "Atera", "ASG Remote Desktop", "BeAnywhere", "Chrome Remote Desktop", "Domotz", "DWAgent", 
    "eHorus", "FixMeIt", "Fleetdeck", "GoToAssist", "ITarian", "Level.io", "LogMeIn", "ManageEngineRMM", "MeshAgent", 
    "MobaXterm", "N-Able", "NetSupport", "NinjaOne", "Parsec", "PDQ Deploy", "PowerAdmin", "Pulseway", "Radmin", 
    "Remote Desktop Plus (RDP+)", "Remote Manipulator System (RMS)", "RemotePC", "RemoteUtilities", "RPort", "RSAT", 
    "RustDesk", "ScreenConnect", "SimpleHelp", "Sorillus", "Splashtop", "SuperOps", "Supremo", "Syncro", "TacticalRMM", 
    "TeamViewer", "TightVNC", "TrendMicro Basecamp", "Twingate", "ZeroTier", "ZohoAssist"
]

SEARCH_PATHS = [
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "C:\\Windows\\System32",
    "C:\\Windows",
    os.path.expanduser("~\\AppData\\Local"),
    os.path.expanduser("~\\AppData\\Roaming")
]

def get_hash_from_abuse_ch(tool):
    """Fetch known malware hashes for a given tool from Abuse.ch Malware Bazaar API using the 'tag' option."""
    url = "https://mb-api.abuse.ch/api/v1/"
    payload = {"query": "get_taginfo", "tag": tool}
    
    try:
        response = requests.post(url, data=payload)
        response.raise_for_status()  # Raise an exception for HTTP errors
        data = response.json()
        if "data" in data and data["data"]:
            hashes = [entry["sha256_hash"] for entry in data["data"]]
            logging.info(f"Retrieved {len(hashes)} hashes for {tool} from Abuse.ch.")
            return hashes
        else:
            logging.warning(f"No hashes found for {tool} on Abuse.ch.")
            return []
    except requests.RequestException as e:
        logging.error(f"API request failed: {e}")
    return []

def get_file_hash(file_path):
    """Compute SHA-256 hash of a given file."""
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        logging.error(f"Error computing hash for {file_path}: {e}")
        return None

def check_process(tool):
    """Check if the tool is running as a process."""
    try:
        for proc in psutil.process_iter(['name']):
            if tool.lower() in proc.info['name'].lower():
                return True
    except Exception as e:
        logging.error(f"Error checking process for {tool}: {e}")
    return False

def check_files(tool):
    """Check if the tool executable exists in common paths and compute its hash."""
    for path in SEARCH_PATHS:
        try:
            for root, _, files in os.walk(path):
                for file in files:
                    if tool.lower() in file.lower():
                        file_path = os.path.join(root, file)
                        file_hash = get_file_hash(file_path)
                        return file_path, file_hash
        except Exception as e:
            logging.error(f"Error checking files for {tool} in {path}: {e}")
    return None, None

def check_registry(tool):
    """Check if the tool is listed in the registry."""
    registry_paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    ]
    
    for reg_path in registry_paths:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                for i in range(0, winreg.QueryInfoKey(key)[0]):
                    subkey_name = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, subkey_name) as subkey:
                        try:
                            display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                            if tool.lower() in display_name.lower():
                                return True
                        except FileNotFoundError:
                            pass
        except FileNotFoundError:
            pass
        except Exception as e:
            logging.error(f"Error checking registry for {tool}: {e}")
    return False

def check_tool(tool):
    """Check all detection methods for a given tool."""
    logging.info(f"Checking {tool}...")
    process_running = check_process(tool)
    file_path, local_hash = check_files(tool)
    registry_entry = check_registry(tool)
    abuse_ch_hashes = get_hash_from_abuse_ch(tool)

    status = f"{tool} - Not Found"
    if process_running or file_path or registry_entry or abuse_ch_hashes:
        status = f"{tool} - FOUND"
        if file_path:
            status += f"\n    Found Tool on System: {file_path}"
            if local_hash:
                status += f"\n    Computed SHA-256: {local_hash}"
                if local_hash in abuse_ch_hashes:
                    status += f"\n    Local file hash matches a known malicious hash!"
                else:
                    status += f"\n    No known malicious hash match"
        if registry_entry:
            status += f"\n    Found in Registry"
        if process_running:
            status += f"\n    Running Process Detected"
        if abuse_ch_hashes:
            status += f"\n    Found Hashes from Abuse.ch: {', '.join(abuse_ch_hashes)}"
        else:
            status += f"\n    No known hashes from Abuse.ch"
    
    logging.info(status)
    return status

def save_report(results, save_path=None):
    """Save the results to a specified path, defaulting to the Desktop if no path is provided."""
    if not save_path:
        save_path = os.path.join(os.path.expanduser("~"), "Desktop", "Tool_Detection_Report.txt")
    try:
        with open(save_path, "w", encoding="utf-8") as report_file:
            report_file.write("\n".join(results))
        logging.info(f"Scan complete! Results saved to: {save_path}")
    except Exception as e:
        logging.error(f"Error saving report: {e}")

def main(save_path=None):
    """Main function to scan for tools."""
    logging.info("Checking tools... Please wait.")
    results = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        for index, tool in enumerate(TOOLS):
            results.append(executor.submit(check_tool, tool).result())

    save_report(results, save_path)

if __name__ == "__main__":
    # You can pass the save path as an argument to main() if needed
    main()