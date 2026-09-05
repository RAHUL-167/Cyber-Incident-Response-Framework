"""
Comprehensive Automated Mitigation Engine
Reads incidents from analysis_report.txt, parses incidents, and applies mitigation actions
Supports all threat types detected by the rule-based detection system

IMPORTANT:
- Run with administrator/root privileges when you want to actually execute mitigation.
- Default is DRY_RUN=False - set to True for testing without executing commands.
- Tested for Windows and Linux systems.
"""

import os
import re
import subprocess
import platform
import shutil
import json
from datetime import datetime
from collections import defaultdict

# -------------------------
# Configuration
# -------------------------
ANALYSIS_REPORT = r"C:\ThreatDetection\analysis and correlation\analysis_report\analysis_report.txt"
MITIGATION_LOG = r"C:\ThreatDetection\alerts\mitigation_log.txt"
IOC_BLACKLIST = r"C:\ThreatDetection\iocs\bad_ips.txt"
DRY_RUN = False  # Set to True to test without executing commands
PLATFORM = platform.system().lower()  # 'windows', 'linux', 'darwin' etc.

# -------------------------
# Helpers / Logging
# -------------------------
def log_mitigation(action, details, result=None):
    """Log mitigation actions"""
    os.makedirs(os.path.dirname(MITIGATION_LOG), exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] ACTION={action} | DETAILS={details}"
    if result:
        entry += f" | RESULT={result}"
    entry += "\n"
    with open(MITIGATION_LOG, "a", encoding="utf-8") as f:
        f.write(entry)
    print(entry.strip())

def run_cmd(cmd, capture=False, timeout=30):
    """Run OS command (safe wrapper)"""
    cmd_str = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
    log_mitigation("EXEC_CMD" if not DRY_RUN else "DRYRUN_CMD", cmd_str)
    
    if DRY_RUN:
        return {"returncode": 0, "stdout": "[DRY RUN]", "stderr": ""}
    
    try:
        p = subprocess.run(
            cmd, 
            shell=isinstance(cmd, str), 
            capture_output=capture, 
            text=True, 
            check=False,
            timeout=timeout
        )
        result = {
            "returncode": p.returncode,
            "stdout": p.stdout if capture else "",
            "stderr": p.stderr if capture else ""
        }
        if p.returncode != 0 and capture:
            log_mitigation("CMD_WARNING", f"{cmd_str} returned {p.returncode}", result.get("stderr", ""))
        return result
    except subprocess.TimeoutExpired:
        log_mitigation("CMD_TIMEOUT", cmd_str, "Command timed out")
        return {"returncode": -1, "stdout": "", "stderr": "Timeout"}
    except Exception as e:
        log_mitigation("CMD_ERROR", f"{cmd_str} | {e}")
        return {"returncode": -1, "stdout": "", "stderr": str(e)}

# -------------------------
# Parsing analysis_report.txt
# -------------------------
INCIDENT_HEADER_RE = re.compile(r"^\[INCIDENT #(?P<num>\d+)\]", re.MULTILINE)
FIELD_RE = {
    "source_ip": re.compile(r"Source IP:\s*(?P<val>.*)"),
    "source_types": re.compile(r"Source Types:\s*(?P<val>.*)"),
    "processes": re.compile(r"Processes:\s*(?P<val>.*)"),
    "ports": re.compile(r"Ports:\s*(?P<val>.*)"),
    "files": re.compile(r"Files:\s*(?P<val>.*)"),
    "usernames": re.compile(r"Usernames:\s*(?P<val>.*)"),
    "event_ids": re.compile(r"Event IDs:\s*(?P<val>.*)"),
    "threat_categories": re.compile(r"Threat Categories:\s*(?P<val>.*)"),
    "rules": re.compile(r"Rules Triggered:\s*(?P<val>.*)"),
    "timeframe": re.compile(r"Timeframe:\s*(?P<val>.*)"),
    "risk": re.compile(r"Risk Level:\s*(?P<val>.*)"),
    "confidence": re.compile(r"Confidence:\s*(?P<val>.*)"),
}

def parse_analysis_report(path=ANALYSIS_REPORT):
    """Parse analysis report and extract incidents"""
    if not os.path.isfile(path):
        print(f"[!] Analysis report not found: {path}")
        return []
    
    text = open(path, "r", encoding="utf-8", errors="ignore").read()
    parts = INCIDENT_HEADER_RE.split(text)
    incidents = []
    
    for i in range(1, len(parts), 2):
        if i + 1 >= len(parts):
            break
        num = parts[i]
        body = parts[i + 1]
        incident = {"incident_num": int(num)}
        
        for key, rx in FIELD_RE.items():
            m = rx.search(body)
            if m:
                val = m.group("val")
                incident[key] = val.strip() if val else "Unknown"
            else:
                incident[key] = "Unknown"
        
        # Normalize lists
        for k in ("processes", "ports", "files", "usernames", "event_ids", "threat_categories", "rules", "source_types"):
            v = incident.get(k, "Unknown")
            if v == "Unknown" or not v:
                incident[k] = []
            else:
                items = re.split(r",\s*|\s*\|\s*|\s*;\s*|\s+and\s+|\s+/\s+", v)
                items = [it.strip() for it in items if it.strip() and it.strip().lower() not in ("unknown", "none", "")]
                incident[k] = items
        
        incidents.append(incident)
    
    return incidents

# -------------------------
# Network Mitigation Functions
# -------------------------
def block_ip_windows(ip, rule_name=None):
    """Block IP address using Windows Firewall"""
    rule_name = rule_name or f"Block-Threat-{ip.replace('.', '-')}"
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={ip}",
        "enable=yes"
    ]
    return run_cmd(cmd)

def block_ip_iptables(ip):
    """Block IP address using iptables (Linux)"""
    cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    return run_cmd(cmd)

def add_ip_to_ioc(ip):
    """Add IP to IOC blacklist"""
    try:
        os.makedirs(os.path.dirname(IOC_BLACKLIST), exist_ok=True)
        # Check if IP already exists
        if os.path.exists(IOC_BLACKLIST):
            with open(IOC_BLACKLIST, "r", encoding="utf-8") as f:
                existing_ips = set(line.strip() for line in f)
                if ip in existing_ips:
                    return {"returncode": 0, "message": "IP already in blacklist"}
        
        with open(IOC_BLACKLIST, "a", encoding="utf-8") as f:
            f.write(ip + "\n")
        log_mitigation("Add IOC", ip)
        return {"returncode": 0, "message": "IP added to blacklist"}
    except Exception as e:
        log_mitigation("IOC_ADD_FAIL", f"{ip} | {e}")
        return {"returncode": -1, "message": str(e)}

def block_ip_generic(ip):
    """Block IP address (platform-agnostic)"""
    add_ip_to_ioc(ip)
    if PLATFORM.startswith("windows"):
        return block_ip_windows(ip)
    else:
        return block_ip_iptables(ip)

def block_port_windows(port, protocol="TCP"):
    """Block port using Windows Firewall"""
    rule_name = f"Block-Port-{port}"
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        f"protocol={protocol}",
        f"localport={port}",
        "enable=yes"
    ]
    return run_cmd(cmd)

def block_port_iptables(port, protocol="tcp"):
    """Block port using iptables (Linux)"""
    cmd = ["iptables", "-A", "INPUT", "-p", protocol, "--dport", str(port), "-j", "REJECT"]
    return run_cmd(cmd)

def block_port_generic(port, protocol="TCP"):
    """Block port (platform-agnostic)"""
    if PLATFORM.startswith("windows"):
        return block_port_windows(port, protocol)
    else:
        return block_port_iptables(port, protocol.lower())

def modify_hosts_block(ip, reason="blocked_by_mitigation"):
    """Block IP by adding to hosts file"""
    hosts = r"C:\Windows\System32\drivers\etc\hosts" if PLATFORM.startswith("windows") else "/etc/hosts"
    line = f"0.0.0.0\t{ip}\t# {reason}\n"
    try:
        log_mitigation("HostsBlock", f"{ip} -> {hosts}")
        if DRY_RUN:
            return {"returncode": 0}
        with open(hosts, "a", encoding="utf-8") as f:
            f.write(line)
        return {"returncode": 0}
    except Exception as e:
        log_mitigation("HostsBlockFail", f"{ip} | {e}")
        return {"returncode": -1}

def disable_network_adapter_windows(adapter_name="Ethernet"):
    """Disable network adapter (Windows)"""
    cmd = ["netsh", "interface", "set", "interface", adapter_name, "admin=disabled"]
    return run_cmd(cmd)

def disable_network_adapter_linux(interface="eth0"):
    """Disable network adapter (Linux)"""
    cmd = ["ip", "link", "set", interface, "down"]
    return run_cmd(cmd)

# -------------------------
# Process Mitigation Functions
# -------------------------
def kill_process_windows(process_name):
    """Kill process by name (Windows)"""
    cmd = ["taskkill", "/f", "/im", process_name]
    return run_cmd(cmd)

def kill_process_linux(process_name):
    """Kill process by name (Linux)"""
    cmd = ["pkill", "-f", process_name]
    return run_cmd(cmd)

def kill_process_by_pid(pid):
    """Kill process by PID"""
    if PLATFORM.startswith("windows"):
        cmd = ["taskkill", "/f", "/pid", str(pid)]
    else:
        cmd = ["kill", "-9", str(pid)]
    return run_cmd(cmd)

def kill_process_generic(process_identifier):
    """Kill process (platform-agnostic)"""
    if str(process_identifier).isdigit():
        return kill_process_by_pid(process_identifier)
    else:
        if PLATFORM.startswith("windows"):
            return kill_process_windows(process_identifier)
        else:
            return kill_process_linux(process_identifier)

def suspend_process_windows(process_name):
    """Suspend process (Windows)"""
    cmd = ["powershell", "-Command", f"Get-Process -Name {process_name} | Suspend-Process"]
    return run_cmd(cmd)

# -------------------------
# File System Mitigation Functions
# -------------------------
def quarantine_file(filepath):
    """Quarantine suspicious file"""
    if not os.path.exists(filepath):
        log_mitigation("QuarantineFileMissing", filepath)
        return {"returncode": 1, "message": "File not found"}
    
    quarantine_dir = os.path.join(os.path.dirname(filepath), ".quarantine")
    os.makedirs(quarantine_dir, exist_ok=True)
    
    filename = os.path.basename(filepath)
    qpath = os.path.join(quarantine_dir, filename + ".quarantine")
    
    try:
        log_mitigation("QuarantineFile", f"{filepath} -> {qpath}")
        if DRY_RUN:
            return {"returncode": 0, "message": "File quarantined (dry run)"}
        shutil.move(filepath, qpath)
        return {"returncode": 0, "message": "File quarantined"}
    except Exception as e:
        log_mitigation("QuarantineFail", f"{filepath} | {e}")
        return {"returncode": -1, "message": str(e)}

def delete_file(filepath):
    """Delete malicious file"""
    try:
        log_mitigation("DeleteFile", filepath)
        if DRY_RUN:
            return {"returncode": 0, "message": "File deleted (dry run)"}
        os.remove(filepath)
        return {"returncode": 0, "message": "File deleted"}
    except Exception as e:
        log_mitigation("DeleteFail", f"{filepath} | {e}")
        return {"returncode": -1, "message": str(e)}

def set_file_readonly(filepath):
    """Set file to read-only to prevent modification"""
    try:
        log_mitigation("SetFileReadOnly", filepath)
        if DRY_RUN:
            return {"returncode": 0}
        os.chmod(filepath, 0o444)  # Read-only
        return {"returncode": 0}
    except Exception as e:
        log_mitigation("SetReadOnlyFail", f"{filepath} | {e}")
        return {"returncode": -1}

# -------------------------
# Account Management Functions
# -------------------------
def disable_user_windows(username):
    """Disable user account (Windows)"""
    cmd = ["net", "user", username, "/active:no"]
    return run_cmd(cmd)

def disable_user_linux(username):
    """Disable user account (Linux)"""
    cmd = ["usermod", "-L", username]  # Lock account
    return run_cmd(cmd)

def disable_user_generic(username):
    """Disable user account (platform-agnostic)"""
    if PLATFORM.startswith("windows"):
        return disable_user_windows(username)
    else:
        return disable_user_linux(username)

def revoke_admin_windows(username):
    """Revoke administrator privileges (Windows)"""
    cmd = ["net", "localgroup", "Administrators", username, "/delete"]
    return run_cmd(cmd)

def revoke_admin_linux(username):
    """Revoke sudo privileges (Linux)"""
    cmd = ["gpasswd", "-d", username, "sudo"]
    return run_cmd(cmd)

def revoke_admin_generic(username):
    """Revoke admin privileges (platform-agnostic)"""
    if PLATFORM.startswith("windows"):
        return revoke_admin_windows(username)
    else:
        return revoke_admin_linux(username)

def lock_user_account_windows(username):
    """Lock user account (Windows)"""
    cmd = ["net", "user", username, "/active:no"]
    return run_cmd(cmd)

# -------------------------
# Registry and Service Functions (Windows)
# -------------------------
def remove_registry_run_key_windows(keyname):
    """Remove registry run key (Windows)"""
    cmd = f'reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v "{keyname}" /f'
    return run_cmd(cmd)

def remove_scheduled_task_windows(taskname):
    """Remove scheduled task (Windows)"""
    cmd = ["schtasks", "/Delete", "/TN", taskname, "/F"]
    return run_cmd(cmd)

def stop_service_windows(service_name):
    """Stop Windows service"""
    cmd = ["net", "stop", service_name]
    return run_cmd(cmd)

def disable_service_windows(service_name):
    """Disable Windows service"""
    cmd = ["sc", "config", service_name, "start=", "disabled"]
    return run_cmd(cmd)

def stop_service_linux(service_name):
    """Stop Linux service"""
    cmd = ["systemctl", "stop", service_name]
    return run_cmd(cmd)

def disable_service_linux(service_name):
    """Disable Linux service"""
    cmd = ["systemctl", "disable", service_name]
    return run_cmd(cmd)

# -------------------------
# Decision Logic: Comprehensive Mitigation
# -------------------------
def mitigation_for_incident(incident):
    """
    Apply comprehensive mitigation based on incident details
    Supports all threat types detected by the rule-based system
    """
    actions_taken = []
    src_ip = (incident.get("source_ip") or "Unknown").strip()
    rules = incident.get("rules", [])
    threat_categories = incident.get("threat_categories", [])
    procs = incident.get("processes", [])
    files = incident.get("files", [])
    ports = incident.get("ports", [])
    usernames = incident.get("usernames", [])
    source_types = incident.get("source_types", [])
    risk = (incident.get("risk", "LOW") or "LOW").upper()
    
    # Normalize risk
    if "CRITICAL" in risk:
        risk_level = "CRITICAL"
    elif "HIGH" in risk:
        risk_level = "HIGH"
    elif "MEDIUM" in risk:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    log_mitigation("IncidentProcessing", 
                   f"#{incident.get('incident_num')} risk={risk_level} ip={src_ip} "
                   f"threats={threat_categories} rules={rules}")
    
    # ========== CRITICAL RISK MITIGATION ==========
    if risk_level == "CRITICAL":
        # Block IP immediately
        if src_ip and src_ip.lower() not in ("unknown", "none", ""):
            r = block_ip_generic(src_ip)
            actions_taken.append(("block_ip", src_ip, r))
            modify_hosts_block(src_ip, "critical_threat")
            actions_taken.append(("hosts_block", src_ip))
        
        # Kill all suspicious processes
        for p in procs:
            if p and p != "Unknown":
                res = kill_process_generic(p)
                actions_taken.append(("kill_process", p, res))
        
        # Quarantine all suspicious files
        for fpath in files:
            if fpath and fpath != "Unknown" and os.path.exists(fpath):
                res = quarantine_file(fpath)
                actions_taken.append(("quarantine_file", fpath, res))
        
        # Block all involved ports
        for port in ports:
            if port and port.isdigit():
                res = block_port_generic(port)
                actions_taken.append(("block_port", port, res))
        
        # Disable network adapter if severe
        if any("Malware" in t or "Ransomware" in t for t in threat_categories):
            if PLATFORM.startswith("windows"):
                res = disable_network_adapter_windows()
                actions_taken.append(("disable_network_adapter", res))
            else:
                res = disable_network_adapter_linux()
                actions_taken.append(("disable_network_adapter", res))
    
    # ========== HIGH RISK MITIGATION ==========
    elif risk_level == "HIGH":
        # Block IP
        if src_ip and src_ip.lower() not in ("unknown", "none", ""):
            r = block_ip_generic(src_ip)
            actions_taken.append(("block_ip", src_ip, r))
        
        # Kill high-risk processes
        high_risk_procs = ["powershell.exe", "cmd.exe", "wmic.exe", "certutil.exe"]
        for p in procs:
            if p and any(hrp in p.lower() for hrp in high_risk_procs):
                res = kill_process_generic(p)
                actions_taken.append(("kill_process", p, res))
        
        # Quarantine suspicious files
        for fpath in files:
            if fpath and fpath != "Unknown":
                if any(ext in fpath.lower() for ext in [".exe", ".bat", ".ps1", ".vbs", ".js"]):
                    res = quarantine_file(fpath)
                    actions_taken.append(("quarantine_file", fpath, res))
        
        # Block critical ports
        for port in ports:
            if port and port.isdigit():
                port_num = int(port)
                if port_num in [3389, 22, 445, 135, 139]:  # RDP, SSH, SMB
                    res = block_port_generic(port)
                    actions_taken.append(("block_port", port, res))
    
    # ========== MEDIUM RISK MITIGATION ==========
    elif risk_level == "MEDIUM":
        # Add IP to IOC and monitor
        if src_ip and src_ip.lower() not in ("unknown", "none", ""):
            add_ip_to_ioc(src_ip)
            actions_taken.append(("add_ioc", src_ip))
            # Block if repeated
            modify_hosts_block(src_ip, "medium_threat")
            actions_taken.append(("hosts_block", src_ip))
        
        # Quarantine suspicious files
        for fpath in files:
            if fpath and fpath != "Unknown":
                res = quarantine_file(fpath)
                actions_taken.append(("quarantine_file", fpath, res))
        
        # Block non-essential ports
        for port in ports:
            if port and port.isdigit():
                port_num = int(port)
                if port_num > 49152:  # High ports often used for backdoors
                    res = block_port_generic(port)
                    actions_taken.append(("block_port", port, res))
    
    # ========== LOW RISK MITIGATION ==========
    else:
        # Just add to IOC for monitoring
        if src_ip and src_ip.lower() not in ("unknown", "none", ""):
            add_ip_to_ioc(src_ip)
            actions_taken.append(("add_ioc", src_ip))
    
    # ========== THREAT-SPECIFIC MITIGATION ==========
    
    # SQL Injection / XSS / Command Injection
    if any(t in threat_categories for t in ["SQL Injection", "XSS", "Command Injection"]):
        # Quarantine web-related files
        for fpath in files:
            if fpath and fpath != "Unknown":
                if any(ext in fpath.lower() for ext in [".php", ".asp", ".aspx", ".jsp", ".html"]):
                    res = quarantine_file(fpath)
                    actions_taken.append(("quarantine_web_file", fpath, res))
        log_mitigation("WAFRecommendation", f"Add WAF rules for: {threat_categories}")
        actions_taken.append(("waf_recommendation", threat_categories))
    
    # PowerShell / Malware
    if any(t in threat_categories for t in ["PowerShell", "Malware"]) or \
       any("powershell" in p.lower() for p in procs):
        # Kill PowerShell processes
        res = kill_process_generic("powershell.exe")
        actions_taken.append(("kill_process", "powershell.exe", res))
        
        # Quarantine executable files
        for fpath in files:
            if fpath and fpath != "Unknown":
                if any(ext in fpath.lower() for ext in [".exe", ".bat", ".cmd", ".ps1", ".vbs"]):
                    res = quarantine_file(fpath)
                    actions_taken.append(("quarantine_file", fpath, res))
        
        # Block IP
        if src_ip and src_ip.lower() not in ("unknown", "none", ""):
            add_ip_to_ioc(src_ip)
            actions_taken.append(("add_ioc", src_ip))
    
    # Brute Force
    if "Brute Force" in threat_categories:
        # Block IP
        if src_ip and src_ip.lower() not in ("unknown", "none", ""):
            r = block_ip_generic(src_ip)
            actions_taken.append(("block_ip", src_ip, r))
        
        # Disable/lock accounts if username known
        for username in usernames:
            if username and username != "Unknown":
                res = disable_user_generic(username)
                actions_taken.append(("disable_user", username, res))
    
    # Privilege Escalation
    if "Privilege Escalation" in threat_categories or "Privilege Abuse" in threat_categories:
        # Revoke admin privileges
        for username in usernames:
            if username and username != "Unknown":
                res = revoke_admin_generic(username)
                actions_taken.append(("revoke_admin", username, res))
        log_mitigation("ManualActionRequired", "Review all privileged accounts for compromise")
        actions_taken.append(("manual_review_privileges", "all"))
    
    # Account Manipulation
    if "Account Manipulation" in threat_categories:
        # Disable newly created accounts
        for username in usernames:
            if username and username != "Unknown":
                res = disable_user_generic(username)
                actions_taken.append(("disable_user", username, res))
        log_mitigation("ManualActionRequired", "Review all user accounts for unauthorized changes")
        actions_taken.append(("manual_review_accounts", "all"))
    
    # Service Manipulation
    if "Service Manipulation" in threat_categories:
        # Stop and disable suspicious services
        for proc in procs:
            if proc and proc != "Unknown":
                service_name = proc.replace(".exe", "")
                if PLATFORM.startswith("windows"):
                    stop_service_windows(service_name)
                    disable_service_windows(service_name)
                else:
                    stop_service_linux(service_name)
                    disable_service_linux(service_name)
                actions_taken.append(("disable_service", service_name))
    
    # Port Scan / DDoS
    if any(t in threat_categories for t in ["Port Scan", "DDoS"]):
        # Block IP
        if src_ip and src_ip.lower() not in ("unknown", "none", ""):
            r = block_ip_generic(src_ip)
            actions_taken.append(("block_ip", src_ip, r))
        
        # Block scanned ports
        for port in ports:
            if port and port.isdigit():
                res = block_port_generic(port)
                actions_taken.append(("block_port", port, res))
    
    # Registry Modification
    if "Registry" in threat_categories:
        log_mitigation("ManualActionRequired", "Review registry modifications - manual cleanup required")
        actions_taken.append(("manual_review_registry", "all"))
    
    # Firewall Changes
    if "Firewall" in threat_categories:
        log_mitigation("ManualActionRequired", "Review firewall rule changes - manual verification required")
        actions_taken.append(("manual_review_firewall", "all"))
    
    # Data Exfiltration
    if "Data Exfiltration" in threat_categories:
        # Block IP immediately
        if src_ip and src_ip.lower() not in ("unknown", "none", ""):
            r = block_ip_generic(src_ip)
            actions_taken.append(("block_ip", src_ip, r))
        # Disable network if severe
        if risk_level == "CRITICAL":
            if PLATFORM.startswith("windows"):
                res = disable_network_adapter_windows()
                actions_taken.append(("disable_network_adapter", res))
    
    # Lateral Movement
    if "Lateral Movement" in threat_categories:
        # Block IP
        if src_ip and src_ip.lower() not in ("unknown", "none", ""):
            r = block_ip_generic(src_ip)
            actions_taken.append(("block_ip", src_ip, r))
        # Disable network logons
        log_mitigation("ManualActionRequired", "Review network logon policies - restrict lateral movement")
        actions_taken.append(("manual_review_network_policies", "all"))
    
    return actions_taken

# -------------------------
# Main Orchestration
# -------------------------
def run_mitigation_engine():
    """Run the complete mitigation engine"""
    print(f"[*] Automated Mitigation Engine starting (DRY_RUN={DRY_RUN}) on {PLATFORM}")
    print(f"[*] Reading analysis report from: {ANALYSIS_REPORT}")
    
    incidents = parse_analysis_report()
    if not incidents:
        print("[!] No incidents parsed - check analysis report.")
        return {}
    
    print(f"[+] Parsed {len(incidents)} incidents")
    all_results = {}
    
    for inc in incidents:
        print(f"[*] Processing incident #{inc['incident_num']}...")
        results = mitigation_for_incident(inc)
        all_results[inc["incident_num"]] = results
        print(f"[+] Incident #{inc['incident_num']}: {len(results)} actions taken")
    
    print(f"[+] Mitigation run complete. See {MITIGATION_LOG} for details.")
    return all_results

# -------------------------
# If executed directly
# -------------------------
if __name__ == "__main__":
    run_mitigation_engine()
