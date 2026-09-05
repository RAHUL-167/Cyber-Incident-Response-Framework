"""
Comprehensive System-Based Threat Detection Rules
Detects various system threats from Windows Event Logs without using AI
"""

import os
import json
import re
from datetime import datetime, timedelta
from collections import defaultdict, Counter

# Updated paths (AUTOMATIC)
LOG_DIR = r"C:\ThreatDetection\data\winlogbeatdata"
ALERT_FILE = r"C:\ThreatDetection\alerts\alerts.log"


# Windows Event IDs for security monitoring
EVENT_IDS = {
    # Account Management
    'ACCOUNT_CREATED': [4720, 4722],
    'ACCOUNT_DELETED': [4726],
    'ACCOUNT_MODIFIED': [4738, 4781],
    'ACCOUNT_ENABLED': [4722],
    'ACCOUNT_DISABLED': [4725],
    'ACCOUNT_LOCKED': [4740],
    'ACCOUNT_UNLOCKED': [4767],
    
    # Authentication
    'LOGON_SUCCESS': [4624],
    'LOGON_FAILURE': [4625],
    'LOGON_TYPE_2': [4624],  # Interactive logon
    'LOGON_TYPE_3': [4624],  # Network logon
    'LOGON_TYPE_10': [4624], # RemoteInteractive (RDP)
    
    # Privilege Escalation
    'PRIVILEGE_ASSIGNED': [4672],
    'PRIVILEGE_USED': [4673, 4674],
    'SENSITIVE_PRIVILEGE': [4672],
    
    # Process Creation
    'PROCESS_CREATED': [4688],
    'PROCESS_TERMINATED': [4689],
    
    # Service Management
    'SERVICE_STARTED': [7034, 7035],
    'SERVICE_STOPPED': [7036],
    'SERVICE_INSTALLED': [7045],
    'SERVICE_MODIFIED': [7040],
    
    # Registry Changes
    'REGISTRY_MODIFIED': [4657],
    
    # File System
    'FILE_ACCESS': [4663],
    'FILE_DELETED': [4660],
    'FILE_MODIFIED': [4663],
    
    # Network
    'FIREWALL_RULE_ADDED': [4946],
    'FIREWALL_RULE_MODIFIED': [4947],
    'FIREWALL_RULE_DELETED': [4948],
    
    # Policy Changes
    'AUDIT_POLICY_CHANGED': [4719],
    'USER_RIGHTS_ASSIGNED': [4704],
    'USER_RIGHTS_REMOVED': [4705],
    
    # Group Management
    'GROUP_MEMBER_ADDED': [4728, 4732],
    'GROUP_MEMBER_REMOVED': [4729, 4733],
    'GROUP_CREATED': [4727],
    'GROUP_DELETED': [4729],
}

# Suspicious executables
SUSPICIOUS_EXECUTABLES = [
    'cmd.exe', 'powershell.exe', 'wmic.exe', 'certutil.exe',
    'regsvr32.exe', 'mshta.exe', 'rundll32.exe', 'wscript.exe',
    'cscript.exe', 'bitsadmin.exe', 'msbuild.exe', 'msxsl.exe',
    'forfiles.exe', 'schtasks.exe', 'at.exe', 'net.exe',
    'net1.exe', 'sc.exe', 'taskkill.exe', 'tasklist.exe',
    'whoami.exe', 'systeminfo.exe', 'ipconfig.exe', 'netstat.exe',
    'arp.exe', 'route.exe', 'nslookup.exe', 'ping.exe',
]

# High-risk executables
HIGH_RISK_EXECUTABLES = [
    'powershell.exe', 'cmd.exe', 'wmic.exe', 'certutil.exe',
    'regsvr32.exe', 'mshta.exe', 'rundll32.exe',
]

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = [
    '.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jse',
    '.wsf', '.scr', '.com', '.pif', '.dll', '.sct', '.hta',
]

# Suspicious process locations
SUSPICIOUS_LOCATIONS = [
    r'\\temp\\', r'\\tmp\\', r'\\appdata\\local\\temp\\',
    r'\\appdata\\roaming\\', r'\\downloads\\', r'\\desktop\\',
    r'\\users\\public\\', r'\\perflogs\\', r'\\windows\\temp\\',
]

# Tracking for rate-based detection
process_tracker = defaultdict(list)
logon_tracker = defaultdict(list)
file_access_tracker = defaultdict(list)
registry_tracker = defaultdict(list)
service_tracker = defaultdict(list)


def get_event_id(event):
    """
    Extract Windows Event ID as INTEGER from any winlogbeat JSON structure.
    JSON parsing can return strings or ints depending on winlogbeat version,
    so we always cast to int for reliable comparison against EVENT_IDS lists.
    Handles: Winlogbeat 7.x (winlog.event_id), 8.x ECS (event.code), legacy flat fields.
    """
    for key in ("event_id", "EventID"):
        val = event.get(key)
        if val is not None:
            try:
                return int(val)
            except (ValueError, TypeError):
                pass

    # Winlogbeat 7.x: winlog.event_id
    winlog = event.get("winlog", {})
    if isinstance(winlog, dict):
        val = winlog.get("event_id")
        if val is not None:
            try:
                return int(val)
            except (ValueError, TypeError):
                pass

    # Winlogbeat 8.x ECS: event.code
    ev = event.get("event", {})
    if isinstance(ev, dict):
        val = ev.get("code")
        if val is not None:
            try:
                return int(val)
            except (ValueError, TypeError):
                pass

    return None


def detect_new_user_account(event):
    """Detect new user account creation"""
    return get_event_id(event) in EVENT_IDS['ACCOUNT_CREATED']

def detect_account_deletion(event):
    """Detect user account deletion"""
    return get_event_id(event) in EVENT_IDS['ACCOUNT_DELETED']

def detect_account_modification(event):
    """Detect user account modification"""
    return get_event_id(event) in EVENT_IDS['ACCOUNT_MODIFIED']

def detect_privilege_escalation(event):
    """Detect privilege escalation"""
    event_id = get_event_id(event)
    return event_id in EVENT_IDS['PRIVILEGE_ASSIGNED'] or event_id in EVENT_IDS['PRIVILEGE_USED']

def detect_failed_logon(event):
    """Detect failed logon attempts"""
    return get_event_id(event) == EVENT_IDS['LOGON_FAILURE'][0]

def detect_suspicious_logon(event):
    """Detect suspicious logon patterns"""
    if get_event_id(event) == EVENT_IDS['LOGON_SUCCESS'][0]:
        logon_type = event.get("logon_type") or event.get("winlog", {}).get("event_data", {}).get("LogonType")
        if logon_type:
            logon_type = str(logon_type)
            # Alert on network logons (type 3) or remote interactive (type 10)
            if logon_type in ['3', '10']:
                return True
    return False

def detect_suspicious_executable(event):
    """Detect suspicious executable execution"""
    if get_event_id(event) == EVENT_IDS['PROCESS_CREATED'][0]:
        message = str(event.get("message", "")).lower()
        event_data = event.get("winlog", {}).get("event_data", {})
        process_name = event_data.get("NewProcessName", "") or event_data.get("ProcessName", "") or event_data.get("Image", "")
        
        if not process_name:
            for exe in SUSPICIOUS_EXECUTABLES:
                if exe.lower() in message:
                    return True
        else:
            process_name_lower = process_name.lower()
            for exe in SUSPICIOUS_EXECUTABLES:
                if exe.lower() in process_name_lower:
                    return True
            
            process_path = event_data.get("ProcessCommandLine", "") or event_data.get("CommandLine", "")
            if process_path:
                process_path_lower = process_path.lower()
                for location in SUSPICIOUS_LOCATIONS:
                    if re.search(location, process_path_lower, re.IGNORECASE):
                        return True
    return False

def detect_high_risk_executable(event):
    """Detect high-risk executable execution"""
    if get_event_id(event) == EVENT_IDS['PROCESS_CREATED'][0]:
        message = str(event.get("message", "")).lower()
        event_data = event.get("winlog", {}).get("event_data", {})
        process_name = event_data.get("NewProcessName", "") or event_data.get("ProcessName", "") or event_data.get("Image", "")
        
        if not process_name:
            for exe in HIGH_RISK_EXECUTABLES:
                if exe.lower() in message:
                    return True
        else:
            process_name_lower = process_name.lower()
            for exe in HIGH_RISK_EXECUTABLES:
                if exe.lower() in process_name_lower:
                    return True
    return False

def detect_powershell_obfuscation(event):
    """Detect obfuscated PowerShell execution"""
    if get_event_id(event) == EVENT_IDS['PROCESS_CREATED'][0]:
        event_data = event.get("winlog", {}).get("event_data", {})
        command_line = event_data.get("ProcessCommandLine", "") or event_data.get("CommandLine", "")
        
        if command_line and "powershell" in command_line.lower():
            obfuscation_patterns = [
                r'-enc(odedcommand)?',
                r'-e\s+[A-Za-z0-9+/=]+',
                r'-w\s+hidden',
                r'-nop(rofile)?',
                r'-noni(nteractive)?',
                r'invoke-expression',
                r'invoke-command',
                r'downloadstring',
                r'downloadfile',
                r'iex\s*\(',
                r'bypass',
                r'hidden',
                r'-windowstyle\s+hidden',
                r'base64',
            ]
            for pattern in obfuscation_patterns:
                if re.search(pattern, command_line, re.IGNORECASE):
                    return True
    return False

def detect_service_manipulation(event):
    """Detect service manipulation"""
    event_id = get_event_id(event)
    return (event_id in EVENT_IDS['SERVICE_STARTED'] or
            event_id in EVENT_IDS['SERVICE_STOPPED'] or
            event_id in EVENT_IDS['SERVICE_INSTALLED'] or
            event_id in EVENT_IDS['SERVICE_MODIFIED'])

def detect_registry_modification(event):
    """Detect registry modifications"""
    return get_event_id(event) == EVENT_IDS['REGISTRY_MODIFIED'][0]

def detect_firewall_changes(event):
    """Detect firewall rule changes"""
    event_id = get_event_id(event)
    return (event_id in EVENT_IDS['FIREWALL_RULE_ADDED'] or
            event_id in EVENT_IDS['FIREWALL_RULE_MODIFIED'] or
            event_id in EVENT_IDS['FIREWALL_RULE_DELETED'])

def detect_policy_changes(event):
    """Detect security policy changes"""
    event_id = get_event_id(event)
    return (event_id == EVENT_IDS['AUDIT_POLICY_CHANGED'][0] or
            event_id in EVENT_IDS['USER_RIGHTS_ASSIGNED'] or
            event_id in EVENT_IDS['USER_RIGHTS_REMOVED'])

def detect_group_manipulation(event):
    """Detect group membership changes"""
    event_id = get_event_id(event)
    return (event_id in EVENT_IDS['GROUP_MEMBER_ADDED'] or
            event_id in EVENT_IDS['GROUP_MEMBER_REMOVED'] or
            event_id in EVENT_IDS['GROUP_CREATED'] or
            event_id in EVENT_IDS['GROUP_DELETED'])

def detect_rapid_process_creation(event):
    """Detect rapid process creation (potential malware activity)"""
    if get_event_id(event) == EVENT_IDS['PROCESS_CREATED'][0]:
        event_data = event.get("winlog", {}).get("event_data", {})
        process_name = event_data.get("NewProcessName", "") or event_data.get("ProcessName", "") or event_data.get("Image", "")
        
        if process_name:
            now = datetime.now()
            process_tracker[process_name].append(now)
            process_tracker[process_name] = [
                t for t in process_tracker[process_name]
                if now - t < timedelta(minutes=5)
            ]
            if len(process_tracker[process_name]) > 20:
                return True
    return False

def detect_brute_force_logon(event):
    """Detect brute force logon attempts"""
    if get_event_id(event) == EVENT_IDS['LOGON_FAILURE'][0]:
        event_data = event.get("winlog", {}).get("event_data", {})
        account_name = event_data.get("TargetUserName", "") or event_data.get("SubjectUserName", "")
        
        if account_name and account_name not in ["-", "ANONYMOUS LOGON", ""]:
            now = datetime.now()
            logon_tracker[account_name].append(now)
            logon_tracker[account_name] = [
                t for t in logon_tracker[account_name]
                if now - t < timedelta(hours=1)
            ]
            if len(logon_tracker[account_name]) > 5:
                return True
    return False

def detect_suspicious_file_access(event):
    """Detect suspicious file access patterns"""
    event_id = get_event_id(event)
    if event_id == EVENT_IDS['FILE_ACCESS'][0] or event_id == EVENT_IDS['FILE_MODIFIED'][0]:
        event_data = event.get("winlog", {}).get("event_data", {})
        file_path = event_data.get("ObjectName", "") or event_data.get("FileName", "")
        
        if file_path:
            file_path_lower = file_path.lower()
            for ext in SUSPICIOUS_EXTENSIONS:
                if file_path_lower.endswith(ext):
                    return True
            for location in SUSPICIOUS_LOCATIONS:
                if re.search(location, file_path_lower, re.IGNORECASE):
                    return True
            now = datetime.now()
            file_access_tracker[file_path].append(now)
            file_access_tracker[file_path] = [
                t for t in file_access_tracker[file_path]
                if now - t < timedelta(minutes=5)
            ]
            if len(file_access_tracker[file_path]) > 100:
                return True
    return False

def detect_suspicious_registry_access(event):
    """Detect suspicious registry access"""
    if get_event_id(event) == EVENT_IDS['REGISTRY_MODIFIED'][0]:
        event_data = event.get("winlog", {}).get("event_data", {})
        registry_key = event_data.get("ObjectName", "") or event_data.get("RegistryKey", "")
        
        if registry_key:
            registry_key_lower = registry_key.lower()
            suspicious_keys = [
                r'\\run\\', r'\\runonce\\', r'\\runservices\\',
                r'\\winlogon\\', r'\\shell\\', r'\\image\s+file\s+execution',
            ]
            for pattern in suspicious_keys:
                if re.search(pattern, registry_key_lower, re.IGNORECASE):
                    return True
            now = datetime.now()
            registry_tracker[registry_key].append(now)
            registry_tracker[registry_key] = [
                t for t in registry_tracker[registry_key]
                if now - t < timedelta(minutes=5)
            ]
            if len(registry_tracker[registry_key]) > 50:
                return True
    return False

def detect_lateral_movement(event):
    """Detect potential lateral movement"""
    if get_event_id(event) == EVENT_IDS['LOGON_SUCCESS'][0]:
        event_data = event.get("winlog", {}).get("event_data", {})
        logon_type = event_data.get("LogonType", "")
        if str(logon_type) == "3":
            source_ip = event_data.get("IpAddress", "") or event_data.get("SourceIpAddress", "")
            if source_ip and source_ip not in ["-", "::1", ""] and not source_ip.startswith("127."):
                return True
    return False

def detect_privilege_abuse(event):
    """Detect privilege abuse"""
    if get_event_id(event) in EVENT_IDS['PRIVILEGE_USED']:
        event_data = event.get("winlog", {}).get("event_data", {})
        privilege = event_data.get("PrivilegeList", "") or event_data.get("Privileges", "")
        
        if privilege:
            high_risk_privileges = [
                'SeDebugPrivilege', 'SeTcbPrivilege', 'SeTakeOwnershipPrivilege',
                'SeBackupPrivilege', 'SeRestorePrivilege', 'SeLoadDriverPrivilege',
            ]
            for priv in high_risk_privileges:
                if priv.lower() in privilege.lower():
                    return True
    return False

def log_alert(rule_name, event, severity="MEDIUM", details=None):
    """Log security alert"""
    try:
        os.makedirs(os.path.dirname(ALERT_FILE), exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        event_id = get_event_id(event)
        event_info = f"EventID: {event_id}"

        alert_msg = f"[{timestamp}] [{severity}] {rule_name} triggered"
        if details:
            alert_msg += f" - {details}"
        alert_msg += f": {event_info}\n"

        event_str = json.dumps(event)[:500]
        alert_msg += f"    Event: {event_str}\n"

        with open(ALERT_FILE, "a", encoding="utf-8") as af:
            af.write(alert_msg)
            af.flush()  # Force write to disk immediately

    except Exception as e:
        print(f"[ERROR] Failed to write alert: {e}")

def process_json_file(filepath):
    """Process JSON file and detect threats"""
    if not os.path.exists(filepath):
        print(f"[ERROR] Winlogbeat data not found: {filepath}")
        return
    
    threat_count = defaultdict(int)
    event_count = 0
    
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            try:
                event = json.loads(line.strip())
                event_count += 1
                
                if detect_new_user_account(event):
                    log_alert("New User Account Created", event, "HIGH")
                    threat_count["New User Account"] += 1
                
                if detect_account_deletion(event):
                    log_alert("User Account Deleted", event, "HIGH")
                    threat_count["Account Deletion"] += 1
                
                if detect_account_modification(event):
                    log_alert("User Account Modified", event, "MEDIUM")
                    threat_count["Account Modification"] += 1
                
                if detect_privilege_escalation(event):
                    log_alert("Privilege Escalation Detected", event, "CRITICAL")
                    threat_count["Privilege Escalation"] += 1
                
                if detect_failed_logon(event):
                    log_alert("Failed Logon Attempt", event, "MEDIUM")
                    threat_count["Failed Logon"] += 1
                
                if detect_suspicious_logon(event):
                    log_alert("Suspicious Logon Detected", event, "HIGH")
                    threat_count["Suspicious Logon"] += 1
                
                if detect_suspicious_executable(event):
                    log_alert("Suspicious Executable Detected", event, "HIGH")
                    threat_count["Suspicious Executable"] += 1
                
                if detect_high_risk_executable(event):
                    log_alert("High-Risk Executable Detected", event, "CRITICAL")
                    threat_count["High-Risk Executable"] += 1
                
                if detect_powershell_obfuscation(event):
                    log_alert("Obfuscated PowerShell Detected", event, "CRITICAL")
                    threat_count["Obfuscated PowerShell"] += 1
                
                if detect_service_manipulation(event):
                    log_alert("Service Manipulation Detected", event, "HIGH")
                    threat_count["Service Manipulation"] += 1
                
                if detect_registry_modification(event):
                    log_alert("Registry Modification Detected", event, "MEDIUM")
                    threat_count["Registry Modification"] += 1
                
                if detect_firewall_changes(event):
                    log_alert("Firewall Rule Change Detected", event, "HIGH")
                    threat_count["Firewall Changes"] += 1
                
                if detect_policy_changes(event):
                    log_alert("Security Policy Change Detected", event, "HIGH")
                    threat_count["Policy Changes"] += 1
                
                if detect_group_manipulation(event):
                    log_alert("Group Manipulation Detected", event, "MEDIUM")
                    threat_count["Group Manipulation"] += 1
                
                if detect_rapid_process_creation(event):
                    log_alert("Rapid Process Creation Detected", event, "HIGH")
                    threat_count["Rapid Process Creation"] += 1
                
                if detect_brute_force_logon(event):
                    log_alert("Brute Force Logon Attempt", event, "HIGH")
                    threat_count["Brute Force Logon"] += 1
                
                if detect_suspicious_file_access(event):
                    log_alert("Suspicious File Access Detected", event, "MEDIUM")
                    threat_count["Suspicious File Access"] += 1
                
                if detect_suspicious_registry_access(event):
                    log_alert("Suspicious Registry Access Detected", event, "MEDIUM")
                    threat_count["Suspicious Registry Access"] += 1
                
                if detect_lateral_movement(event):
                    log_alert("Potential Lateral Movement", event, "HIGH")
                    threat_count["Lateral Movement"] += 1
                
                if detect_privilege_abuse(event):
                    log_alert("Privilege Abuse Detected", event, "HIGH")
                    threat_count["Privilege Abuse"] += 1
                    
            except json.JSONDecodeError:
                continue
            except Exception as e:
                print(f"[WARNING] Error processing event: {e}")
                continue
    
    # Print summary
    print(f"\n[+] System event file processed: {filepath}")
    print(f"[+] Total events analyzed: {event_count}")
    if threat_count:
        print(f"[!] Threats detected:")
        for threat_type, count in sorted(threat_count.items(), key=lambda x: x[1], reverse=True):
            print(f"    - {threat_type}: {count}")
    else:
        print("[+] No threats detected in system events")

def main():
    if not os.path.isdir(LOG_DIR):
        print(f"[ERROR] Directory not found: {LOG_DIR}")
        return

    json_files = sorted([
        os.path.join(LOG_DIR, f)
        for f in os.listdir(LOG_DIR)
        if f.endswith(".ndjson") and os.path.getsize(os.path.join(LOG_DIR, f)) > 0
    ])

    if not json_files:
        print("[ERROR] No .ndjson files found in winlogbeatdata/")
        return

    print(f"[*] Found {len(json_files)} file(s) to process")
    for filepath in json_files:
        process_json_file(filepath)

    print(f"\n[*] All done. Alerts written to: {ALERT_FILE}")


if __name__ == "__main__":
    main()