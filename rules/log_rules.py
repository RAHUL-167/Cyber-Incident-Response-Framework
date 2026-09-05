"""
Comprehensive Log-Based Threat Detection Rules
Detects various threats from log files without using AI
"""

import os
import re
import json
from datetime import datetime, timedelta
from collections import defaultdict, Counter


# Updated paths (AUTOMATIC – NO MANUAL CHANGE NEEDED)
LOG_DIR = r"C:\ThreatDetection\data\filebeatdata"
ALERT_FILE = r"C:\ThreatDetection\alerts\alerts.log"


# Threat patterns and indicators
SQL_INJECTION_PATTERNS = [
    r"('|(\\')|(;)|(--)|(/\*)|(\*/)|(\+)|(\%)|(\|)|(\&)|(\^)|(\~)|(\<)|(\>)|(\=)|(\!)|(\?)|(\*)|(\()|(\))|(\[)|(\])|(\{)|(\}))",
    r"(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|update\s+.*\s+set|drop\s+table|exec\s*\(|execute\s*\(|xp_cmdshell)",
    r"('|(\\')|(;)|(--)|(/\*)|(\*/)|(\+)|(\%)|(\|)|(\&)|(\^)|(\~)|(\<)|(\>)|(\=)|(\!)|(\?)|(\*)|(\()|(\))|(\[)|(\])|(\{)|(\}))",
    r"(or\s+1\s*=\s*1|or\s+'1'\s*=\s*'1'|or\s+\"1\"\s*=\s*\"1\")",
    r"(and\s+1\s*=\s*1|and\s+'1'\s*=\s*'1'|and\s+\"1\"\s*=\s*\"1\")",
    r"(1\s*=\s*1|'1'\s*=\s*'1'|\"1\"\s*=\s*\"1\")",
]

XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"onclick\s*=",
    r"onmouseover\s*=",
    r"<iframe[^>]*>",
    r"<img[^>]*src\s*=\s*['\"]?javascript:",
    r"<svg[^>]*onload",
    r"eval\s*\(",
    r"document\.cookie",
    r"document\.write",
    r"innerHTML\s*=",
]

COMMAND_INJECTION_PATTERNS = [
    r"[;&|`]\s*(rm\s+-rf|del\s+/f|format\s+c:|mkfs|dd\s+if=)",
    r"(cmd\.exe|/bin/sh|/bin/bash|powershell\.exe).*[;&|`]",
    r"(\||;|&|`|&&|\\|\\|).*(cat|type|more|less|head|tail).*[;&|`]",
    r"(\||;|&|`).*(wget|curl|nc|netcat|telnet).*[;&|`]",
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./\.\./",
    r"\.\.\\\.\.\\",
    r"/etc/passwd",
    r"/etc/shadow",
    r"\\windows\\system32",
    r"c:\\windows\\system32",
    r"/proc/self/environ",
    r"/proc/version",
]

SUSPICIOUS_POWERSHELL_PATTERNS = [
    r"powershell.*-enc(odedcommand)?",
    r"powershell.*-e\s+[A-Za-z0-9+/=]+",
    r"powershell.*-w\s+hidden",
    r"powershell.*-nop(rofile)?",
    r"powershell.*-noni(nteractive)?",
    r"powershell.*invoke-expression",
    r"powershell.*invoke-command",
    r"powershell.*downloadstring",
    r"powershell.*downloadfile",
    r"powershell.*iex\s*\(",
    r"powershell.*bypass",
    r"powershell.*hidden",
    r"powershell.*-windowstyle\s+hidden",
]

BRUTE_FORCE_INDICATORS = [
    r"failed\s+login",
    r"authentication\s+failure",
    r"invalid\s+password",
    r"invalid\s+credentials",
    r"access\s+denied",
    r"login\s+failed",
    r"authentication\s+error",
    r"wrong\s+password",
    r"incorrect\s+password",
    r"unauthorized\s+access",
]

PRIVILEGE_ESCALATION_INDICATORS = [
    r"sudo\s+.*",
    r"su\s+-",
    r"runas\s+/user:",
    r"privilege\s+escalation",
    r"elevated\s+privileges",
    r"administrator\s+access",
    r"root\s+access",
]

MALWARE_INDICATORS = [
    r"trojan|virus|malware|ransomware|spyware|adware|rootkit",
    r"\.exe.*download",
    r"\.bat.*execution",
    r"\.ps1.*execution",
    r"\.vbs.*execution",
    r"\.scr.*execution",
    r"wscript\.exe|cscript\.exe",
    r"regsvr32.*\.sct",
    r"mshta\.exe",
    r"certutil.*urlcache",
]

DATA_EXFILTRATION_INDICATORS = [
    r"large\s+data\s+transfer",
    r"bulk\s+export",
    r"database\s+dump",
    r"mass\s+download",
    r"excessive\s+outbound\s+traffic",
    r"unusual\s+data\s+access",
]

SUSPICIOUS_FILE_OPERATIONS = [
    r"mass\s+file\s+deletion",
    r"bulk\s+file\s+modification",
    r"encryption\s+of\s+files",
    r"\.encrypted|\.locked|\.crypto",
    r"file\s+encryption",
]

# Tracking for rate-based detection
failed_login_tracker = defaultdict(list)
suspicious_activity_tracker = defaultdict(list)

def detect_sql_injection(log_line):
    """Detect SQL injection attempts"""
    log_lower = log_line.lower()
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, log_lower, re.IGNORECASE):
            return True
    return False

def detect_xss(log_line):
    """Detect Cross-Site Scripting (XSS) attempts"""
    log_lower = log_line.lower()
    for pattern in XSS_PATTERNS:
        if re.search(pattern, log_lower, re.IGNORECASE):
            return True
    return False

def detect_command_injection(log_line):
    """Detect command injection attempts"""
    log_lower = log_line.lower()
    for pattern in COMMAND_INJECTION_PATTERNS:
        if re.search(pattern, log_lower, re.IGNORECASE):
            return True
    return False

def detect_path_traversal(log_line):
    """Detect path traversal attempts"""
    log_lower = log_line.lower()
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, log_lower, re.IGNORECASE):
            return True
    return False

def detect_suspicious_powershell(log_line):
    """Detect suspicious PowerShell usage"""
    log_lower = log_line.lower()
    if "powershell" not in log_lower:
        return False
    for pattern in SUSPICIOUS_POWERSHELL_PATTERNS:
        if re.search(pattern, log_lower, re.IGNORECASE):
            return True
    return False

def detect_brute_force(log_line, source_ip=None):
    """Detect brute force attacks"""
    log_lower = log_line.lower()
    for indicator in BRUTE_FORCE_INDICATORS:
        if re.search(indicator, log_lower, re.IGNORECASE):
            if source_ip:
                now = datetime.now()
                failed_login_tracker[source_ip].append(now)
                # Keep only last hour
                failed_login_tracker[source_ip] = [
                    t for t in failed_login_tracker[source_ip]
                    if now - t < timedelta(hours=1)
                ]
                # Alert if more than 5 failed attempts in an hour
                if len(failed_login_tracker[source_ip]) > 5:
                    return True
            return True
    return False

def detect_privilege_escalation(log_line):
    """Detect privilege escalation attempts"""
    log_lower = log_line.lower()
    for indicator in PRIVILEGE_ESCALATION_INDICATORS:
        if re.search(indicator, log_lower, re.IGNORECASE):
            return True
    return False

def detect_malware_indicators(log_line):
    """Detect malware-related activity"""
    log_lower = log_line.lower()
    for indicator in MALWARE_INDICATORS:
        if re.search(indicator, log_lower, re.IGNORECASE):
            return True
    return False

def detect_data_exfiltration(log_line):
    """Detect potential data exfiltration"""
    log_lower = log_line.lower()
    for indicator in DATA_EXFILTRATION_INDICATORS:
        if re.search(indicator, log_lower, re.IGNORECASE):
            return True
    return False

def detect_suspicious_file_operations(log_line):
    """Detect suspicious file operations"""
    log_lower = log_line.lower()
    for indicator in SUSPICIOUS_FILE_OPERATIONS:
        if re.search(indicator, log_lower, re.IGNORECASE):
            return True
    return False

def detect_log_injection_attempt(log_line):
    """Detect log injection attempts"""
    suspicious_chars = ["<script>", "' or 1=1", "--", ";--", "\n", "\r", "\x00"]
    log_lower = log_line.lower()
    return any(x in log_lower for x in suspicious_chars)

def detect_failed_logins(log_line):
    """Detect failed login attempts"""
    return detect_brute_force(log_line)

def detect_unauthorized_access(log_line):
    """Detect unauthorized access attempts"""
    log_lower = log_line.lower()
    unauthorized_patterns = [
        r"unauthorized\s+access",
        r"access\s+denied",
        r"permission\s+denied",
        r"forbidden",
        r"403",
        r"401",
    ]
    for pattern in unauthorized_patterns:
        if re.search(pattern, log_lower, re.IGNORECASE):
            return True
    return False

def detect_account_manipulation(log_line):
    """Detect account manipulation attempts"""
    log_lower = log_line.lower()
    account_patterns = [
        r"user\s+account\s+created",
        r"user\s+account\s+deleted",
        r"user\s+account\s+modified",
        r"password\s+changed",
        r"account\s+locked",
        r"account\s+unlocked",
    ]
    for pattern in account_patterns:
        if re.search(pattern, log_lower, re.IGNORECASE):
            return True
    return False

def detect_configuration_changes(log_line):
    """Detect configuration changes"""
    log_lower = log_line.lower()
    config_patterns = [
        r"configuration\s+changed",
        r"settings\s+modified",
        r"registry\s+modified",
        r"firewall\s+rule\s+changed",
        r"service\s+modified",
    ]
    for pattern in config_patterns:
        if re.search(pattern, log_lower, re.IGNORECASE):
            return True
    return False

def detect_anomalous_activity(log_line):
    """Detect anomalous activity patterns"""
    log_lower = log_line.lower()
    anomalous_patterns = [
        r"unusual\s+activity",
        r"anomalous\s+behavior",
        r"unexpected\s+event",
        r"irregular\s+pattern",
    ]
    for pattern in anomalous_patterns:
        if re.search(pattern, log_lower, re.IGNORECASE):
            return True
    return False

def extract_source_ip(log_entry):
    """Extract source IP from log entry"""
    if isinstance(log_entry, dict):
        # Try various common fields
        for field in ['source_ip', 'src_ip', 'ip', 'client_ip', 'remote_addr', 'source']:
            if field in log_entry:
                return str(log_entry[field])
        # Try nested fields
        if 'source' in log_entry and isinstance(log_entry['source'], dict):
            if 'ip' in log_entry['source']:
                return str(log_entry['source']['ip'])
    return None

def log_alert(rule_name, log_line, severity="MEDIUM", details=None):
    """Log security alert"""
    os.makedirs(os.path.dirname(ALERT_FILE), exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_msg = f"[{timestamp}] [{severity}] {rule_name} triggered"
    if details:
        alert_msg += f" - {details}"
    alert_msg += f": {log_line.strip()[:500]}\n"  # Limit log line length
    with open(ALERT_FILE, "a", encoding="utf-8") as af:
        af.write(alert_msg)

def process_log_file(filepath):
    """Process log file and detect threats"""
    if not os.path.exists(filepath):
        print(f"[ERROR] Log file not found: {filepath}")
        return
    
    threat_count = defaultdict(int)
    
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            
            # Try to parse as JSON (Filebeat outputs JSON lines)
            try:
                log_entry = json.loads(line)
                # Extract message field if it exists
                message = log_entry.get("message", "")
                if isinstance(message, dict):
                    message = str(message)
                log_text = str(message) + " " + str(log_entry)
                source_ip = extract_source_ip(log_entry)
            except (json.JSONDecodeError, ValueError):
                # If not JSON, use line as-is
                log_text = line
                source_ip = None
            
            # Run all detection rules
            if detect_sql_injection(log_text):
                log_alert("SQL Injection Attempt", log_text, "CRITICAL", f"Line {line_num}")
                threat_count["SQL Injection"] += 1
            
            if detect_xss(log_text):
                log_alert("Cross-Site Scripting (XSS) Attempt", log_text, "CRITICAL", f"Line {line_num}")
                threat_count["XSS"] += 1
            
            if detect_command_injection(log_text):
                log_alert("Command Injection Attempt", log_text, "CRITICAL", f"Line {line_num}")
                threat_count["Command Injection"] += 1
            
            if detect_path_traversal(log_text):
                log_alert("Path Traversal Attempt", log_text, "HIGH", f"Line {line_num}")
                threat_count["Path Traversal"] += 1
            
            if detect_suspicious_powershell(log_text):
                log_alert("Suspicious PowerShell Usage", log_text, "HIGH", f"Line {line_num}")
                threat_count["Suspicious PowerShell"] += 1
            
            if detect_brute_force(log_text, source_ip):
                log_alert("Brute Force Attack Detected", log_text, "HIGH", f"IP: {source_ip}, Line {line_num}")
                threat_count["Brute Force"] += 1
            
            if detect_privilege_escalation(log_text):
                log_alert("Privilege Escalation Attempt", log_text, "HIGH", f"Line {line_num}")
                threat_count["Privilege Escalation"] += 1
            
            if detect_malware_indicators(log_text):
                log_alert("Malware Indicator Detected", log_text, "CRITICAL", f"Line {line_num}")
                threat_count["Malware"] += 1
            
            if detect_data_exfiltration(log_text):
                log_alert("Potential Data Exfiltration", log_text, "HIGH", f"Line {line_num}")
                threat_count["Data Exfiltration"] += 1
            
            if detect_suspicious_file_operations(log_text):
                log_alert("Suspicious File Operation", log_text, "HIGH", f"Line {line_num}")
                threat_count["Suspicious File Operations"] += 1
            
            if detect_log_injection_attempt(log_text):
                log_alert("Log Injection Attempt", log_text, "MEDIUM", f"Line {line_num}")
                threat_count["Log Injection"] += 1
            
            if detect_failed_logins(log_text):
                log_alert("Failed Login Attempt", log_text, "MEDIUM", f"Line {line_num}")
                threat_count["Failed Logins"] += 1
            
            if detect_unauthorized_access(log_text):
                log_alert("Unauthorized Access Attempt", log_text, "HIGH", f"Line {line_num}")
                threat_count["Unauthorized Access"] += 1
            
            if detect_account_manipulation(log_text):
                log_alert("Account Manipulation Detected", log_text, "HIGH", f"Line {line_num}")
                threat_count["Account Manipulation"] += 1
            
            if detect_configuration_changes(log_text):
                log_alert("Configuration Change Detected", log_text, "MEDIUM", f"Line {line_num}")
                threat_count["Configuration Changes"] += 1
            
            if detect_anomalous_activity(log_text):
                log_alert("Anomalous Activity Detected", log_text, "MEDIUM", f"Line {line_num}")
                threat_count["Anomalous Activity"] += 1
    
    # Print summary
    print(f"\n[+] Log file processed: {filepath}")
    if threat_count:
        print(f"[!] Threats detected:")
        for threat_type, count in sorted(threat_count.items(), key=lambda x: x[1], reverse=True):
            print(f"    - {threat_type}: {count}")
    else:
        print("[+] No threats detected in log file")

def main():
    if not os.path.isdir(LOG_DIR):
        print(f"[ERROR] Log directory not found: {LOG_DIR}")
        return

    files = [
        os.path.join(LOG_DIR, f)
        for f in os.listdir(LOG_DIR)
        if f.endswith(".ndjson")
    ]

    if not files:
        print("[ERROR] No log files found")
        return

    latest_file = max(files, key=os.path.getmtime)
    process_log_file(latest_file)
if __name__ == "__main__":
    main()
