"""
Comprehensive Threat Analysis and Correlation Engine
Analyzes alerts, correlates incidents, and provides threat intelligence
All detection is rule-based without using AI
"""

import os
import re
import json
from datetime import datetime, timedelta
from collections import defaultdict, Counter

# ========================
# Paths (AUTOMATIC)
# ========================
ALERTS_FILE = r"C:\ThreatDetection\alerts\alerts.log"
OUTPUT_FILE = r"C:\ThreatDetection\analysis and correlation\analysis_report\analysis_report.txt"

# Ensure output folder exists
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

# ========================
# Regex Patterns
# ========================
TIMESTAMP_PATTERN = re.compile(r"\[(.*?)\]")
SEVERITY_PATTERN = re.compile(r"\[(CRITICAL|HIGH|MEDIUM|LOW)\]")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PROCESS_PATTERN = re.compile(r"(?:process|executable|image)[\s:=]+([a-zA-Z0-9_\-\.]+\.(exe|bat|cmd|ps1|vbs|js))", re.IGNORECASE)
PORT_PATTERN = re.compile(r"(?:port|dstport|dport)[\s:=]+(\d+)", re.IGNORECASE)
FILE_PATTERN = re.compile(r"(?:[A-Za-z]:\\[^\s]+|\/[^\s]+|file[:\s]+([^\s]+))", re.IGNORECASE)
EVENT_ID_PATTERN = re.compile(r"(?:event[_\s]?id|eventid)[\s:=]+(\d+)", re.IGNORECASE)
USER_PATTERN = re.compile(r"(?:user|username|account)[\s:=]+([a-zA-Z0-9_\-\.]+)", re.IGNORECASE)

# Remove ANSI escape sequences
ANSI_ESCAPE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

# ========================
# Threat Classification
# ========================
THREAT_CATEGORIES = {
    "SQL Injection": ["sql injection", "sql injection attempt", "union select", "or 1=1"],
    "XSS": ["xss", "cross-site scripting", "<script>", "javascript:"],
    "Command Injection": ["command injection", "rm -rf", "del /f", "cmd.exe"],
    "Path Traversal": ["path traversal", "../", "..\\", "/etc/passwd"],
    "PowerShell": ["powershell", "obfuscated powershell", "encodedcommand"],
    "Brute Force": ["brute force", "failed login", "authentication failure"],
    "Privilege Escalation": ["privilege escalation", "privilege assigned", "privilege abuse"],
    "Malware": ["malware", "trojan", "virus", "ransomware", "spyware"],
    "Data Exfiltration": ["data exfiltration", "large data transfer", "bulk export"],
    "Port Scan": ["port scan", "port scanning"],
    "DDoS": ["syn flood", "icmp flood", "ddos", "flood attack"],
    "DNS Tunneling": ["dns tunneling", "dns tunnel"],
    "Lateral Movement": ["lateral movement", "network logon", "remote logon"],
    "Account Manipulation": ["new user account", "account deleted", "account modified"],
    "Service Manipulation": ["service", "service started", "service stopped"],
    "Registry": ["registry modified", "registry access"],
    "Firewall": ["firewall rule", "firewall change"],
    "Policy": ["policy change", "audit policy"],
    "Group": ["group member", "group created", "group deleted"],
    "File Operations": ["suspicious file", "file access", "file deleted"],
    "Network Anomaly": ["connection anomaly", "suspicious protocol", "fragmented packet"],
    "HTTP Anomaly": ["http anomaly", "suspicious http"],
    "SSL/TLS": ["ssl anomaly", "tls anomaly"],
    "Blacklisted IP": ["blacklisted ip", "communication with blacklisted"],
    "ARP Spoofing": ["arp spoofing", "arp"],
}

# ========================
# Helper Functions
# ========================
def clean_line(line):
    """Remove ANSI escape sequences from line"""
    return ANSI_ESCAPE.sub('', line).strip()

def extract_severity(line):
    """Extract severity level from alert line"""
    match = SEVERITY_PATTERN.search(line)
    if match:
        return match.group(1)
    # Infer severity from threat type
    line_lower = line.lower()
    if any(keyword in line_lower for keyword in ["critical", "sql injection", "xss", "malware", "ransomware"]):
        return "CRITICAL"
    elif any(keyword in line_lower for keyword in ["high", "privilege", "brute force", "port scan"]):
        return "HIGH"
    elif any(keyword in line_lower for keyword in ["medium", "suspicious", "anomaly"]):
        return "MEDIUM"
    return "LOW"

def classify_threat(line):
    """Classify threat type from alert line"""
    line_lower = line.lower()
    for category, keywords in THREAT_CATEGORIES.items():
        if any(keyword in line_lower for keyword in keywords):
            return category
    return "Other Alert"

def extract_source_type(line):
    """Determine source type from alert line"""
    line_upper = line.upper()
    if any(x in line_upper for x in ["TCP", "UDP", "IPV4", "IPV6", "PCAP", "NETWORK"]):
        return "Network"
    elif any(x in line_upper for x in ["WINLOGBEAT", "EVENTID", "EVENT_ID", "SYSTEM"]):
        return "System"
    elif any(x in line_upper for x in ["FILEBEAT", "LOGFILE", "LOG"]):
        return "Log"
    return "Unknown"

# ========================
# Load Alerts
# ========================
def load_alerts():
    """Load and parse alerts from alert file"""
    alerts = []
    if not os.path.isfile(ALERTS_FILE):
        print(f"[!] Alert file not found: {ALERTS_FILE}")
        return alerts

    with open(ALERTS_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line_num, line in enumerate(f, 1):
            line = clean_line(line)
            if not line.strip():
                continue

            # Extract timestamp
            ts_match = TIMESTAMP_PATTERN.search(line)
            timestamp = None
            if ts_match:
                ts_str = ts_match.group(1)
                # Try multiple timestamp formats
                for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
                    try:
                        timestamp = datetime.strptime(ts_str, fmt)
                        break
                    except ValueError:
                        continue

            # Extract IP addresses
            ips = IP_PATTERN.findall(line)
            ip = ips[0] if ips else "Unknown"

            # Extract process
            process_match = PROCESS_PATTERN.search(line)
            process = process_match.group(1) if process_match else "Unknown"

            # Extract port
            port_match = PORT_PATTERN.search(line)
            port = port_match.group(1) if port_match else "Unknown"

            # Extract file path
            file_match = FILE_PATTERN.search(line)
            filepath = file_match.group(0) if file_match else "Unknown"

            # Extract event ID
            event_match = EVENT_ID_PATTERN.search(line)
            event_id = event_match.group(1) if event_match else "Unknown"

            # Extract username
            user_match = USER_PATTERN.search(line)
            username = user_match.group(1) if user_match else "Unknown"

            # Determine source type
            source_type = extract_source_type(line)

            # Classify threat
            threat_category = classify_threat(line)

            # Extract severity
            severity = extract_severity(line)

            # Extract rule name (text between severity and "triggered")
            rule_match = re.search(r"\[.*?\]\s+([^:]+?)\s+triggered", line, re.IGNORECASE)
            rule = rule_match.group(1).strip() if rule_match else threat_category

            alerts.append({
                "line_number": line_num,
                "timestamp": timestamp,
                "ip": ip,
                "process": process,
                "port": port,
                "filepath": filepath,
                "event_id": event_id,
                "username": username,
                "source_type": source_type,
                "threat_category": threat_category,
                "rule": rule,
                "severity": severity,
                "raw": line.strip()
            })

    return alerts

# ========================
# Correlate Alerts
# ========================
def correlate_alerts(alerts, time_window=5):
    """Correlate alerts into incidents based on IP, time window, and threat patterns"""
    incidents = []
    alerts.sort(key=lambda x: x["timestamp"] or datetime.min)
    
    # Group by IP first
    ip_groups = defaultdict(list)
    for alert in alerts:
        if alert["ip"] != "Unknown":
            ip_groups[alert["ip"]].append(alert)
    
    # Also group by process, file, and username for correlation
    process_groups = defaultdict(list)
    file_groups = defaultdict(list)
    user_groups = defaultdict(list)
    
    for alert in alerts:
        if alert["process"] != "Unknown":
            process_groups[alert["process"]].append(alert)
        if alert["filepath"] != "Unknown":
            file_groups[alert["filepath"]].append(alert)
        if alert["username"] != "Unknown":
            user_groups[alert["username"]].append(alert)
    
    # Create incidents from IP groups
    for ip, ip_alerts in ip_groups.items():
        current_incident = []
        last_time = None
        
        for alert in sorted(ip_alerts, key=lambda x: x["timestamp"] or datetime.min):
            if not last_time or (alert["timestamp"] and 
                (alert["timestamp"] - last_time <= timedelta(minutes=time_window))):
                current_incident.append(alert)
            else:
                if len(current_incident) > 0:
                    incidents.append(current_incident)
                current_incident = [alert]
            last_time = alert["timestamp"] or last_time
        
        if len(current_incident) > 0:
            incidents.append(current_incident)
    
    # Create incidents from process groups (for process-based attacks)
    for process, proc_alerts in process_groups.items():
        if len(proc_alerts) > 3:  # Multiple alerts for same process
            current_incident = []
            last_time = None
            
            for alert in sorted(proc_alerts, key=lambda x: x["timestamp"] or datetime.min):
                if not last_time or (alert["timestamp"] and 
                    (alert["timestamp"] - last_time <= timedelta(minutes=time_window))):
                    current_incident.append(alert)
                else:
                    if len(current_incident) > 0:
                        incidents.append(current_incident)
                    current_incident = [alert]
                last_time = alert["timestamp"] or last_time
            
            if len(current_incident) > 0:
                incidents.append(current_incident)
    
    # Remove duplicate incidents (same alerts in multiple groups)
    unique_incidents = []
    seen_alert_sets = set()
    
    for incident in incidents:
        alert_ids = tuple(sorted(a["line_number"] for a in incident))
        if alert_ids not in seen_alert_sets:
            seen_alert_sets.add(alert_ids)
            unique_incidents.append(incident)
    
    return unique_incidents

# ========================
# Risk Assessment
# ========================
def assess_risk(incident):
    """Assess risk level based on threat types, severity, and patterns"""
    if not incident:
        return "LOW"
    
    # Count threat categories
    threat_categories = Counter(a["threat_category"] for a in incident)
    severities = Counter(a["severity"] for a in incident)
    
    # Critical threats
    critical_threats = ["SQL Injection", "XSS", "Command Injection", "Malware", "Privilege Escalation"]
    if any(threat in threat_categories for threat in critical_threats):
        if severities.get("CRITICAL", 0) > 0:
            return "CRITICAL"
        return "HIGH"
    
    # High-risk combinations
    if "PowerShell" in threat_categories and "Privilege Escalation" in threat_categories:
        return "CRITICAL"
    
    if "Brute Force" in threat_categories and "Lateral Movement" in threat_categories:
        return "HIGH"
    
    if "Port Scan" in threat_categories and "Data Exfiltration" in threat_categories:
        return "HIGH"
    
    if "Malware" in threat_categories:
        return "HIGH"
    
    # Medium-risk threats
    medium_threats = ["Brute Force", "Port Scan", "Account Manipulation", "Service Manipulation"]
    if any(threat in threat_categories for threat in medium_threats):
        if severities.get("HIGH", 0) > 0:
            return "HIGH"
        return "MEDIUM"
    
    # Volume-based risk
    if len(incident) > 20:
        return "HIGH"
    elif len(incident) > 10:
        return "MEDIUM"
    
    # Severity-based
    if severities.get("CRITICAL", 0) > 0:
        return "CRITICAL"
    elif severities.get("HIGH", 0) > 2:
        return "HIGH"
    elif severities.get("HIGH", 0) > 0:
        return "MEDIUM"
    
    return "LOW"

def calculate_confidence(incident):
    """Calculate confidence level for incident"""
    if len(incident) < 2:
        return "LOW"
    
    # Multiple source types increase confidence
    source_types = set(a["source_type"] for a in incident)
    if len(source_types) > 1:
        return "HIGH"
    
    # Multiple threat categories increase confidence
    threat_categories = set(a["threat_category"] for a in incident)
    if len(threat_categories) > 2:
        return "HIGH"
    elif len(threat_categories) > 1:
        return "MEDIUM"
    
    return "LOW"

# ========================
# Threat Intelligence Summary
# ========================
def threat_intel_summary(incident):
    """Generate comprehensive threat intelligence summary"""
    threat_categories = Counter(a["threat_category"] for a in incident)
    sources = set(a["source_type"] for a in incident)
    risk = assess_risk(incident)
    confidence = calculate_confidence(incident)
    
    # Where it occurred
    if "Network" in sources and "System" in sources and "Log" in sources:
        where = "The threat was detected across network, system, and log sources, indicating a multi-vector attack."
    elif "Network" in sources and "System" in sources:
        where = "The threat originated from network traffic and system-level activity."
    elif "Network" in sources:
        where = "The threat originated from network traffic analysis."
    elif "System" in sources:
        where = "The threat was detected in system-level activity and Windows event logs."
    elif "Log" in sources:
        where = "The threat was identified from application or service logs."
    else:
        where = "The threat source could not be determined."
    
    # What it's doing
    primary_threats = [t for t, count in threat_categories.most_common(3)]
    
    if "SQL Injection" in primary_threats:
        doing = "SQL injection attempts detected, attempting to manipulate database queries."
    elif "XSS" in primary_threats:
        doing = "Cross-site scripting (XSS) attempts detected, attempting to inject malicious scripts."
    elif "Command Injection" in primary_threats:
        doing = "Command injection attempts detected, attempting to execute system commands."
    elif "Malware" in primary_threats:
        doing = "Malware execution and indicators detected, potentially compromising system integrity."
    elif "PowerShell" in primary_threats:
        doing = "Suspicious PowerShell activity detected, potentially fileless malware or script-based attack."
    elif "Brute Force" in primary_threats:
        doing = "Brute force attack detected, attempting to gain unauthorized access through credential guessing."
    elif "Privilege Escalation" in primary_threats:
        doing = "Privilege escalation attempts detected, attempting to gain elevated permissions."
    elif "Port Scan" in primary_threats:
        doing = "Port scanning activity detected, performing reconnaissance on network services."
    elif "Data Exfiltration" in primary_threats:
        doing = "Potential data exfiltration detected, attempting to steal sensitive information."
    elif "Lateral Movement" in primary_threats:
        doing = "Lateral movement detected, attempting to spread across the network."
    elif "DDoS" in primary_threats:
        doing = "Distributed denial-of-service (DDoS) attack detected, attempting to overwhelm services."
    else:
        doing = f"Multiple suspicious activities detected: {', '.join(primary_threats[:3])}."
    
    # How it might be triggered
    if "Brute Force" in primary_threats:
        trigger = "Likely caused by automated credential stuffing or brute-force attacks targeting weak passwords."
    elif "Malware" in primary_threats or "PowerShell" in primary_threats:
        trigger = "Possibly triggered by malicious file execution, phishing email, or drive-by download."
    elif "SQL Injection" in primary_threats or "XSS" in primary_threats:
        trigger = "Likely from web application exploitation, potentially through vulnerable input validation."
    elif "Port Scan" in primary_threats:
        trigger = "Likely from automated reconnaissance tools scanning for vulnerable services."
    elif "Lateral Movement" in primary_threats:
        trigger = "Likely from compromised credentials or initial access, attempting to expand foothold."
    else:
        trigger = "Triggered by abnormal system, network, or application behavior patterns."
    
    # How much it can spread
    if risk == "CRITICAL":
        spread = "CRITICAL: Immediate risk of widespread compromise across multiple systems. Requires immediate containment."
    elif risk == "HIGH":
        spread = "HIGH: Significant probability of spreading to multiple systems if not contained quickly."
    elif risk == "MEDIUM":
        spread = "MEDIUM: Moderate chance of lateral movement within the network. Requires monitoring and containment."
    else:
        spread = "LOW: Limited risk of spread, but still requires monitoring and investigation."
    
    # Attack stage
    if "Port Scan" in primary_threats:
        stage = "Reconnaissance"
    elif "Brute Force" in primary_threats or "SQL Injection" in primary_threats:
        stage = "Initial Access / Exploitation"
    elif "Privilege Escalation" in primary_threats or "Lateral Movement" in primary_threats:
        stage = "Privilege Escalation / Lateral Movement"
    elif "Data Exfiltration" in primary_threats:
        stage = "Exfiltration"
    else:
        stage = "Multiple Stages"
    
    return {
        "where": where,
        "doing": doing,
        "trigger": trigger,
        "spread": spread,
        "stage": stage,
        "confidence": confidence,
        "primary_threats": primary_threats
    }

# ========================
# Write Report
# ========================
def write_report(incidents):
    """Write comprehensive analysis report"""
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("THREAT DETECTION ANALYSIS REPORT\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")
        
        if not incidents:
            f.write("No incidents detected.\n")
            return
        
        f.write(f"Total Incidents Detected: {len(incidents)}\n\n")
        
        for idx, incident in enumerate(incidents, 1):
            # Extract incident details
            ip = incident[0]["ip"] if incident else "Unknown"
            processes = set(a["process"] for a in incident if a["process"] != "Unknown")
            ports = set(a["port"] for a in incident if a["port"] != "Unknown")
            files = set(a["filepath"] for a in incident if a["filepath"] != "Unknown")
            usernames = set(a["username"] for a in incident if a["username"] != "Unknown")
            event_ids = set(a["event_id"] for a in incident if a["event_id"] != "Unknown")
            
            start_time = min((a["timestamp"] for a in incident if a["timestamp"]), default=None)
            end_time = max((a["timestamp"] for a in incident if a["timestamp"]), default=None)
            
            threat_categories = Counter(a["threat_category"] for a in incident)
            rules = set(a["rule"] for a in incident)
            sources = set(a["source_type"] for a in incident)
            severities = Counter(a["severity"] for a in incident)
            
            risk = assess_risk(incident)
            confidence = calculate_confidence(incident)
            intel = threat_intel_summary(incident)
            
            # Write incident header
            f.write("=" * 80 + "\n")
            f.write(f"[INCIDENT #{idx}]\n")
            f.write("=" * 80 + "\n\n")
            
            # Basic Information
            f.write("BASIC INFORMATION:\n")
            f.write(f"  Source IP: {ip}\n")
            f.write(f"  Source Types: {', '.join(sources) if sources else 'Unknown'}\n")
            f.write(f"  Timeframe: {start_time} - {end_time if end_time else 'Ongoing'}\n")
            f.write(f"  Alert Count: {len(incident)}\n")
            f.write(f"  Risk Level: {risk}\n")
            f.write(f"  Confidence: {confidence}\n")
            f.write(f"  Attack Stage: {intel['stage']}\n\n")
            
            # Threat Details
            f.write("THREAT DETAILS:\n")
            f.write(f"  Threat Categories: {', '.join(threat_categories.keys())}\n")
            f.write(f"  Rules Triggered: {', '.join(sorted(rules))}\n")
            f.write(f"  Severity Distribution: {dict(severities)}\n\n")
            
            # Entities Involved
            f.write("ENTITIES INVOLVED:\n")
            if processes:
                f.write(f"  Processes: {', '.join(sorted(processes))}\n")
            if ports:
                f.write(f"  Ports: {', '.join(sorted(ports))}\n")
            if files:
                f.write(f"  Files: {', '.join(sorted(files))}\n")
            if usernames:
                f.write(f"  Usernames: {', '.join(sorted(usernames))}\n")
            if event_ids:
                f.write(f"  Event IDs: {', '.join(sorted(event_ids))}\n")
            f.write("\n")
            
            # Threat Intelligence Summary
            f.write("THREAT INTELLIGENCE SUMMARY:\n")
            f.write(f"  Where: {intel['where']}\n")
            f.write(f"  What: {intel['doing']}\n")
            f.write(f"  Trigger: {intel['trigger']}\n")
            f.write(f"  Spread Potential: {intel['spread']}\n")
            f.write(f"  Primary Threats: {', '.join(intel['primary_threats'])}\n\n")
            
            # Alert Details
            f.write("ALERT DETAILS:\n")
            for a in incident[:20]:  # Limit to first 20 alerts per incident
                f.write(f"  [{a['severity']}] {a['rule']} - {a['raw'][:200]}\n")
            if len(incident) > 20:
                f.write(f"  ... and {len(incident) - 20} more alerts\n")
            f.write("\n" + "-" * 80 + "\n\n")
        
        # Summary Statistics
        f.write("=" * 80 + "\n")
        f.write("SUMMARY STATISTICS\n")
        f.write("=" * 80 + "\n\n")
        
        all_threats = Counter()
        all_severities = Counter()
        all_sources = Counter()
        
        for incident in incidents:
            for alert in incident:
                all_threats[alert["threat_category"]] += 1
                all_severities[alert["severity"]] += 1
                all_sources[alert["source_type"]] += 1
        
        f.write("Threat Category Distribution:\n")
        for threat, count in all_threats.most_common():
            f.write(f"  {threat}: {count}\n")
        f.write("\n")
        
        f.write("Severity Distribution:\n")
        for severity, count in all_severities.most_common():
            f.write(f"  {severity}: {count}\n")
        f.write("\n")
        
        f.write("Source Type Distribution:\n")
        for source, count in all_sources.most_common():
            f.write(f"  {source}: {count}\n")
        f.write("\n")

# ========================
# Main
# ========================
def main():
    """Main analysis function"""
    print("[*] Loading alerts...")
    alerts = load_alerts()
    
    if not alerts:
        print("[!] No alerts found to process.")
        return
    
    print(f"[+] Loaded {len(alerts)} alerts")
    print("[*] Correlating alerts into incidents...")
    incidents = correlate_alerts(alerts)
    print(f"[+] Identified {len(incidents)} incidents")
    print("[*] Generating analysis report...")
    write_report(incidents)
    print(f"[+] Analysis complete. Report saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
