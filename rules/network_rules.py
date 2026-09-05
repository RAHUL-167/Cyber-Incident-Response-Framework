"""
Comprehensive Network-Based Threat Detection Rules
Detects various network threats from PCAP files without using AI
"""

import os
import pyshark
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import ipaddress

# Updated paths (AUTOMATIC)
PCAP_DIR = r"C:\ThreatDetection\data\network data"
ALERT_FILE = r"C:\ThreatDetection\alerts\alerts.log"
BAD_IP_LIST = r"C:\ThreatDetection\iocs\bad_ips.txt"


# Known malicious ports
MALICIOUS_PORTS = {
    4444,  # Metasploit
    31337,  # Back Orifice
    12345,  # NetBus
    54321,  # Back Orifice
    5555,   # Android Debug Bridge
    6666,   # IRC
    6667,   # IRC
    6668,   # IRC
    6669,   # IRC
    8080,   # HTTP Proxy (often abused)
    1080,   # SOCKS Proxy
    3128,   # HTTP Proxy
    3389,   # RDP (often targeted)
    5900,   # VNC
    1433,   # MSSQL (often targeted)
    3306,   # MySQL (often targeted)
    5432,   # PostgreSQL (often targeted)
    27017,  # MongoDB (often targeted)
}

# Suspicious DNS domains
SUSPICIOUS_DOMAINS = [
    'bitcoin', 'cryptocurrency', 'mining', 'pool',
    'tor', 'onion', 'vpn', 'proxy',
    'malware', 'trojan', 'virus',
]

# Tracking for rate-based detection
port_scan_tracker = defaultdict(set)
connection_tracker = defaultdict(list)
dns_query_tracker = defaultdict(list)
packet_size_tracker = defaultdict(list)
syn_flood_tracker = defaultdict(list)

def load_bad_ips():
    """Load list of known bad IPs"""
    try:
        with open(BAD_IP_LIST, "r") as f:
            return set(ip.strip() for ip in f if ip.strip())
    except FileNotFoundError:
        return set()

def is_private_ip(ip_str):
    """Check if IP is private/internal"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except:
        return False

def detect_bad_ip(packet, bad_ips):
    """Detect communication with blacklisted IPs"""
    try:
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            return src_ip in bad_ips or dst_ip in bad_ips
    except AttributeError:
        pass
    return False

def detect_port_scan(packet):
    """Detect port scanning activity"""
    try:
        if hasattr(packet, 'tcp'):
            src_ip = packet.ip.src
            dst_port = int(packet.tcp.dstport)
            
            # Track port scan attempts
            port_scan_tracker[src_ip].add(dst_port)
            
            # Alert if scanning multiple ports
            if len(port_scan_tracker[src_ip]) > 10:
                return True
            
            # Alert if scanning well-known ports
            if dst_port < 1024 and len(port_scan_tracker[src_ip]) > 5:
                return True
    except (AttributeError, ValueError):
        pass
    return False

def detect_syn_flood(packet):
    """Detect SYN flood attacks"""
    try:
        if hasattr(packet, 'tcp'):
            if packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '0':
                src_ip = packet.ip.src
                now = datetime.now()
                syn_flood_tracker[src_ip].append(now)
                
                # Keep only last minute
                syn_flood_tracker[src_ip] = [
                    t for t in syn_flood_tracker[src_ip]
                    if now - t < timedelta(minutes=1)
                ]
                
                # Alert if more than 100 SYN packets per minute
                if len(syn_flood_tracker[src_ip]) > 100:
                    return True
    except (AttributeError, ValueError):
        pass
    return False

def detect_malicious_port(packet):
    """Detect connections to known malicious ports"""
    try:
        if hasattr(packet, 'tcp'):
            dst_port = int(packet.tcp.dstport)
            if dst_port in MALICIOUS_PORTS:
                return True
        elif hasattr(packet, 'udp'):
            dst_port = int(packet.udp.dstport)
            if dst_port in MALICIOUS_PORTS:
                return True
    except (AttributeError, ValueError):
        pass
    return False

def detect_unusual_port_activity(packet):
    """Detect unusual port activity"""
    try:
        if hasattr(packet, 'tcp'):
            dst_port = int(packet.tcp.dstport)
            # Alert on very high port numbers (often used for backdoors)
            if dst_port > 49152:
                return True
            # Alert on uncommon but not malicious ports
            if dst_port in range(20000, 30000):
                return True
    except (AttributeError, ValueError):
        pass
    return False

def detect_dns_tunneling(packet):
    """Detect potential DNS tunneling"""
    try:
        if hasattr(packet, 'dns'):
            query = packet.dns.qry_name.lower()
            
            # Check for suspicious domain patterns
            for suspicious in SUSPICIOUS_DOMAINS:
                if suspicious in query:
                    return True
            
            # Check for very long domain names (common in DNS tunneling)
            if len(query) > 100:
                return True
            
            # Check for excessive DNS queries
            src_ip = packet.ip.src
            now = datetime.now()
            dns_query_tracker[src_ip].append(now)
            
            # Keep only last minute
            dns_query_tracker[src_ip] = [
                t for t in dns_query_tracker[src_ip]
                if now - t < timedelta(minutes=1)
            ]
            
            # Alert if more than 50 DNS queries per minute
            if len(dns_query_tracker[src_ip]) > 50:
                return True
    except (AttributeError, ValueError):
        pass
    return False

def detect_data_exfiltration(packet):
    """Detect potential data exfiltration"""
    try:
        if hasattr(packet, 'tcp'):
            # Check for large outbound packets
            if hasattr(packet, 'length'):
                packet_size = int(packet.length)
                src_ip = packet.ip.src
                
                # Track packet sizes
                packet_size_tracker[src_ip].append(packet_size)
                
                # Keep only last 5 minutes
                now = datetime.now()
                if len(packet_size_tracker[src_ip]) > 1000:
                    packet_size_tracker[src_ip] = packet_size_tracker[src_ip][-1000:]
                
                # Alert on very large packets
                if packet_size > 65535:
                    return True
                
                # Alert on sustained large data transfer
                if len(packet_size_tracker[src_ip]) > 100:
                    avg_size = sum(packet_size_tracker[src_ip][-100:]) / 100
                    if avg_size > 10000:  # Average packet size > 10KB
                        return True
    except (AttributeError, ValueError):
        pass
    return False

def detect_icmp_flood(packet):
    """Detect ICMP flood attacks"""
    try:
        if hasattr(packet, 'icmp'):
            src_ip = packet.ip.src
            now = datetime.now()
            
            if src_ip not in connection_tracker:
                connection_tracker[src_ip] = []
            
            connection_tracker[src_ip].append(now)
            
            # Keep only last minute
            connection_tracker[src_ip] = [
                t for t in connection_tracker[src_ip]
                if now - t < timedelta(minutes=1)
            ]
            
            # Alert if more than 100 ICMP packets per minute
            if len(connection_tracker[src_ip]) > 100:
                return True
    except (AttributeError, ValueError):
        pass
    return False

def detect_arp_spoofing(packet):
    """Detect ARP spoofing attempts"""
    try:
        if hasattr(packet, 'arp'):
            # Check for multiple ARP responses from same IP
            src_ip = packet.arp.src_proto_ipv4
            if src_ip:
                # This is a simplified check - real ARP spoofing detection needs more context
                if hasattr(packet.arp, 'opcode'):
                    if packet.arp.opcode == '2':  # ARP reply
                        # Track ARP replies
                        if src_ip not in connection_tracker:
                            connection_tracker[src_ip] = []
                        connection_tracker[src_ip].append(datetime.now())
                        
                        # Alert on excessive ARP replies
                        if len(connection_tracker[src_ip]) > 50:
                            return True
    except (AttributeError, ValueError):
        pass
    return False

def detect_suspicious_protocol(packet):
    """Detect suspicious protocol usage"""
    try:
        # Check for uncommon protocols
        if hasattr(packet, 'highest_layer'):
            protocol = packet.highest_layer.lower()
            suspicious_protocols = ['icmp', 'igmp', 'ipv6']
            
            # Count protocol usage
            if protocol in suspicious_protocols:
                src_ip = packet.ip.src if hasattr(packet, 'ip') else None
                if src_ip:
                    if src_ip not in connection_tracker:
                        connection_tracker[src_ip] = []
                    connection_tracker[src_ip].append(datetime.now())
                    
                    # Keep only last minute
                    now = datetime.now()
                    connection_tracker[src_ip] = [
                        t for t in connection_tracker[src_ip]
                        if now - t < timedelta(minutes=1)
                    ]
                    
                    # Alert on excessive protocol usage
                    if len(connection_tracker[src_ip]) > 200:
                        return True
    except (AttributeError, ValueError):
        pass
    return False

def detect_connection_anomaly(packet):
    """Detect connection anomalies"""
    try:
        if hasattr(packet, 'tcp'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            
            # Track connections
            connection_key = f"{src_ip}->{dst_ip}"
            now = datetime.now()
            
            if connection_key not in connection_tracker:
                connection_tracker[connection_key] = []
            
            connection_tracker[connection_key].append(now)
            
            # Keep only last 5 minutes
            connection_tracker[connection_key] = [
                t for t in connection_tracker[connection_key]
                if now - t < timedelta(minutes=5)
            ]
            
            # Alert on excessive connections
            if len(connection_tracker[connection_key]) > 1000:
                return True
            
            # Alert on connections to external IPs from internal network
            if is_private_ip(src_ip) and not is_private_ip(dst_ip):
                if len(connection_tracker[connection_key]) > 100:
                    return True
    except (AttributeError, ValueError):
        pass
    return False

def detect_fragmented_packets(packet):
    """Detect fragmented packets (potential evasion technique)"""
    try:
        if hasattr(packet, 'ip'):
            if hasattr(packet.ip, 'flags'):
                flags = str(packet.ip.flags)
                # Check for more fragments flag
                if 'more' in flags.lower() or 'mf' in flags.lower():
                    return True
    except (AttributeError, ValueError):
        pass
    return False

def detect_suspicious_payload(packet):
    """Detect suspicious payload patterns"""
    try:
        # Check for common exploit patterns in payload
        if hasattr(packet, 'tcp'):
            if hasattr(packet.tcp, 'payload'):
                payload = str(packet.tcp.payload).lower()
                
                # Common exploit patterns
                exploit_patterns = [
                    'cmd.exe',
                    'powershell',
                    'bash -i',
                    '/bin/sh',
                    'eval(',
                    'base64',
                    'exec(',
                    'system(',
                ]
                
                for pattern in exploit_patterns:
                    if pattern in payload:
                        return True
    except (AttributeError, ValueError):
        pass
    return False

def detect_http_anomalies(packet):
    """Detect HTTP anomalies"""
    try:
        if hasattr(packet, 'http'):
            # Check for suspicious HTTP methods
            if hasattr(packet.http, 'request_method'):
                method = str(packet.http.request_method).upper()
                suspicious_methods = ['TRACE', 'OPTIONS', 'CONNECT']
                if method in suspicious_methods:
                    return True
            
            # Check for suspicious user agents
            if hasattr(packet.http, 'user_agent'):
                user_agent = str(packet.http.user_agent).lower()
                suspicious_agents = ['sqlmap', 'nikto', 'nmap', 'masscan', 'zap']
                for agent in suspicious_agents:
                    if agent in user_agent:
                        return True
            
            # Check for suspicious URIs
            if hasattr(packet.http, 'request_uri'):
                uri = str(packet.http.request_uri).lower()
                suspicious_patterns = ['../', '..\\', 'cmd=', 'exec=', 'eval=']
                for pattern in suspicious_patterns:
                    if pattern in uri:
                        return True
    except (AttributeError, ValueError):
        pass
    return False

def detect_ssl_tls_anomalies(packet):
    """Detect SSL/TLS anomalies"""
    try:
        if hasattr(packet, 'ssl') or hasattr(packet, 'tls'):
            # Check for weak cipher suites
            if hasattr(packet, 'tls'):
                if hasattr(packet.tls, 'handshake_type'):
                    # Alert on multiple handshakes (potential MITM)
                    return False  # Placeholder for more complex detection
    except (AttributeError, ValueError):
        pass
    return False

def log_alert(rule_name, packet, severity="MEDIUM", details=None):
    """Log security alert"""
    os.makedirs(os.path.dirname(ALERT_FILE), exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Extract packet information
    packet_info = ""
    try:
        if hasattr(packet, 'ip'):
            packet_info = f"IP: {packet.ip.src} -> {packet.ip.dst}"
        if hasattr(packet, 'tcp'):
            packet_info += f" TCP:{packet.tcp.dstport}"
        elif hasattr(packet, 'udp'):
            packet_info += f" UDP:{packet.udp.dstport}"
    except:
        packet_info = str(packet)[:200]
    
    alert_msg = f"[{timestamp}] [{severity}] {rule_name} triggered"
    if details:
        alert_msg += f" - {details}"
    alert_msg += f": {packet_info}\n"
    
    with open(ALERT_FILE, "a", encoding="utf-8") as af:
        af.write(alert_msg)

def process_pcap_file(filepath):
    """Process PCAP file and detect threats"""
    if not os.path.exists(filepath):
        print(f"[ERROR] PCAP file not found: {filepath}")
        return
    
    bad_ips = load_bad_ips()
    threat_count = defaultdict(int)
    packet_count = 0
    
    try:
        cap = pyshark.FileCapture(filepath, only_summaries=False)
        
        for packet in cap:
            packet_count += 1
            
            # Run all detection rules
            if detect_bad_ip(packet, bad_ips):
                log_alert("Communication with Blacklisted IP", packet, "CRITICAL")
                threat_count["Blacklisted IP"] += 1
            
            if detect_port_scan(packet):
                log_alert("Port Scan Detected", packet, "HIGH")
                threat_count["Port Scan"] += 1
            
            if detect_syn_flood(packet):
                log_alert("SYN Flood Attack", packet, "CRITICAL")
                threat_count["SYN Flood"] += 1
            
            if detect_malicious_port(packet):
                log_alert("Connection to Malicious Port", packet, "HIGH")
                threat_count["Malicious Port"] += 1
            
            if detect_unusual_port_activity(packet):
                log_alert("Unusual Port Activity", packet, "MEDIUM")
                threat_count["Unusual Port"] += 1
            
            if detect_dns_tunneling(packet):
                log_alert("Potential DNS Tunneling", packet, "HIGH")
                threat_count["DNS Tunneling"] += 1
            
            if detect_data_exfiltration(packet):
                log_alert("Potential Data Exfiltration", packet, "HIGH")
                threat_count["Data Exfiltration"] += 1
            
            if detect_icmp_flood(packet):
                log_alert("ICMP Flood Attack", packet, "HIGH")
                threat_count["ICMP Flood"] += 1
            
            if detect_arp_spoofing(packet):
                log_alert("ARP Spoofing Detected", packet, "HIGH")
                threat_count["ARP Spoofing"] += 1
            
            if detect_suspicious_protocol(packet):
                log_alert("Suspicious Protocol Usage", packet, "MEDIUM")
                threat_count["Suspicious Protocol"] += 1
            
            if detect_connection_anomaly(packet):
                log_alert("Connection Anomaly Detected", packet, "MEDIUM")
                threat_count["Connection Anomaly"] += 1
            
            if detect_fragmented_packets(packet):
                log_alert("Fragmented Packet Detected", packet, "LOW")
                threat_count["Fragmented Packets"] += 1
            
            if detect_suspicious_payload(packet):
                log_alert("Suspicious Payload Detected", packet, "HIGH")
                threat_count["Suspicious Payload"] += 1
            
            if detect_http_anomalies(packet):
                log_alert("HTTP Anomaly Detected", packet, "MEDIUM")
                threat_count["HTTP Anomaly"] += 1
            
            if detect_ssl_tls_anomalies(packet):
                log_alert("SSL/TLS Anomaly Detected", packet, "MEDIUM")
                threat_count["SSL/TLS Anomaly"] += 1
        
        cap.close()
        
        # Print summary
        print(f"\n[+] PCAP file processed: {filepath}")
        print(f"[+] Total packets analyzed: {packet_count}")
        if threat_count:
            print(f"[!] Threats detected:")
            for threat_type, count in sorted(threat_count.items(), key=lambda x: x[1], reverse=True):
                print(f"    - {threat_type}: {count}")
        else:
            print("[+] No threats detected in network traffic")
            
    except Exception as e:
        print(f"[ERROR] Error processing PCAP file: {e}")
        import traceback
        traceback.print_exc()

def main():
    if not os.path.isdir(PCAP_DIR):
        print(f"[ERROR] PCAP directory not found: {PCAP_DIR}")
        return

    pcap_files = [
        os.path.join(PCAP_DIR, f)
        for f in os.listdir(PCAP_DIR)
        if f.endswith(".pcap")
    ]

    if not pcap_files:
        print("[ERROR] No PCAP files found")
        return

    latest_pcap = max(pcap_files, key=os.path.getmtime)
    process_pcap_file(latest_pcap)


if __name__ == "__main__":
    main()
