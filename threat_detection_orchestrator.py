"""
Unified Threat Detection Orchestrator
Processes system, log, and network data separately and generates alerts
"""

import os
import sys
import subprocess
import json
from datetime import datetime

# Add rules directory to path
RULES_DIR = os.path.join(os.path.dirname(__file__), 'rules')
sys.path.insert(0, RULES_DIR)

from system_rules import process_json_file as process_system_data
from log_rules import process_log_file as process_log_data
from network_rules import process_pcap_file as process_network_data

# Paths
SYSTEM_DATA_DIR = r"C:\ThreatDetection\data\winlogbeatdata"
LOG_DATA_DIR = r"C:\ThreatDetection\data\filebeatdata"
NETWORK_DATA_DIR = r"C:\ThreatDetection\data\network data"
ALERT_FILE = r"C:\ThreatDetection\alerts\alerts_2025-07-23.log"

def get_latest_file(directory, extension=".ndjson"):
    """Get the most recent file in a directory"""
    if not os.path.exists(directory):
        return None
    files = [f for f in os.listdir(directory) if f.endswith(extension)]
    if not files:
        return None
    files.sort(key=lambda x: os.path.getmtime(os.path.join(directory, x)), reverse=True)
    return os.path.join(directory, files[0])

def detect_threats_system():
    """Detect threats from system data (Winlogbeat)"""
    print("[*] Processing System Data (Winlogbeat)...")
    latest_file = get_latest_file(SYSTEM_DATA_DIR, ".ndjson")
    if latest_file:
        try:
            # Import and update the system_rules module to use this file temporarily
            import importlib
            import sys
            # Remove module from cache if already imported
            if 'system_rules' in sys.modules:
                del sys.modules['system_rules']
            sys_rules = importlib.import_module('system_rules')
            original_file = sys_rules.LOG_FILE
            sys_rules.LOG_FILE = latest_file
            try:
                process_system_data(latest_file)
                print(f"[+] System data processed: {latest_file}")
            except Exception as e:
                print(f"[!] Error processing system data: {e}")
            finally:
                sys_rules.LOG_FILE = original_file
        except Exception as e:
            print(f"[!] Error importing system_rules: {e}")
    else:
        print("[!] No system data files found")

def detect_threats_logs():
    """Detect threats from log data (Filebeat)"""
    print("[*] Processing Log Data (Filebeat)...")
    latest_file = get_latest_file(LOG_DATA_DIR, ".ndjson")
    if latest_file:
        try:
            import importlib
            import sys
            # Remove module from cache if already imported
            if 'log_rules' in sys.modules:
                del sys.modules['log_rules']
            log_rules = importlib.import_module('log_rules')
            original_file = log_rules.LOG_FILE
            log_rules.LOG_FILE = latest_file
            try:
                process_log_data(latest_file)
                print(f"[+] Log data processed: {latest_file}")
            except Exception as e:
                print(f"[!] Error processing log data: {e}")
            finally:
                log_rules.LOG_FILE = original_file
        except Exception as e:
            print(f"[!] Error importing log_rules: {e}")
    else:
        print("[!] No log data files found")

def detect_threats_network():
    """Detect threats from network data (tcpdump/Wireshark)"""
    print("[*] Processing Network Data (PCAP)...")
    pcap_file = os.path.join(NETWORK_DATA_DIR, "capture.pcap")
    if os.path.exists(pcap_file):
        try:
            process_network_data(pcap_file)
            print(f"[+] Network data processed: {pcap_file}")
        except Exception as e:
            print(f"[!] Error processing network data: {e}")
    else:
        print("[!] No network data file found")

def run_detection(data_type=None):
    """
    Run threat detection for specified data type or all types
    data_type: 'system', 'logs', 'network', or None for all
    """
    if data_type == 'system' or data_type is None:
        detect_threats_system()
    if data_type == 'logs' or data_type is None:
        detect_threats_logs()
    if data_type == 'network' or data_type is None:
        detect_threats_network()

if __name__ == "__main__":
    import sys
    data_type = sys.argv[1] if len(sys.argv) > 1 else None
    run_detection(data_type)

