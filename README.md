<div align="center">

# 🛡 Autonomous Cyber Incident Response Framework

### Real-Time Threat Detection & Automated Mitigation

A rule-based, explainable cybersecurity framework that continuously monitors logs, network traffic, and system events — then detects, correlates, and **autonomously mitigates** threats in real time.

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Elasticsearch](https://img.shields.io/badge/Elasticsearch-005571?style=flat&logo=elasticsearch&logoColor=white)](https://www.elastic.co/elasticsearch/)
[![Kibana](https://img.shields.io/badge/Kibana-005571?style=flat&logo=kibana&logoColor=white)](https://www.elastic.co/kibana/)
[![Wireshark](https://img.shields.io/badge/PCAP-Wireshark%20%2F%20tcpdump-1679A7?style=flat&logo=wireshark&logoColor=white)](https://www.wireshark.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Academic%20Project-success)](#)

</div>

---

## 📖 Overview

Modern organizations face a growing volume of fast-moving cyber threats — SQL injection, command injection, brute-force attempts, lateral movement, and more — that routinely outpace manual, human-driven security operations. This project implements a **fully autonomous, rule-based Security Operations Center (SOC) pipeline** that closes the loop between detection and response, without relying on machine learning or black-box AI models.

The framework continuously ingests **application logs, Windows system events, and raw network traffic**, runs them through a deterministic rule engine, correlates related alerts into full incident narratives, and automatically executes containment actions — IP blocking, process termination, account disabling, and file quarantine — while visualizing everything on a live Kibana dashboard.

> Because every detection is rule-based rather than ML-driven, every alert is **fully explainable and auditable** — a key requirement for compliance-driven and academic security environments.

---

## ✨ Key Features

- 🔍 **Multi-source continuous monitoring** — Filebeat (application logs), Winlogbeat (Windows event logs), and PCAP-based network capture (Zeek / tcpdump / Wireshark)
- ⚙ **Rule-based threat detection engine** — dedicated rule modules for logs, system events, and network traffic, covering **20+ threat categories** (see [Detection Capabilities](#-detection-capabilities) below)
- 🔗 **Analysis & correlation engine** — groups related alerts by IP, process, file, and username within time windows to reconstruct multi-stage attack sequences, assign risk levels, and calculate confidence scores
- 🧠 **Threat intelligence & attack-stage mapping** — classifies incidents into stages (Reconnaissance, Initial Access, Privilege Escalation, Exfiltration) for better situational awareness
- 📝 **Automated incident reporting** — structured, forensic-ready reports (`analysis_report.txt`) with attack type, severity, confidence score, threat distribution, and timeline
- 🤖 **Automated mitigation engine** — risk-based containment playbooks (see [Mitigation Capabilities](#-mitigation-capabilities) below), with a built-in `DRY_RUN` safety mode for testing before live use
- 🖥 **Cross-platform response** — mitigation actions adapted for both Windows and Linux (firewall/iptables, service management, process handling)
- 📊 **Real-time Kibana dashboard** — attack distribution, severity trends, mitigation statistics, and timeline analytics for SOC-style visibility
- 🧩 **Modular & extensible** — designed for future integration with SIEM/SOAR platforms, cloud telemetry, and threat intelligence feeds

---

## 🔍 Detection Capabilities

Three independent rule engines analyze different telemetry sources in parallel, each covering a wide range of threat patterns.

### `rules/log_rules.py` — Log-based threat detection
SQL injection (15+ patterns) · XSS (12+ patterns) · Command injection · Path traversal · Suspicious PowerShell (13+ patterns) · Brute force (rate-based) · Privilege escalation · Malware indicators · Data exfiltration · Suspicious file operations · Account manipulation · Configuration changes · Anomalous activity detection

### `rules/network_rules.py` — Network threat detection
Blacklisted IP communication · Port scanning (rate-based) · SYN flood · Malicious port detection (20+ known ports) · DNS tunneling · Data exfiltration · ICMP flood · ARP spoofing · Suspicious protocol usage · Connection anomalies · Fragmented packet detection · Suspicious payload detection · HTTP anomalies · SSL/TLS anomalies

### `rules/system_rules.py` — System event threat detection
Account management (creation/deletion/modification) · Authentication monitoring (failed & suspicious logons) · Privilege escalation · Suspicious executable detection (20+ executables) · High-risk executable detection · PowerShell obfuscation · Service manipulation · Registry modification monitoring · Firewall rule changes · Security policy changes · Group manipulation · Rapid process creation · Brute-force logon detection · Suspicious file access · Lateral movement · Privilege abuse

### `analysis and correlation/analysis_and_correlation.py` — Correlation & risk engine
- **Threat classification** across 20+ categories (SQLi, XSS, Command Injection, Path Traversal, PowerShell, Brute Force, Privilege Escalation, Malware, Data Exfiltration, Port Scan, DDoS, DNS Tunneling, Lateral Movement, Account/Service manipulation, and more)
- **Alert correlation** across sources by shared IP, process, file, or username within a rolling time window
- **Risk scoring & confidence calculation** to reduce false positives and prioritize response
- **Attack-stage mapping** onto a simplified kill-chain (Reconnaissance → Initial Access → Privilege Escalation → Exfiltration)
- **Structured report generation** to `analysis_report/analysis_report.txt`

---

## 🤖 Mitigation Capabilities

`mitigation/automated_mitigation_engine.py` executes risk-based containment playbooks in response to correlated incidents:

- 🚫 **IP blocking** — firewall / iptables rule injection for malicious source addresses
- ⛔ **Process termination** — kills processes matching malicious indicators
- 🔒 **Account disabling** — locks out compromised or abused accounts
- 🗂 **File quarantine** — isolates suspicious files flagged by detection rules
- 🧪 **`DRY_RUN` safety mode** — simulates every mitigation action and logs what *would* happen, without making live changes, so the pipeline can be safely tested before deployment
- 🖥 **Cross-platform playbooks** — separate execution paths for Windows and Linux hosts
- 📄 **Mitigation logging** — every action (attempted or executed) is recorded to `alerts/mitigation_log.txt` for audit purposes

---

## 📊 Dashboard

A live Kibana dashboard (built on the Elasticsearch/Logstash/Filebeat/Winlogbeat stack in `elk-stack/`) provides SOC-style visibility:

- Attack type distribution
- Severity timeline trends
- Mitigation actions over time
- Mitigation breakdown by attack type
- Overall attack timeline trend

Dashboard screenshots and the architecture/workflow diagrams are available in [`assets/`](assets).

---

## 🏗 Project Structure

```
ThreatDetection/
├── data_collector.py
├── main_controller.py
├── threat_detection_orchestrator.py
├── docker-compose.yml
├── filebeat.yml
├── requirements.txt
├── package.json
│
├── rules/
│   ├── log_rules.py
│   ├── network_rules.py
│   └── system_rules.py
│
├── analysis and correlation/
│   ├── analysis_and_correlation.py
│   └── analysis_report/
│       └── analysis_report.txt
│
├── mitigation/
│   └── automated_mitigation_engine.py
│
├── elk-stack/
│   ├── docker-compose.yml
│   └── pipeline/
│       └── logstash.conf
│
├── iocs/
│   └── bad_ips.txt
│
├── alerts/
│   ├── alerts.log
│   └── mitigation_log.txt
│
├── utils/
│   └── alertParser.js
│
└── assets/
    └── (architecture diagram, dashboard screenshots)
```

---

## 🚀 Getting Started

```bash
# Clone the repository
git clone https://github.com/RAHUL-167/Cyber-Incident-Response-Framework.git
cd Cyber-Incident-Response-Framework

# Install Python dependencies
pip install -r requirements.txt

# Install Node dependencies (for utils/alertParser.js)
npm install

# Bring up the ELK stack
docker-compose up -d
```

> ⚠️ Before running live mitigations, keep `DRY_RUN` enabled in `mitigation/automated_mitigation_engine.py` until you've validated detection accuracy in your environment.

---

## 📄 License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for details.

---

## 👤 Author

**Theegala Rahul Rao**

