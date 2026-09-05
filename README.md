<div align="center">



\# 🛡️ Autonomous Cyber Incident Response Framework



\### Real-Time Threat Detection \& Automated Mitigation



A rule-based, explainable cybersecurity framework that continuously monitors logs, network traffic, and system events — then detects, correlates, and \*\*autonomously mitigates\*\* threats in real time.



\[!\[Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat\&logo=python\&logoColor=white)](https://www.python.org/)

\[!\[Elasticsearch](https://img.shields.io/badge/Elasticsearch-005571?style=flat\&logo=elasticsearch\&logoColor=white)](https://www.elastic.co/elasticsearch/)

\[!\[Kibana](https://img.shields.io/badge/Kibana-005571?style=flat\&logo=kibana\&logoColor=white)](https://www.elastic.co/kibana/)

\[!\[Wireshark](https://img.shields.io/badge/PCAP-Wireshark%20%2F%20tcpdump-1679A7?style=flat\&logo=wireshark\&logoColor=white)](https://www.wireshark.org/)

\[!\[License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

\[!\[Status](https://img.shields.io/badge/Status-Academic%20Project-success)](#)



</div>



\---



\## 📖 Overview



Modern organizations face a growing volume of fast-moving cyber threats — SQL injection, command injection, brute-force attempts, lateral movement, and more — that routinely outpace manual, human-driven security operations. This project implements a \*\*fully autonomous, rule-based Security Operations Center (SOC) pipeline\*\* that closes the loop between detection and response, without relying on machine learning or black-box AI models.



The framework continuously ingests \*\*application logs, Windows system events, and raw network traffic\*\*, runs them through a deterministic rule engine, correlates related alerts into full incident narratives, and automatically executes containment actions — IP blocking, process termination, account disabling, and file quarantine — while visualizing everything on a live Kibana dashboard.



> Because every detection is rule-based rather than ML-driven, every alert is \*\*fully explainable and auditable\*\* — a key requirement for compliance-driven and academic security environments.



\---



\## ✨ Key Features



\- 🔍 \*\*Multi-source continuous monitoring\*\* — Filebeat (application logs), Winlogbeat (Windows event logs), and PCAP-based network capture (Zeek / tcpdump / Wireshark)

\- ⚙️ \*\*Rule-based threat detection engine\*\* — dedicated rule modules for logs, system events, and network traffic, covering \*\*20+ threat categories\*\* (see \[Detection Capabilities](#-detection-capabilities) below)

\- 🔗 \*\*Analysis \& correlation engine\*\* — groups related alerts by IP, process, file, and username within time windows to reconstruct multi-stage attack sequences, assign risk levels, and calculate confidence scores

\- 🧠 \*\*Threat intelligence \& attack-stage mapping\*\* — classifies incidents into stages (Reconnaissance, Initial Access, Privilege Escalation, Exfiltration) for better situational awareness

\- 📝 \*\*Automated incident reporting\*\* — structured, forensic-ready reports (`analysis\_report.txt`) with attack type, severity, confidence score, threat distribution, and timeline

\- 🤖 \*\*Automated mitigation engine\*\* — risk-based containment playbooks (see \[Mitigation Capabilities](#-mitigation-capabilities) below), with a built-in `DRY\_RUN` safety mode for testing before live use

\- 🖥️ \*\*Cross-platform response\*\* — mitigation actions adapted for both Windows and Linux (firewall/iptables, service management, process handling)

\- 📊 \*\*Real-time Kibana dashboard\*\* — attack distribution, severity trends, mitigation statistics, and timeline analytics for SOC-style visibility

\- 🧩 \*\*Modular \& extensible\*\* — designed for future integration with SIEM/SOAR platforms, cloud telemetry, and threat intelligence feeds



\---



\## 🔍 Detection Capabilities



Three independent rule engines analyze different telemetry sources in parallel, each covering a wide range of threat patterns.



\### `rules/log\_rules.py` — Log-based threat detection

SQL injection (15+ patterns) · XSS (12+ patterns) · Command injection · Path traversal · Suspicious PowerShell (13+ patterns) · Brute force (rate-based) · Privilege escalation · Malware indicators · Data exfiltration · Suspicious file operations · Account manipulation · Configuration changes · Anomalous activity detection



\### `rules/network\_rules.py` — Network threat detection

Blacklisted IP communication · Port scanning (rate-based) · SYN flood · Malicious port detection (20+ known ports) · DNS tunneling · Data exfiltration · ICMP flood · ARP spoofing · Suspicious protocol usage · Connection anomalies · Fragmented packet detection · Suspicious payload detection · HTTP anomalies · SSL/TLS anomalies



\### `rules/system\_rules.py` — System event threat detection

Account management (creation/deletion/modification) · Authentication monitoring (failed \& suspicious logons) · Privilege escalation · Suspicious executable detection (20+ executables) · High-risk executable detection · PowerShell obfuscation · Service manipulation · Registry modification monitoring · Firewall rule changes · Security policy changes · Group manipulation · Rapid process creation · Brute-force logon detection · Suspicious file access · Lateral movement · Privilege abuse



\### `analysis and correlation/analysis\_and\_correlation.py` — Correlation \& risk engine

\- \*\*Threat classification\*\* across 20+ categories (SQLi, XSS, Command Injection, Path Traversal, PowerShell, Brute Force, Privilege Escalation, Malware, Data Exfiltration, Port Scan, DDoS, DNS Tunneling, Lateral Movement, Account/Service/Registry/Firewall/Policy/Group manipulation, File Operations, Network/HTTP/SSL anomalies, Blacklisted IP, ARP Spoofing)

\- \*\*Correlation\*\* by IP, process, file, and username within time windows, with deduplication of correlated incidents

\- \*\*Risk assessment\*\* (CRITICAL / HIGH / MEDIUM / LOW) based on threat combinations and severity

\- \*\*Confidence scoring\*\* based on multi-source corroboration

\- \*\*Attack-stage identification\*\* (Reconnaissance → Initial Access → Privilege Escalation → Exfiltration)

\- Pattern extraction for IPs, processes, ports, files, event IDs, and usernames



\---



\## 🤖 Mitigation Capabilities



`mitigation/automated\_mitigation\_engine.py` executes risk-based containment automatically once an incident is confirmed:



| Layer | Actions |

|---|---|

| \*\*Network\*\* | IP blocking (Windows Firewall / iptables), port blocking, hosts-file blocking, network adapter disabling, IOC blacklist management |

| \*\*Process\*\* | Process termination (by name/PID), process suspension, platform-specific handling (Windows/Linux) |

| \*\*File system\*\* | Quarantine, deletion, read-only protection |

| \*\*Accounts\*\* | Disable account, revoke admin privileges, lock account |

| \*\*Services\*\* | Stop/disable service (Windows \& Linux) |

| \*\*Persistence\*\* | Registry run-key removal, scheduled task removal |



\*\*Risk-based response tiers:\*\*

\- \*\*CRITICAL\*\* → immediate isolation, process termination, file quarantine, network disabling

\- \*\*HIGH\*\* → IP blocking, high-risk process termination, file quarantine

\- \*\*MEDIUM\*\* → IOC monitoring, file quarantine, port blocking

\- \*\*LOW\*\* → IOC logging and monitoring



\*\*Threat-specific playbooks\*\* include: SQLi/XSS/Command Injection → web file quarantine + WAF recommendations · PowerShell/Malware → process termination + executable quarantine · Brute Force → IP blocking + account disabling · Privilege Escalation → admin revocation + manual review · Data Exfiltration → immediate IP blocking + network isolation · Lateral Movement → IP blocking + network policy review.



\*\*Safety features:\*\* a `DRY\_RUN` mode for testing without taking live action, full logging of every action taken, error handling with timeout protection, and manual-action recommendations for scenarios too complex for full automation.



\---



\## 🏗️ Architecture



The framework processes security data through five cooperating layers: monitoring → detection → analysis → mitigation → visualization, forming a \*\*closed-loop autonomous defense cycle\*\*.



<p align="center">

&#x20; <img src="assets/architecture-diagram.png" alt="Framework Architecture Diagram" width="750">

</p>



\*\*Flow:\*\* `Log Data / Network Traffic / System Events` → \*\*Monitoring Engine\*\* → \*\*Threat Detection Engine\*\* → \*\*Alerts\*\* (visualized instantly) → \*\*Analysis Module\*\* → \*\*Mitigation Module\*\* → \*\*Dashboard System\*\*



\---



\## 🔄 System Workflow



<p align="center">

&#x20; <img src="assets/system-workflow.png" alt="End-to-End System Workflow" width="480">

</p>



1\. \*\*Data Ingestion\*\* — Filebeat NDJSON logs, Winlogbeat Windows events, and PCAP network captures are collected continuously.

2\. \*\*Threat Detection\*\* — Log rules, system rules, and network rules run in parallel against the incoming telemetry.

3\. \*\*Analysis \& Correlation\*\* — Related alerts are aggregated by IP, user, process, and timestamp into unified incident profiles.

4\. \*\*Incident Reporting\*\* — Correlated incidents are written to `analysis\_report.txt` with severity, confidence, and timeline.

5\. \*\*Automated Mitigation\*\* — Predefined playbooks trigger IP blocking, process termination, account disabling, and file quarantine based on severity.

6\. \*\*Dashboard \& Logging\*\* — All alerts and actions are stored in `alerts.log` and rendered live on the Kibana dashboard for analyst review.



\---



\## 🧰 Tech Stack



| Category | Technologies |

|---|---|

| \*\*Core Engine\*\* | Python 3.10+ (`os`, `re`, `json`, `datetime`, `subprocess`, `scapy`, `pyshark`, `collections`, `ipaddress`, `threading`, `logging`) |

| \*\*Monitoring \& Visualization\*\* | Elastic Stack — Filebeat, Winlogbeat, Elasticsearch, Kibana |

| \*\*Network Analysis\*\* | tcpdump, Wireshark, Zeek, PCAP |

| \*\*Orchestration\*\* | Docker Compose |

| \*\*Alert Utilities\*\* | Node.js (alert parsing) |

| \*\*Environment\*\* | Windows · VS Code |



\---



\## 📊 Results \& Dashboards



Sample results from the framework running against a large-scale test dataset of application, system, and network logs.



<p align="center">

&#x20; <img src="assets/dashboard-attack-type-distribution.png" alt="Attack Type Distribution" width="600">

&#x20; <br><em>Attack Type Distribution — SQL Injection and Command Injection dominate detected threats.</em>

</p>



<p align="center">

&#x20; <img src="assets/dashboard-severity-timeline.png" alt="Threat Severity Timeline" width="600">

&#x20; <br><em>Threat Severity Timeline — CRITICAL/HIGH incident spikes followed by successful containment.</em>

</p>



<p align="center">

&#x20; <img src="assets/dashboard-mitigation-actions-over-time.png" alt="Mitigation Actions Over Time" width="600">

&#x20; <br><em>Mitigation Actions Over Time — autonomous response volume decreasing as threats are contained.</em>

</p>



<p align="center">

&#x20; <img src="assets/dashboard-mitigation-by-attack-type.png" alt="Mitigation Mapping by Attack Type" width="600">

&#x20; <br><em>Mitigation Mapping by Attack Type — multi-action response strategy (firewall rules, IP blocks, WAF recommendations).</em>

</p>



<p align="center">

&#x20; <img src="assets/dashboard-attack-timeline-trend.png" alt="Attack Timeline and Trend Analysis" width="600">

&#x20; <br><em>Attack Timeline \& Trend Analysis — attack volume drops sharply after automated mitigation kicks in.</em>

</p>



\---



\## 📂 Project Structure



```

ThreatDetection/

├── main\_controller.py                     # Entry point — orchestrates the full pipeline

├── threat\_detection\_orchestrator.py       # Coordinates detection → analysis → mitigation

├── data\_collector.py                      # Pulls in Filebeat / Winlogbeat / PCAP telemetry

├── docker-compose.yml                     # Elastic Stack (Elasticsearch + Kibana) services

├── filebeat.yml                           # Filebeat shipper configuration

│

├── rules/                                 # Rule-based detection engine

│   ├── log\_rules.py                       #   → SQLi, command injection, brute force, etc.

│   ├── system\_rules.py                    #   → Windows Event IDs, PowerShell abuse, privilege escalation

│   └── network\_rules.py                   #   → suspicious ports, malicious IPs, lateral movement

│

├── analysis and correlation/

│   ├── analysis\_and\_correlation.py        # Correlates alerts into multi-stage incidents

│   └── analysis\_report/

│       └── analysis\_report.txt            # Generated incident report (forensic record)

│

├── mitigation/

│   └── automated\_mitigation\_engine.py     # Executes IP block / kill process / disable account / quarantine

│

├── alerts/

│   ├── alerts.log                         # Live alert stream

│   └── mitigation\_log.txt                 # Record of autonomous actions taken

│

├── iocs/

│   └── bad\_ips.txt                        # Blacklisted / known-malicious IP indicators

│

├── data/                                  # Raw telemetry (see .gitignore — not committed)

│   ├── filebeatdata/                      #   Filebeat NDJSON logs

│   ├── winlogbeatdata/                    #   Winlogbeat NDJSON logs

│   └── network data/                      #   PCAP / PCAPNG captures

│

├── utils/

│   └── alertParser.js                     # Node.js alert-parsing utility

│

├── assets/                                # Architecture diagram \& dashboard screenshots (this package)

├── requirements.txt

├── package.json

├── .gitignore

├── LICENSE

└── README.md

```



\### Elastic Stack setup (`elk-stack/`)

Elasticsearch, Kibana, and the Logstash ingest pipeline run as a separate stack:

```

elk-stack/

├── docker-compose.yml     # Elasticsearch + Kibana + Logstash services

└── pipeline/

&#x20;   └── logstash.conf      # Logstash ingest pipeline config

```

You can push this as a subfolder of the same repo, or as its own `elk-stack` repo linked from here — either works, just update the clone command below to match.



\---



\## 🚀 Getting Started



```bash

\# 1. Clone the repository

git clone https://github.com/RAHUL-167/Cyber-Incident-Response-Framework.git

cd Cyber-Incident-Response-Framework



\# 2. Spin up the Elastic Stack (Elasticsearch + Kibana + Logstash)

cd elk-stack \&\& docker-compose up -d \&\& cd ..



\# 3. Install Python dependencies

pip install -r requirements.txt



\# 4. (Optional) install Node dependencies for the alert-parsing utility

npm install



\# 5. Configure filebeat.yml to ship logs to your Elasticsearch instance,

\#    and point data\_collector.py at your log/PCAP directories under data/



\# 6. Run the full detection \& mitigation pipeline

python main\_controller.py

\#   → internally drives threat\_detection\_orchestrator.py, which runs

\#     rules/\*.py → analysis and correlation/analysis\_and\_correlation.py →

\#     mitigation/automated\_mitigation\_engine.py



\# 7. Open Kibana (default: http://localhost:5601) and load the dashboard/

\#    index patterns to view live results

```



\*\*Prerequisites:\*\* Python 3.10+, Docker \& Docker Compose, Elastic Stack (Elasticsearch + Kibana + Logstash), Filebeat, Winlogbeat, and a packet capture tool (tcpdump / Wireshark / Zeek). Node.js is required for the `utils/alertParser.js` utility.



\---



\## 🔮 Future Enhancements



\- Integration with SIEM/SOAR platforms and cloud-native telemetry

\- Machine-learning-assisted anomaly detection for zero-day threats

\- MITRE ATT\&CK technique mapping

\- Enterprise-scale distributed deployment and horizontal scaling



\---



\## 👤 Author



\*\*Theegala Rahul Rao\*\*

B.Tech, CSE (Cyber Security) — CMR College of Engineering \& Technology

Under the guidance of Mrs. G. Saranya, Assistant Professor



\---



\## 📄 License



This project is released under the \[MIT License](LICENSE).



\---



<div align="center">

<sub>⭐ If you find this project useful, consider giving it a star!</sub>

</div>

