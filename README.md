# Final-Year-Project
A cybersecurity concept where attackers abuse legitimate system tools and built-in applications to perform malicious activities while avoiding detection.

# LotL Sentinel

LotL Sentinel is a Python-based cybersecurity detection tool designed to identify suspicious Living off the Land (LotL) activities by analyzing Windows Sysmon logs and command-line behavior.

The project focuses on detecting abuse of legitimate Windows utilities such as PowerShell, commonly used by attackers to evade detection and execute malicious actions.

---

## Features

- Detects suspicious PowerShell activity
- Identifies:
  - Encoded PowerShell commands
  - Execution Policy bypass attempts
  - DownloadString abuse
  - Hidden PowerShell execution
- Maps detections to MITRE ATT&CK techniques
- Provides severity levels and recommended actions
- Parses Sysmon event logs
- Supports live monitoring simulation

---

## Technologies Used

- Python
- Sysmon Logs
- MITRE ATT&CK Framework
- JSON
- XML Parsing

---

## Project Structure

MITRE ATT&CK Techniques
Technique ID	Description
T1059.001	PowerShell
T1105	Ingress Tool Transfer
T1218	System Binary Proxy Execution
Objectives

The main objective of this project is to:

Understand Living off the Land attack techniques
Improve detection engineering skills
Practice threat detection using Sysmon logs
Simulate SOC analyst workflows
Map malicious behavior to MITRE ATT&CK
Learning Outcomes

Through this project, I learned:

How attackers abuse legitimate system tools
How to detect suspicious command-line behavior
How to analyze Windows Sysmon events
How detection rules are implemented in Python
The importance of threat intelligence mapping
Future Improvements
Add real-time log monitoring
Integrate with SIEM platforms
Add more Living off the Land detection rules
Improve alert visualization dashboard
Export alerts to external systems
Author

GitHub: Kugesh12

```text
LotL_Sentinel/
│
├── app/
│   ├── detector.py
│   ├── parser.py
│   ├── live_monitor.py
│   ├── sample_events.py
│   └── main.py
│
├── logs/
│   ├── demo_lotl_events.xml
│   └── test_sysmon.xml
│
├── alerts.json
├── requirements.txt
└── README.md


