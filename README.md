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
