def detect_lotl(event: dict):
    process_name = event.get("process_name", "").lower()
    parent_process = event.get("parent_process", "").lower()
    command_line = event.get("command_line", "").lower()

    # -----------------------------
    # PowerShell rules
    # -----------------------------
    if "powershell.exe" in process_name and "-encodedcommand" in command_line:
        return {
            "rule": "PowerShell Encoded Command",
            "severity": "High",
            "reason": "PowerShell used with -EncodedCommand, which can hide malicious commands using Base64 encoding.",
            "mitre_id": "T1059.001",
            "mitre_tactic": "Execution",
            "recommended_action": "Review the encoded payload, verify the user/process that launched it, and block if unauthorised."
        }

    if "powershell.exe" in process_name and "-executionpolicy bypass" in command_line:
        return {
            "rule": "PowerShell ExecutionPolicy Bypass",
            "severity": "High",
            "reason": "PowerShell attempted to bypass execution policy restrictions.",
            "mitre_id": "T1059.001",
            "mitre_tactic": "Defense Evasion / Execution",
            "recommended_action": "Check whether the bypass was required for an approved script. Investigate if launched unexpectedly."
        }

    if "powershell.exe" in process_name and "downloadstring" in command_line:
        return {
            "rule": "PowerShell DownloadString Usage",
            "severity": "High",
            "reason": "PowerShell used DownloadString, which is commonly abused to retrieve and execute remote scripts.",
            "mitre_id": "T1105",
            "mitre_tactic": "Command and Control",
            "recommended_action": "Inspect the URL and downloaded content. Block suspicious domains and isolate the host if needed."
        }

    if "powershell.exe" in process_name and "-nop" in command_line and ("-w hidden" in command_line or "-windowstyle hidden" in command_line):
        return {
            "rule": "PowerShell Hidden Execution",
            "severity": "High",
            "reason": "PowerShell was launched with hidden window behaviour, which may indicate stealthy execution.",
            "mitre_id": "T1059.001",
            "mitre_tactic": "Execution / Defense Evasion",
            "recommended_action": "Review the parent process and confirm whether the hidden execution was legitimate."
        }

    # -----------------------------
    # LOLBin rules
    # -----------------------------
    if "certutil.exe" in process_name and "-urlcache" in command_line:
        return {
            "rule": "Certutil Suspicious Download",
            "severity": "High",
            "reason": "Certutil was used with -urlcache, which can be abused to download remote payloads.",
            "mitre_id": "T1105",
            "mitre_tactic": "Command and Control",
            "recommended_action": "Verify the remote URL, check downloaded files, and block suspicious network indicators."
        }

    if "certutil.exe" in process_name and "http" in command_line:
        return {
            "rule": "Certutil Remote URL Access",
            "severity": "High",
            "reason": "Certutil command references a remote URL, which may indicate payload retrieval.",
            "mitre_id": "T1105",
            "mitre_tactic": "Command and Control",
            "recommended_action": "Review the URL and confirm whether certutil network usage was authorised."
        }

    if "mshta.exe" in process_name and ("http" in command_line or ".hta" in command_line):
        return {
            "rule": "MSHTA Suspicious Execution",
            "severity": "High",
            "reason": "MSHTA was used to execute HTA or remote content.",
            "mitre_id": "T1218.005",
            "mitre_tactic": "Defense Evasion",
            "recommended_action": "Inspect the HTA source and parent process. Block remote HTA execution if unauthorised."
        }

    if "rundll32.exe" in process_name and "javascript:" in command_line:
        return {
            "rule": "Rundll32 JavaScript Proxy Execution",
            "severity": "Critical",
            "reason": "Rundll32 was used with JavaScript-style execution, which is a known LOLBin abuse pattern.",
            "mitre_id": "T1218.011",
            "mitre_tactic": "Defense Evasion",
            "recommended_action": "Treat as high risk. Investigate parent process, command line, and related network activity."
        }

    if "regsvr32.exe" in process_name and ("scrobj.dll" in command_line or "http" in command_line):
        return {
            "rule": "Regsvr32 Scriptlet Execution",
            "severity": "Critical",
            "reason": "Regsvr32 was used with scriptlet-related behaviour, which can support fileless execution.",
            "mitre_id": "T1218.010",
            "mitre_tactic": "Defense Evasion",
            "recommended_action": "Investigate the scriptlet source and block unauthorised regsvr32 remote execution."
        }

    if "wmic.exe" in process_name and "process call create" in command_line:
        return {
            "rule": "WMI Process Creation",
            "severity": "High",
            "reason": "WMIC was used to create a process, which may indicate remote or automated execution.",
            "mitre_id": "T1047",
            "mitre_tactic": "Execution",
            "recommended_action": "Check whether the process creation was administrative. Investigate if unexpected."
        }

    # -----------------------------
    # Abnormal parent-child process rules
    # -----------------------------
    suspicious_children = [
        "powershell.exe",
        "cmd.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "certutil.exe",
        "wmic.exe"
    ]

    suspicious_parents = [
        "winword.exe",
        "excel.exe",
        "outlook.exe",
        "powerpnt.exe",
        "chrome.exe",
        "msedge.exe",
        "firefox.exe"
    ]

    if process_name in suspicious_children and parent_process in suspicious_parents:
        return {
            "rule": "Abnormal Parent-Child Process",
            "severity": "Critical",
            "reason": f"Suspicious child process '{process_name}' was launched by '{parent_process}'.",
            "mitre_id": "T1204 / T1059",
            "mitre_tactic": "Execution",
            "recommended_action": "Investigate the parent application, check whether a document or browser triggered command execution."
        }

    return None