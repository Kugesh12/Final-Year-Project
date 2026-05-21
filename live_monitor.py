import subprocess

from app.parser import parse_sysmon_xml_string


def read_live_sysmon_events(limit=30):
    command = [
        "wevtutil",
        "qe",
        "Microsoft-Windows-Sysmon/Operational",
        f"/c:{limit}",
        "/rd:true",
        "/f:xml"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore"
    )

    if result.returncode != 0:
        error_message = result.stderr.strip() or "Failed to query Sysmon logs."
        raise RuntimeError(error_message)

    raw_xml = result.stdout.strip()

    if not raw_xml:
        return []

    wrapped_xml = f"<Events>{raw_xml}</Events>"
    return parse_sysmon_xml_string(wrapped_xml)