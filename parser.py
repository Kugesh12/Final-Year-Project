import os
import xml.etree.ElementTree as ET


def extract_filename(path: str) -> str:
    if not path:
        return ""
    return os.path.basename(path).lower()


def strip_namespace(tag: str) -> str:
    return tag.split("}", 1)[-1]


def _convert_event_elements_to_dicts(event_elements):
    events = []

    for event in event_elements:
        event_data = {}

        for element in event.iter():
            if strip_namespace(element.tag) == "Data":
                name = element.attrib.get("Name", "")
                value = element.text if element.text else ""
                if name:
                    event_data[name] = value

        parsed_event = {
            "process_name": extract_filename(event_data.get("Image", "")),
            "parent_process": extract_filename(event_data.get("ParentImage", "")),
            "command_line": event_data.get("CommandLine", ""),
            "timestamp": event_data.get("UtcTime", "")
        }

        if any(parsed_event.values()):
            events.append(parsed_event)

    return events


def parse_sysmon_xml(file_path: str):
    tree = ET.parse(file_path)
    root = tree.getroot()

    event_elements = [
        element for element in root.iter()
        if strip_namespace(element.tag) == "Event"
    ]

    return _convert_event_elements_to_dicts(event_elements)


def parse_sysmon_xml_string(xml_text: str):
    root = ET.fromstring(xml_text)

    event_elements = [
        element for element in root.iter()
        if strip_namespace(element.tag) == "Event"
    ]

    return _convert_event_elements_to_dicts(event_elements)