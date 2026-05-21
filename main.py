import sys
import json

from PySide6.QtCore import QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QMessageBox,
    QFrame,
    QFileDialog,
    QTextEdit
)

from app.parser import parse_sysmon_xml
from app.detector import detect_lotl
from app.live_monitor import read_live_sysmon_events


class SummaryCard(QFrame):
    def __init__(self, title, value="0"):
        super().__init__()

        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setStyleSheet("""
            QFrame {
                background-color: #1e1e1e;
                border: 1px solid #3a3a3a;
                border-radius: 10px;
                padding: 10px;
            }
            QLabel {
                color: white;
            }
        """)

        layout = QVBoxLayout()

        self.title_label = QLabel(title)
        self.value_label = QLabel(value)
        self.value_label.setStyleSheet(
            "font-size: 24px; font-weight: bold; color: #4FC3F7;"
        )

        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)

        self.setLayout(layout)

    def update_value(self, value):
        self.value_label.setText(str(value))


class LoTLSentinelWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.current_file = "logs/demo_lotl_events.xml"
        self.last_alerts = []
        self.last_scan_results = []
        self.displayed_rows = []
        self.current_view_mode = "all"

        self.auto_monitor_running = False
        self.auto_timer = QTimer(self)
        self.auto_timer.timeout.connect(self.auto_scan_live_sysmon)

        self.setWindowTitle("LoTL Sentinel")
        self.setGeometry(150, 80, 1300, 850)

        self.setStyleSheet("""
            QWidget {
                background-color: #121212;
                color: white;
                font-size: 13px;
            }
            QPushButton {
                background-color: #1f6feb;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2b7fff;
            }
            QTableWidget {
                background-color: #1a1a1a;
                gridline-color: #333333;
                color: white;
            }
            QHeaderView::section {
                background-color: #2a2a2a;
                color: white;
                padding: 6px;
                border: 1px solid #333333;
            }
            QTextEdit {
                background-color: #1a1a1a;
                color: white;
                border: 1px solid #333333;
                border-radius: 8px;
                padding: 8px;
            }
        """)

        self.layout = QVBoxLayout()

        self.title_label = QLabel("LoTL Sentinel - Behaviour-Based Detection Prototype")
        self.title_label.setStyleSheet(
            "font-size: 18px; font-weight: bold; margin-bottom: 8px;"
        )
        self.layout.addWidget(self.title_label)

        self.subtitle_label = QLabel(
            "Detecting suspicious Living-off-the-Land activity from Sysmon-style logs"
        )
        self.subtitle_label.setStyleSheet("color: #bbbbbb; margin-bottom: 10px;")
        self.layout.addWidget(self.subtitle_label)

        self.card_layout = QHBoxLayout()

        self.total_card = SummaryCard("Total Events", "0")
        self.alert_card = SummaryCard("Alerts", "0")
        self.safe_card = SummaryCard("Safe Events", "0")

        self.card_layout.addWidget(self.total_card)
        self.card_layout.addWidget(self.alert_card)
        self.card_layout.addWidget(self.safe_card)

        self.layout.addLayout(self.card_layout)

        self.button_layout = QHBoxLayout()

        self.scan_default_button = QPushButton("Scan Default XML")
        self.scan_default_button.clicked.connect(self.scan_default_log)
        self.button_layout.addWidget(self.scan_default_button)

        self.open_file_button = QPushButton("Open and Scan XML File")
        self.open_file_button.clicked.connect(self.open_and_scan_file)
        self.button_layout.addWidget(self.open_file_button)

        self.live_scan_button = QPushButton("Scan Live Sysmon")
        self.live_scan_button.clicked.connect(self.scan_live_sysmon)
        self.button_layout.addWidget(self.live_scan_button)

        self.start_monitor_button = QPushButton("Start Auto Monitor")
        self.start_monitor_button.clicked.connect(self.start_auto_monitor)
        self.button_layout.addWidget(self.start_monitor_button)

        self.stop_monitor_button = QPushButton("Stop Auto Monitor")
        self.stop_monitor_button.clicked.connect(self.stop_auto_monitor)
        self.button_layout.addWidget(self.stop_monitor_button)

        self.export_button = QPushButton("Export Alerts to JSON")
        self.export_button.clicked.connect(self.export_alerts)
        self.button_layout.addWidget(self.export_button)

        self.layout.addLayout(self.button_layout)

        self.filter_layout = QHBoxLayout()

        self.show_all_button = QPushButton("Show All")
        self.show_all_button.clicked.connect(self.show_all_results)
        self.filter_layout.addWidget(self.show_all_button)

        self.show_alerts_button = QPushButton("Show Alerts Only")
        self.show_alerts_button.clicked.connect(self.show_alerts_only)
        self.filter_layout.addWidget(self.show_alerts_button)

        self.layout.addLayout(self.filter_layout)

        self.file_label = QLabel(f"Current source: {self.current_file}")
        self.file_label.setStyleSheet(
            "color: #bbbbbb; margin-top: 8px; margin-bottom: 8px;"
        )
        self.layout.addWidget(self.file_label)

        self.result_label = QLabel("Choose a scan option to begin.")
        self.result_label.setStyleSheet("margin-top: 4px; margin-bottom: 8px;")
        self.layout.addWidget(self.result_label)

        self.monitor_status_label = QLabel("Monitoring Status: OFF")
        self.monitor_status_label.setStyleSheet(
            "color: #ffcc00; font-weight: bold; margin-bottom: 8px;"
        )
        self.layout.addWidget(self.monitor_status_label)

        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "Timestamp",
            "Process",
            "Parent",
            "Command",
            "Status",
            "Rule",
            "Severity"
        ])

        self.table.setColumnWidth(0, 170)
        self.table.setColumnWidth(1, 140)
        self.table.setColumnWidth(2, 140)
        self.table.setColumnWidth(3, 380)
        self.table.setColumnWidth(4, 90)
        self.table.setColumnWidth(5, 230)
        self.table.setColumnWidth(6, 100)

        self.table.setMaximumHeight(330)
        self.table.itemSelectionChanged.connect(self.show_selected_details)

        self.layout.addWidget(self.table)

        self.details_title = QLabel("Alert / Event Details")
        self.details_title.setStyleSheet(
            "font-size: 15px; font-weight: bold; margin-top: 8px;"
        )
        self.layout.addWidget(self.details_title)

        self.details_box = QTextEdit()
        self.details_box.setReadOnly(True)
        self.details_box.setMinimumHeight(160)
        self.details_box.setPlainText("Select a row to view detailed information.")
        self.layout.addWidget(self.details_box)

        self.setLayout(self.layout)

    def scan_default_log(self):
        self.current_file = "logs/demo_lotl_events.xml"
        self.file_label.setText(f"Current source: {self.current_file}")

        try:
            events = parse_sysmon_xml(self.current_file)
            self.process_events(events)
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to read XML log:\n{str(e)}"
            )

    def open_and_scan_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select XML Log File",
            "",
            "XML Files (*.xml);;All Files (*)"
        )

        if not file_path:
            return

        self.current_file = file_path
        self.file_label.setText(f"Current source: {self.current_file}")

        try:
            events = parse_sysmon_xml(file_path)
            self.process_events(events)
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to read XML log:\n{str(e)}"
            )

    def scan_live_sysmon(self):
        self.current_file = "Live Windows Event Log (Sysmon)"
        self.file_label.setText(f"Current source: {self.current_file}")

        try:
            events = read_live_sysmon_events(limit=100)

            if not events:
                QMessageBox.information(
                    self,
                    "No Events",
                    "No live Sysmon events were returned."
                )
                return

            self.process_events(events)

        except Exception as e:
            QMessageBox.critical(
                self,
                "Live Scan Error",
                f"Failed to scan live Sysmon events.\n\n{str(e)}"
            )

    def start_auto_monitor(self):
        self.auto_monitor_running = True
        self.auto_timer.start(5000)

        self.current_file = "Auto Monitor: Live Windows Event Log (Sysmon)"
        self.file_label.setText(f"Current source: {self.current_file}")
        self.result_label.setText(
            "Auto Monitor started. Scanning live Sysmon events every 5 seconds."
        )

        self.monitor_status_label.setText("Monitoring Status: ON - Scanning every 5 seconds")
        self.monitor_status_label.setStyleSheet(
            "color: #00ff99; font-weight: bold; margin-bottom: 8px;"
        )

        self.auto_scan_live_sysmon()

    def stop_auto_monitor(self):
        self.auto_monitor_running = False
        self.auto_timer.stop()

        self.result_label.setText("Auto Monitor stopped.")

        self.monitor_status_label.setText("Monitoring Status: OFF")
        self.monitor_status_label.setStyleSheet(
            "color: #ffcc00; font-weight: bold; margin-bottom: 8px;"
        )

    def auto_scan_live_sysmon(self):
        try:
            events = read_live_sysmon_events(limit=100)

            if not events:
                self.result_label.setText(
                    "Auto Monitor running. No live Sysmon events returned."
                )
                return

            self.process_events(events)

            self.result_label.setText(
                f"Auto Monitor running. Last scan completed. Total events: {len(events)} | Alerts: {len(self.last_alerts)}"
            )

        except Exception as e:
            self.auto_timer.stop()
            self.auto_monitor_running = False

            self.monitor_status_label.setText("Monitoring Status: OFF - Error Occurred")
            self.monitor_status_label.setStyleSheet(
                "color: #ff4444; font-weight: bold; margin-bottom: 8px;"
            )

            QMessageBox.critical(
                self,
                "Auto Monitor Error",
                f"Auto Monitor stopped because live Sysmon scan failed.\n\n{str(e)}"
            )

    def process_events(self, events):
        self.last_alerts = []
        self.last_scan_results = []
        self.displayed_rows = []
        self.current_view_mode = "all"

        alert_count = 0
        safe_count = 0

        for event in events:
            alert = detect_lotl(event)

            status = "ALERT" if alert else "Safe"
            rule_name = alert["rule"] if alert else "-"
            severity = alert["severity"] if alert else "-"
            reason = alert["reason"] if alert else "No suspicious behaviour matched the current rules."

            mitre_id = alert.get("mitre_id", "-") if alert else "-"
            mitre_tactic = alert.get("mitre_tactic", "-") if alert else "-"
            recommended_action = (
                alert.get("recommended_action", "No action required.")
                if alert else "No action required."
            )

            row_data = {
                "timestamp": event.get("timestamp", ""),
                "process_name": event.get("process_name", ""),
                "parent_process": event.get("parent_process", ""),
                "command_line": event.get("command_line", ""),
                "status": status,
                "rule": rule_name,
                "severity": severity,
                "reason": reason,
                "mitre_id": mitre_id,
                "mitre_tactic": mitre_tactic,
                "recommended_action": recommended_action,
                "is_alert": bool(alert)
            }

            self.last_scan_results.append(row_data)

            if alert:
                alert_count += 1

                self.last_alerts.append({
                    "timestamp": row_data["timestamp"],
                    "process_name": row_data["process_name"],
                    "parent_process": row_data["parent_process"],
                    "command_line": row_data["command_line"],
                    "rule": row_data["rule"],
                    "severity": row_data["severity"],
                    "reason": row_data["reason"],
                    "mitre_id": row_data["mitre_id"],
                    "mitre_tactic": row_data["mitre_tactic"],
                    "recommended_action": row_data["recommended_action"]
                })
            else:
                safe_count += 1

        self.total_card.update_value(len(events))
        self.alert_card.update_value(alert_count)
        self.safe_card.update_value(safe_count)

        self.result_label.setText(
            f"Scan completed. Total events: {len(events)} | Alerts: {alert_count} | Safe: {safe_count}"
        )

        self.populate_table(self.last_scan_results)

    def populate_table(self, rows):
        self.table.setRowCount(0)
        self.displayed_rows = rows
        self.details_box.setPlainText("Select a row to view detailed information.")

        for row in rows:
            row_position = self.table.rowCount()
            self.table.insertRow(row_position)

            values = [
                row["timestamp"],
                row["process_name"],
                row["parent_process"],
                row["command_line"],
                row["status"],
                row["rule"],
                row["severity"]
            ]

            for col, value in enumerate(values):
                item = QTableWidgetItem(value)

                if row["is_alert"]:
                    item.setBackground(QColor("#4a1f1f"))
                else:
                    item.setBackground(QColor("#1f3a1f"))

                self.table.setItem(row_position, col, item)

    def show_selected_details(self):
        selected_row = self.table.currentRow()

        if selected_row < 0 or selected_row >= len(self.displayed_rows):
            return

        row = self.displayed_rows[selected_row]

        details_text = (
            f"Timestamp          : {row['timestamp']}\n"
            f"Process            : {row['process_name']}\n"
            f"Parent Process     : {row['parent_process']}\n"
            f"Status             : {row['status']}\n"
            f"Rule               : {row['rule']}\n"
            f"Severity           : {row['severity']}\n"
            f"MITRE Technique    : {row['mitre_id']}\n"
            f"MITRE Tactic       : {row['mitre_tactic']}\n"
            f"Reason             : {row['reason']}\n"
            f"Recommended Action : {row['recommended_action']}\n\n"
            f"Full Command Line:\n{row['command_line']}"
        )

        self.details_box.setPlainText(details_text)

    def show_all_results(self):
        if not self.last_scan_results:
            QMessageBox.information(
                self,
                "No Data",
                "No scan results available yet."
            )
            return

        self.current_view_mode = "all"
        self.populate_table(self.last_scan_results)

        self.result_label.setText(
            f"Viewing mode: All Results | Total rows shown: {len(self.last_scan_results)}"
        )

    def show_alerts_only(self):
        if not self.last_scan_results:
            QMessageBox.information(
                self,
                "No Data",
                "No scan results available yet."
            )
            return

        alert_rows = [
            row for row in self.last_scan_results
            if row["is_alert"]
        ]

        self.current_view_mode = "alerts_only"
        self.populate_table(alert_rows)

        self.result_label.setText(
            f"Viewing mode: Alerts Only | Total alerts shown: {len(alert_rows)}"
        )

    def export_alerts(self):
        if not self.last_alerts:
            QMessageBox.information(
                self,
                "No Alerts",
                "There are no alerts to export yet."
            )
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Alerts As",
            "alerts.json",
            "JSON Files (*.json);;All Files (*)"
        )

        if not file_path:
            return

        try:
            with open(file_path, "w", encoding="utf-8") as file:
                json.dump(self.last_alerts, file, indent=4)

            QMessageBox.information(
                self,
                "Export Successful",
                f"Alerts exported to:\n{file_path}"
            )

        except Exception as e:
            QMessageBox.critical(
                self,
                "Export Failed",
                f"Failed to export alerts:\n{str(e)}"
            )


def main():
    app = QApplication(sys.argv)
    window = LoTLSentinelWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()