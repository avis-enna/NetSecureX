"""
IP Reputation Widget for NetSecureX
===================================

GUI widget for IP reputation and threat intelligence lookup with full functionality.
"""

import asyncio
import json
from datetime import datetime
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QLineEdit, QTextEdit, QGroupBox,
    QProgressBar, QFrame, QMessageBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QSplitter, QScrollArea,
    QFileDialog, QCheckBox
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont, QColor, QPixmap, QPainter

from core.ip_reputation import IPReputationChecker


class IPWorker(QThread):
    """Worker thread for IP reputation checking."""

    # Signals
    progress_updated = Signal(int)
    result_ready = Signal(object)
    error_occurred = Signal(str)
    finished = Signal()

    def __init__(self, ip_address):
        super().__init__()
        self.ip_address = ip_address
        self.ip_checker = None

    def run(self):
        """Run IP reputation check in background."""
        try:
            self.ip_checker = IPReputationChecker()

            # Run async IP reputation check with timeout
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            result = loop.run_until_complete(
                asyncio.wait_for(
                    self.ip_checker.check_ip_reputation(self.ip_address),
                    timeout=20  # 20 second timeout
                )
            )

            loop.close()
            self.result_ready.emit(result)

        except asyncio.TimeoutError:
            self.error_occurred.emit("IP reputation check timed out after 20 seconds")
        except Exception as e:
            self.error_occurred.emit(str(e))
        finally:
            self.finished.emit()


class IPReputationWidget(QWidget):
    """Enhanced IP reputation widget with full threat intelligence."""

    def __init__(self):
        super().__init__()
        self.ip_worker = None
        self.current_result = None
        self.setup_ui()

        # Auto-monitoring timer
        self.monitor_timer = QTimer()
        self.monitor_timer.timeout.connect(self.auto_check)
        self.monitoring_enabled = False

    def setup_ui(self):
        """Setup enhanced IP reputation interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Create splitter for input and results
        splitter = QSplitter(Qt.Vertical)
        layout.addWidget(splitter)

        # Input section
        input_section = self.create_input_section()
        splitter.addWidget(input_section)

        # Results section
        results_section = self.create_results_section()
        splitter.addWidget(results_section)

        # Set splitter proportions
        splitter.setSizes([150, 650])

    def create_input_section(self):
        """Create IP input and configuration section."""
        group = QGroupBox(">>> IP THREAT INTELLIGENCE SCANNER")
        group.setStyleSheet("QGroupBox { font-weight: bold; }")
        layout = QVBoxLayout(group)

        # IP input row
        ip_layout = QHBoxLayout()

        ip_layout.addWidget(QLabel("TARGET IP:"))
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("8.8.8.8, 192.168.1.1, malicious.ip.com...")
        self.ip_input.returnPressed.connect(self.check_ip_reputation)
        ip_layout.addWidget(self.ip_input)

        self.check_button = QPushButton("SCAN")
        self.check_button.clicked.connect(self.check_ip_reputation)
        ip_layout.addWidget(self.check_button)

        layout.addLayout(ip_layout)

        # Options row
        options_layout = QHBoxLayout()

        # Monitoring checkbox
        self.monitor_check = QCheckBox("CONTINUOUS MONITORING")
        self.monitor_check.toggled.connect(self.toggle_monitoring)
        options_layout.addWidget(self.monitor_check)

        options_layout.addStretch()

        # Export button
        self.export_button = QPushButton("EXPORT")
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self.export_results)
        options_layout.addWidget(self.export_button)

        layout.addLayout(options_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        return group

    def create_results_section(self):
        """Create results display section."""
        group = QGroupBox(">>> THREAT INTELLIGENCE RESULTS")
        group.setStyleSheet("QGroupBox { font-weight: bold; }")
        layout = QVBoxLayout(group)

        # Create tabbed results view
        results_splitter = QSplitter(Qt.Horizontal)

        # Left side - Summary and scores
        summary_section = self.create_summary_section()
        results_splitter.addWidget(summary_section)

        # Right side - Detailed information
        details_section = self.create_details_section()
        results_splitter.addWidget(details_section)

        results_splitter.setSizes([300, 500])
        layout.addWidget(results_splitter)

        # Status bar
        self.status_label = QLabel("READY - Enter IP address and click SCAN")
        self.status_label.setStyleSheet("font-family: monospace; color: #00ff00;")
        layout.addWidget(self.status_label)

        return group

    def create_summary_section(self):
        """Create threat summary section."""
        group = QGroupBox("THREAT SUMMARY")
        layout = QVBoxLayout(group)

        # Threat score display
        score_frame = QFrame()
        score_frame.setStyleSheet("border: 2px solid #00ff00; padding: 10px;")
        score_layout = QVBoxLayout(score_frame)

        self.threat_score_label = QLabel("THREAT SCORE: --")
        self.threat_score_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #00ff00;")
        self.threat_score_label.setAlignment(Qt.AlignCenter)
        score_layout.addWidget(self.threat_score_label)

        self.threat_level_label = QLabel("LEVEL: UNKNOWN")
        self.threat_level_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        self.threat_level_label.setAlignment(Qt.AlignCenter)
        score_layout.addWidget(self.threat_level_label)

        layout.addWidget(score_frame)

        # Quick stats
        stats_layout = QGridLayout()

        self.malware_label = QLabel("MALWARE: --")
        self.malware_label.setStyleSheet("font-weight: bold;")
        stats_layout.addWidget(self.malware_label, 0, 0)

        self.botnet_label = QLabel("BOTNET: --")
        self.botnet_label.setStyleSheet("font-weight: bold;")
        stats_layout.addWidget(self.botnet_label, 0, 1)

        self.spam_label = QLabel("SPAM: --")
        self.spam_label.setStyleSheet("font-weight: bold;")
        stats_layout.addWidget(self.spam_label, 1, 0)

        self.proxy_label = QLabel("PROXY: --")
        self.proxy_label.setStyleSheet("font-weight: bold;")
        stats_layout.addWidget(self.proxy_label, 1, 1)

        layout.addLayout(stats_layout)

        # Geolocation info
        geo_group = QGroupBox("GEOLOCATION")
        geo_layout = QVBoxLayout(geo_group)

        self.country_label = QLabel("COUNTRY: --")
        geo_layout.addWidget(self.country_label)

        self.city_label = QLabel("CITY: --")
        geo_layout.addWidget(self.city_label)

        self.isp_label = QLabel("ISP: --")
        geo_layout.addWidget(self.isp_label)

        layout.addWidget(geo_group)

        layout.addStretch()

        return group

    def create_details_section(self):
        """Create detailed information section."""
        group = QGroupBox("DETAILED ANALYSIS")
        layout = QVBoxLayout(group)

        # Sources table
        self.sources_table = QTableWidget()
        self.sources_table.setColumnCount(3)
        self.sources_table.setHorizontalHeaderLabels(["SOURCE", "STATUS", "DETAILS"])

        # Configure table
        header = self.sources_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)

        self.sources_table.setAlternatingRowColors(True)
        self.sources_table.setMaximumHeight(200)

        layout.addWidget(self.sources_table)

        # Additional details text area
        details_group = QGroupBox("ADDITIONAL INFORMATION")
        details_layout = QVBoxLayout(details_group)

        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMaximumHeight(200)
        details_layout.addWidget(self.details_text)

        layout.addWidget(details_group)

        return group

    def check_ip_reputation(self):
        """Check IP reputation and threat intelligence."""
        ip = self.ip_input.text().strip()
        if not ip:
            QMessageBox.warning(self, "Warning", "Please enter an IP address.")
            return

        # Validate IP format (basic validation)
        import re
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if not re.match(ip_pattern, ip):
            # Could be hostname, try to resolve
            try:
                import socket
                ip = socket.gethostbyname(ip)
            except:
                QMessageBox.warning(self, "Warning", "Invalid IP address or hostname.")
                return

        # Update UI state
        self.check_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.status_label.setText(f"SCANNING IP: {ip}...")

        # Clear previous results
        self.clear_results()

        # Start IP reputation worker
        self.ip_worker = IPWorker(ip)
        self.ip_worker.result_ready.connect(self.on_check_complete)
        self.ip_worker.error_occurred.connect(self.on_check_error)
        self.ip_worker.finished.connect(self.on_check_finished)
        self.ip_worker.start()

    def on_check_complete(self, result):
        """Handle IP reputation check completion."""
        self.current_result = result
        self.display_results(result)

    def on_check_error(self, error_message):
        """Handle IP reputation check error."""
        self.status_label.setText(f"ERROR: {error_message}")
        QMessageBox.critical(self, "IP Reputation Error", f"Check failed: {error_message}")

    def on_check_finished(self):
        """Handle IP reputation check completion."""
        self.check_button.setEnabled(True)
        self.progress_bar.setVisible(False)
        if self.current_result:
            self.export_button.setEnabled(True)

    def display_results(self, result):
        """Display IP reputation results."""
        # Update threat score and level
        threat_score = result.get('threat_score', 0)
        self.threat_score_label.setText(f"THREAT SCORE: {threat_score}/100")

        # Determine threat level and color
        if threat_score >= 80:
            level = "CRITICAL"
            color = "#ff0000"  # Red
        elif threat_score >= 60:
            level = "HIGH"
            color = "#ff8800"  # Orange
        elif threat_score >= 40:
            level = "MEDIUM"
            color = "#ffff00"  # Yellow
        elif threat_score >= 20:
            level = "LOW"
            color = "#00ff00"  # Green
        else:
            level = "CLEAN"
            color = "#00ff00"  # Green

        self.threat_level_label.setText(f"LEVEL: {level}")
        self.threat_level_label.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {color};")
        self.threat_score_label.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {color};")

        # Update quick stats
        self.malware_label.setText(f"MALWARE: {'YES' if result.get('is_malware') else 'NO'}")
        self.malware_label.setStyleSheet(f"font-weight: bold; color: {'#ff0000' if result.get('is_malware') else '#00ff00'};")

        self.botnet_label.setText(f"BOTNET: {'YES' if result.get('is_botnet') else 'NO'}")
        self.botnet_label.setStyleSheet(f"font-weight: bold; color: {'#ff0000' if result.get('is_botnet') else '#00ff00'};")

        self.spam_label.setText(f"SPAM: {'YES' if result.get('is_spam') else 'NO'}")
        self.spam_label.setStyleSheet(f"font-weight: bold; color: {'#ff0000' if result.get('is_spam') else '#00ff00'};")

        self.proxy_label.setText(f"PROXY: {'YES' if result.get('is_proxy') else 'NO'}")
        self.proxy_label.setStyleSheet(f"font-weight: bold; color: {'#ff8800' if result.get('is_proxy') else '#00ff00'};")

        # Update geolocation
        geo = result.get('geolocation', {})
        self.country_label.setText(f"COUNTRY: {geo.get('country', 'Unknown')}")
        self.city_label.setText(f"CITY: {geo.get('city', 'Unknown')}")
        self.isp_label.setText(f"ISP: {geo.get('isp', 'Unknown')}")

        # Update sources table
        sources = result.get('sources', {})
        self.sources_table.setRowCount(len(sources))

        for row, (source_name, source_data) in enumerate(sources.items()):
            # Source name
            self.sources_table.setItem(row, 0, QTableWidgetItem(source_name.upper()))

            # Status
            status = "THREAT" if source_data.get('is_threat') else "CLEAN"
            status_item = QTableWidgetItem(status)
            status_item.setForeground(QColor(255, 0, 0) if source_data.get('is_threat') else QColor(0, 255, 0))
            self.sources_table.setItem(row, 1, status_item)

            # Details
            details = source_data.get('details', 'No additional information')
            self.sources_table.setItem(row, 2, QTableWidgetItem(details))

        # Update additional details
        details_text = f"""IP ADDRESS: {result.get('ip_address', 'N/A')}
SCAN TIMESTAMP: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

REPUTATION SUMMARY:
- Overall Threat Score: {threat_score}/100
- Risk Level: {level}
- Total Sources Checked: {len(sources)}
- Malicious Sources: {sum(1 for s in sources.values() if s.get('is_threat'))}

GEOLOCATION DETAILS:
- Country: {geo.get('country', 'Unknown')}
- Region: {geo.get('region', 'Unknown')}
- City: {geo.get('city', 'Unknown')}
- ISP: {geo.get('isp', 'Unknown')}
- Organization: {geo.get('org', 'Unknown')}
- Timezone: {geo.get('timezone', 'Unknown')}

THREAT INDICATORS:
- Malware Activity: {'Detected' if result.get('is_malware') else 'Not Detected'}
- Botnet Membership: {'Detected' if result.get('is_botnet') else 'Not Detected'}
- Spam Source: {'Detected' if result.get('is_spam') else 'Not Detected'}
- Proxy/VPN: {'Detected' if result.get('is_proxy') else 'Not Detected'}
- Tor Exit Node: {'Detected' if result.get('is_tor') else 'Not Detected'}

ADDITIONAL INFORMATION:
{result.get('additional_info', 'No additional information available')}
"""

        self.details_text.setPlainText(details_text)

        # Update status
        self.status_label.setText(f"SCAN COMPLETE - Threat Level: {level}")

    def clear_results(self):
        """Clear previous results."""
        self.threat_score_label.setText("THREAT SCORE: --")
        self.threat_level_label.setText("LEVEL: UNKNOWN")
        self.threat_score_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #00ff00;")
        self.threat_level_label.setStyleSheet("font-size: 14px; font-weight: bold;")

        self.malware_label.setText("MALWARE: --")
        self.botnet_label.setText("BOTNET: --")
        self.spam_label.setText("SPAM: --")
        self.proxy_label.setText("PROXY: --")

        self.country_label.setText("COUNTRY: --")
        self.city_label.setText("CITY: --")
        self.isp_label.setText("ISP: --")

        self.sources_table.setRowCount(0)
        self.details_text.clear()

    def toggle_monitoring(self, enabled):
        """Toggle continuous monitoring."""
        self.monitoring_enabled = enabled
        if enabled:
            self.monitor_timer.start(60000)  # Check every minute
            self.status_label.setText("CONTINUOUS MONITORING ENABLED")
        else:
            self.monitor_timer.stop()

    def auto_check(self):
        """Perform automatic IP reputation check."""
        if self.monitoring_enabled and self.ip_input.text().strip():
            self.check_ip_reputation()

    def export_results(self):
        """Export IP reputation results."""
        if not self.current_result:
            return

        filename, _ = QFileDialog.getSaveFileName(
            self, "Export IP Reputation Results",
            f"ip_reputation_{self.current_result.get('ip_address', 'unknown')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON Files (*.json);;Text Files (*.txt)"
        )

        if filename:
            try:
                if filename.endswith('.json'):
                    with open(filename, 'w') as f:
                        json.dump(self.current_result, f, indent=2, default=str)
                else:
                    # Text format
                    with open(filename, 'w') as f:
                        f.write("NetSecureX IP Reputation Analysis Report\n")
                        f.write("=" * 50 + "\n\n")
                        f.write(self.details_text.toPlainText())

                QMessageBox.information(self, "Export Complete",
                                      f"IP reputation results exported to {filename}")

            except Exception as e:
                QMessageBox.critical(self, "Export Error",
                                   f"Failed to export results: {e}")
