"""
Real-time Monitoring Dashboard for NetSecureX
=============================================

Real-time security monitoring dashboard with live threat feeds and statistics.
"""

import json
from datetime import datetime, timedelta
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QGroupBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QProgressBar,
    QTextEdit, QFrame, QScrollArea, QCheckBox
)
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QFont, QColor, QPainter, QPen


class ThreatIndicatorWidget(QFrame):
    """Custom widget for displaying threat indicators."""
    
    def __init__(self, title, value=0, max_value=100, color="#00ff00"):
        super().__init__()
        self.title = title
        self.value = value
        self.max_value = max_value
        self.color = color
        self.setup_ui()
        
    def setup_ui(self):
        """Setup threat indicator UI."""
        self.setFixedSize(150, 100)
        self.setStyleSheet(f"""
            QFrame {{
                border: 2px solid {self.color};
                background-color: #000000;
                padding: 5px;
            }}
        """)
        
        layout = QVBoxLayout(self)
        
        # Title
        title_label = QLabel(self.title)
        title_label.setStyleSheet(f"color: {self.color}; font-weight: bold; font-size: 12px;")
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # Value
        self.value_label = QLabel(str(self.value))
        self.value_label.setStyleSheet(f"color: {self.color}; font-weight: bold; font-size: 24px;")
        self.value_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.value_label)
        
        # Progress bar
        self.progress = QProgressBar()
        self.progress.setMaximum(self.max_value)
        self.progress.setValue(self.value)
        self.progress.setStyleSheet(f"""
            QProgressBar::chunk {{
                background-color: {self.color};
            }}
        """)
        layout.addWidget(self.progress)
        
    def update_value(self, value):
        """Update the indicator value."""
        self.value = value
        self.value_label.setText(str(value))
        self.progress.setValue(value)


class MonitoringDashboardWidget(QWidget):
    """Real-time monitoring dashboard for security events."""
    
    # Signals
    alert_triggered = Signal(str, str)  # severity, message
    
    def __init__(self):
        super().__init__()
        self.monitoring_active = False
        self.threat_data = {
            'total_scans': 0,
            'threats_detected': 0,
            'critical_alerts': 0,
            'blocked_ips': 0,
            'suspicious_activity': 0
        }
        self.setup_ui()
        self.setup_timers()
        
    def setup_ui(self):
        """Setup monitoring dashboard interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        # Header with controls
        header = self.create_header()
        layout.addWidget(header)
        
        # Main dashboard grid
        dashboard_grid = QGridLayout()
        
        # Threat indicators (top row)
        indicators_section = self.create_indicators_section()
        dashboard_grid.addWidget(indicators_section, 0, 0, 1, 2)
        
        # Live threat feed (left column)
        threat_feed = self.create_threat_feed()
        dashboard_grid.addWidget(threat_feed, 1, 0)
        
        # System status (right column)
        system_status = self.create_system_status()
        dashboard_grid.addWidget(system_status, 1, 1)
        
        # Recent alerts (bottom row)
        alerts_section = self.create_alerts_section()
        dashboard_grid.addWidget(alerts_section, 2, 0, 1, 2)
        
        layout.addLayout(dashboard_grid)
        
    def create_header(self):
        """Create dashboard header with controls."""
        group = QGroupBox(">>> REAL-TIME SECURITY MONITORING")
        group.setStyleSheet("QGroupBox { font-weight: bold; }")
        layout = QHBoxLayout(group)
        
        # Status indicator
        self.status_label = QLabel("STATUS: OFFLINE")
        self.status_label.setStyleSheet("font-weight: bold; color: #ff0000;")
        layout.addWidget(self.status_label)
        
        layout.addStretch()
        
        # Controls
        self.start_button = QPushButton("START MONITORING")
        self.start_button.clicked.connect(self.toggle_monitoring)
        layout.addWidget(self.start_button)
        
        self.clear_button = QPushButton("CLEAR LOGS")
        self.clear_button.clicked.connect(self.clear_logs)
        layout.addWidget(self.clear_button)
        
        return group
        
    def create_indicators_section(self):
        """Create threat indicators section."""
        group = QGroupBox("THREAT INDICATORS")
        layout = QHBoxLayout(group)
        
        # Create threat indicators
        self.total_scans_indicator = ThreatIndicatorWidget("TOTAL SCANS", 0, 1000, "#00ff00")
        layout.addWidget(self.total_scans_indicator)
        
        self.threats_indicator = ThreatIndicatorWidget("THREATS", 0, 100, "#ff8800")
        layout.addWidget(self.threats_indicator)
        
        self.critical_indicator = ThreatIndicatorWidget("CRITICAL", 0, 50, "#ff0000")
        layout.addWidget(self.critical_indicator)
        
        self.blocked_indicator = ThreatIndicatorWidget("BLOCKED IPs", 0, 200, "#ffff00")
        layout.addWidget(self.blocked_indicator)
        
        self.suspicious_indicator = ThreatIndicatorWidget("SUSPICIOUS", 0, 100, "#ff8800")
        layout.addWidget(self.suspicious_indicator)
        
        layout.addStretch()
        
        return group
        
    def create_threat_feed(self):
        """Create live threat feed section."""
        group = QGroupBox("LIVE THREAT FEED")
        layout = QVBoxLayout(group)
        
        # Threat feed table
        self.threat_table = QTableWidget()
        self.threat_table.setColumnCount(4)
        self.threat_table.setHorizontalHeaderLabels(["TIME", "TYPE", "SOURCE", "DETAILS"])
        
        # Configure table
        header = self.threat_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        
        self.threat_table.setAlternatingRowColors(True)
        self.threat_table.setMaximumHeight(300)
        
        layout.addWidget(self.threat_table)
        
        return group
        
    def create_system_status(self):
        """Create system status section."""
        group = QGroupBox("SYSTEM STATUS")
        layout = QVBoxLayout(group)
        
        # Status items
        status_items = [
            ("NETWORK SCANNER", "ACTIVE"),
            ("CVE MONITOR", "ACTIVE"),
            ("IP REPUTATION", "ACTIVE"),
            ("SSL MONITOR", "ACTIVE"),
            ("THREAT FEEDS", "CONNECTED"),
            ("DATABASE", "ONLINE")
        ]
        
        self.status_labels = {}
        for service, status in status_items:
            item_layout = QHBoxLayout()
            
            service_label = QLabel(f"{service}:")
            service_label.setStyleSheet("font-weight: bold;")
            item_layout.addWidget(service_label)
            
            status_label = QLabel(status)
            status_label.setStyleSheet("color: #00ff00; font-weight: bold;")
            self.status_labels[service] = status_label
            item_layout.addWidget(status_label)
            
            item_layout.addStretch()
            
            layout.addLayout(item_layout)
            
        layout.addStretch()
        
        return group
        
    def create_alerts_section(self):
        """Create recent alerts section."""
        group = QGroupBox("RECENT SECURITY ALERTS")
        layout = QVBoxLayout(group)
        
        # Alerts text area
        self.alerts_text = QTextEdit()
        self.alerts_text.setReadOnly(True)
        self.alerts_text.setMaximumHeight(150)
        self.alerts_text.setStyleSheet("background-color: #000000; color: #00ff00; font-family: monospace;")
        
        # Add initial message
        self.alerts_text.append("[SYSTEM] NetSecureX Monitoring Dashboard Initialized")
        self.alerts_text.append("[INFO] Waiting for monitoring to start...")
        
        layout.addWidget(self.alerts_text)
        
        return group
        
    def setup_timers(self):
        """Setup monitoring timers."""
        # Main monitoring timer
        self.monitor_timer = QTimer()
        self.monitor_timer.timeout.connect(self.update_monitoring_data)
        
        # UI update timer
        self.ui_timer = QTimer()
        self.ui_timer.timeout.connect(self.update_ui)
        self.ui_timer.start(1000)  # Update UI every second
        
    def toggle_monitoring(self):
        """Toggle monitoring on/off."""
        if self.monitoring_active:
            self.stop_monitoring()
        else:
            self.start_monitoring()
            
    def start_monitoring(self):
        """Start real-time monitoring."""
        self.monitoring_active = True
        self.monitor_timer.start(5000)  # Update every 5 seconds
        
        self.start_button.setText("STOP MONITORING")
        self.status_label.setText("STATUS: ACTIVE")
        self.status_label.setStyleSheet("font-weight: bold; color: #00ff00;")
        
        self.add_alert("SYSTEM", "Real-time monitoring started")
        
    def stop_monitoring(self):
        """Stop real-time monitoring."""
        self.monitoring_active = False
        self.monitor_timer.stop()
        
        self.start_button.setText("START MONITORING")
        self.status_label.setText("STATUS: OFFLINE")
        self.status_label.setStyleSheet("font-weight: bold; color: #ff0000;")
        
        self.add_alert("SYSTEM", "Real-time monitoring stopped")
        
    def update_monitoring_data(self):
        """Update monitoring data (simulated for demo)."""
        import random
        
        # Simulate threat detection
        if random.random() < 0.3:  # 30% chance of new threat
            threat_types = ["MALWARE", "BOTNET", "SUSPICIOUS_IP", "CVE_EXPLOIT", "BRUTE_FORCE"]
            threat_type = random.choice(threat_types)
            
            # Generate fake IP
            fake_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            
            self.add_threat_event(threat_type, fake_ip, f"Detected {threat_type.lower()} activity")
            
        # Update counters
        self.threat_data['total_scans'] += random.randint(1, 10)
        
        if random.random() < 0.2:  # 20% chance of threat
            self.threat_data['threats_detected'] += 1
            
        if random.random() < 0.1:  # 10% chance of critical
            self.threat_data['critical_alerts'] += 1
            
        if random.random() < 0.15:  # 15% chance of blocked IP
            self.threat_data['blocked_ips'] += 1
            
        if random.random() < 0.25:  # 25% chance of suspicious activity
            self.threat_data['suspicious_activity'] += 1
            
    def add_threat_event(self, threat_type, source, details):
        """Add a new threat event to the feed."""
        current_time = datetime.now().strftime("%H:%M:%S")
        
        # Add to threat table
        row = self.threat_table.rowCount()
        self.threat_table.insertRow(row)
        
        self.threat_table.setItem(row, 0, QTableWidgetItem(current_time))
        
        type_item = QTableWidgetItem(threat_type)
        if "CRITICAL" in threat_type or "MALWARE" in threat_type:
            type_item.setForeground(QColor(255, 0, 0))
        elif "SUSPICIOUS" in threat_type:
            type_item.setForeground(QColor(255, 136, 0))
        else:
            type_item.setForeground(QColor(255, 255, 0))
        self.threat_table.setItem(row, 1, type_item)
        
        self.threat_table.setItem(row, 2, QTableWidgetItem(source))
        self.threat_table.setItem(row, 3, QTableWidgetItem(details))
        
        # Scroll to bottom
        self.threat_table.scrollToBottom()
        
        # Limit table size
        if self.threat_table.rowCount() > 100:
            self.threat_table.removeRow(0)
            
        # Add to alerts
        self.add_alert("THREAT", f"{threat_type} detected from {source}")
        
    def add_alert(self, severity, message):
        """Add an alert to the alerts section."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_text = f"[{timestamp}] [{severity}] {message}"
        
        self.alerts_text.append(alert_text)
        
        # Scroll to bottom
        self.alerts_text.moveCursor(self.alerts_text.textCursor().End)
        
        # Emit signal for external handling
        self.alert_triggered.emit(severity, message)
        
    def update_ui(self):
        """Update UI elements."""
        if self.monitoring_active:
            # Update threat indicators
            self.total_scans_indicator.update_value(self.threat_data['total_scans'])
            self.threats_indicator.update_value(self.threat_data['threats_detected'])
            self.critical_indicator.update_value(self.threat_data['critical_alerts'])
            self.blocked_indicator.update_value(self.threat_data['blocked_ips'])
            self.suspicious_indicator.update_value(self.threat_data['suspicious_activity'])
            
    def clear_logs(self):
        """Clear all logs and reset counters."""
        self.threat_table.setRowCount(0)
        self.alerts_text.clear()
        
        # Reset counters
        self.threat_data = {
            'total_scans': 0,
            'threats_detected': 0,
            'critical_alerts': 0,
            'blocked_ips': 0,
            'suspicious_activity': 0
        }
        
        # Reset indicators
        self.total_scans_indicator.update_value(0)
        self.threats_indicator.update_value(0)
        self.critical_indicator.update_value(0)
        self.blocked_indicator.update_value(0)
        self.suspicious_indicator.update_value(0)
        
        self.add_alert("SYSTEM", "Logs cleared and counters reset")
