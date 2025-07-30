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
from PySide6.QtGui import QFont, QColor, QPainter, QPen, QTextCursor


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
                border-radius: 8px;
                background-color: #ffffff;
                padding: 10px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
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
        self.update_counter = 0  # Counter for less frequent network updates
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
        group = QGroupBox("Real-time Security Monitoring")
        group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                color: #2c3e50;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        layout = QHBoxLayout(group)

        # Status indicator
        self.status_label = QLabel("Status: Offline")
        self.status_label.setStyleSheet("""
            font-weight: bold;
            color: #e74c3c;
            background-color: #fdf2f2;
            padding: 5px 10px;
            border-radius: 3px;
            border: 1px solid #e74c3c;
        """)
        layout.addWidget(self.status_label)
        
        layout.addStretch()
        
        # Controls
        self.start_button = QPushButton("Start Monitoring")
        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2ecc71;
            }
            QPushButton:pressed {
                background-color: #229954;
            }
        """)
        self.start_button.clicked.connect(self.toggle_monitoring)
        layout.addWidget(self.start_button)

        self.clear_button = QPushButton("Clear Logs")
        self.clear_button.setStyleSheet("""
            QPushButton {
                background-color: #95a5a6;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #7f8c8d;
            }
        """)
        self.clear_button.clicked.connect(self.clear_logs)
        layout.addWidget(self.clear_button)
        
        return group
        
    def create_indicators_section(self):
        """Create system monitoring indicators section."""
        group = QGroupBox("System Monitoring")
        group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 12px;
                color: #2c3e50;
                border: 1px solid #bdc3c7;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        layout = QHBoxLayout(group)

        # Create system monitoring indicators with professional colors
        self.total_scans_indicator = ThreatIndicatorWidget("Network Connections", 0, 100, "#3498db")
        layout.addWidget(self.total_scans_indicator)

        self.threats_indicator = ThreatIndicatorWidget("CPU Usage", 0, 100, "#f39c12")
        layout.addWidget(self.threats_indicator)

        self.critical_indicator = ThreatIndicatorWidget("Memory Usage", 0, 100, "#e74c3c")
        layout.addWidget(self.critical_indicator)

        self.blocked_indicator = ThreatIndicatorWidget("Disk Usage", 0, 100, "#9b59b6")
        layout.addWidget(self.blocked_indicator)

        self.suspicious_indicator = ThreatIndicatorWidget("System Load", 0, 100, "#27ae60")
        layout.addWidget(self.suspicious_indicator)
        
        layout.addStretch()
        
        return group
        
    def create_threat_feed(self):
        """Create network statistics monitor section."""
        group = QGroupBox("Network Statistics")
        group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 12px;
                color: #2c3e50;
                border: 1px solid #bdc3c7;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        layout = QVBoxLayout(group)

        # Network statistics table
        self.threat_table = QTableWidget()
        self.threat_table.setColumnCount(4)
        self.threat_table.setHorizontalHeaderLabels(["Metric", "Value", "", ""])

        # Configure table with modern styling
        header = self.threat_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)

        self.threat_table.setAlternatingRowColors(True)
        self.threat_table.setMaximumHeight(300)
        self.threat_table.setStyleSheet("""
            QTableWidget {
                background-color: #ffffff;
                alternate-background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 4px;
            }
            QHeaderView::section {
                background-color: #e9ecef;
                color: #495057;
                padding: 8px;
                border: none;
                font-weight: bold;
            }
        """)

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
            if status == "ACTIVE":
                status_label.setStyleSheet("""
                    color: #27ae60;
                    font-weight: bold;
                    background-color: #d5f4e6;
                    padding: 2px 6px;
                    border-radius: 3px;
                """)
            else:
                status_label.setStyleSheet("""
                    color: #e74c3c;
                    font-weight: bold;
                    background-color: #fdf2f2;
                    padding: 2px 6px;
                    border-radius: 3px;
                """)
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
        self.alerts_text.setStyleSheet("""
            QTextEdit {
                background-color: #f8f9fa;
                color: #2c3e50;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                padding: 8px;
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 12px;
            }
        """)
        
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
        self.monitor_timer.start(15000)  # Update every 15 seconds (reduced frequency)
        
        self.start_button.setText("Stop Monitoring")
        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
        """)
        self.status_label.setText("Status: Active")
        self.status_label.setStyleSheet("""
            font-weight: bold;
            color: #27ae60;
            background-color: #d5f4e6;
            padding: 5px 10px;
            border-radius: 3px;
            border: 1px solid #27ae60;
        """)
        
        self.add_alert("SYSTEM", "Real-time monitoring started")
        
    def stop_monitoring(self):
        """Stop real-time monitoring."""
        self.monitoring_active = False
        self.monitor_timer.stop()
        
        self.start_button.setText("Start Monitoring")
        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2ecc71;
            }
        """)
        self.status_label.setText("Status: Offline")
        self.status_label.setStyleSheet("""
            font-weight: bold;
            color: #e74c3c;
            background-color: #fdf2f2;
            padding: 5px 10px;
            border-radius: 3px;
            border: 1px solid #e74c3c;
        """)
        
        self.add_alert("SYSTEM", "Real-time monitoring stopped")
        
    def update_monitoring_data(self):
        """Update monitoring data with real system information."""
        if not self.monitoring_active:
            return

        try:
            # Get real system metrics
            import psutil

            # Get system metrics
            cpu_percent = psutil.cpu_percent(interval=None)
            memory_percent = psutil.virtual_memory().percent
            disk_percent = psutil.disk_usage('/').percent

            # Get network connections
            connections = psutil.net_connections(kind='inet')
            active_connections = len([c for c in connections if c.status == 'ESTABLISHED'])

            # Get system load average (Unix-like systems)
            try:
                load_avg = psutil.getloadavg()[0] * 100 / psutil.cpu_count()
            except:
                load_avg = cpu_percent

            # Update indicators with real data
            self.total_scans_indicator.update_value(min(active_connections, 100))
            self.threats_indicator.update_value(int(cpu_percent))
            self.critical_indicator.update_value(int(memory_percent))
            self.blocked_indicator.update_value(int(disk_percent))
            self.suspicious_indicator.update_value(int(load_avg))

            # Only show alerts for actual concerning metrics
            if cpu_percent > 80:
                self.add_alert("WARNING", f"High CPU usage: {cpu_percent:.1f}%")

            if memory_percent > 85:
                self.add_alert("WARNING", f"High memory usage: {memory_percent:.1f}%")

            if disk_percent > 90:
                self.add_alert("WARNING", f"Low disk space: {disk_percent:.1f}% used")

            # Update network connections table less frequently (every 5th update)
            self.update_counter += 1
            if self.update_counter % 5 == 0:
                try:
                    self.update_network_connections()
                except Exception as e:
                    # If network monitoring fails, show a message and disable it
                    self.threat_table.setRowCount(1)
                    self.threat_table.setItem(0, 0, QTableWidgetItem("Network monitoring"))
                    self.threat_table.setItem(0, 1, QTableWidgetItem("requires elevated"))
                    self.threat_table.setItem(0, 2, QTableWidgetItem("permissions"))
                    self.threat_table.setItem(0, 3, QTableWidgetItem("Run as admin"))

        except ImportError:
            # Fallback if psutil not available
            self.add_alert("INFO", "Install psutil for real-time system monitoring: pip install psutil")
        except Exception as e:
            # More specific error handling
            error_msg = str(e)
            if "Access is denied" in error_msg or "permission" in error_msg.lower():
                self.add_alert("WARNING", "Some system information requires elevated permissions")
            elif len(error_msg) > 100:
                self.add_alert("ERROR", f"Monitoring error: {error_msg[:100]}...")
            else:
                self.add_alert("ERROR", f"Monitoring error: {error_msg}")

    def update_network_connections(self):
        """Update the network connections table with real data."""
        try:
            import psutil

            # Clear existing rows
            self.threat_table.setRowCount(0)

            # Get basic network statistics instead of detailed connections
            net_io = psutil.net_io_counters()

            # Show network statistics instead of connections
            self.threat_table.setRowCount(4)

            # Bytes sent
            self.threat_table.setItem(0, 0, QTableWidgetItem("Bytes Sent"))
            self.threat_table.setItem(0, 1, QTableWidgetItem(f"{net_io.bytes_sent:,}"))
            self.threat_table.setItem(0, 2, QTableWidgetItem(""))
            self.threat_table.setItem(0, 3, QTableWidgetItem(""))

            # Bytes received
            self.threat_table.setItem(1, 0, QTableWidgetItem("Bytes Received"))
            self.threat_table.setItem(1, 1, QTableWidgetItem(f"{net_io.bytes_recv:,}"))
            self.threat_table.setItem(1, 2, QTableWidgetItem(""))
            self.threat_table.setItem(1, 3, QTableWidgetItem(""))

            # Packets sent
            self.threat_table.setItem(2, 0, QTableWidgetItem("Packets Sent"))
            self.threat_table.setItem(2, 1, QTableWidgetItem(f"{net_io.packets_sent:,}"))
            self.threat_table.setItem(2, 2, QTableWidgetItem(""))
            self.threat_table.setItem(2, 3, QTableWidgetItem(""))

            # Packets received
            self.threat_table.setItem(3, 0, QTableWidgetItem("Packets Received"))
            self.threat_table.setItem(3, 1, QTableWidgetItem(f"{net_io.packets_recv:,}"))
            self.threat_table.setItem(3, 2, QTableWidgetItem(""))
            self.threat_table.setItem(3, 3, QTableWidgetItem(""))



        except ImportError:
            # Show message if psutil not available
            self.threat_table.setRowCount(1)
            self.threat_table.setItem(0, 0, QTableWidgetItem("Install psutil for network monitoring"))
            self.threat_table.setItem(0, 1, QTableWidgetItem("pip install psutil"))
            self.threat_table.setItem(0, 2, QTableWidgetItem(""))
            self.threat_table.setItem(0, 3, QTableWidgetItem(""))
        except psutil.AccessDenied:
            # Show access denied message
            self.threat_table.setRowCount(1)
            self.threat_table.setItem(0, 0, QTableWidgetItem("Access denied"))
            self.threat_table.setItem(0, 1, QTableWidgetItem("Run as administrator"))
            self.threat_table.setItem(0, 2, QTableWidgetItem("for full access"))
            self.threat_table.setItem(0, 3, QTableWidgetItem(""))
        except Exception as e:
            # Show error
            self.threat_table.setRowCount(1)
            self.threat_table.setItem(0, 0, QTableWidgetItem("Error loading connections"))
            self.threat_table.setItem(0, 1, QTableWidgetItem(str(e)[:50]))
            self.threat_table.setItem(0, 2, QTableWidgetItem(""))
            self.threat_table.setItem(0, 3, QTableWidgetItem(""))

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
        cursor = self.alerts_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.alerts_text.setTextCursor(cursor)
        
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
