"""
Host System Scanner Widget for NetSecureX
=========================================

GUI widget for scanning the local host system for open ports and security issues.
"""

import asyncio
import socket
import psutil
import subprocess
from datetime import datetime
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QTableWidget, QTableWidgetItem,
    QGroupBox, QProgressBar, QTextEdit, QHeaderView,
    QMessageBox, QFileDialog, QCheckBox, QSplitter
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont, QColor

from core.scanner import PortScanner


class HostScanWorker(QThread):
    """Worker thread for host system scanning."""
    
    # Signals
    progress_updated = Signal(int)
    port_found = Signal(dict)
    scan_complete = Signal(list)
    error_occurred = Signal(str)
    finished = Signal()
    
    def __init__(self, scan_type="quick"):
        super().__init__()
        self.scan_type = scan_type
        self.scanner = PortScanner()
        
    def run(self):
        """Run host system scan."""
        try:
            if self.scan_type == "quick":
                results = self.quick_scan()
            elif self.scan_type == "full":
                results = self.full_scan()
            else:
                results = self.process_scan()
                
            self.scan_complete.emit(results)
            
        except Exception as e:
            self.error_occurred.emit(str(e))
        finally:
            self.finished.emit()
            
    def quick_scan(self):
        """Quick scan of common ports on localhost."""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 
                       1433, 3306, 3389, 5432, 5900, 8080, 8443]
        results = []
        
        for i, port in enumerate(common_ports):
            self.progress_updated.emit(int((i / len(common_ports)) * 100))
            
            if self.is_port_open("127.0.0.1", port):
                port_info = self.get_port_info("127.0.0.1", port)
                results.append(port_info)
                self.port_found.emit(port_info)
                
        return results
        
    def full_scan(self):
        """Full scan of all ports 1-65535 on localhost."""
        results = []
        
        for port in range(1, 65536):
            if port % 1000 == 0:
                self.progress_updated.emit(int((port / 65535) * 100))
                
            if self.is_port_open("127.0.0.1", port):
                port_info = self.get_port_info("127.0.0.1", port)
                results.append(port_info)
                self.port_found.emit(port_info)
                
        return results
        
    def process_scan(self):
        """Scan based on running processes."""
        results = []
        
        try:
            # Get all network connections
            connections = psutil.net_connections(kind='inet')
            
            for i, conn in enumerate(connections):
                if i % 10 == 0:
                    self.progress_updated.emit(int((i / len(connections)) * 100))
                    
                if conn.status == 'LISTEN' and conn.laddr:
                    port_info = {
                        'host': conn.laddr.ip,
                        'port': conn.laddr.port,
                        'status': 'open',
                        'service': self.get_service_name(conn.laddr.port),
                        'process': self.get_process_info(conn.pid) if conn.pid else 'Unknown',
                        'protocol': 'tcp',
                        'risk_level': self.assess_risk(conn.laddr.port)
                    }
                    results.append(port_info)
                    self.port_found.emit(port_info)
                    
        except Exception as e:
            self.error_occurred.emit(f"Process scan failed: {e}")
            
        return results
        
    def is_port_open(self, host, port):
        """Check if a port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
            
    def get_port_info(self, host, port):
        """Get detailed information about a port."""
        return {
            'host': host,
            'port': port,
            'status': 'open',
            'service': self.get_service_name(port),
            'process': self.get_process_by_port(port),
            'protocol': 'tcp',
            'risk_level': self.assess_risk(port)
        }
        
    def get_service_name(self, port):
        """Get service name for a port."""
        try:
            return socket.getservbyport(port)
        except:
            # Common services
            services = {
                21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
                53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
                443: 'https', 993: 'imaps', 995: 'pop3s',
                1433: 'mssql', 3306: 'mysql', 3389: 'rdp',
                5432: 'postgresql', 5900: 'vnc', 8080: 'http-alt',
                8443: 'https-alt'
            }
            return services.get(port, 'unknown')
            
    def get_process_by_port(self, port):
        """Get process using a specific port."""
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr and conn.laddr.port == port and conn.status == 'LISTEN':
                    if conn.pid:
                        process = psutil.Process(conn.pid)
                        return f"{process.name()} (PID: {conn.pid})"
            return "Unknown"
        except:
            return "Unknown"
            
    def get_process_info(self, pid):
        """Get process information by PID."""
        try:
            if pid:
                process = psutil.Process(pid)
                return f"{process.name()} (PID: {pid})"
            return "Unknown"
        except:
            return "Unknown"
            
    def assess_risk(self, port):
        """Assess security risk level for a port."""
        # High risk ports
        high_risk = [21, 23, 135, 139, 445, 1433, 3389, 5900]
        # Medium risk ports  
        medium_risk = [22, 25, 53, 110, 143, 993, 995, 3306, 5432]
        # Low risk ports
        low_risk = [80, 443, 8080, 8443]
        
        if port in high_risk:
            return "HIGH"
        elif port in medium_risk:
            return "MEDIUM"
        elif port in low_risk:
            return "LOW"
        else:
            return "UNKNOWN"


class HostScannerWidget(QWidget):
    """Host system scanner widget for security assessment."""
    
    def __init__(self):
        super().__init__()
        self.scan_worker = None
        self.scan_results = []
        self.setup_ui()
        
        # Auto-refresh timer
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.auto_scan)
        
    def setup_ui(self):
        """Setup host scanner interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        # Create splitter for controls and results
        splitter = QSplitter(Qt.Vertical)
        layout.addWidget(splitter)
        
        # Control section
        control_section = self.create_control_section()
        splitter.addWidget(control_section)
        
        # Results section
        results_section = self.create_results_section()
        splitter.addWidget(results_section)
        
        # Set splitter proportions
        splitter.setSizes([150, 650])
        
    def create_control_section(self):
        """Create scan control section."""
        group = QGroupBox(">>> HOST SYSTEM SECURITY SCANNER")
        group.setStyleSheet("QGroupBox { font-weight: bold; }")
        layout = QVBoxLayout(group)
        
        # Scan options
        options_layout = QHBoxLayout()
        
        self.quick_scan_btn = QPushButton("QUICK SCAN")
        self.quick_scan_btn.clicked.connect(lambda: self.start_scan("quick"))
        options_layout.addWidget(self.quick_scan_btn)
        
        self.full_scan_btn = QPushButton("FULL SCAN")
        self.full_scan_btn.clicked.connect(lambda: self.start_scan("full"))
        options_layout.addWidget(self.full_scan_btn)
        
        self.process_scan_btn = QPushButton("PROCESS SCAN")
        self.process_scan_btn.clicked.connect(lambda: self.start_scan("process"))
        options_layout.addWidget(self.process_scan_btn)
        
        options_layout.addStretch()
        
        # Auto-refresh
        self.auto_refresh_check = QCheckBox("AUTO-REFRESH")
        self.auto_refresh_check.toggled.connect(self.toggle_auto_refresh)
        options_layout.addWidget(self.auto_refresh_check)
        
        # Export button
        self.export_btn = QPushButton("EXPORT")
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self.export_results)
        options_layout.addWidget(self.export_btn)
        
        layout.addLayout(options_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Status
        self.status_label = QLabel("READY - Select scan type to begin")
        self.status_label.setStyleSheet("font-family: monospace; color: #00ff00;")
        layout.addWidget(self.status_label)
        
        return group
        
    def create_results_section(self):
        """Create results display section."""
        group = QGroupBox(">>> OPEN PORTS AND SECURITY ISSUES")
        group.setStyleSheet("QGroupBox { font-weight: bold; }")
        layout = QVBoxLayout(group)
        
        # Statistics
        stats_layout = QHBoxLayout()
        
        self.total_ports_label = QLabel("TOTAL PORTS: 0")
        self.total_ports_label.setStyleSheet("font-weight: bold; color: #00ff00;")
        stats_layout.addWidget(self.total_ports_label)
        
        self.high_risk_label = QLabel("HIGH RISK: 0")
        self.high_risk_label.setStyleSheet("font-weight: bold; color: #ff0000;")
        stats_layout.addWidget(self.high_risk_label)
        
        self.medium_risk_label = QLabel("MEDIUM RISK: 0")
        self.medium_risk_label.setStyleSheet("font-weight: bold; color: #ff8800;")
        stats_layout.addWidget(self.medium_risk_label)
        
        self.low_risk_label = QLabel("LOW RISK: 0")
        self.low_risk_label.setStyleSheet("font-weight: bold; color: #ffff00;")
        stats_layout.addWidget(self.low_risk_label)
        
        stats_layout.addStretch()
        
        layout.addLayout(stats_layout)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels([
            "PORT", "SERVICE", "PROCESS", "RISK", "PROTOCOL", "STATUS"
        ])
        
        # Configure table
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.setSortingEnabled(True)
        
        layout.addWidget(self.results_table)

        return group

    def start_scan(self, scan_type):
        """Start host system scan."""
        # Update UI state
        self.quick_scan_btn.setEnabled(False)
        self.full_scan_btn.setEnabled(False)
        self.process_scan_btn.setEnabled(False)
        self.export_btn.setEnabled(False)

        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setText(f"SCANNING - {scan_type.upper()} scan in progress...")

        # Clear previous results
        self.results_table.setRowCount(0)
        self.scan_results = []
        self.update_statistics()

        # Start scan worker
        self.scan_worker = HostScanWorker(scan_type)
        self.scan_worker.progress_updated.connect(self.progress_bar.setValue)
        self.scan_worker.port_found.connect(self.add_port_result)
        self.scan_worker.scan_complete.connect(self.on_scan_complete)
        self.scan_worker.error_occurred.connect(self.on_scan_error)
        self.scan_worker.finished.connect(self.on_scan_finished)
        self.scan_worker.start()

    def add_port_result(self, port_info):
        """Add a port result to the table."""
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)

        # Port
        port_item = QTableWidgetItem(str(port_info['port']))
        port_item.setFont(QFont("Courier New", 10, QFont.Bold))
        self.results_table.setItem(row, 0, port_item)

        # Service
        self.results_table.setItem(row, 1, QTableWidgetItem(port_info['service']))

        # Process
        self.results_table.setItem(row, 2, QTableWidgetItem(port_info['process']))

        # Risk level with color coding
        risk_item = QTableWidgetItem(port_info['risk_level'])
        risk_item.setTextAlignment(Qt.AlignCenter)
        risk_item.setFont(QFont("Courier New", 10, QFont.Bold))

        if port_info['risk_level'] == "HIGH":
            risk_item.setForeground(QColor(255, 0, 0))
        elif port_info['risk_level'] == "MEDIUM":
            risk_item.setForeground(QColor(255, 136, 0))
        elif port_info['risk_level'] == "LOW":
            risk_item.setForeground(QColor(255, 255, 0))
        else:
            risk_item.setForeground(QColor(128, 128, 128))

        self.results_table.setItem(row, 3, risk_item)

        # Protocol
        self.results_table.setItem(row, 4, QTableWidgetItem(port_info['protocol']))

        # Status
        status_item = QTableWidgetItem(port_info['status'].upper())
        status_item.setForeground(QColor(0, 255, 0))
        self.results_table.setItem(row, 5, status_item)

        # Scroll to bottom
        self.results_table.scrollToBottom()

    def on_scan_complete(self, results):
        """Handle scan completion."""
        self.scan_results = results
        self.update_statistics()

    def on_scan_error(self, error_message):
        """Handle scan error."""
        self.status_label.setText(f"ERROR: {error_message}")
        QMessageBox.critical(self, "Scan Error", f"Scan failed: {error_message}")

    def on_scan_finished(self):
        """Handle scan completion."""
        self.quick_scan_btn.setEnabled(True)
        self.full_scan_btn.setEnabled(True)
        self.process_scan_btn.setEnabled(True)
        self.progress_bar.setVisible(False)

        if self.scan_results:
            self.export_btn.setEnabled(True)
            self.status_label.setText(f"SCAN COMPLETE - Found {len(self.scan_results)} open ports")
        else:
            self.status_label.setText("SCAN COMPLETE - No open ports found")

    def update_statistics(self):
        """Update port statistics."""
        total = len(self.scan_results)
        high_risk = sum(1 for r in self.scan_results if r.get('risk_level') == 'HIGH')
        medium_risk = sum(1 for r in self.scan_results if r.get('risk_level') == 'MEDIUM')
        low_risk = sum(1 for r in self.scan_results if r.get('risk_level') == 'LOW')

        self.total_ports_label.setText(f"TOTAL PORTS: {total}")
        self.high_risk_label.setText(f"HIGH RISK: {high_risk}")
        self.medium_risk_label.setText(f"MEDIUM RISK: {medium_risk}")
        self.low_risk_label.setText(f"LOW RISK: {low_risk}")

    def toggle_auto_refresh(self, enabled):
        """Toggle auto-refresh functionality."""
        if enabled:
            self.refresh_timer.start(60000)  # Refresh every minute
            self.status_label.setText("AUTO-REFRESH ENABLED - Monitoring host system...")
        else:
            self.refresh_timer.stop()

    def auto_scan(self):
        """Perform automatic scan."""
        if not self.scan_worker or not self.scan_worker.isRunning():
            self.start_scan("process")  # Use process scan for auto-refresh

    def export_results(self):
        """Export scan results."""
        if not self.scan_results:
            return

        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Host Scan Results",
            f"host_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON Files (*.json);;CSV Files (*.csv);;Text Files (*.txt)"
        )

        if filename:
            try:
                if filename.endswith('.json'):
                    import json
                    with open(filename, 'w') as f:
                        json.dump(self.scan_results, f, indent=2)
                elif filename.endswith('.csv'):
                    import csv
                    with open(filename, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['Port', 'Service', 'Process', 'Risk Level', 'Protocol', 'Status'])
                        for result in self.scan_results:
                            writer.writerow([
                                result['port'], result['service'], result['process'],
                                result['risk_level'], result['protocol'], result['status']
                            ])
                else:
                    # Text format
                    with open(filename, 'w') as f:
                        f.write("NetSecureX Host System Scan Results\n")
                        f.write("=" * 50 + "\n\n")
                        f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"Total Open Ports: {len(self.scan_results)}\n\n")

                        for result in self.scan_results:
                            f.write(f"Port: {result['port']}\n")
                            f.write(f"Service: {result['service']}\n")
                            f.write(f"Process: {result['process']}\n")
                            f.write(f"Risk Level: {result['risk_level']}\n")
                            f.write(f"Protocol: {result['protocol']}\n")
                            f.write(f"Status: {result['status']}\n")
                            f.write("-" * 30 + "\n")

                QMessageBox.information(self, "Export Complete",
                                      f"Host scan results exported to {filename}")

            except Exception as e:
                QMessageBox.critical(self, "Export Error",
                                   f"Failed to export results: {e}")
