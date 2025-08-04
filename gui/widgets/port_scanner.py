"""
Port Scanner Widget for NetSecureX
==================================

GUI widget for port scanning functionality with target input,
scan configuration, and results display.
"""

import asyncio
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QLineEdit, QTextEdit, QTableWidget,
    QTableWidgetItem, QGroupBox, QSpinBox, QCheckBox,
    QProgressBar, QComboBox, QSplitter, QHeaderView,
    QMessageBox, QFileDialog
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont

from core.scanner import PortScanner


class ScanWorker(QThread):
    """Worker thread for port scanning to avoid blocking UI."""
    
    # Signals
    progress_updated = Signal(int)
    result_ready = Signal(object)
    error_occurred = Signal(str)
    finished = Signal()
    
    def __init__(self, target, ports, options):
        super().__init__()
        self.target = target
        self.ports = ports
        self.options = options
        self.scanner = None
        
    def run(self):
        """Run the port scan in background thread."""
        try:
            # Create scanner with options
            self.scanner = PortScanner(
                timeout=self.options.get('timeout', 3.0),
                max_concurrent=self.options.get('max_concurrent', 100),
                delay=self.options.get('delay', 0.01),
                enable_banner_grab=self.options.get('banner_grab', False)
            )
            
            # Run scan
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            result = loop.run_until_complete(
                self.scanner.scan_target(
                    target=self.target,
                    ports=self.ports,
                    use_top_ports=self.options.get('use_top_ports', True),
                    top_ports_count=self.options.get('top_ports_count', 1000)
                )
            )
            
            loop.close()
            self.result_ready.emit(result)
            
        except Exception as e:
            self.error_occurred.emit(str(e))
        finally:
            self.finished.emit()


class PortScannerWidget(QWidget):
    """Port scanner widget with GUI controls and results display."""
    
    def __init__(self):
        super().__init__()
        self.scan_worker = None
        self.current_results = None
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the port scanner user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
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
        splitter.setSizes([300, 500])
        
    def create_input_section(self):
        """Create scan input and configuration section."""
        group = QGroupBox("Port Scan Configuration")
        layout = QVBoxLayout(group)
        
        # Target input
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target:"))
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter IP address, hostname, or IP range (e.g., 192.168.1.1, google.com, 192.168.1.0/24)")
        target_layout.addWidget(self.target_input)
        
        layout.addLayout(target_layout)
        
        # Scan options
        options_layout = QGridLayout()
        
        # Port range
        options_layout.addWidget(QLabel("Port Range:"), 0, 0)
        self.port_range_combo = QComboBox()
        self.port_range_combo.addItems([
            "Top 1000 ports",
            "Top 100 ports", 
            "Common ports (1-1024)",
            "All ports (1-65535)",
            "Custom range"
        ])
        options_layout.addWidget(self.port_range_combo, 0, 1)
        
        # Custom port range input
        self.custom_ports_input = QLineEdit()
        self.custom_ports_input.setPlaceholderText("e.g., 80,443,8080-8090")
        self.custom_ports_input.setEnabled(False)
        options_layout.addWidget(self.custom_ports_input, 0, 2)
        
        # Timeout
        options_layout.addWidget(QLabel("Timeout (s):"), 1, 0)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 30)
        self.timeout_spin.setValue(3)
        options_layout.addWidget(self.timeout_spin, 1, 1)
        
        # Max concurrent
        options_layout.addWidget(QLabel("Max Concurrent:"), 1, 2)
        self.concurrent_spin = QSpinBox()
        self.concurrent_spin.setRange(1, 1000)
        self.concurrent_spin.setValue(100)
        options_layout.addWidget(self.concurrent_spin, 1, 3)
        
        # Banner grabbing
        self.banner_check = QCheckBox("Enable banner grabbing")
        options_layout.addWidget(self.banner_check, 2, 0, 1, 2)
        
        layout.addLayout(options_layout)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.setStyleSheet("""
            QPushButton {
                background-color: #0096c8;
                font-weight: bold;
                padding: 10px 20px;
            }
            QPushButton:hover {
                background-color: #00b4e6;
            }
        """)
        self.scan_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.scan_button)
        
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_scan)
        button_layout.addWidget(self.stop_button)
        
        button_layout.addStretch()
        
        self.export_button = QPushButton("Export Results")
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self.export_results)
        button_layout.addWidget(self.export_button)
        
        layout.addLayout(button_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Connect signals
        self.port_range_combo.currentTextChanged.connect(self.on_port_range_changed)
        
        return group
        
    def create_results_section(self):
        """Create results display section."""
        group = QGroupBox("Scan Results")
        layout = QVBoxLayout(group)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(8)
        self.results_table.setHorizontalHeaderLabels([
            "IP", "Port", "Status", "Service", "Version", "Banner", "Scan Type", "Response Time"
        ])
        
        # Configure table
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # IP
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Port
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # Status
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Service
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Version
        header.setSectionResizeMode(5, QHeaderView.Stretch)          # Banner
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)  # Scan Type
        header.setSectionResizeMode(7, QHeaderView.ResizeToContents)  # Response Time
        
        layout.addWidget(self.results_table)
        
        # Summary label
        self.summary_label = QLabel("Ready to scan")
        self.summary_label.setStyleSheet("font-weight: bold; color: #0096c8;")
        layout.addWidget(self.summary_label)
        
        return group
        
    def on_port_range_changed(self, text):
        """Handle port range selection change."""
        self.custom_ports_input.setEnabled(text == "Custom range")
        
    def start_scan(self):
        """Start port scanning."""
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Warning", "Please enter a target to scan.")
            return
            
        # Prepare scan options
        options = {
            'timeout': self.timeout_spin.value(),
            'max_concurrent': self.concurrent_spin.value(),
            'delay': 0.01,
            'banner_grab': self.banner_check.isChecked()
        }

        # Add advanced options if enabled
        use_advanced = self.advanced_check.isChecked()
        if use_advanced:
            # Map GUI selections to enums
            scan_type_map = {
                "TCP Connect": ScanType.TCP_CONNECT,
                "TCP SYN (Stealth)": ScanType.TCP_SYN,
                "TCP FIN": ScanType.TCP_FIN,
                "TCP NULL": ScanType.TCP_NULL,
                "TCP Xmas": ScanType.TCP_XMAS,
                "UDP": ScanType.UDP
            }

            timing_map = {
                "Paranoid (Very Slow)": TimingTemplate.PARANOID,
                "Sneaky (Slow)": TimingTemplate.SNEAKY,
                "Polite (Normal)": TimingTemplate.POLITE,
                "Normal (Default)": TimingTemplate.NORMAL,
                "Aggressive (Fast)": TimingTemplate.AGGRESSIVE,
                "Insane (Very Fast)": TimingTemplate.INSANE
            }

            options.update({
                'scan_type': scan_type_map.get(self.scan_type_combo.currentText(), ScanType.TCP_CONNECT),
                'timing': timing_map.get(self.timing_combo.currentText(), TimingTemplate.NORMAL),
                'service_detection': self.service_detection_check.isChecked(),
                'version_detection': self.version_detection_check.isChecked(),
                'randomize_ports': self.randomize_ports_check.isChecked(),
                'randomize_timing': self.randomize_timing_check.isChecked()
            })
        
        # Determine ports to scan
        ports = None
        port_range = self.port_range_combo.currentText()
        
        if port_range == "Custom range":
            custom_ports = self.custom_ports_input.text().strip()
            if not custom_ports:
                QMessageBox.warning(self, "Warning", "Please enter custom port range.")
                return
            # Parse custom ports (simplified)
            try:
                ports = [int(p.strip()) for p in custom_ports.split(',') if p.strip().isdigit()]
                if not ports:
                    raise ValueError("No valid ports")
            except:
                QMessageBox.warning(self, "Warning", "Invalid port range format.")
                return
        else:
            # Use predefined ranges
            options['use_top_ports'] = True
            if "100" in port_range:
                options['top_ports_count'] = 100
            elif "1000" in port_range:
                options['top_ports_count'] = 1000
            elif "1-1024" in port_range:
                ports = list(range(1, 1025))
            elif "1-65535" in port_range:
                ports = list(range(1, 65536))
                
        # Update UI state
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.export_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        self.results_table.setRowCount(0)
        self.summary_label.setText("Scanning...")
        
        # Start scan worker
        self.scan_worker = ScanWorker(target, ports, options, use_advanced)
        self.scan_worker.result_ready.connect(self.on_scan_complete)
        self.scan_worker.error_occurred.connect(self.on_scan_error)
        self.scan_worker.finished.connect(self.on_scan_finished)
        self.scan_worker.start()
        
    def stop_scan(self):
        """Stop current scan."""
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.terminate()
            self.scan_worker.wait()
        self.on_scan_finished()
        
    def on_scan_complete(self, results):
        """Handle scan completion with results."""
        self.current_results = results
        self.display_results(results)
        
    def on_scan_error(self, error_message):
        """Handle scan error."""
        QMessageBox.critical(self, "Scan Error", f"Scan failed: {error_message}")
        
    def on_scan_finished(self):
        """Handle scan completion (success or failure)."""
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)
        if self.current_results:
            self.export_button.setEnabled(True)
            
    def display_results(self, results):
        """Display scan results in the table."""
        # Clear existing results
        self.results_table.setRowCount(0)
        
        # Add results to table
        open_ports = [r for r in results.results if r.status == 'open']
        
        self.results_table.setRowCount(len(open_ports))
        
        for row, result in enumerate(open_ports):
            self.results_table.setItem(row, 0, QTableWidgetItem(result.ip))
            self.results_table.setItem(row, 1, QTableWidgetItem(str(result.port)))

            # Status with color
            status_item = QTableWidgetItem(result.status.upper())
            if result.status == 'open':
                status_item.setBackground(Qt.darkGreen)
            self.results_table.setItem(row, 2, status_item)

            self.results_table.setItem(row, 3, QTableWidgetItem(result.service or "unknown"))

            # Version information (for advanced results)
            version_info = ""
            if hasattr(result, 'service_version') and result.service_version:
                version_info = result.service_version
            self.results_table.setItem(row, 4, QTableWidgetItem(version_info))

            self.results_table.setItem(row, 5, QTableWidgetItem(result.banner or ""))

            # Scan type (for advanced results)
            scan_type = ""
            if hasattr(result, 'scan_type') and result.scan_type:
                scan_type = result.scan_type
            self.results_table.setItem(row, 6, QTableWidgetItem(scan_type))

            response_time = f"{result.response_time:.3f}s" if result.response_time else ""
            self.results_table.setItem(row, 7, QTableWidgetItem(response_time))
            
        # Update summary
        summary = (f"Scan completed: {results.open_ports} open, "
                  f"{results.closed_ports} closed, {results.filtered_ports} filtered "
                  f"({results.scan_duration:.2f}s)")
        self.summary_label.setText(summary)
        
    def export_results(self):
        """Export scan results to file."""
        if not self.current_results:
            return
            
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Scan Results", 
            f"scan_results_{self.current_results.target}.json",
            "JSON Files (*.json);;CSV Files (*.csv);;Text Files (*.txt)"
        )
        
        if filename:
            try:
                if filename.endswith('.json'):
                    import json
                    with open(filename, 'w') as f:
                        json.dump(self.current_results.to_dict(), f, indent=2, default=str)
                elif filename.endswith('.csv'):
                    import csv
                    with open(filename, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['IP', 'Port', 'Status', 'Service', 'Banner', 'Response Time'])
                        for result in self.current_results.results:
                            if result.status == 'open':
                                writer.writerow([
                                    result.ip, result.port, result.status,
                                    result.service or '', result.banner or '',
                                    result.response_time or ''
                                ])
                else:
                    # Text format
                    with open(filename, 'w') as f:
                        f.write(self.current_results.format_results('table'))
                        
                QMessageBox.information(self, "Export Complete", f"Results exported to {filename}")
                
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export results: {e}")
