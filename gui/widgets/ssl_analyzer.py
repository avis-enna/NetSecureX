"""
SSL Analyzer Widget for NetSecureX
==================================

GUI widget for SSL/TLS certificate analysis with visual certificate details.
"""

import asyncio
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QLineEdit, QTextEdit, QGroupBox,
    QSpinBox, QProgressBar, QSplitter, QScrollArea,
    QMessageBox, QFileDialog, QFrame
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont, QPixmap

from core.ssl_check import SSLAnalyzer


class SSLWorker(QThread):
    """Worker thread for SSL analysis."""
    
    result_ready = Signal(object)
    error_occurred = Signal(str)
    finished = Signal()
    
    def __init__(self, target, port):
        super().__init__()
        self.target = target
        self.port = port
        
    def run(self):
        """Run SSL analysis in background."""
        try:
            analyzer = SSLAnalyzer()
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            result = loop.run_until_complete(
                analyzer.analyze_ssl(self.target, self.port)
            )
            
            loop.close()
            self.result_ready.emit(result)
            
        except Exception as e:
            self.error_occurred.emit(str(e))
        finally:
            self.finished.emit()


class SSLAnalyzerWidget(QWidget):
    """SSL analyzer widget with certificate details display."""
    
    def __init__(self):
        super().__init__()
        self.ssl_worker = None
        self.current_result = None
        self.setup_ui()
        
    def setup_ui(self):
        """Setup SSL analyzer interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Input section
        input_section = self.create_input_section()
        layout.addWidget(input_section)
        
        # Results section
        results_section = self.create_results_section()
        layout.addWidget(results_section)
        
    def create_input_section(self):
        """Create SSL check input section."""
        group = QGroupBox("SSL/TLS Certificate Analysis")
        layout = QVBoxLayout(group)
        
        # Target input
        input_layout = QHBoxLayout()
        
        input_layout.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter hostname or IP address (e.g., google.com)")
        input_layout.addWidget(self.target_input)
        
        input_layout.addWidget(QLabel("Port:"))
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(443)
        input_layout.addWidget(self.port_input)
        
        layout.addLayout(input_layout)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.analyze_button = QPushButton("Analyze Certificate")
        self.analyze_button.setStyleSheet("""
            QPushButton {
                background-color: #0096c8;
                font-weight: bold;
                padding: 10px 20px;
            }
            QPushButton:hover {
                background-color: #00b4e6;
            }
        """)
        self.analyze_button.clicked.connect(self.start_analysis)
        button_layout.addWidget(self.analyze_button)
        
        button_layout.addStretch()
        
        self.export_button = QPushButton("Export Certificate")
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self.export_certificate)
        button_layout.addWidget(self.export_button)
        
        layout.addLayout(button_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        return group
        
    def create_results_section(self):
        """Create certificate results display."""
        group = QGroupBox("Certificate Details")
        layout = QVBoxLayout(group)
        
        # Create scroll area for certificate details
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setMinimumHeight(400)
        
        self.cert_widget = QWidget()
        self.cert_layout = QVBoxLayout(self.cert_widget)
        
        # Initial message
        initial_label = QLabel("No certificate analyzed yet. Enter a target and click 'Analyze Certificate'.")
        initial_label.setAlignment(Qt.AlignCenter)
        initial_label.setStyleSheet("color: #888; font-style: italic; padding: 50px;")
        self.cert_layout.addWidget(initial_label)
        
        scroll.setWidget(self.cert_widget)
        layout.addWidget(scroll)
        
        return group
        
    def start_analysis(self):
        """Start SSL certificate analysis."""
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Warning", "Please enter a target hostname or IP.")
            return
            
        port = self.port_input.value()
        
        # Update UI state
        self.analyze_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
        # Clear previous results
        self.clear_results()
        
        # Start analysis
        self.ssl_worker = SSLWorker(target, port)
        self.ssl_worker.result_ready.connect(self.on_analysis_complete)
        self.ssl_worker.error_occurred.connect(self.on_analysis_error)
        self.ssl_worker.finished.connect(self.on_analysis_finished)
        self.ssl_worker.start()
        
    def on_analysis_complete(self, result):
        """Handle analysis completion."""
        self.current_result = result
        self.display_certificate(result)
        
    def on_analysis_error(self, error_message):
        """Handle analysis error."""
        QMessageBox.critical(self, "Analysis Error", f"SSL analysis failed: {error_message}")
        
    def on_analysis_finished(self):
        """Handle analysis completion."""
        self.analyze_button.setEnabled(True)
        self.progress_bar.setVisible(False)
        if self.current_result:
            self.export_button.setEnabled(True)
            
    def clear_results(self):
        """Clear previous certificate results."""
        # Clear the layout
        while self.cert_layout.count():
            child = self.cert_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
                
    def display_certificate(self, result):
        """Display certificate analysis results."""
        self.clear_results()
        
        # Status header
        status_frame = QFrame()
        status_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {'#2d5016' if result.status == 'valid' else '#5d1616'};
                border-radius: 8px;
                padding: 15px;
                margin-bottom: 10px;
            }}
        """)
        
        status_layout = QHBoxLayout(status_frame)
        
        status_icon = QLabel("✅" if result.status == 'valid' else "❌")
        status_icon.setStyleSheet("font-size: 24px;")
        status_layout.addWidget(status_icon)
        
        status_text = QLabel(f"Certificate Status: {result.status.upper()}")
        status_text.setStyleSheet("font-size: 18px; font-weight: bold; color: white;")
        status_layout.addWidget(status_text)
        
        status_layout.addStretch()
        
        self.cert_layout.addWidget(status_frame)
        
        if result.error:
            error_label = QLabel(f"Error: {result.error}")
            error_label.setStyleSheet("color: #ff6b6b; font-weight: bold;")
            self.cert_layout.addWidget(error_label)
            return
            
        # Certificate details
        if result.certificate_info:
            cert_info = result.certificate_info
            
            # Basic certificate info
            basic_group = self.create_info_group("Certificate Information", [
                ("Common Name", cert_info.get('common_name', 'N/A')),
                ("Subject", cert_info.get('subject', 'N/A')),
                ("Issuer", cert_info.get('issuer', 'N/A')),
                ("Serial Number", cert_info.get('serial_number', 'N/A')),
                ("Version", str(cert_info.get('version', 'N/A'))),
            ])
            self.cert_layout.addWidget(basic_group)
            
            # Validity period
            validity_group = self.create_info_group("Validity Period", [
                ("Valid From", cert_info.get('not_before', 'N/A')),
                ("Valid Until", cert_info.get('not_after', 'N/A')),
                ("Days Until Expiry", str(cert_info.get('days_until_expiry', 'N/A'))),
            ])
            self.cert_layout.addWidget(validity_group)
            
            # Connection details
            if result.connection_info:
                conn_info = result.connection_info
                connection_group = self.create_info_group("Connection Details", [
                    ("TLS Version", conn_info.get('tls_version', 'N/A')),
                    ("Cipher Suite", conn_info.get('cipher_suite', 'N/A')),
                    ("Key Exchange", conn_info.get('key_exchange', 'N/A')),
                ])
                self.cert_layout.addWidget(connection_group)
                
            # Subject Alternative Names
            if cert_info.get('san_list'):
                san_text = QTextEdit()
                san_text.setMaximumHeight(150)
                san_text.setPlainText('\n'.join(cert_info['san_list']))
                san_text.setReadOnly(True)
                
                san_group = QGroupBox("Subject Alternative Names")
                san_layout = QVBoxLayout(san_group)
                san_layout.addWidget(san_text)
                
                self.cert_layout.addWidget(san_group)
                
        self.cert_layout.addStretch()
        
    def create_info_group(self, title, items):
        """Create an information group widget."""
        group = QGroupBox(title)
        layout = QGridLayout(group)
        
        for row, (label, value) in enumerate(items):
            label_widget = QLabel(f"{label}:")
            label_widget.setStyleSheet("font-weight: bold;")
            layout.addWidget(label_widget, row, 0)
            
            value_widget = QLabel(str(value))
            value_widget.setWordWrap(True)
            value_widget.setTextInteractionFlags(Qt.TextSelectableByMouse)
            layout.addWidget(value_widget, row, 1)
            
        return group
        
    def export_certificate(self):
        """Export certificate details."""
        if not self.current_result:
            return
            
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Certificate Details",
            f"certificate_{self.target_input.text()}.json",
            "JSON Files (*.json);;Text Files (*.txt)"
        )
        
        if filename:
            try:
                if filename.endswith('.json'):
                    import json
                    with open(filename, 'w') as f:
                        json.dump(self.current_result.to_dict(), f, indent=2, default=str)
                else:
                    with open(filename, 'w') as f:
                        f.write(f"SSL Certificate Analysis Results\n")
                        f.write(f"Target: {self.current_result.target}:{self.current_result.port}\n")
                        f.write(f"Status: {self.current_result.status}\n\n")
                        
                        if self.current_result.certificate_info:
                            cert_info = self.current_result.certificate_info
                            f.write("Certificate Information:\n")
                            f.write(f"  Common Name: {cert_info.get('common_name', 'N/A')}\n")
                            f.write(f"  Subject: {cert_info.get('subject', 'N/A')}\n")
                            f.write(f"  Issuer: {cert_info.get('issuer', 'N/A')}\n")
                            f.write(f"  Valid From: {cert_info.get('not_before', 'N/A')}\n")
                            f.write(f"  Valid Until: {cert_info.get('not_after', 'N/A')}\n")
                            
                QMessageBox.information(self, "Export Complete", f"Certificate details exported to {filename}")
                
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export certificate: {e}")
