"""
Settings Widget for NetSecureX
==============================

GUI widget for application settings and API key configuration.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QLineEdit, QTextEdit, QGroupBox,
    QCheckBox, QSpinBox, QComboBox, QTabWidget,
    QMessageBox, QFileDialog, QScrollArea
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont

from utils.config import ConfigManager


class SettingsWidget(QWidget):
    """Settings widget for configuration management."""
    
    # Signals
    settings_changed = Signal()
    
    def __init__(self):
        super().__init__()
        self.config_manager = ConfigManager()
        self.setup_ui()
        self.load_settings()
        
    def setup_ui(self):
        """Setup settings interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Create tab widget for different setting categories
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)
        
        # API Keys tab
        api_tab = self.create_api_keys_tab()
        self.tab_widget.addTab(api_tab, "🔑 API Keys")
        
        # General Settings tab
        general_tab = self.create_general_settings_tab()
        self.tab_widget.addTab(general_tab, "⚙️ General")
        
        # About tab
        about_tab = self.create_about_tab()
        self.tab_widget.addTab(about_tab, "ℹ️ About")
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.save_button = QPushButton("Save Settings")
        self.save_button.setStyleSheet("""
            QPushButton {
                background-color: #00aa00;
                font-weight: bold;
                padding: 10px 20px;
            }
            QPushButton:hover {
                background-color: #00cc00;
            }
        """)
        self.save_button.clicked.connect(self.save_settings)
        button_layout.addWidget(self.save_button)
        
        self.reset_button = QPushButton("Reset to Defaults")
        self.reset_button.clicked.connect(self.reset_settings)
        button_layout.addWidget(self.reset_button)
        
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        
    def create_api_keys_tab(self):
        """Create API keys configuration tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Create scroll area for API keys
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        
        # API key groups
        api_services = [
            ("AbuseIPDB", "abuseipdb", "Free tier available - IP reputation and abuse reporting"),
            ("IPQualityScore", "ipqualityscore", "Free tier available - IP and domain reputation"),
            ("VirusTotal", "virustotal", "Free tier available - File and URL analysis"),
            ("Vulners", "vulners", "Free tier available - Vulnerability database"),
            ("Shodan", "shodan", "Paid service - Internet-connected device search"),
            ("GreyNoise", "greynoise", "Free tier available - Internet noise analysis")
        ]
        
        self.api_inputs = {}
        
        for service_name, key_name, description in api_services:
            group = QGroupBox(service_name)
            group_layout = QVBoxLayout(group)
            
            # Description
            desc_label = QLabel(description)
            desc_label.setStyleSheet("color: #888; font-style: italic;")
            desc_label.setWordWrap(True)
            group_layout.addWidget(desc_label)
            
            # API key input
            key_layout = QHBoxLayout()
            key_layout.addWidget(QLabel("API Key:"))
            
            key_input = QLineEdit()
            key_input.setPlaceholderText(f"Enter your {service_name} API key")
            key_input.setEchoMode(QLineEdit.Password)
            self.api_inputs[key_name] = key_input
            key_layout.addWidget(key_input)
            
            # Show/hide button
            show_button = QPushButton("Show")
            show_button.setFixedWidth(60)
            show_button.clicked.connect(lambda checked, inp=key_input, btn=show_button: self.toggle_password_visibility(inp, btn))
            key_layout.addWidget(show_button)
            
            group_layout.addLayout(key_layout)
            scroll_layout.addWidget(group)
            
        scroll_layout.addStretch()
        scroll.setWidget(scroll_widget)
        layout.addWidget(scroll)
        
        # API key help
        help_text = QLabel("""
        <b>How to get API keys:</b><br>
        • Most services offer free tiers with rate limits<br>
        • Visit the service websites to register and get API keys<br>
        • API keys are stored securely in your local configuration<br>
        • You can use NetSecureX without API keys, but functionality will be limited
        """)
        help_text.setStyleSheet("background-color: #2a2a2a; padding: 15px; border-radius: 8px;")
        help_text.setWordWrap(True)
        layout.addWidget(help_text)
        
        return widget
        
    def create_general_settings_tab(self):
        """Create general settings tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Network settings
        network_group = QGroupBox("Network Settings")
        network_layout = QGridLayout(network_group)
        
        network_layout.addWidget(QLabel("Default Timeout (seconds):"), 0, 0)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 60)
        self.timeout_spin.setValue(10)
        network_layout.addWidget(self.timeout_spin, 0, 1)
        
        network_layout.addWidget(QLabel("Max Concurrent Connections:"), 1, 0)
        self.concurrent_spin = QSpinBox()
        self.concurrent_spin.setRange(1, 1000)
        self.concurrent_spin.setValue(100)
        network_layout.addWidget(self.concurrent_spin, 1, 1)
        
        layout.addWidget(network_group)
        
        # Output settings
        output_group = QGroupBox("Output Settings")
        output_layout = QGridLayout(output_group)
        
        output_layout.addWidget(QLabel("Default Output Format:"), 0, 0)
        self.output_combo = QComboBox()
        self.output_combo.addItems(["table", "json", "csv", "xml"])
        output_layout.addWidget(self.output_combo, 0, 1)
        
        output_layout.addWidget(QLabel("Log Level:"), 1, 0)
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        self.log_level_combo.setCurrentText("INFO")
        output_layout.addWidget(self.log_level_combo, 1, 1)
        
        layout.addWidget(output_group)
        
        # UI settings
        ui_group = QGroupBox("User Interface")
        ui_layout = QVBoxLayout(ui_group)
        
        self.dark_theme_check = QCheckBox("Use dark theme (requires restart)")
        self.dark_theme_check.setChecked(True)
        ui_layout.addWidget(self.dark_theme_check)
        
        self.auto_save_check = QCheckBox("Auto-save results")
        self.auto_save_check.setChecked(True)
        ui_layout.addWidget(self.auto_save_check)
        
        layout.addWidget(ui_group)
        
        layout.addStretch()
        
        return widget
        
    def create_about_tab(self):
        """Create about tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # App info
        info_text = QLabel("""
        <h2>NetSecureX v1.0.1</h2>
        <p><b>Unified Cybersecurity Toolkit</b></p>
        
        <p>NetSecureX is a comprehensive cybersecurity assessment tool that provides:</p>
        <ul>
        <li>Port scanning and service detection</li>
        <li>SSL/TLS certificate analysis</li>
        <li>CVE vulnerability lookup</li>
        <li>IP reputation checking</li>
        <li>Network security assessment</li>
        </ul>
        
        <p><b>Built with:</b></p>
        <ul>
        <li>Python 3.11+</li>
        <li>PySide6 (Qt6) for GUI</li>
        <li>Asyncio for high-performance networking</li>
        <li>Multiple threat intelligence APIs</li>
        </ul>
        
        <p><b>License:</b> MIT License</p>
        <p><b>Repository:</b> <a href="https://github.com/avis-enna/NetSecureX">github.com/avis-enna/NetSecureX</a></p>
        """)
        info_text.setWordWrap(True)
        info_text.setOpenExternalLinks(True)
        info_text.setStyleSheet("background-color: #2a2a2a; padding: 20px; border-radius: 8px;")
        
        layout.addWidget(info_text)
        layout.addStretch()
        
        return widget
        
    def toggle_password_visibility(self, input_field, button):
        """Toggle password visibility for API key inputs."""
        if input_field.echoMode() == QLineEdit.Password:
            input_field.setEchoMode(QLineEdit.Normal)
            button.setText("Hide")
        else:
            input_field.setEchoMode(QLineEdit.Password)
            button.setText("Show")
            
    def load_settings(self):
        """Load settings from configuration."""
        try:
            # Load API keys
            for key_name, input_field in self.api_inputs.items():
                api_key = self.config_manager.get_api_key(key_name)
                if api_key:
                    input_field.setText(api_key)
                    
            # Load general settings
            settings = self.config_manager.get_all_settings()
            
            if 'timeout' in settings:
                self.timeout_spin.setValue(int(settings['timeout']))
            if 'max_concurrent' in settings:
                self.concurrent_spin.setValue(int(settings['max_concurrent']))
            if 'output_format' in settings:
                self.output_combo.setCurrentText(settings['output_format'])
            if 'log_level' in settings:
                self.log_level_combo.setCurrentText(settings['log_level'])
                
        except Exception as e:
            QMessageBox.warning(self, "Load Error", f"Failed to load settings: {e}")
            
    def save_settings(self):
        """Save current settings to configuration."""
        try:
            # Save API keys
            for key_name, input_field in self.api_inputs.items():
                api_key = input_field.text().strip()
                if api_key:
                    self.config_manager.set_api_key(key_name, api_key)
                    
            # Save general settings
            self.config_manager.set_setting('timeout', self.timeout_spin.value())
            self.config_manager.set_setting('max_concurrent', self.concurrent_spin.value())
            self.config_manager.set_setting('output_format', self.output_combo.currentText())
            self.config_manager.set_setting('log_level', self.log_level_combo.currentText())
            
            # Save configuration
            self.config_manager.save_config()
            
            QMessageBox.information(self, "Settings Saved", "Settings have been saved successfully.")
            self.settings_changed.emit()
            
        except Exception as e:
            QMessageBox.critical(self, "Save Error", f"Failed to save settings: {e}")
            
    def reset_settings(self):
        """Reset settings to defaults."""
        reply = QMessageBox.question(
            self, "Reset Settings",
            "Are you sure you want to reset all settings to defaults?\nThis will clear all API keys.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Clear API keys
            for input_field in self.api_inputs.values():
                input_field.clear()
                
            # Reset general settings
            self.timeout_spin.setValue(10)
            self.concurrent_spin.setValue(100)
            self.output_combo.setCurrentText("table")
            self.log_level_combo.setCurrentText("INFO")
            self.dark_theme_check.setChecked(True)
            self.auto_save_check.setChecked(True)
