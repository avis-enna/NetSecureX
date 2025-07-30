"""
About Dialog for NetSecureX
===========================

About dialog showing application information and credits.
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
    QPushButton, QTextEdit, QTabWidget, QWidget
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QPixmap


class AboutDialog(QDialog):
    """About dialog for NetSecureX application."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About NetSecureX")
        self.setFixedSize(500, 400)
        self.setup_ui()
        
    def setup_ui(self):
        """Setup about dialog interface."""
        layout = QVBoxLayout(self)
        
        # Header with logo and title
        header_layout = QHBoxLayout()
        
        # Title section
        title_widget = QWidget()
        title_layout = QVBoxLayout(title_widget)
        
        title_label = QLabel("NetSecureX")
        title_label.setStyleSheet("""
            QLabel {
                font-size: 24px;
                font-weight: bold;
                color: #0096c8;
            }
        """)
        title_layout.addWidget(title_label)
        
        version_label = QLabel("Version 1.0.1")
        version_label.setStyleSheet("font-size: 14px; color: #888;")
        title_layout.addWidget(version_label)
        
        subtitle_label = QLabel("Unified Cybersecurity Toolkit")
        subtitle_label.setStyleSheet("font-size: 12px; color: #888;")
        title_layout.addWidget(subtitle_label)
        
        header_layout.addWidget(title_widget)
        header_layout.addStretch()
        
        layout.addLayout(header_layout)
        
        # Tab widget for different sections
        tab_widget = QTabWidget()
        
        # About tab
        about_tab = self.create_about_tab()
        tab_widget.addTab(about_tab, "About")
        
        # Credits tab
        credits_tab = self.create_credits_tab()
        tab_widget.addTab(credits_tab, "Credits")
        
        # License tab
        license_tab = self.create_license_tab()
        tab_widget.addTab(license_tab, "License")
        
        layout.addWidget(tab_widget)
        
        # Close button
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.accept)
        button_layout.addWidget(close_button)
        
        layout.addLayout(button_layout)
        
    def create_about_tab(self):
        """Create about tab content."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        about_text = QLabel("""
        <p><b>NetSecureX</b> is a comprehensive cybersecurity assessment toolkit 
        designed for security professionals, penetration testers, and network administrators.</p>
        
        <p><b>Key Features:</b></p>
        <ul>
        <li>High-performance port scanning with service detection</li>
        <li>SSL/TLS certificate analysis and validation</li>
        <li>CVE vulnerability database lookup</li>
        <li>IP reputation and threat intelligence</li>
        <li>Network security assessment tools</li>
        <li>Modern GUI and command-line interfaces</li>
        </ul>
        
        <p><b>Built for:</b></p>
        <ul>
        <li>Security assessments and penetration testing</li>
        <li>Network infrastructure analysis</li>
        <li>Vulnerability research and management</li>
        <li>Compliance and security auditing</li>
        </ul>
        """)
        about_text.setWordWrap(True)
        about_text.setTextFormat(Qt.RichText)
        
        layout.addWidget(about_text)
        layout.addStretch()
        
        return widget
        
    def create_credits_tab(self):
        """Create credits tab content."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        credits_text = QLabel("""
        <p><b>Development Team:</b></p>
        <p>NetSecureX Development Team</p>
        
        <p><b>Built with:</b></p>
        <ul>
        <li><b>Python 3.11+</b> - Core programming language</li>
        <li><b>PySide6 (Qt6)</b> - Modern GUI framework</li>
        <li><b>asyncio</b> - Asynchronous networking</li>
        <li><b>aiohttp</b> - HTTP client/server framework</li>
        <li><b>cryptography</b> - SSL/TLS certificate handling</li>
        <li><b>click</b> - Command-line interface</li>
        <li><b>rich</b> - Terminal formatting and styling</li>
        </ul>
        
        <p><b>Special Thanks:</b></p>
        <ul>
        <li>Open source security community</li>
        <li>Threat intelligence API providers</li>
        <li>Python and Qt development teams</li>
        <li>Security researchers and contributors</li>
        </ul>
        """)
        credits_text.setWordWrap(True)
        credits_text.setTextFormat(Qt.RichText)
        
        layout.addWidget(credits_text)
        layout.addStretch()
        
        return widget
        
    def create_license_tab(self):
        """Create license tab content."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        license_text = QTextEdit()
        license_text.setReadOnly(True)
        license_text.setPlainText("""
MIT License

Copyright (c) 2024 NetSecureX

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

DISCLAIMER:
This tool is intended for authorized security testing and educational purposes only.
Users are responsible for complying with applicable laws and regulations.
The developers assume no liability for misuse of this software.
        """)
        
        layout.addWidget(license_text)
        
        return widget
