"""
NetSecureX Main Window
=====================

Main application window with tabbed interface for cybersecurity tools.
Provides access to all NetSecureX functionality through a modern GUI.
"""

import sys
from PySide6.QtWidgets import (
    QMainWindow, QTabWidget, QVBoxLayout, QHBoxLayout, 
    QWidget, QLabel, QStatusBar, QMenuBar, QToolBar,
    QPushButton, QSplitter, QTextEdit, QFrame
)
from PySide6.QtCore import Qt, QTimer, QThread, Signal
from PySide6.QtGui import QAction, QFont, QPixmap, QIcon

from .widgets.dashboard import DashboardWidget
from .widgets.port_scanner import PortScannerWidget
from .widgets.ssl_analyzer import SSLAnalyzerWidget
from .widgets.cve_lookup import CVELookupWidget
from .widgets.ip_reputation import IPReputationWidget
from .widgets.zenmap_dashboard import ZenmapStyleDashboard
from .widgets.host_scanner import HostScannerWidget
from .widgets.settings import SettingsWidget
from .dialogs.about import AboutDialog


class NetSecureXMainWindow(QMainWindow):
    """Main application window for NetSecureX GUI."""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetSecureX - Cybersecurity Toolkit")
        self.setMinimumSize(1200, 800)
        self.resize(1400, 900)
        
        # Initialize UI components
        self.setup_ui()
        self.setup_menu_bar()
        self.setup_tool_bar()
        self.setup_status_bar()
        
        # Connect signals
        self.setup_connections()
        
    def setup_ui(self):
        """Setup the main user interface."""
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create main layout
        layout = QVBoxLayout(central_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Create header
        header = self.create_header()
        layout.addWidget(header)
        
        # Create tab widget for tools
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabPosition(QTabWidget.North)
        self.tab_widget.setMovable(True)
        layout.addWidget(self.tab_widget)
        
        # Add tool tabs
        self.add_tool_tabs()
        
    def create_header(self):
        """Create application header with logo and title."""
        header = QFrame()
        header.setFixedHeight(80)
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1e3c72, stop:1 #2a5298);
                border-bottom: 2px solid #0096c8;
            }
        """)
        
        layout = QHBoxLayout(header)
        layout.setContentsMargins(20, 10, 20, 10)
        
        # Title and subtitle
        title_widget = QWidget()
        title_layout = QVBoxLayout(title_widget)
        title_layout.setContentsMargins(0, 0, 0, 0)
        
        title_label = QLabel("NetSecureX")
        title_label.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 28px;
                font-weight: bold;
                background: transparent;
            }
        """)
        
        subtitle_label = QLabel("Unified Cybersecurity Toolkit v1.2.0")
        subtitle_label.setStyleSheet("""
            QLabel {
                color: #b0d4f1;
                font-size: 14px;
                background: transparent;
            }
        """)
        
        title_layout.addWidget(title_label)
        title_layout.addWidget(subtitle_label)
        
        layout.addWidget(title_widget)
        layout.addStretch()
        
        return header
        
    def add_tool_tabs(self):
        """Add tabs for each cybersecurity tool."""
        # Dashboard tab
        self.dashboard = DashboardWidget()
        self.tab_widget.addTab(self.dashboard, "🏠 Dashboard")
        
        # Port Scanner tab
        self.port_scanner = PortScannerWidget()
        self.tab_widget.addTab(self.port_scanner, "🔍 Port Scanner")
        
        # SSL Analyzer tab
        self.ssl_analyzer = SSLAnalyzerWidget()
        self.tab_widget.addTab(self.ssl_analyzer, "🔒 SSL Analyzer")
        
        # CVE Lookup tab
        self.cve_lookup = CVELookupWidget()
        self.tab_widget.addTab(self.cve_lookup, "🛡️ CVE Lookup")
        
        # IP Reputation tab
        self.ip_reputation = IPReputationWidget()
        self.tab_widget.addTab(self.ip_reputation, "🌐 IP Reputation")

        # Zenmap-style Security Dashboard tab
        self.monitoring = ZenmapStyleDashboard()
        self.tab_widget.addTab(self.monitoring, "🛡️ Security Monitor")

        # Host Scanner tab
        self.host_scanner = HostScannerWidget()
        self.tab_widget.addTab(self.host_scanner, "🖥️ Host Scanner")

        # Settings tab
        self.settings = SettingsWidget()
        self.tab_widget.addTab(self.settings, "⚙️ Settings")
        
    def setup_menu_bar(self):
        """Setup application menu bar."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("&File")
        
        export_action = QAction("&Export Results...", self)
        export_action.setShortcut("Ctrl+E")
        export_action.triggered.connect(self.export_results)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("E&xit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("&Tools")
        
        scan_action = QAction("Quick &Port Scan", self)
        scan_action.setShortcut("Ctrl+P")
        scan_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(1))
        tools_menu.addAction(scan_action)
        
        ssl_action = QAction("&SSL Check", self)
        ssl_action.setShortcut("Ctrl+S")
        ssl_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(2))
        tools_menu.addAction(ssl_action)
        
        # Help menu
        help_menu = menubar.addMenu("&Help")
        
        about_action = QAction("&About NetSecureX", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
    def setup_tool_bar(self):
        """Setup application toolbar."""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        
        # Quick action buttons
        scan_btn = QPushButton("Quick Scan")
        scan_btn.clicked.connect(lambda: self.tab_widget.setCurrentIndex(1))
        toolbar.addWidget(scan_btn)
        
        ssl_btn = QPushButton("SSL Check")
        ssl_btn.clicked.connect(lambda: self.tab_widget.setCurrentIndex(2))
        toolbar.addWidget(ssl_btn)
        
        toolbar.addSeparator()
        
        settings_btn = QPushButton("Settings")
        settings_btn.clicked.connect(lambda: self.tab_widget.setCurrentIndex(5))
        toolbar.addWidget(settings_btn)
        
    def setup_status_bar(self):
        """Setup application status bar."""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Status message
        self.status_bar.showMessage("Ready")
        
        # Add permanent widgets
        self.status_bar.addPermanentWidget(QLabel("NetSecureX v1.2.0"))
        
    def setup_connections(self):
        """Setup signal connections between components."""
        # Connect tab change signal
        self.tab_widget.currentChanged.connect(self.on_tab_changed)
        
    def on_tab_changed(self, index):
        """Handle tab change events."""
        tab_names = ["Dashboard", "Port Scanner", "SSL Analyzer",
                    "CVE Lookup", "IP Reputation", "Live Monitor", "Host Scanner", "Settings"]
        if 0 <= index < len(tab_names):
            self.status_bar.showMessage(f"Active: {tab_names[index]}")
            
    def export_results(self):
        """Export current results to file."""
        # Get current tab and export its results
        current_widget = self.tab_widget.currentWidget()
        if hasattr(current_widget, 'export_results'):
            current_widget.export_results()
        else:
            self.status_bar.showMessage("No results to export", 3000)
            
    def show_about(self):
        """Show about dialog."""
        dialog = AboutDialog(self)
        dialog.exec()
        
    def closeEvent(self, event):
        """Handle application close event."""
        # Save settings or perform cleanup if needed
        event.accept()
