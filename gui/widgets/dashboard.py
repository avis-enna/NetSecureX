"""
Dashboard Widget for NetSecureX
===============================

Main dashboard showing tool overview, recent activity, and quick actions.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QFrame, QScrollArea, QGroupBox,
    QProgressBar, QListWidget, QListWidgetItem
)
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QFont, QPixmap, QIcon


class DashboardWidget(QWidget):
    """Main dashboard widget with overview and quick actions."""
    
    # Signals
    tool_requested = Signal(str)  # Emitted when user wants to switch to a tool
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.setup_timer()
        
    def setup_ui(self):
        """Setup the dashboard user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Welcome section
        welcome_section = self.create_welcome_section()
        layout.addWidget(welcome_section)
        
        # Quick actions grid
        quick_actions = self.create_quick_actions()
        layout.addWidget(quick_actions)
        
        # Status and activity section
        status_layout = QHBoxLayout()
        
        # System status
        status_section = self.create_status_section()
        status_layout.addWidget(status_section)
        
        # Recent activity
        activity_section = self.create_activity_section()
        status_layout.addWidget(activity_section)
        
        layout.addLayout(status_layout)
        
        # Add stretch to push content to top
        layout.addStretch()
        
    def create_welcome_section(self):
        """Create welcome section with app info."""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2d5aa0, stop:1 #1e3c72);
                border-radius: 10px;
                padding: 20px;
            }
        """)
        frame.setFixedHeight(120)
        
        layout = QVBoxLayout(frame)
        
        title = QLabel("Welcome to NetSecureX")
        title.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 24px;
                font-weight: bold;
                background: transparent;
            }
        """)
        
        subtitle = QLabel("Your unified cybersecurity toolkit for network security assessment")
        subtitle.setStyleSheet("""
            QLabel {
                color: #b0d4f1;
                font-size: 14px;
                background: transparent;
            }
        """)
        
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addStretch()
        
        return frame
        
    def create_quick_actions(self):
        """Create quick action buttons grid."""
        group = QGroupBox("Quick Actions")
        group.setStyleSheet("""
            QGroupBox {
                font-size: 16px;
                font-weight: bold;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        
        layout = QGridLayout(group)
        layout.setSpacing(15)
        
        # Define quick action buttons
        actions = [
            ("🔍 Port Scanner", "Scan network ports and services", "port_scanner"),
            ("🔒 SSL Analyzer", "Analyze SSL/TLS certificates", "ssl_analyzer"),
            ("🛡️ CVE Lookup", "Search vulnerability databases", "cve_lookup"),
            ("🌐 IP Reputation", "Check IP threat intelligence", "ip_reputation"),
            ("📊 Live Monitor", "Real-time security monitoring", "monitoring"),
            ("⚙️ Settings", "Configure API keys and settings", "settings")
        ]
        
        for i, (title, description, tool) in enumerate(actions):
            button = self.create_action_button(title, description, tool)
            row = i // 3
            col = i % 3
            layout.addWidget(button, row, col)
            
        return group
        
    def create_action_button(self, title, description, tool):
        """Create a styled action button."""
        button = QPushButton()
        button.setFixedSize(200, 100)
        button.setStyleSheet("""
            QPushButton {
                text-align: left;
                padding: 15px;
                border-radius: 8px;
                background-color: #3a3a3a;
                border: 2px solid #555;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
                border-color: #0096c8;
            }
            QPushButton:pressed {
                background-color: #0096c8;
            }
        """)
        
        # Create button content
        layout = QVBoxLayout(button)
        layout.setContentsMargins(5, 5, 5, 5)
        
        title_label = QLabel(title)
        title_label.setStyleSheet("""
            QLabel {
                font-size: 14px;
                font-weight: bold;
                color: white;
                background: transparent;
            }
        """)
        
        desc_label = QLabel(description)
        desc_label.setStyleSheet("""
            QLabel {
                font-size: 11px;
                color: #ccc;
                background: transparent;
            }
        """)
        desc_label.setWordWrap(True)
        
        layout.addWidget(title_label)
        layout.addWidget(desc_label)
        layout.addStretch()
        
        # Connect button click
        button.clicked.connect(lambda: self.tool_requested.emit(tool))
        
        return button
        
    def create_status_section(self):
        """Create system status section."""
        group = QGroupBox("System Status")
        group.setFixedWidth(300)
        
        layout = QVBoxLayout(group)
        
        # API Keys status
        api_status = QLabel("API Keys: Checking...")
        api_status.setStyleSheet("color: orange;")
        layout.addWidget(api_status)
        
        # Network status
        network_status = QLabel("Network: Connected")
        network_status.setStyleSheet("color: #00ff96;")
        layout.addWidget(network_status)
        
        # Memory usage
        self.memory_label = QLabel("Memory Usage: --")
        layout.addWidget(self.memory_label)

        self.memory_bar = QProgressBar()
        self.memory_bar.setValue(0)
        self.memory_bar.setStyleSheet("""
            QProgressBar::chunk {
                background-color: #00ff96;
            }
        """)
        layout.addWidget(self.memory_bar)

        # CPU usage
        self.cpu_label = QLabel("CPU Usage: --")
        layout.addWidget(self.cpu_label)

        self.cpu_bar = QProgressBar()
        self.cpu_bar.setValue(0)
        self.cpu_bar.setStyleSheet("""
            QProgressBar::chunk {
                background-color: #ffaa00;
            }
        """)
        layout.addWidget(self.cpu_bar)
        
        layout.addStretch()
        
        return group
        
    def create_activity_section(self):
        """Create recent activity section."""
        group = QGroupBox("Recent Activity")
        
        layout = QVBoxLayout(group)
        
        # Activity list
        self.activity_list = QListWidget()
        self.activity_list.setMaximumHeight(150)
        
        # Add some sample activities
        activities = [
            "Application started",
            "Checking API key configuration...",
            "Ready for security assessment"
        ]
        
        for activity in activities:
            item = QListWidgetItem(activity)
            self.activity_list.addItem(item)
            
        layout.addWidget(self.activity_list)
        
        return group
        
    def setup_timer(self):
        """Setup timer for periodic updates."""
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_status)
        self.timer.start(5000)  # Update every 5 seconds
        
    def update_status(self):
        """Update dashboard status information."""
        try:
            import psutil

            # Update memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            self.memory_label.setText(f"Memory Usage: {memory_percent:.1f}%")
            self.memory_bar.setValue(int(memory_percent))

            # Update CPU usage
            cpu_percent = psutil.cpu_percent(interval=None)
            self.cpu_label.setText(f"CPU Usage: {cpu_percent:.1f}%")
            self.cpu_bar.setValue(int(cpu_percent))

            # Change colors based on usage
            if memory_percent > 80:
                self.memory_bar.setStyleSheet("QProgressBar::chunk { background-color: #ff4444; }")
            elif memory_percent > 60:
                self.memory_bar.setStyleSheet("QProgressBar::chunk { background-color: #ffaa00; }")
            else:
                self.memory_bar.setStyleSheet("QProgressBar::chunk { background-color: #00ff96; }")

            if cpu_percent > 80:
                self.cpu_bar.setStyleSheet("QProgressBar::chunk { background-color: #ff4444; }")
            elif cpu_percent > 60:
                self.cpu_bar.setStyleSheet("QProgressBar::chunk { background-color: #ffaa00; }")
            else:
                self.cpu_bar.setStyleSheet("QProgressBar::chunk { background-color: #00ff96; }")

        except ImportError:
            # Fallback if psutil is not available
            self.memory_label.setText("Memory Usage: N/A")
            self.cpu_label.setText("CPU Usage: N/A")
        except Exception as e:
            # Handle any other errors gracefully
            pass
        
    def add_activity(self, message):
        """Add an activity message to the list."""
        import datetime
        current_time = datetime.datetime.now().strftime("%H:%M:%S")
        
        if self.activity_list.count() >= 10:
            self.activity_list.takeItem(0)
            
        item = QListWidgetItem(f"{current_time} - {message}")
        self.activity_list.addItem(item)
        self.activity_list.scrollToBottom()
