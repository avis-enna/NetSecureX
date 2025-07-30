#!/usr/bin/env python3
"""
NetSecureX GUI Application
==========================

Main application class for the NetSecureX graphical interface.
Handles application initialization, theming, and window management.
"""

import sys
import os
from pathlib import Path
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt, QDir
from PySide6.QtGui import QIcon, QPixmap

from .main_window import NetSecureXMainWindow
from .themes.dark_theme import apply_dark_theme


class NetSecureXApp(QApplication):
    """Main NetSecureX GUI application."""
    
    def __init__(self, argv):
        super().__init__(argv)
        
        # Set application properties
        self.setApplicationName("NetSecureX")
        self.setApplicationVersion("1.1.0")
        self.setOrganizationName("NetSecureX")
        self.setOrganizationDomain("netsecurex.dev")
        
        # Set application icon
        self.setup_icon()
        
        # Apply dark cybersecurity theme
        apply_dark_theme(self)
        
        # Create main window
        self.main_window = NetSecureXMainWindow()
        
    def setup_icon(self):
        """Setup application icon."""
        # Create a simple icon if none exists
        icon_path = Path(__file__).parent / "assets" / "icon.png"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))
        else:
            # Create a simple default icon
            pixmap = QPixmap(64, 64)
            pixmap.fill(Qt.darkBlue)
            self.setWindowIcon(QIcon(pixmap))
    
    def run(self):
        """Run the application."""
        self.main_window.show()
        return self.exec()


def main():
    """Main entry point for GUI application."""
    app = NetSecureXApp(sys.argv)
    sys.exit(app.run())


if __name__ == "__main__":
    main()
