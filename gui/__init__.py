"""
NetSecureX GUI Package
=====================

Modern graphical user interface for NetSecureX cybersecurity toolkit.
Built with PySide6 (Qt6) for professional appearance and cross-platform compatibility.

Components:
- main_window: Primary application window with tool selection
- widgets: Custom widgets for cybersecurity tools
- dialogs: Modal dialogs for settings and configuration
- themes: Dark cybersecurity theme and styling
"""

__version__ = "1.2.0"

# Import main components
from .main_window import NetSecureXMainWindow
from .app import NetSecureXApp

__all__ = [
    "NetSecureXMainWindow",
    "NetSecureXApp"
]
