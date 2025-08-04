#!/usr/bin/env python3
"""
GUI Launch Test
===============

Launch the GUI and test basic interactions to ensure everything works visually.
"""

import sys
import time
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QTimer
from gui.app import NetSecureXApp


def main():
    """Launch GUI for testing."""
    print("🚀 Launching NetSecureX GUI for testing...")
    
    # Create and run application
    app = NetSecureXApp(sys.argv)
    
    # Show the main window
    app.main_window.show()
    
    print("✅ GUI launched successfully!")
    print("📋 Available tabs:")
    
    # List all tabs
    for i in range(app.main_window.tab_widget.count()):
        tab_name = app.main_window.tab_widget.tabText(i)
        widget = app.main_window.tab_widget.widget(i)
        print(f"   {i+1}. {tab_name} - {type(widget).__name__}")
    
    print("\n🎯 GUI Features Available:")
    print("   • Port Scanner - Network port scanning")
    print("   • SSL Analyzer - Certificate analysis")
    print("   • CVE Lookup - Vulnerability database search")
    print("   • IP Reputation - Threat intelligence")
    print("   • Security Monitor - Real-time monitoring")
    print("   • Host Scanner - Local system scanning")
    print("   • Settings - Configuration management")
    
    print("\n💡 Test Instructions:")
    print("   1. Try switching between tabs")
    print("   2. Enter test data in input fields")
    print("   3. Click buttons to test functionality")
    print("   4. Check if all widgets respond properly")
    print("   5. Close the window when done testing")
    
    # Auto-close after 30 seconds for automated testing
    def auto_close():
        print("\n⏰ Auto-closing GUI after 30 seconds...")
        app.quit()
    
    timer = QTimer()
    timer.timeout.connect(auto_close)
    timer.start(30000)  # 30 seconds
    
    # Run the application
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
