#!/usr/bin/env python3
"""
NetSecureX GUI Launcher
=======================

Simple launcher script for the NetSecureX GUI application.
This can be used to start the GUI without installing the package.
"""

import sys
import os
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

try:
    from gui.app import main
    
    if __name__ == "__main__":
        print("🚀 Launching NetSecureX GUI...")
        main()
        
except ImportError as e:
    print(f"❌ Failed to import GUI modules: {e}")
    print("\n📦 Please install the required dependencies:")
    print("   pip install PySide6")
    print("\n💡 Or install all dependencies:")
    print("   pip install -r requirements.txt")
    sys.exit(1)
    
except Exception as e:
    print(f"❌ Failed to start GUI: {e}")
    sys.exit(1)
