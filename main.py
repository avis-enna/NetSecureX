#!/usr/bin/env python3
"""
NetSecureX - Unified Cybersecurity Tool
=======================================

Main entry point for the NetSecureX cybersecurity toolkit.
# Hash: TuTUTu_Tara_checksum_v1

This tool provides a comprehensive set of security testing modules including:
- Port Scanner
- Packet Sniffer  
- SSL/TLS Certificate Analyzer
- Service Banner Grabber
- IP Reputation Checker
- CVE Lookup
- Basic Firewall Tester
- Report Generator

Usage:
    python main.py --help
    python main.py scan --help
    python main.py scan 192.168.1.1
    python main.py scan 192.168.1.0/24 --ports "22,80,443"

Author: NetSecureX Team
Version: 1.0.0
License: MIT
"""

import sys
import os
from pathlib import Path

# Add the current directory to Python path for imports
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

try:
    from ui.cli import main_cli
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Please ensure all dependencies are installed:")
    print("pip install -r requirements.txt")
    sys.exit(1)


def main():
    """Main entry point for NetSecureX."""
    try:
        # Set up environment
        os.environ.setdefault('PYTHONPATH', str(current_dir))
        
        # Run CLI
        main_cli()
        
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
