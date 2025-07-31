#!/usr/bin/env python3
"""
Test if nmap is available and working
"""

import subprocess
import shutil
import sys

def test_nmap():
    """Test if nmap is available and working."""
    print("🔍 Testing nmap availability...")
    
    # Check if nmap is in PATH
    nmap_path = shutil.which('nmap')
    if not nmap_path:
        print("❌ nmap not found in PATH")
        print("   Install nmap:")
        print("   - macOS: brew install nmap")
        print("   - Ubuntu: sudo apt install nmap")
        print("   - Windows: Download from https://nmap.org/download.html")
        return False
    
    print(f"✅ nmap found at: {nmap_path}")
    
    # Test nmap version
    try:
        result = subprocess.run([nmap_path, '--version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            version_line = result.stdout.split('\n')[0]
            print(f"✅ {version_line}")
        else:
            print(f"❌ nmap version check failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Error checking nmap version: {e}")
        return False
    
    # Test simple scan
    print("🔍 Testing simple nmap scan...")
    try:
        result = subprocess.run([nmap_path, '-sn', '127.0.0.1'], 
                              capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print("✅ Simple nmap scan successful")
            print("   Output preview:")
            for line in result.stdout.split('\n')[:3]:
                if line.strip():
                    print(f"   {line}")
            return True
        else:
            print(f"❌ nmap scan failed: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print("❌ nmap scan timed out")
        return False
    except Exception as e:
        print(f"❌ Error running nmap scan: {e}")
        return False

def install_nmap_instructions():
    """Show installation instructions for nmap."""
    print("\n📦 How to install nmap:")
    print("=" * 40)
    
    if sys.platform == "darwin":  # macOS
        print("macOS:")
        print("  brew install nmap")
        print("  # or download from https://nmap.org/download.html")
    elif sys.platform.startswith("linux"):  # Linux
        print("Linux (Ubuntu/Debian):")
        print("  sudo apt update && sudo apt install nmap")
        print("")
        print("Linux (CentOS/RHEL):")
        print("  sudo yum install nmap")
        print("  # or: sudo dnf install nmap")
    elif sys.platform == "win32":  # Windows
        print("Windows:")
        print("  Download from: https://nmap.org/download.html")
        print("  Install the Windows version")
    else:
        print("Other platforms:")
        print("  Visit: https://nmap.org/download.html")

if __name__ == "__main__":
    print("🧪 NetSecureX nmap Test")
    print("=" * 30)
    
    success = test_nmap()
    
    print("\n" + "=" * 30)
    if success:
        print("🎉 nmap is working correctly!")
        print("   The real scanning functionality should work.")
    else:
        print("⚠️ nmap is not available or not working.")
        install_nmap_instructions()
