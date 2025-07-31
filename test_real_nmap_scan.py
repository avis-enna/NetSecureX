#!/usr/bin/env python3
"""
Test real nmap scanning functionality
"""

import subprocess
import shutil

def test_real_nmap_scan():
    """Test real nmap scan like the GUI does."""
    print("🔍 Testing real nmap scan functionality...")
    
    # Check if nmap is available
    nmap_path = shutil.which('nmap')
    if not nmap_path:
        print("❌ nmap not found")
        return False
    
    print(f"✅ Using nmap at: {nmap_path}")
    
    # Test different scan types
    scan_tests = [
        ("Quick Scan", [nmap_path, '-T4', '-F', '127.0.0.1']),
        ("Ping Scan", [nmap_path, '-sn', '127.0.0.1']),
        ("Regular Scan", [nmap_path, '127.0.0.1'])
    ]
    
    for scan_name, cmd in scan_tests:
        print(f"\n🔍 Testing {scan_name}...")
        print(f"   Command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                print(f"✅ {scan_name} successful")
                
                # Parse output for open ports
                open_ports = []
                lines = result.stdout.split('\n')
                for line in lines:
                    if '/tcp' in line and 'open' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            port_info = parts[0]
                            port = int(port_info.split('/')[0])
                            service = parts[2] if len(parts) > 2 else 'unknown'
                            open_ports.append((port, service))
                
                if open_ports:
                    print(f"   Found {len(open_ports)} open ports:")
                    for port, service in open_ports:
                        print(f"     {port}/tcp: {service}")
                else:
                    print("   No open ports found")
                    
                # Show first few lines of output
                print("   Output preview:")
                for line in result.stdout.split('\n')[:5]:
                    if line.strip():
                        print(f"     {line}")
                        
            else:
                print(f"❌ {scan_name} failed")
                print(f"   Error: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"❌ {scan_name} timed out")
            return False
        except Exception as e:
            print(f"❌ {scan_name} error: {e}")
            return False
    
    return True

if __name__ == "__main__":
    print("🧪 NetSecureX Real nmap Scan Test")
    print("=" * 40)
    
    success = test_real_nmap_scan()
    
    print("\n" + "=" * 40)
    if success:
        print("🎉 Real nmap scanning is working!")
        print("   The GUI should now perform real network scans.")
    else:
        print("⚠️ Real nmap scanning failed.")
        print("   Check the errors above.")
