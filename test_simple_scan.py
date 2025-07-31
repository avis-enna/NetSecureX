#!/usr/bin/env python3
"""
Simple test to verify scanning works
"""

import sys
import os
from pathlib import Path

# Add the current directory to Python path for imports
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

def test_simple_scan():
    """Test a simple scan to verify it works."""
    try:
        from core.scanner import PortScanner
        import asyncio
        
        print("🔍 Testing simple port scan...")
        scanner = PortScanner()
        
        async def run_scan():
            try:
                # Test scan on localhost
                scan_summary = await scanner.scan_target(
                    target="127.0.0.1",
                    ports=[22, 80, 443],
                    use_top_ports=False
                )
                
                print(f"✅ Scan completed successfully!")
                print(f"   Target: {scan_summary.target}")
                print(f"   Total ports scanned: {scan_summary.total_ports}")
                print(f"   Open ports: {scan_summary.open_ports}")
                print(f"   Closed ports: {scan_summary.closed_ports}")
                print(f"   Duration: {scan_summary.scan_duration:.2f}s")
                
                if scan_summary.results:
                    print(f"   Results:")
                    for result in scan_summary.results[:5]:  # Show first 5
                        print(f"     {result.ip}:{result.port} = {result.status}")
                
                return True
                
            except Exception as e:
                print(f"❌ Scan failed: {e}")
                return False
        
        # Run the scan
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            success = loop.run_until_complete(run_scan())
            return success
        finally:
            loop.close()
            
    except Exception as e:
        print(f"❌ Test setup failed: {e}")
        return False

if __name__ == "__main__":
    print("🧪 NetSecureX Simple Scan Test")
    print("=" * 40)
    
    success = test_simple_scan()
    
    print("\n" + "=" * 40)
    if success:
        print("🎉 Scan test passed! The scanner is working correctly.")
    else:
        print("⚠️ Scan test failed. Check the errors above.")
