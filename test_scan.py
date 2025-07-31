#!/usr/bin/env python3
"""
Test script to debug scanning issues
"""

import sys
import os
from pathlib import Path

# Add the current directory to Python path for imports
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

def test_scanner_import():
    """Test if we can import the scanner module."""
    try:
        from core.scanner import PortScanner
        print("✅ PortScanner import successful")
        return True
    except Exception as e:
        print(f"❌ PortScanner import failed: {e}")
        return False

def test_simple_scan():
    """Test a simple scan."""
    try:
        from core.scanner import PortScanner
        import asyncio
        
        scanner = PortScanner()
        print("✅ PortScanner created")
        
        # Test a simple scan
        async def run_test_scan():
            try:
                scan_summary = await scanner.scan_target(
                    target="127.0.0.1",
                    ports=[80, 443],
                    use_top_ports=False
                )
                print(f"✅ Scan completed with {len(scan_summary.results)} results")
                for result in scan_summary.results:
                    print(f"  - {result.ip}:{result.port} = {result.status}")
                return True
            except Exception as e:
                print(f"❌ Scan failed: {e}")
                import traceback
                print(f"Traceback: {traceback.format_exc()}")
                return False
        
        # Run the async scan
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            success = loop.run_until_complete(run_test_scan())
            return success
        finally:
            loop.close()
            
    except Exception as e:
        print(f"❌ Test scan setup failed: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False

def test_thread_worker():
    """Test the NetworkScanWorker in isolation."""
    try:
        from gui.widgets.zenmap_dashboard import NetworkScanWorker
        from PySide6.QtCore import QCoreApplication
        import sys
        
        # Create minimal Qt application
        app = QCoreApplication(sys.argv)
        
        print("✅ NetworkScanWorker import successful")
        
        # Create worker
        worker = NetworkScanWorker("127.0.0.1", "quick_scan")
        print("✅ NetworkScanWorker created")
        
        # Test signals
        def on_progress(progress):
            print(f"Progress: {progress}%")
            
        def on_result(result):
            print(f"Result: {result}")
            
        def on_finished():
            print("Scan finished")
            app.quit()
        
        worker.scan_progress.connect(on_progress)
        worker.scan_result.connect(on_result)
        worker.scan_finished.connect(on_finished)
        
        print("✅ Signals connected")
        
        # Start worker
        worker.start()
        print("✅ Worker started")
        
        # Run event loop for a short time
        import time
        start_time = time.time()
        while time.time() - start_time < 10:  # Run for max 10 seconds
            app.processEvents()
            time.sleep(0.1)
            if not worker.isRunning():
                break
        
        if worker.isRunning():
            worker.stop()
            worker.wait()
            
        print("✅ Thread worker test completed")
        return True
        
    except Exception as e:
        print(f"❌ Thread worker test failed: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False

def main():
    """Run all tests."""
    print("🔍 Testing NetSecureX Scanning Components")
    print("=" * 50)
    
    # Test 1: Import scanner
    print("\n1. Testing PortScanner import...")
    scanner_import_ok = test_scanner_import()
    
    # Test 2: Simple scan
    print("\n2. Testing simple scan...")
    if scanner_import_ok:
        simple_scan_ok = test_simple_scan()
    else:
        simple_scan_ok = False
        print("⏭️ Skipping simple scan test (import failed)")
    
    # Test 3: Thread worker
    print("\n3. Testing NetworkScanWorker...")
    try:
        thread_worker_ok = test_thread_worker()
    except Exception as e:
        print(f"❌ Thread worker test setup failed: {e}")
        thread_worker_ok = False
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 Test Summary:")
    print(f"  Scanner Import: {'✅' if scanner_import_ok else '❌'}")
    print(f"  Simple Scan: {'✅' if simple_scan_ok else '❌'}")
    print(f"  Thread Worker: {'✅' if thread_worker_ok else '❌'}")
    
    if all([scanner_import_ok, simple_scan_ok, thread_worker_ok]):
        print("\n🎉 All tests passed! Scanning should work.")
    else:
        print("\n⚠️ Some tests failed. Check the errors above.")

if __name__ == "__main__":
    main()
