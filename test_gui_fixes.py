#!/usr/bin/env python3
"""
Test GUI Fixes
==============

Test the fixes for quick action buttons and port scanning.
"""

import sys
import time
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QTimer
from gui.app import NetSecureXApp


def test_quick_actions(app):
    """Test quick action buttons."""
    print("\n🔘 Testing Quick Action Buttons...")
    
    try:
        main_window = app.main_window
        dashboard = main_window.dashboard
        
        # Test if signal is connected
        if hasattr(dashboard, 'tool_requested'):
            print("✅ Dashboard has tool_requested signal")
            
            # Test if main window has switch_to_tool method
            if hasattr(main_window, 'switch_to_tool'):
                print("✅ Main window has switch_to_tool method")
                
                # Test the signal connection by manually triggering it
                dashboard.tool_requested.emit('port_scanner')
                current_tab = main_window.tab_widget.currentIndex()
                
                if current_tab == 1:  # Port scanner tab
                    print("✅ Quick action signal working - switched to port scanner")
                    return True
                else:
                    print(f"❌ Quick action failed - current tab: {current_tab}")
                    return False
            else:
                print("❌ Main window missing switch_to_tool method")
                return False
        else:
            print("❌ Dashboard missing tool_requested signal")
            return False
            
    except Exception as e:
        print(f"❌ Quick action test error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_port_scanner_setup(app):
    """Test port scanner widget setup."""
    print("\n🔍 Testing Port Scanner Setup...")
    
    try:
        main_window = app.main_window
        port_scanner = main_window.port_scanner
        
        # Test default settings
        default_range = port_scanner.port_range_combo.currentText()
        if "10" in default_range:
            print("✅ Default port range is quick (10 ports)")
        else:
            print(f"❌ Default port range is: {default_range}")
            
        # Test timeout setting
        timeout = port_scanner.timeout_spin.value()
        if timeout <= 5:
            print(f"✅ Timeout is reasonable: {timeout}s")
        else:
            print(f"⚠️  Timeout might be too high: {timeout}s")
            
        # Test concurrent setting
        concurrent = port_scanner.concurrent_spin.value()
        if concurrent <= 100:
            print(f"✅ Concurrency is reasonable: {concurrent}")
        else:
            print(f"⚠️  Concurrency might be too high: {concurrent}")
            
        return True
        
    except Exception as e:
        print(f"❌ Port scanner setup test error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_worker_creation(app):
    """Test worker thread creation."""
    print("\n🧵 Testing Worker Thread Creation...")
    
    try:
        from gui.widgets.port_scanner import ScanWorker
        
        # Test worker creation with safe options
        options = {
            'timeout': 2,
            'max_concurrent': 10,
            'delay': 0.01,
            'banner_grab': False,
            'use_top_ports': True,
            'top_ports_count': 5  # Very small for testing
        }
        
        worker = ScanWorker('127.0.0.1', None, options)
        print("✅ Worker thread created successfully")
        
        # Test if worker has required signals
        if hasattr(worker, 'progress_updated') and hasattr(worker, 'result_ready'):
            print("✅ Worker has required signals")
            return True
        else:
            print("❌ Worker missing required signals")
            return False
            
    except Exception as e:
        print(f"❌ Worker creation test error: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Test GUI fixes."""
    print("🚀 Testing NetSecureX GUI Fixes")
    print("=" * 40)
    
    # Create application
    app = NetSecureXApp(sys.argv)
    print("✅ GUI application created")
    
    # Test fixes
    results = {}
    results['quick_actions'] = test_quick_actions(app)
    results['port_scanner_setup'] = test_port_scanner_setup(app)
    results['worker_creation'] = test_worker_creation(app)
    
    # Summary
    print("\n" + "=" * 40)
    print("📊 GUI FIXES TEST SUMMARY")
    print("=" * 40)
    
    working_count = sum(1 for result in results.values() if result)
    total_count = len(results)
    
    for test_name, status in results.items():
        status_icon = "✅" if status else "❌"
        print(f"{status_icon} {test_name.replace('_', ' ').title()}")
    
    print(f"\n🎯 Overall Status: {working_count}/{total_count} fixes working")
    
    if working_count == total_count:
        print("🎉 All GUI fixes are working!")
        print("🚀 Ready to test with real operations")
    else:
        print(f"⚠️  {total_count - working_count} fixes need more work")
    
    return working_count == total_count


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
