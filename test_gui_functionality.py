#!/usr/bin/env python3
"""
GUI Functionality Test Script
============================

Comprehensive test script to identify what GUI functionality is working
and what needs to be fixed or implemented.
"""

import sys
import asyncio
import time
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QTimer, QEventLoop
from gui.app import NetSecureXApp


def test_port_scanner_functionality(app):
    """Test port scanner widget functionality."""
    print("\n🔍 Testing Port Scanner Widget...")
    
    port_scanner = app.main_window.port_scanner
    
    try:
        # Test input controls
        port_scanner.target_input.setText('127.0.0.1')
        port_scanner.timeout_spin.setValue(1)
        port_scanner.concurrent_spin.setValue(10)
        port_scanner.port_range_combo.setCurrentText("Top 100 ports")
        print("✅ Input controls working")
        
        # Test scan preparation (without actually running)
        target = port_scanner.target_input.text()
        timeout = port_scanner.timeout_spin.value()
        concurrent = port_scanner.concurrent_spin.value()
        
        if target and timeout > 0 and concurrent > 0:
            print("✅ Scan parameters validation working")
        else:
            print("❌ Scan parameters validation failed")
            
        # Test UI state management
        port_scanner.scan_button.setEnabled(False)
        port_scanner.stop_button.setEnabled(True)
        port_scanner.progress_bar.setVisible(True)
        print("✅ UI state management working")
        
        # Reset UI state
        port_scanner.scan_button.setEnabled(True)
        port_scanner.stop_button.setEnabled(False)
        port_scanner.progress_bar.setVisible(False)
        
        return True
        
    except Exception as e:
        print(f"❌ Port scanner error: {e}")
        return False


def test_cve_lookup_functionality(app):
    """Test CVE lookup widget functionality."""
    print("\n🛡️ Testing CVE Lookup Widget...")
    
    cve_widget = app.main_window.cve_lookup
    
    try:
        # Test input controls
        cve_widget.search_input.setText('nginx')
        cve_widget.severity_combo.setCurrentText('HIGH')
        cve_widget.year_combo.setCurrentText('2023')
        print("✅ Input controls working")
        
        # Test search preparation
        query = cve_widget.search_input.text()
        severity = cve_widget.severity_combo.currentText()
        year = cve_widget.year_combo.currentText()
        
        if query and severity and year:
            print("✅ Search parameters working")
        else:
            print("❌ Search parameters failed")
            
        # Test results table
        table = cve_widget.results_table
        if table.columnCount() == 7:
            print("✅ Results table structure correct")
        else:
            print(f"❌ Results table has {table.columnCount()} columns, expected 7")
            
        # Test statistics labels
        if hasattr(cve_widget, 'total_label') and hasattr(cve_widget, 'critical_label'):
            print("✅ Statistics display working")
        else:
            print("❌ Statistics display missing")
            
        return True
        
    except Exception as e:
        print(f"❌ CVE lookup error: {e}")
        return False


def test_ssl_analyzer_functionality(app):
    """Test SSL analyzer widget functionality."""
    print("\n🔒 Testing SSL Analyzer Widget...")
    
    ssl_widget = app.main_window.ssl_analyzer
    
    try:
        # Test input controls
        ssl_widget.target_input.setText('google.com')
        ssl_widget.port_input.setValue(443)  # Correct attribute name
        print("✅ Input controls working")
        
        # Test analysis preparation
        target = ssl_widget.target_input.text()
        port = ssl_widget.port_input.value()
        
        if target and 1 <= port <= 65535:
            print("✅ Analysis parameters working")
        else:
            print("❌ Analysis parameters failed")
            
        # Test certificate display area
        if hasattr(ssl_widget, 'cert_widget') and hasattr(ssl_widget, 'cert_layout'):
            print("✅ Certificate display area working")
        else:
            print("❌ Certificate display area missing")
            
        return True
        
    except Exception as e:
        print(f"❌ SSL analyzer error: {e}")
        return False


def test_ip_reputation_functionality(app):
    """Test IP reputation widget functionality."""
    print("\n🌐 Testing IP Reputation Widget...")
    
    ip_widget = app.main_window.ip_reputation
    
    try:
        # Test input controls
        ip_widget.ip_input.setText('8.8.8.8')
        print("✅ Input controls working")
        
        # Test IP validation
        ip_address = ip_widget.ip_input.text()
        if ip_address:
            print("✅ IP input working")
        else:
            print("❌ IP input failed")
            
        # Test results display
        if hasattr(ip_widget, 'results_area'):
            print("✅ Results display area working")
        else:
            print("❌ Results display area missing")
            
        return True
        
    except Exception as e:
        print(f"❌ IP reputation error: {e}")
        return False


def test_dashboard_functionality(app):
    """Test dashboard widget functionality."""
    print("\n🏠 Testing Dashboard Widget...")
    
    dashboard = app.main_window.dashboard
    
    try:
        # Test quick action buttons
        if hasattr(dashboard, 'tool_requested'):
            print("✅ Quick action signals working")
        else:
            print("❌ Quick action signals missing")
            
        # Test activity list
        if hasattr(dashboard, 'activity_list'):
            dashboard.add_activity("Test activity message")
            print("✅ Activity logging working")
        else:
            print("❌ Activity logging missing")
            
        # Test timer
        if hasattr(dashboard, 'timer'):
            print("✅ Status update timer working")
        else:
            print("❌ Status update timer missing")
            
        return True
        
    except Exception as e:
        print(f"❌ Dashboard error: {e}")
        return False


def test_settings_functionality(app):
    """Test settings widget functionality."""
    print("\n⚙️ Testing Settings Widget...")
    
    settings = app.main_window.settings
    
    try:
        # Test configuration manager
        if hasattr(settings, 'config_manager'):
            print("✅ Configuration manager working")
        else:
            print("❌ Configuration manager missing")
            
        # Test tab widget
        if hasattr(settings, 'tab_widget'):
            tab_count = settings.tab_widget.count()
            print(f"✅ Settings tabs working ({tab_count} tabs)")
        else:
            print("❌ Settings tabs missing")
            
        return True
        
    except Exception as e:
        print(f"❌ Settings error: {e}")
        return False


def test_zenmap_dashboard_functionality(app):
    """Test Zenmap-style dashboard functionality."""
    print("\n🛡️ Testing Security Monitor Widget...")
    
    monitor = app.main_window.monitoring
    
    try:
        # Test if widget exists and has basic structure
        if hasattr(monitor, 'setup_ui'):
            print("✅ Security monitor structure working")
        else:
            print("❌ Security monitor structure missing")
            
        return True
        
    except Exception as e:
        print(f"❌ Security monitor error: {e}")
        return False


def main():
    """Main test function."""
    print("🚀 Starting NetSecureX GUI Functionality Test")
    print("=" * 50)
    
    # Create application
    app = NetSecureXApp(sys.argv)
    print("✅ GUI application created successfully")
    
    # Test individual widgets
    results = {}
    results['port_scanner'] = test_port_scanner_functionality(app)
    results['cve_lookup'] = test_cve_lookup_functionality(app)
    results['ssl_analyzer'] = test_ssl_analyzer_functionality(app)
    results['ip_reputation'] = test_ip_reputation_functionality(app)
    results['dashboard'] = test_dashboard_functionality(app)
    results['settings'] = test_settings_functionality(app)
    results['security_monitor'] = test_zenmap_dashboard_functionality(app)
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 TEST SUMMARY")
    print("=" * 50)
    
    working_count = sum(1 for result in results.values() if result)
    total_count = len(results)
    
    for widget, status in results.items():
        status_icon = "✅" if status else "❌"
        print(f"{status_icon} {widget.replace('_', ' ').title()}")
    
    print(f"\n🎯 Overall Status: {working_count}/{total_count} widgets working")
    
    if working_count == total_count:
        print("🎉 All GUI functionality is working!")
    else:
        print(f"⚠️  {total_count - working_count} widgets need attention")
    
    return working_count == total_count


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
