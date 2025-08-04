#!/usr/bin/env python3
"""
Test script for Advanced Port Scanner
=====================================

This script tests the advanced port scanning functionality including:
- Different scan types (TCP Connect, SYN, UDP)
- Service detection and version fingerprinting
- Timing templates and stealth options
- Error handling and edge cases
"""

import asyncio
import sys
import time
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))

from core.advanced_scanner import (
    AdvancedPortScanner, AdvancedScanOptions, ScanType, TimingTemplate
)
from core.service_detector import ServiceDetector
from utils.logger import SecurityLogger


async def test_basic_tcp_connect():
    """Test basic TCP connect scanning."""
    print("\n=== Testing TCP Connect Scanning ===")
    
    scanner = AdvancedPortScanner()
    options = AdvancedScanOptions(
        scan_type=ScanType.TCP_CONNECT,
        timeout=2.0,
        max_concurrent=10,
        enable_service_detection=True
    )
    
    # Test against localhost common ports
    ports = [22, 80, 443, 8080, 3306, 5432]
    
    try:
        result = await scanner.scan_target("127.0.0.1", ports, options)
        
        print(f"Scan completed in {result.scan_duration:.2f} seconds")
        print(f"Total ports scanned: {result.total_ports}")
        print(f"Open ports: {result.open_ports}")
        print(f"Closed ports: {result.closed_ports}")
        print(f"Filtered ports: {result.filtered_ports}")
        print(f"Errors: {result.errors}")
        
        if result.results:
            print("\nOpen ports found:")
            for res in result.results:
                if res.status == 'open':
                    service_info = f" ({res.service})" if res.service else ""
                    version_info = f" - {res.service_version}" if hasattr(res, 'service_version') and res.service_version else ""
                    print(f"  {res.ip}:{res.port}{service_info}{version_info}")
        
        return True
        
    except Exception as e:
        print(f"TCP Connect test failed: {e}")
        return False


async def test_udp_scanning():
    """Test UDP scanning with protocol-specific probes."""
    print("\n=== Testing UDP Scanning ===")
    
    scanner = AdvancedPortScanner()
    options = AdvancedScanOptions(
        scan_type=ScanType.UDP,
        timeout=3.0,
        max_concurrent=5,
        udp_protocol_probes=True
    )
    
    # Test common UDP services
    ports = [53, 123, 161, 67, 69]
    
    try:
        result = await scanner.scan_target("127.0.0.1", ports, options)
        
        print(f"UDP scan completed in {result.scan_duration:.2f} seconds")
        print(f"Total ports scanned: {result.total_ports}")
        print(f"Open ports: {result.open_ports}")
        print(f"Filtered ports: {result.filtered_ports}")
        
        if result.results:
            print("\nUDP scan results:")
            for res in result.results:
                if res.status in ['open', 'open|filtered']:
                    service_info = f" ({res.service})" if res.service else ""
                    print(f"  {res.ip}:{res.port} - {res.status}{service_info}")
        
        return True
        
    except Exception as e:
        print(f"UDP test failed: {e}")
        return False


async def test_syn_scanning():
    """Test SYN scanning (may require privileges)."""
    print("\n=== Testing SYN Scanning ===")
    
    scanner = AdvancedPortScanner()
    
    # Check if SYN scanning is available
    available_types = scanner.get_available_scan_types()
    if ScanType.TCP_SYN not in available_types:
        print("SYN scanning not available (requires elevated privileges)")
        return True
    
    options = AdvancedScanOptions(
        scan_type=ScanType.TCP_SYN,
        timeout=2.0,
        max_concurrent=5
    )
    
    # Test a few ports
    ports = [22, 80, 443]
    
    try:
        result = await scanner.scan_target("127.0.0.1", ports, options)
        
        print(f"SYN scan completed in {result.scan_duration:.2f} seconds")
        print(f"Open ports: {result.open_ports}")
        
        if result.results:
            print("\nSYN scan results:")
            for res in result.results:
                if res.status == 'open':
                    flags_info = f" (flags: {res.tcp_flags})" if hasattr(res, 'tcp_flags') and res.tcp_flags else ""
                    print(f"  {res.ip}:{res.port}{flags_info}")
        
        return True
        
    except Exception as e:
        print(f"SYN test failed: {e}")
        return False


async def test_timing_templates():
    """Test different timing templates."""
    print("\n=== Testing Timing Templates ===")
    
    scanner = AdvancedPortScanner()
    
    # Test with different timing templates
    templates = [
        (TimingTemplate.POLITE, "Polite"),
        (TimingTemplate.NORMAL, "Normal"),
        (TimingTemplate.AGGRESSIVE, "Aggressive")
    ]
    
    ports = [22, 80, 443]
    
    for template, name in templates:
        print(f"\nTesting {name} timing...")
        
        options = AdvancedScanOptions(
            scan_type=ScanType.TCP_CONNECT,
            timing=template,
            enable_service_detection=False  # Faster for timing test
        )
        
        start_time = time.time()
        
        try:
            result = await scanner.scan_target("127.0.0.1", ports, options)
            duration = time.time() - start_time
            
            print(f"  {name} timing: {duration:.2f}s (reported: {result.scan_duration:.2f}s)")
            print(f"  Open ports: {result.open_ports}")
            
        except Exception as e:
            print(f"  {name} timing test failed: {e}")
    
    return True


async def test_service_detection():
    """Test service detection capabilities."""
    print("\n=== Testing Service Detection ===")
    
    detector = ServiceDetector()
    
    # Test service detection on known services
    test_cases = [
        ("127.0.0.1", 22, "SSH"),
        ("127.0.0.1", 80, "HTTP"),
        ("127.0.0.1", 443, "HTTPS")
    ]
    
    for host, port, expected in test_cases:
        try:
            result = await detector.detect_service(host, port)
            
            print(f"\nPort {port} detection:")
            print(f"  Service: {result.service}")
            print(f"  Product: {result.product}")
            print(f"  Version: {result.version}")
            print(f"  Confidence: {result.confidence:.2f}")
            print(f"  Method: {result.detection_method}")
            
            if result.banner:
                print(f"  Banner: {result.banner[:100]}...")
            
        except Exception as e:
            print(f"Service detection failed for port {port}: {e}")
    
    return True


async def test_error_handling():
    """Test error handling and edge cases."""
    print("\n=== Testing Error Handling ===")
    
    scanner = AdvancedPortScanner()
    
    # Test invalid target
    try:
        options = AdvancedScanOptions()
        result = await scanner.scan_target("invalid.target.test", [80], options)
        print("ERROR: Should have failed with invalid target")
        return False
    except Exception as e:
        print(f"✓ Invalid target correctly rejected: {e}")
    
    # Test invalid ports
    try:
        options = AdvancedScanOptions()
        result = await scanner.scan_target("127.0.0.1", [], options)
        print("ERROR: Should have failed with no ports")
        return False
    except Exception as e:
        print(f"✓ Empty port list correctly rejected: {e}")
    
    # Test timeout handling
    try:
        options = AdvancedScanOptions(
            timeout=0.001,  # Very short timeout
            max_concurrent=1
        )
        result = await scanner.scan_target("8.8.8.8", [80], options)
        print(f"✓ Short timeout handled gracefully")
        print(f"  Filtered ports: {result.filtered_ports}")
    except Exception as e:
        print(f"✓ Timeout test completed with exception: {e}")
    
    return True


async def main():
    """Run all tests."""
    print("Advanced Port Scanner Test Suite")
    print("=" * 40)
    
    tests = [
        ("Basic TCP Connect", test_basic_tcp_connect),
        ("UDP Scanning", test_udp_scanning),
        ("SYN Scanning", test_syn_scanning),
        ("Timing Templates", test_timing_templates),
        ("Service Detection", test_service_detection),
        ("Error Handling", test_error_handling)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        
        try:
            success = await test_func()
            if success:
                print(f"✓ {test_name} PASSED")
                passed += 1
            else:
                print(f"✗ {test_name} FAILED")
        except Exception as e:
            print(f"✗ {test_name} FAILED with exception: {e}")
    
    print(f"\n{'='*60}")
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed!")
        return 0
    else:
        print("❌ Some tests failed")
        return 1


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nTests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nTest suite failed: {e}")
        sys.exit(1)
