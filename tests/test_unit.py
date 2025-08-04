#!/usr/bin/env python3
"""
Unit Tests for NetSecureX
=========================

Basic unit tests that can run in CI environments without external dependencies.
These tests focus on imports, initialization, and basic functionality.
"""

import pytest
import sys
import os
import platform
from pathlib import Path

# Cross-platform path handling with debugging
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Windows-specific path handling
if platform.system() == "Windows":
    # Ensure Windows paths are properly normalized
    project_root = project_root.resolve()
    sys.path.insert(0, str(project_root).replace('\\', '/'))
    # Add current directory for Windows compatibility
    sys.path.insert(0, os.getcwd())

# Debug information for CI troubleshooting
print(f"🔧 Platform: {platform.system()} {platform.release()}")
print(f"📁 Project root: {project_root}")
print(f"🐍 Python version: {sys.version}")
print(f"📍 Current working directory: {os.getcwd()}")
print(f"🛤️ Python path entries:")
for i, path in enumerate(sys.path[:5]):  # Show first 5 entries
    print(f"  {i}: {path}")

# Verify core directory exists
core_dir = project_root / "core"
print(f"📂 Core directory exists: {core_dir.exists()}")
if core_dir.exists():
    core_files = list(core_dir.glob("*.py"))
    print(f"📄 Core Python files: {[f.name for f in core_files[:5]]}")  # Show first 5


def test_imports():
    """Test that all core modules can be imported."""
    print("\n🧪 Testing imports...")

    # Test imports one by one for better error reporting
    modules_to_test = [
        ("core.scanner", "PortScanner"),
        ("core.advanced_scanner", "AdvancedPortScanner"),
        ("core.service_detector", "ServiceDetector"),
        ("utils.logger", "SecurityLogger"),
        ("utils.network", "validate_ip"),
    ]

    for module_name, class_name in modules_to_test:
        try:
            print(f"  📦 Importing {module_name}.{class_name}...")
            module = __import__(module_name, fromlist=[class_name])
            getattr(module, class_name)
            print(f"  ✅ {module_name}.{class_name} imported successfully")
        except ImportError as e:
            print(f"  ❌ Failed to import {module_name}.{class_name}: {e}")
            # Windows-specific debugging
            if platform.system() == "Windows":
                print(f"  🪟 Windows debugging info:")
                print(f"     Current directory: {os.getcwd()}")
                print(f"     Module path attempted: {module_name}")
                print(f"     Python path: {sys.path[:3]}")
            pytest.fail(f"Import failed for {module_name}.{class_name}: {e}")
        except AttributeError as e:
            print(f"  ❌ {class_name} not found in {module_name}: {e}")
            pytest.fail(f"Attribute error for {module_name}.{class_name}: {e}")

    print("  🎉 All imports successful!")


def test_port_scanner_initialization():
    """Test that port scanner initializes correctly."""
    from core.scanner import PortScanner

    scanner = PortScanner()
    assert scanner.timeout == 3.0
    assert scanner.max_concurrent == 100
    assert scanner.delay == 0.01


def test_advanced_scanner_initialization():
    """Test that advanced scanner initializes correctly."""
    from core.advanced_scanner import AdvancedPortScanner, ScanType

    scanner = AdvancedPortScanner()
    assert scanner is not None

    # Test available scan types
    scan_types = scanner.get_available_scan_types()
    assert len(scan_types) > 0
    assert ScanType.TCP_CONNECT in scan_types


def test_service_detector_initialization():
    """Test that service detector initializes correctly."""
    from core.service_detector import ServiceDetector

    detector = ServiceDetector()
    assert detector is not None
    assert hasattr(detector, 'detect_service')


def test_network_utils():
    """Test network utility functions."""
    from utils.network import validate_ip, is_private_ip

    # Test IP validation
    assert validate_ip("127.0.0.1") is True
    assert validate_ip("192.168.1.1") is True
    assert validate_ip("8.8.8.8") is True
    assert validate_ip("::1") is True  # IPv6 localhost

    # Test invalid IPs
    assert validate_ip("256.256.256.256") is False
    assert validate_ip("not.an.ip") is False
    assert validate_ip("") is False
    assert validate_ip("192.168.1") is False

    # Test private IP detection
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("10.0.0.1") is True
    assert is_private_ip("172.16.0.1") is True
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("1.1.1.1") is False


def test_security_logger():
    """Test security logger initialization."""
    from utils.logger import SecurityLogger

    logger = SecurityLogger("test")
    assert logger is not None
    assert logger.logger is not None


def test_scan_result_creation():
    """Test creating scan results."""
    from core.scanner import ScanResult

    result = ScanResult(
        ip="127.0.0.1",
        port=80,
        status="open",
        service="http",
        banner="Apache/2.4.41",
        timestamp="2025-08-04T12:00:00Z",
        response_time=0.1
    )

    assert result.ip == "127.0.0.1"
    assert result.port == 80
    assert result.status == "open"
    assert result.service == "http"
    assert result.banner == "Apache/2.4.41"
    assert result.response_time == 0.1


if __name__ == "__main__":
    # Run tests directly without pytest for CI compatibility
    print("🧪 Running NetSecureX Unit Tests...")

    test_functions = [
        test_imports,
        test_port_scanner_initialization,
        test_advanced_scanner_initialization,
        test_service_detector_initialization,
        test_network_utils,
        test_security_logger,
        test_scan_result_creation
    ]

    passed = 0
    failed = 0

    for test_func in test_functions:
        try:
            print(f"Running {test_func.__name__}...", end=" ")
            test_func()
            print("✅ PASSED")
            passed += 1
        except Exception as e:
            print(f"❌ FAILED: {e}")
            failed += 1

    print(f"\n📊 Test Results: {passed} passed, {failed} failed")

    if failed > 0:
        exit(1)
    else:
        print("🎉 All tests passed!")
        exit(0)
