#!/usr/bin/env python3
"""
Unit Tests for NetSecureX
=========================

Basic unit tests that can run in CI environments without external dependencies.
These tests focus on imports, initialization, and basic functionality.
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def test_imports():
    """Test that all core modules can be imported."""
    try:
        from core.scanner import PortScanner
        from core.advanced_scanner import AdvancedPortScanner, ScanType, TimingTemplate
        from core.service_detector import ServiceDetector
        from utils.logger import SecurityLogger
        from utils.network import validate_ip, is_private_ip
        assert True  # If we get here, imports worked
    except ImportError as e:
        pytest.fail(f"Import failed: {e}")


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
    pytest.main([__file__, "-v"])
