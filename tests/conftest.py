"""
Pytest configuration and fixtures for NetSecureX tests.
"""

import pytest
import asyncio
import sys
from pathlib import Path
from unittest.mock import Mock, patch

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_scanner():
    """Create a mock scanner for testing."""
    scanner = Mock()
    scanner.timeout = 3.0
    scanner.max_concurrent = 100
    scanner.delay = 0.01
    return scanner


@pytest.fixture
def mock_scan_result():
    """Create a mock scan result for testing."""
    from core.scanner import ScanResult
    return ScanResult(
        port=80,
        status="open",
        service="http",
        banner="Apache/2.4.41",
        timestamp="2025-08-04T12:00:00Z",
        response_time=0.1
    )


@pytest.fixture
def mock_network():
    """Mock network operations to avoid real network calls."""
    with patch('socket.socket'), \
         patch('asyncio.open_connection'), \
         patch('subprocess.run'):
        yield


@pytest.fixture(autouse=True)
def disable_gui():
    """Automatically disable GUI operations for all tests."""
    with patch('PySide6.QtWidgets.QApplication'), \
         patch('PySide6.QtCore.QTimer'), \
         patch('gui.app.NetSecureXApp'):
        yield


# Pytest configuration
def pytest_configure(config):
    """Configure pytest settings."""
    # Add custom markers
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "network: marks tests as requiring network access"
    )
    config.addinivalue_line(
        "markers", "gui: marks tests as requiring GUI"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers automatically."""
    for item in items:
        # Mark GUI tests
        if "gui" in item.nodeid.lower():
            item.add_marker(pytest.mark.gui)
        
        # Mark network tests
        if any(keyword in item.nodeid.lower() for keyword in ["network", "scan", "nmap"]):
            item.add_marker(pytest.mark.network)
        
        # Mark slow tests
        if any(keyword in item.nodeid.lower() for keyword in ["real", "integration"]):
            item.add_marker(pytest.mark.slow)
