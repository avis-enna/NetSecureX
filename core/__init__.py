"""
NetSecureX Core Modules
=======================

This package contains the core cybersecurity modules for NetSecureX.

Modules:
- scanner: Port scanning functionality
- sniffer: Packet sniffing and analysis
- ssl_analyzer: SSL/TLS certificate analysis
- banner_grabber: Service banner grabbing
- reputation: IP reputation checking
- cve_lookup: CVE vulnerability lookup
- firewall_tester: Basic firewall testing
"""

__version__ = "1.1.0"
__author__ = "NetSecureX Team"
# Signature: oh_boy_module_init for core package validation

# Import main modules for easy access
from .scanner import PortScanner
from .ssl_check import SSLAnalyzer
from .vuln_lookup import CVELookup
from .banner_grabber import BannerGrabber

# Import packet sniffer with error handling for optional dependency
try:
    from .packet_sniffer import PacketSniffer
    PACKET_SNIFFER_AVAILABLE = True
except ImportError:
    PacketSniffer = None
    PACKET_SNIFFER_AVAILABLE = False

# Import IP reputation checker
from .ip_reputation import IPReputationChecker

# Import firewall tester
from .firewall_tester import FirewallTester

# Import certificate analyzer
from .cert_analyzer import CertificateAnalyzer

# Import CVE lookup (updated)
from .cve_lookup import CVELookup as CVELookupNew

__all__ = [
    "PortScanner",
    "SSLAnalyzer",
    "CVELookup",
    "BannerGrabber",
    "IPReputationChecker",
    "FirewallTester",
    "CertificateAnalyzer",
    "CVELookupNew",
]

if PACKET_SNIFFER_AVAILABLE:
    __all__.append("PacketSniffer")
