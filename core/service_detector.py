"""
Service Detection Module for NetSecureX
=======================================

Enhanced service detection and version fingerprinting capabilities.
Provides comprehensive service identification, version detection,
and protocol-specific probing for accurate service enumeration.
"""

import asyncio
import socket
import re
import hashlib
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime

from utils.logger import SecurityLogger


@dataclass
class ServiceSignature:
    """Service signature for pattern matching."""
    service: str
    product: Optional[str] = None
    version: Optional[str] = None
    pattern: str = ""
    flags: int = 0  # regex flags
    confidence: float = 1.0
    port_hint: Optional[int] = None


@dataclass
class ServiceDetectionResult:
    """Result of service detection."""
    host: str
    port: int
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    confidence: float = 0.0
    detection_method: str = "unknown"
    additional_info: Dict[str, Any] = None
    timestamp: Optional[str] = None
    
    def __post_init__(self):
        if self.additional_info is None:
            self.additional_info = {}
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat() + 'Z'
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


class ServiceDetector:
    """
    Advanced service detection and version fingerprinting.
    """
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.logger = SecurityLogger(__name__)
        
        # Load service signatures
        self.signatures = self._load_signatures()
        
        # Protocol-specific probes
        self.probes = self._load_probes()
        
        # Common service mappings
        self.port_services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc', 139: 'netbios-ssn',
            143: 'imap', 443: 'https', 445: 'microsoft-ds', 993: 'imaps', 995: 'pop3s',
            1433: 'mssql', 3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 5900: 'vnc',
            8080: 'http-proxy', 8443: 'https-alt'
        }
    
    def _load_signatures(self) -> List[ServiceSignature]:
        """Load service detection signatures."""
        signatures = [
            # SSH signatures
            ServiceSignature("ssh", "OpenSSH", r"SSH-2\.0-OpenSSH_([0-9\.]+)", confidence=0.95),
            ServiceSignature("ssh", "Dropbear", r"SSH-2\.0-dropbear_([0-9\.]+)", confidence=0.95),
            ServiceSignature("ssh", "libssh", r"SSH-2\.0-libssh_([0-9\.]+)", confidence=0.90),
            
            # HTTP signatures
            ServiceSignature("http", "Apache", r"Server: Apache/([0-9\.]+)", confidence=0.90),
            ServiceSignature("http", "nginx", r"Server: nginx/([0-9\.]+)", confidence=0.90),
            ServiceSignature("http", "IIS", r"Server: Microsoft-IIS/([0-9\.]+)", confidence=0.90),
            ServiceSignature("http", "lighttpd", r"Server: lighttpd/([0-9\.]+)", confidence=0.90),
            
            # FTP signatures
            ServiceSignature("ftp", "vsftpd", r"220.*vsftpd ([0-9\.]+)", confidence=0.90),
            ServiceSignature("ftp", "ProFTPD", r"220.*ProFTPD ([0-9\.]+)", confidence=0.90),
            ServiceSignature("ftp", "Pure-FTPd", r"220.*Pure-FTPd ([0-9\.]+)", confidence=0.90),
            
            # SMTP signatures
            ServiceSignature("smtp", "Postfix", r"220.*Postfix", confidence=0.85),
            ServiceSignature("smtp", "Sendmail", r"220.*Sendmail ([0-9\.]+)", confidence=0.85),
            ServiceSignature("smtp", "Exim", r"220.*Exim ([0-9\.]+)", confidence=0.85),
            
            # Database signatures
            ServiceSignature("mysql", "MySQL", r"([0-9\.]+)-.*MySQL", confidence=0.90),
            ServiceSignature("postgresql", "PostgreSQL", r"PostgreSQL ([0-9\.]+)", confidence=0.90),
            ServiceSignature("mssql", "Microsoft SQL Server", r"Microsoft SQL Server.*([0-9\.]+)", confidence=0.90),
            
            # DNS signatures
            ServiceSignature("dns", "BIND", r"BIND ([0-9\.]+)", confidence=0.85),
            ServiceSignature("dns", "dnsmasq", r"dnsmasq-([0-9\.]+)", confidence=0.85),
            
            # Generic patterns
            ServiceSignature("unknown", None, r"([A-Za-z0-9\-_]+)/([0-9\.]+)", confidence=0.50),
        ]
        
        return signatures
    
    def _load_probes(self) -> Dict[str, Dict[str, Any]]:
        """Load protocol-specific probes."""
        probes = {
            'http': {
                'probe': b'GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: NetSecureX/1.0\r\nConnection: close\r\n\r\n',
                'expect_response': True,
                'parse_headers': True
            },
            'https': {
                'probe': b'GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: NetSecureX/1.0\r\nConnection: close\r\n\r\n',
                'expect_response': True,
                'parse_headers': True,
                'ssl': True
            },
            'ssh': {
                'probe': b'SSH-2.0-NetSecureX_Scanner\r\n',
                'expect_response': True,
                'immediate': True
            },
            'ftp': {
                'probe': b'',  # FTP sends banner immediately
                'expect_response': True,
                'immediate': True
            },
            'smtp': {
                'probe': b'EHLO scanner.local\r\n',
                'expect_response': True,
                'wait_for_banner': True
            },
            'pop3': {
                'probe': b'',  # POP3 sends banner immediately
                'expect_response': True,
                'immediate': True
            },
            'imap': {
                'probe': b'',  # IMAP sends banner immediately
                'expect_response': True,
                'immediate': True
            },
            'telnet': {
                'probe': b'',  # Telnet often sends banner immediately
                'expect_response': True,
                'immediate': True
            }
        }
        
        return probes
    
    async def detect_service(self, host: str, port: int, banner: Optional[str] = None) -> ServiceDetectionResult:
        """
        Detect service and version for a given host:port.
        
        Args:
            host: Target hostname or IP
            port: Target port
            banner: Optional banner from initial connection
            
        Returns:
            ServiceDetectionResult with detection information
        """
        result = ServiceDetectionResult(host=host, port=port)
        
        # Start with port-based hint
        if port in self.port_services:
            result.service = self.port_services[port]
            result.confidence = 0.3  # Low confidence, just a hint
            result.detection_method = "port_hint"
        
        # If we have a banner, analyze it first
        if banner:
            banner_result = self._analyze_banner(banner, port)
            if banner_result.confidence > result.confidence:
                result = banner_result
                result.host = host
                result.port = port
                result.banner = banner
                result.detection_method = "banner_analysis"
        
        # If confidence is still low, try active probing
        if result.confidence < 0.7:
            probe_result = await self._active_probe(host, port)
            if probe_result.confidence > result.confidence:
                result = probe_result
                result.host = host
                result.port = port
                result.detection_method = "active_probe"
        
        return result
    
    def _analyze_banner(self, banner: str, port: int) -> ServiceDetectionResult:
        """Analyze banner string against known signatures."""
        result = ServiceDetectionResult(host="", port=port, banner=banner)
        
        # Try each signature
        for signature in self.signatures:
            # Skip if port hint doesn't match
            if signature.port_hint and signature.port_hint != port:
                continue
            
            # Try to match pattern
            try:
                match = re.search(signature.pattern, banner, signature.flags)
                if match:
                    result.service = signature.service
                    result.product = signature.product
                    
                    # Extract version if pattern has groups
                    if match.groups():
                        result.version = match.group(1)
                    
                    result.confidence = signature.confidence
                    break
                    
            except re.error as e:
                self.logger.logger.warning(f"Invalid regex pattern: {signature.pattern}: {e}")
                continue
        
        return result
    
    async def _active_probe(self, host: str, port: int) -> ServiceDetectionResult:
        """Perform active service probing."""
        result = ServiceDetectionResult(host=host, port=port)
        
        # Determine which probe to use
        service_hint = self.port_services.get(port, 'unknown')
        probe_config = self.probes.get(service_hint)
        
        if not probe_config:
            # Try generic probing
            return await self._generic_probe(host, port)
        
        try:
            # Connect to service
            if probe_config.get('ssl', False):
                # SSL/TLS connection
                import ssl
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=context),
                    timeout=self.timeout
                )
            else:
                # Plain connection
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout
                )
            
            # Handle immediate banner services
            if probe_config.get('immediate', False):
                response = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                if response:
                    result.banner = response.decode('utf-8', errors='ignore').strip()
                    banner_result = self._analyze_banner(result.banner, port)
                    if banner_result.confidence > 0:
                        result = banner_result
                        result.host = host
                        result.port = port
            
            # Send probe if specified
            probe_data = probe_config.get('probe', b'')
            if probe_data:
                if b'%s' in probe_data:
                    probe_data = probe_data % host.encode()
                
                writer.write(probe_data)
                await writer.drain()
                
                # Read response
                if probe_config.get('expect_response', False):
                    response = await asyncio.wait_for(reader.read(4096), timeout=3.0)
                    if response:
                        response_str = response.decode('utf-8', errors='ignore').strip()
                        result.banner = response_str
                        
                        # Analyze response
                        banner_result = self._analyze_banner(response_str, port)
                        if banner_result.confidence > result.confidence:
                            result = banner_result
                            result.host = host
                            result.port = port
            
            # Close connection
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            result.additional_info['probe_error'] = str(e)
            self.logger.logger.debug(f"Active probe failed for {host}:{port}: {e}")
        
        return result
    
    async def _generic_probe(self, host: str, port: int) -> ServiceDetectionResult:
        """Generic probing for unknown services."""
        result = ServiceDetectionResult(host=host, port=port)
        
        try:
            # Simple connection test
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            
            # Try to read any immediate banner
            try:
                response = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                if response:
                    result.banner = response.decode('utf-8', errors='ignore').strip()
                    banner_result = self._analyze_banner(result.banner, port)
                    if banner_result.confidence > 0:
                        result = banner_result
                        result.host = host
                        result.port = port
            except asyncio.TimeoutError:
                pass  # No immediate banner
            
            # Try sending HTTP probe as fallback
            try:
                http_probe = f'GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'
                writer.write(http_probe.encode())
                await writer.drain()
                
                response = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                if response and b'HTTP/' in response:
                    result.service = 'http'
                    result.confidence = 0.6
                    result.banner = response.decode('utf-8', errors='ignore').strip()[:200]
                    
            except Exception:
                pass  # Not HTTP
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            result.additional_info['generic_probe_error'] = str(e)
        
        return result
    
    async def detect_multiple_services(self, targets: List[Tuple[str, int]]) -> List[ServiceDetectionResult]:
        """
        Detect services for multiple host:port combinations.
        
        Args:
            targets: List of (host, port) tuples
            
        Returns:
            List of ServiceDetectionResult objects
        """
        tasks = [self.detect_service(host, port) for host, port in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        valid_results = []
        for result in results:
            if isinstance(result, ServiceDetectionResult):
                valid_results.append(result)
            elif isinstance(result, Exception):
                self.logger.logger.error(f"Service detection error: {result}")
        
        return valid_results
    
    def get_service_info(self, service: str) -> Dict[str, Any]:
        """Get additional information about a detected service."""
        service_info = {
            'ssh': {
                'description': 'Secure Shell (SSH) remote access protocol',
                'security_notes': 'Check for weak authentication, outdated versions',
                'common_ports': [22, 2222],
                'risk_level': 'medium'
            },
            'http': {
                'description': 'Hypertext Transfer Protocol web server',
                'security_notes': 'Check for web vulnerabilities, directory traversal',
                'common_ports': [80, 8080, 8000],
                'risk_level': 'medium'
            },
            'https': {
                'description': 'HTTP over SSL/TLS encrypted web server',
                'security_notes': 'Check SSL/TLS configuration, certificate validity',
                'common_ports': [443, 8443],
                'risk_level': 'low'
            },
            'ftp': {
                'description': 'File Transfer Protocol server',
                'security_notes': 'Often allows anonymous access, unencrypted',
                'common_ports': [21],
                'risk_level': 'high'
            },
            'smtp': {
                'description': 'Simple Mail Transfer Protocol server',
                'security_notes': 'Check for open relay, authentication bypass',
                'common_ports': [25, 587, 465],
                'risk_level': 'medium'
            },
            'mysql': {
                'description': 'MySQL database server',
                'security_notes': 'Check for weak passwords, remote access',
                'common_ports': [3306],
                'risk_level': 'high'
            },
            'postgresql': {
                'description': 'PostgreSQL database server',
                'security_notes': 'Check for weak passwords, remote access',
                'common_ports': [5432],
                'risk_level': 'high'
            },
            'rdp': {
                'description': 'Remote Desktop Protocol server',
                'security_notes': 'Check for weak passwords, BlueKeep vulnerability',
                'common_ports': [3389],
                'risk_level': 'high'
            }
        }
        
        return service_info.get(service, {
            'description': f'Unknown service: {service}',
            'security_notes': 'Requires manual investigation',
            'common_ports': [],
            'risk_level': 'unknown'
        })
