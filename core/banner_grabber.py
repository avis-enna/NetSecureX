"""
Banner Grabbing and Version Detection Module for NetSecureX
===========================================================

This module provides banner grabbing and service version detection including:
- TCP banner grabbing for various protocols
- Intelligent version parsing and extraction
- Protocol-specific service identification
- Integration with CVE lookup for vulnerability assessment
- Safe scanning modes to avoid IDS/IPS detection
"""

import asyncio
import re
import socket
import ssl
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
import json

from utils.logger import SecurityLogger
from utils.network import validate_ip, is_port_valid


@dataclass
class BannerResult:
    """Data class for banner grabbing and service detection results."""
    host: str
    port: int
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    protocol: Optional[str] = None
    status: str = "unknown"  # 'detected', 'partial', 'failed', 'timeout'
    confidence: float = 0.0  # 0.0 to 1.0
    additional_info: Optional[Dict[str, Any]] = None
    timestamp: Optional[str] = None
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    @property
    def product_version(self) -> Optional[str]:
        """Get product:version string for CVE lookup."""
        if self.product and self.version:
            return f"{self.product}:{self.version}"
        return None


class ServiceParser:
    """Base class for service-specific parsers."""
    
    def __init__(self):
        self.logger = SecurityLogger(__name__)
    
    def parse(self, banner: str, host: str, port: int) -> BannerResult:
        """Parse banner and extract service information."""
        raise NotImplementedError
    
    def extract_version(self, text: str, patterns: List[str]) -> Optional[str]:
        """Extract version using regex patterns."""
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1) if match.groups() else match.group(0)
        return None
    
    def normalize_product_name(self, product: str) -> str:
        """Normalize product name for CVE lookup."""
        # Common product name mappings
        mappings = {
            'httpd': 'apache',
            'apache_httpd': 'apache',
            'apache_http_server': 'apache',
            'openssh': 'openssh',
            'mysql': 'mysql',
            'mariadb': 'mariadb',
            'postgresql': 'postgresql',
            'nginx': 'nginx',
            'iis': 'iis',
            'lighttpd': 'lighttpd',
            'vsftpd': 'vsftpd',
            'proftpd': 'proftpd',
            'postfix': 'postfix',
            'sendmail': 'sendmail',
            'dovecot': 'dovecot'
        }
        
        product_lower = product.lower().strip()
        return mappings.get(product_lower, product_lower)


class HTTPParser(ServiceParser):
    """Parser for HTTP services."""
    
    def parse(self, banner: str, host: str, port: int) -> BannerResult:
        """Parse HTTP banner and extract server information."""
        result = BannerResult(
            host=host,
            port=port,
            service="http",
            protocol="http",
            banner=banner,
            timestamp=datetime.utcnow().isoformat() + 'Z'
        )
        
        # Extract Server header
        server_patterns = [
            r'Server:\s*([^\r\n]+)',
            r'server:\s*([^\r\n]+)'
        ]
        
        server_info = self.extract_version(banner, server_patterns)
        if server_info:
            result.additional_info = {"server_header": server_info}
            
            # Parse common server formats
            if 'apache' in server_info.lower():
                result.product = 'apache'
                version_match = re.search(r'apache[/\s]+(\d+\.\d+\.\d+)', server_info, re.IGNORECASE)
                if version_match:
                    result.version = version_match.group(1)
                    result.confidence = 0.9
                    result.status = "detected"
            
            elif 'nginx' in server_info.lower():
                result.product = 'nginx'
                version_match = re.search(r'nginx[/\s]+(\d+\.\d+\.\d+)', server_info, re.IGNORECASE)
                if version_match:
                    result.version = version_match.group(1)
                    result.confidence = 0.9
                    result.status = "detected"
            
            elif 'iis' in server_info.lower() or 'microsoft' in server_info.lower():
                result.product = 'iis'
                version_match = re.search(r'iis[/\s]+(\d+\.\d+)', server_info, re.IGNORECASE)
                if version_match:
                    result.version = version_match.group(1)
                    result.confidence = 0.8
                    result.status = "detected"
            
            elif 'lighttpd' in server_info.lower():
                result.product = 'lighttpd'
                version_match = re.search(r'lighttpd[/\s]+(\d+\.\d+\.\d+)', server_info, re.IGNORECASE)
                if version_match:
                    result.version = version_match.group(1)
                    result.confidence = 0.9
                    result.status = "detected"
        
        # Extract X-Powered-By header
        powered_by_patterns = [
            r'X-Powered-By:\s*([^\r\n]+)',
            r'x-powered-by:\s*([^\r\n]+)'
        ]
        
        powered_by = self.extract_version(banner, powered_by_patterns)
        if powered_by:
            if not result.additional_info:
                result.additional_info = {}
            result.additional_info["powered_by"] = powered_by
            
            # Parse PHP version
            if 'php' in powered_by.lower():
                php_match = re.search(r'php[/\s]+(\d+\.\d+\.\d+)', powered_by, re.IGNORECASE)
                if php_match and not result.product:
                    result.product = 'php'
                    result.version = php_match.group(1)
                    result.confidence = 0.7
                    result.status = "detected"
        
        if result.status == "unknown" and server_info:
            result.status = "partial"
            result.confidence = 0.3
        
        return result


class SSHParser(ServiceParser):
    """Parser for SSH services."""
    
    def parse(self, banner: str, host: str, port: int) -> BannerResult:
        """Parse SSH banner and extract version information."""
        result = BannerResult(
            host=host,
            port=port,
            service="ssh",
            protocol="ssh",
            banner=banner,
            timestamp=datetime.utcnow().isoformat() + 'Z'
        )
        
        # SSH banner format: SSH-2.0-OpenSSH_8.4p1 Ubuntu-6ubuntu2.1
        ssh_patterns = [
            r'SSH-[\d\.]+-(OpenSSH[_\s]+(\d+\.\d+))',
            r'SSH-[\d\.]+-(OpenSSH[_\s]+(\d+\.\d+\w*))',
            r'SSH-[\d\.]+-(.*?)[\s\r\n]'
        ]
        
        for pattern in ssh_patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                if 'openssh' in match.group(1).lower():
                    result.product = 'openssh'
                    if len(match.groups()) > 1:
                        result.version = match.group(2)
                    else:
                        # Extract version from the full match
                        version_match = re.search(r'(\d+\.\d+)', match.group(1))
                        if version_match:
                            result.version = version_match.group(1)
                    result.confidence = 0.9
                    result.status = "detected"
                    break
                else:
                    # Generic SSH server
                    result.product = 'ssh'
                    result.additional_info = {"ssh_version": match.group(1)}
                    result.confidence = 0.5
                    result.status = "partial"
        
        return result


class SMTPParser(ServiceParser):
    """Parser for SMTP services."""
    
    def parse(self, banner: str, host: str, port: int) -> BannerResult:
        """Parse SMTP banner and extract server information."""
        result = BannerResult(
            host=host,
            port=port,
            service="smtp",
            protocol="smtp",
            banner=banner,
            timestamp=datetime.utcnow().isoformat() + 'Z'
        )
        
        # SMTP banner patterns
        smtp_patterns = [
            r'220.*?(Postfix)\s*(\d+\.\d+\.\d+)?',
            r'220.*?(Sendmail)\s*(\d+\.\d+\.\d+)?',
            r'220.*?(Exim)\s*(\d+\.\d+)',
            r'220.*?(Microsoft ESMTP MAIL Service)',
            r'220\s+([^\s]+)\s+ESMTP\s+([^\s]+)'
        ]
        
        for pattern in smtp_patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                server_name = match.group(1).lower()
                
                if 'postfix' in server_name:
                    result.product = 'postfix'
                elif 'sendmail' in server_name:
                    result.product = 'sendmail'
                elif 'exim' in server_name:
                    result.product = 'exim'
                elif 'microsoft' in server_name:
                    result.product = 'exchange'
                
                if len(match.groups()) > 1 and match.group(2):
                    result.version = match.group(2)
                    result.confidence = 0.8
                    result.status = "detected"
                else:
                    result.confidence = 0.6
                    result.status = "partial"
                break
        
        return result


class FTPParser(ServiceParser):
    """Parser for FTP services."""
    
    def parse(self, banner: str, host: str, port: int) -> BannerResult:
        """Parse FTP banner and extract server information."""
        result = BannerResult(
            host=host,
            port=port,
            service="ftp",
            protocol="ftp",
            banner=banner,
            timestamp=datetime.utcnow().isoformat() + 'Z'
        )
        
        # FTP banner patterns
        ftp_patterns = [
            r'220.*?(vsftpd)\s*(\d+\.\d+\.\d+)',
            r'220.*?(ProFTPD)\s*(\d+\.\d+\.\d+)',
            r'220.*?(Pure-FTPd)\s*(\d+\.\d+\.\d+)',
            r'220.*?(FileZilla Server)\s*(\d+\.\d+\.\d+)',
            r'220.*?(Microsoft FTP Service)'
        ]
        
        for pattern in ftp_patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                server_name = match.group(1).lower()
                
                if 'vsftpd' in server_name:
                    result.product = 'vsftpd'
                elif 'proftpd' in server_name:
                    result.product = 'proftpd'
                elif 'pure-ftpd' in server_name:
                    result.product = 'pure-ftpd'
                elif 'filezilla' in server_name:
                    result.product = 'filezilla'
                elif 'microsoft' in server_name:
                    result.product = 'iis-ftp'
                
                if len(match.groups()) > 1 and match.group(2):
                    result.version = match.group(2)
                    result.confidence = 0.8
                    result.status = "detected"
                else:
                    result.confidence = 0.6
                    result.status = "partial"
                break
        
        return result


class MySQLParser(ServiceParser):
    """Parser for MySQL services."""

    def parse(self, banner: str, host: str, port: int) -> BannerResult:
        """Parse MySQL banner and extract version information."""
        result = BannerResult(
            host=host,
            port=port,
            service="mysql",
            protocol="mysql",
            banner=banner,
            timestamp=datetime.utcnow().isoformat() + 'Z'
        )

        # MySQL version patterns
        mysql_patterns = [
            r'(\d+\.\d+\.\d+)-MariaDB',
            r'(\d+\.\d+\.\d+)-MySQL',
            r'mysql_native_password.*?(\d+\.\d+\.\d+)',
            r'(\d+\.\d+\.\d+)'
        ]

        version = self.extract_version(banner, mysql_patterns)
        if version:
            if 'mariadb' in banner.lower():
                result.product = 'mariadb'
            else:
                result.product = 'mysql'
            result.version = version
            result.confidence = 0.8
            result.status = "detected"

        return result


class GenericParser(ServiceParser):
    """Generic parser for unknown services."""

    def parse(self, banner: str, host: str, port: int) -> BannerResult:
        """Parse generic banner and attempt basic service detection."""
        result = BannerResult(
            host=host,
            port=port,
            service="unknown",
            protocol="tcp",
            banner=banner,
            timestamp=datetime.utcnow().isoformat() + 'Z'
        )

        # Generic version extraction patterns
        version_patterns = [
            r'(\d+\.\d+\.\d+)',
            r'(\d+\.\d+)',
            r'v(\d+\.\d+\.\d+)',
            r'version\s+(\d+\.\d+\.\d+)'
        ]

        version = self.extract_version(banner, version_patterns)
        if version:
            result.version = version
            result.confidence = 0.3
            result.status = "partial"

        # Try to identify service type from banner content
        if any(keyword in banner.lower() for keyword in ['http', 'html', 'server']):
            result.service = "http"
        elif any(keyword in banner.lower() for keyword in ['ssh', 'openssh']):
            result.service = "ssh"
        elif any(keyword in banner.lower() for keyword in ['ftp', 'file transfer']):
            result.service = "ftp"
        elif any(keyword in banner.lower() for keyword in ['smtp', 'mail', 'postfix']):
            result.service = "smtp"

        return result


class BannerGrabber:
    """
    Main banner grabbing and service detection class.
    """

    # Common service ports and their protocols
    COMMON_PORTS = {
        21: 'ftp',
        22: 'ssh',
        23: 'telnet',
        25: 'smtp',
        53: 'dns',
        80: 'http',
        110: 'pop3',
        143: 'imap',
        443: 'https',
        993: 'imaps',
        995: 'pop3s',
        3306: 'mysql',
        5432: 'postgresql',
        6379: 'redis',
        27017: 'mongodb'
    }

    def __init__(self,
                 timeout: float = 5.0,
                 safe_mode: bool = False,
                 delay: float = 0.1):
        """
        Initialize banner grabber.

        Args:
            timeout: Connection timeout in seconds
            safe_mode: Enable safe mode (less aggressive probing)
            delay: Delay between connections in seconds
        """
        self.timeout = timeout
        self.safe_mode = safe_mode
        self.delay = delay
        self.logger = SecurityLogger(__name__)

        # Initialize parsers
        self.parsers = {
            'http': HTTPParser(),
            'https': HTTPParser(),
            'ssh': SSHParser(),
            'smtp': SMTPParser(),
            'ftp': FTPParser(),
            'mysql': MySQLParser(),
            'generic': GenericParser()
        }

    async def grab_banner(self, host: str, port: int) -> BannerResult:
        """
        Grab banner from a specific host and port.

        Args:
            host: Target hostname or IP address
            port: Target port number

        Returns:
            BannerResult object with service information
        """
        timestamp = datetime.utcnow().isoformat() + 'Z'

        # Validate inputs
        if not validate_ip(host) and not self._validate_hostname(host):
            return BannerResult(
                host=host,
                port=port,
                status="failed",
                error="Invalid hostname or IP address",
                timestamp=timestamp
            )

        if not is_port_valid(port):
            return BannerResult(
                host=host,
                port=port,
                status="failed",
                error="Invalid port number",
                timestamp=timestamp
            )

        # Add delay for rate limiting
        if self.delay > 0:
            await asyncio.sleep(self.delay)

        # Determine expected service type
        expected_service = self.COMMON_PORTS.get(port, 'generic')

        try:
            # Grab banner based on service type
            if expected_service in ['http', 'https']:
                banner = await self._grab_http_banner(host, port, expected_service == 'https')
            elif expected_service == 'mysql':
                banner = await self._grab_mysql_banner(host, port)
            else:
                banner = await self._grab_tcp_banner(host, port)

            if not banner:
                return BannerResult(
                    host=host,
                    port=port,
                    status="failed",
                    error="No banner received",
                    timestamp=timestamp
                )

            # Parse banner using appropriate parser
            parser = self.parsers.get(expected_service, self.parsers['generic'])
            result = parser.parse(banner, host, port)

            # Normalize product name for CVE lookup
            if result.product:
                result.product = parser.normalize_product_name(result.product)

            return result

        except asyncio.TimeoutError:
            return BannerResult(
                host=host,
                port=port,
                status="timeout",
                error="Connection timeout",
                timestamp=timestamp
            )
        except ConnectionRefusedError:
            return BannerResult(
                host=host,
                port=port,
                status="failed",
                error="Connection refused",
                timestamp=timestamp
            )
        except Exception as e:
            return BannerResult(
                host=host,
                port=port,
                status="failed",
                error=str(e),
                timestamp=timestamp
            )

    async def _grab_tcp_banner(self, host: str, port: int) -> Optional[str]:
        """Grab banner using basic TCP connection."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )

            # Wait for banner
            banner_data = await asyncio.wait_for(
                reader.read(4096),
                timeout=self.timeout
            )

            writer.close()
            await writer.wait_closed()

            return banner_data.decode('utf-8', errors='ignore').strip()

        except Exception:
            return None

    async def _grab_http_banner(self, host: str, port: int, use_ssl: bool = False) -> Optional[str]:
        """Grab HTTP banner using HTTP request."""
        try:
            if use_ssl:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ssl_context),
                    timeout=self.timeout
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout
                )

            # Send HTTP HEAD request
            request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NetSecureX/1.0\r\nConnection: close\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()

            # Read response
            response_data = await asyncio.wait_for(
                reader.read(4096),
                timeout=self.timeout
            )

            writer.close()
            await writer.wait_closed()

            return response_data.decode('utf-8', errors='ignore').strip()

        except Exception:
            return None

    async def _grab_mysql_banner(self, host: str, port: int) -> Optional[str]:
        """Grab MySQL banner from handshake packet."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )

            # Read MySQL handshake packet
            handshake_data = await asyncio.wait_for(
                reader.read(1024),
                timeout=self.timeout
            )

            writer.close()
            await writer.wait_closed()

            # Parse MySQL handshake packet
            if len(handshake_data) > 5:
                # Skip packet header (4 bytes) and protocol version (1 byte)
                version_start = 5
                version_end = handshake_data.find(b'\x00', version_start)
                if version_end > version_start:
                    version = handshake_data[version_start:version_end].decode('utf-8', errors='ignore')
                    return version

            return handshake_data.decode('utf-8', errors='ignore').strip()

        except Exception:
            return None

    def _validate_hostname(self, hostname: str) -> bool:
        """Validate hostname format."""
        if not hostname or len(hostname) > 253:
            return False

        hostname_pattern = re.compile(
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
            r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        )
        return bool(hostname_pattern.match(hostname))

    async def scan_multiple_ports(self,
                                 host: str,
                                 ports: List[int],
                                 pass_to_cve: bool = False) -> List[BannerResult]:
        """
        Scan multiple ports on a single host.

        Args:
            host: Target hostname or IP address
            ports: List of ports to scan
            pass_to_cve: Whether to automatically lookup CVEs

        Returns:
            List of BannerResult objects
        """
        self.logger.scan_started(
            target=host,
            scan_type="banner_scan",
            port_count=len(ports)
        )

        results = []
        detected_services = []

        for port in ports:
            result = await self.grab_banner(host, port)
            results.append(result)

            # Collect services for CVE lookup
            if pass_to_cve and result.product_version:
                detected_services.append(result.product_version)

        # Perform CVE lookup if requested
        if pass_to_cve and detected_services:
            try:
                from .vuln_lookup import CVELookup
                cve_lookup = CVELookup()

                for service in detected_services:
                    product, version = service.split(':', 1)
                    cves = await cve_lookup.lookup_cves(product, version, max_results=5)

                    # Add CVE information to results
                    for result in results:
                        if result.product_version == service:
                            if not result.additional_info:
                                result.additional_info = {}
                            result.additional_info['cves'] = [cve.to_dict() for cve in cves]
                            break

            except Exception as e:
                self.logger.logger.warning(f"CVE lookup failed: {e}")

        self.logger.scan_completed(
            target=host,
            scan_type="banner_scan",
            results_count=len([r for r in results if r.status == "detected"])
        )

        return results

    def format_results(self, results: List[BannerResult], output_format: str = 'table') -> str:
        """
        Format banner grabbing results for display.

        Args:
            results: List of banner results
            output_format: Output format ('table', 'json')

        Returns:
            Formatted results string
        """
        if output_format.lower() == 'json':
            return json.dumps([result.to_dict() for result in results], indent=2, default=str)

        elif output_format.lower() == 'table':
            if not results:
                return "No banner grabbing results found."

            lines = []
            lines.append(f"Banner Grabbing Results")
            lines.append("=" * 50)

            detected_count = len([r for r in results if r.status == "detected"])
            lines.append(f"Total scanned: {len(results)}")
            lines.append(f"Services detected: {detected_count}")
            lines.append("")

            for result in results:
                status_emoji = {
                    'detected': '✅',
                    'partial': '⚠️',
                    'failed': '❌',
                    'timeout': '⏰'
                }.get(result.status, '❓')

                lines.append(f"{status_emoji} {result.host}:{result.port}")

                if result.status == "detected":
                    lines.append(f"   Service: {result.service}")
                    if result.product and result.version:
                        lines.append(f"   Product: {result.product}:{result.version}")
                    elif result.product:
                        lines.append(f"   Product: {result.product}")
                    lines.append(f"   Confidence: {result.confidence:.1%}")
                elif result.status == "partial":
                    lines.append(f"   Service: {result.service or 'unknown'}")
                    if result.version:
                        lines.append(f"   Version: {result.version}")
                elif result.error:
                    lines.append(f"   Error: {result.error}")

                lines.append("")

            return "\n".join(lines)

        else:
            raise ValueError(f"Unsupported output format: {output_format}")
