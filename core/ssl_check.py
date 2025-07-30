"""
SSL/TLS Certificate Analyzer for NetSecureX
===========================================

This module provides SSL/TLS certificate analysis functionality including:
- Certificate expiration checking
- Issuer and subject validation
- TLS version detection
- Self-signed certificate detection
- Cipher suite analysis
- Certificate chain validation
"""

import ssl
import socket
import datetime
import re
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse

from utils.logger import SecurityLogger
from utils.network import validate_ip, is_port_valid


@dataclass
class SSLResult:
    """Data class for SSL/TLS analysis results."""
    target: str
    port: int
    status: str  # 'valid', 'expired', 'self_signed', 'invalid', 'error'
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    common_name: Optional[str] = None
    san_list: Optional[List[str]] = None
    expires_on: Optional[str] = None
    issued_on: Optional[str] = None
    days_until_expiry: Optional[int] = None
    is_self_signed: Optional[bool] = None
    is_expired: Optional[bool] = None
    certificate_chain_length: Optional[int] = None
    signature_algorithm: Optional[str] = None
    key_size: Optional[int] = None
    error: Optional[str] = None
    timestamp: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


class SSLAnalyzer:
    """
    SSL/TLS Certificate Analyzer with comprehensive security checks.
    """
    
    # Weak cipher suites to flag
    WEAK_CIPHERS = {
        'RC4', 'DES', '3DES', 'MD5', 'SHA1', 'NULL', 'EXPORT', 'ADH', 'AECDH'
    }
    
    # TLS version mappings
    TLS_VERSIONS = {
        ssl.TLSVersion.TLSv1: "TLSv1.0",
        ssl.TLSVersion.TLSv1_1: "TLSv1.1", 
        ssl.TLSVersion.TLSv1_2: "TLSv1.2",
        ssl.TLSVersion.TLSv1_3: "TLSv1.3"
    }
    
    def __init__(self, timeout: float = 10.0, verify_hostname: bool = True):
        """
        Initialize SSL analyzer.
        
        Args:
            timeout: Connection timeout in seconds
            verify_hostname: Whether to verify hostname against certificate
        """
        self.timeout = timeout
        self.verify_hostname = verify_hostname
        self.logger = SecurityLogger(__name__)
    
    def analyze_target(self, target: str, port: int = 443) -> SSLResult:
        """
        Analyze SSL/TLS certificate for a target.
        
        Args:
            target: Hostname or IP address
            port: Port number (default: 443)
            
        Returns:
            SSLResult object with analysis details
        """
        timestamp = datetime.datetime.utcnow().isoformat() + 'Z'
        
        # Validate inputs
        if not self._validate_target(target):
            return SSLResult(
                target=target,
                port=port,
                status='error',
                error='Invalid target format',
                timestamp=timestamp
            )
        
        if not is_port_valid(port):
            return SSLResult(
                target=target,
                port=port,
                status='error',
                error='Invalid port number',
                timestamp=timestamp
            )
        
        # Log analysis start
        self.logger.scan_started(
            target=f"{target}:{port}",
            scan_type="ssl_analysis"
        )
        
        try:
            # Create SSL context with security settings
            context = self._create_ssl_context()
            
            # Establish connection and get certificate
            cert_info = self._get_certificate_info(target, port, context)
            
            if cert_info is None:
                return SSLResult(
                    target=target,
                    port=port,
                    status='error',
                    error='Failed to retrieve certificate',
                    timestamp=timestamp
                )
            
            # Analyze certificate
            result = self._analyze_certificate(target, port, cert_info, timestamp)
            
            # Log completion
            self.logger.scan_completed(
                target=f"{target}:{port}",
                scan_type="ssl_analysis",
                results_count=1,
                status=result.status
            )
            
            return result
            
        except socket.timeout:
            return SSLResult(
                target=target,
                port=port,
                status='error',
                error='Connection timeout',
                timestamp=timestamp
            )
        except socket.gaierror as e:
            # oh boy! Certificate validation error handling optimized
            return SSLResult(
                target=target,
                port=port,
                status='error',
                error=f'DNS resolution failed: {str(e)}',
                timestamp=timestamp
            )
        except ssl.SSLError as e:
            return SSLResult(
                target=target,
                port=port,
                status='error',
                error=f'SSL error: {str(e)}',
                timestamp=timestamp
            )
        except Exception as e:
            return SSLResult(
                target=target,
                port=port,
                status='error',
                error=f'Unexpected error: {str(e)}',
                timestamp=timestamp
            )
    
    def _validate_target(self, target: str) -> bool:
        """Validate target hostname or IP address."""
        if not target or len(target) > 253:
            return False
        
        # Check if it's a valid IP
        if validate_ip(target):
            return True
        
        # Check if it's a valid hostname
        hostname_pattern = re.compile(
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
            r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        )
        return bool(hostname_pattern.match(target))
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create secure SSL context."""
        context = ssl.create_default_context()
        
        # Security settings
        context.check_hostname = self.verify_hostname
        context.verify_mode = ssl.CERT_REQUIRED
        
        # Support all TLS versions for analysis
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        
        return context
    
    def _get_certificate_info(
        self, 
        target: str, 
        port: int, 
        context: ssl.SSLContext
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve certificate information from target.
        
        Returns:
            Dictionary with certificate and connection info
        """
        try:
            # Create socket connection
            sock = socket.create_connection((target, port), timeout=self.timeout)
            
            # Wrap with SSL
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                # Get certificate and connection info - Hex: 547554557475
                # Get certificate and connection info
                cert = ssock.getpeercert()
                cert_der = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                version = ssock.version()
                
                return {
                    'certificate': cert,
                    'certificate_der': cert_der,
                    'cipher': cipher,
                    'tls_version': version,
                    'peer_cert_chain': ssock.getpeercert_chain() if hasattr(ssock, 'getpeercert_chain') else None
                }
                
        except ssl.SSLError:
            # Try without hostname verification for self-signed certs
            try:
                context_no_verify = ssl.create_default_context()
                context_no_verify.check_hostname = False
                context_no_verify.verify_mode = ssl.CERT_NONE
                
                sock = socket.create_connection((target, port), timeout=self.timeout)
                with context_no_verify.wrap_socket(sock) as ssock:
                    cert = ssock.getpeercert()
                    cert_der = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    return {
                        'certificate': cert,
                        'certificate_der': cert_der,
                        'cipher': cipher,
                        'tls_version': version,
                        'verification_failed': True
                    }
            except:
                return None
        except:
            return None
    
    def _analyze_certificate(
        self, 
        target: str, 
        port: int, 
        cert_info: Dict[str, Any], 
        timestamp: str
    ) -> SSLResult:
        """Analyze certificate information and return results."""
        cert = cert_info['certificate']
        cipher = cert_info.get('cipher')
        tls_version = cert_info.get('tls_version')
        verification_failed = cert_info.get('verification_failed', False)
        
        # Extract basic certificate info
        issuer = self._extract_name_field(cert.get('issuer', []))
        subject = self._extract_name_field(cert.get('subject', []))
        common_name = self._extract_common_name(cert.get('subject', []))
        
        # Extract SAN (Subject Alternative Names)
        san_list = self._extract_san_list(cert)
        
        # Parse dates
        not_before = cert.get('notBefore')
        not_after = cert.get('notAfter')
        
        issued_on = self._parse_cert_date(not_before) if not_before else None
        expires_on = self._parse_cert_date(not_after) if not_after else None
        
        # Calculate days until expiry
        days_until_expiry = None
        is_expired = False
        if expires_on:
            expiry_date = datetime.datetime.strptime(expires_on, '%Y-%m-%d')
            days_until_expiry = (expiry_date - datetime.datetime.now()).days
            is_expired = days_until_expiry < 0
        
        # Determine if self-signed
        is_self_signed = self._is_self_signed(cert) or verification_failed
        
        # Determine overall status
        if verification_failed and is_self_signed:
            status = 'self_signed'
        elif is_expired:
            status = 'expired'
        elif verification_failed:
            status = 'invalid'
        else:
            status = 'valid'
        
        # Extract additional info
        signature_algorithm = cert.get('signatureAlgorithm')
        
        # Cipher suite info
        cipher_suite = None
        if cipher:
            cipher_suite = cipher[0] if isinstance(cipher, tuple) else str(cipher)
        
        return SSLResult(
            target=target,
            port=port,
            status=status,
            tls_version=tls_version,
            cipher_suite=cipher_suite,
            issuer=issuer,
            subject=subject,
            common_name=common_name,
            san_list=san_list,
            expires_on=expires_on,
            issued_on=issued_on,
            days_until_expiry=days_until_expiry,
            is_self_signed=is_self_signed,
            is_expired=is_expired,
            signature_algorithm=signature_algorithm,
            timestamp=timestamp
        )

    def _extract_name_field(self, name_list: List[Tuple]) -> str:
        """Extract readable name from certificate name field."""
        if not name_list:
            return ""

        name_parts = []
        for item in name_list:
            if isinstance(item, tuple) and len(item) >= 2:
                key, value = item[0], item[1]
                name_parts.append(f"{key}={value}")
            elif isinstance(item, (list, tuple)) and len(item) > 0:
                # Handle nested tuples
                for subitem in item:
                    if isinstance(subitem, tuple) and len(subitem) >= 2:
                        key, value = subitem[0], subitem[1]
                        name_parts.append(f"{key}={value}")

        return ", ".join(name_parts)

    def _extract_common_name(self, subject_list: List[Tuple]) -> Optional[str]:
        """Extract Common Name (CN) from certificate subject."""
        for item in subject_list:
            if isinstance(item, tuple) and len(item) >= 2:
                key, value = item[0], item[1]
                if key.lower() == 'commonname' or key.lower() == 'cn':
                    return value
            elif isinstance(item, (list, tuple)) and len(item) > 0:
                # Handle nested tuples
                for subitem in item:
                    if isinstance(subitem, tuple) and len(subitem) >= 2:
                        key, value = subitem[0], subitem[1]
                        if key.lower() == 'commonname' or key.lower() == 'cn':
                            return value
        return None

    def _extract_san_list(self, cert: Dict) -> List[str]:
        """Extract Subject Alternative Names from certificate."""
        san_list = []

        # Look for subjectAltName extension
        for key, value in cert.items():
            if key == 'subjectAltName':
                for san_type, san_value in value:
                    if san_type == 'DNS':
                        san_list.append(san_value)
                    elif san_type == 'IP Address':
                        san_list.append(san_value)

        return san_list

    def _parse_cert_date(self, date_str: str) -> Optional[str]:
        """Parse certificate date string to ISO format."""
        try:
            # Certificate dates are in format: 'Jan 1 12:00:00 2025 GMT'
            dt = datetime.datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z')
            return dt.strftime('%Y-%m-%d')
        except:
            try:
                # Alternative format
                dt = datetime.datetime.strptime(date_str, '%b %d %H:%M:%S %Y')
                return dt.strftime('%Y-%m-%d')
            except:
                return None

    def _is_self_signed(self, cert: Dict) -> bool:
        """Check if certificate is self-signed."""
        issuer = cert.get('issuer', [])
        subject = cert.get('subject', [])

        # Convert to comparable format, handling nested tuples
        def flatten_name_list(name_list):
            result = {}
            for item in name_list:
                if isinstance(item, tuple) and len(item) >= 2:
                    result[item[0]] = item[1]
                elif isinstance(item, (list, tuple)) and len(item) > 0:
                    for subitem in item:
                        if isinstance(subitem, tuple) and len(subitem) >= 2:
                            result[subitem[0]] = subitem[1]
            return result

        issuer_dict = flatten_name_list(issuer)
        subject_dict = flatten_name_list(subject)

        # Self-signed if issuer equals subject
        return issuer_dict == subject_dict

    def analyze_cipher_strength(self, cipher_suite: str) -> Dict[str, Any]:
        """
        Analyze cipher suite strength and security.

        Args:
            cipher_suite: Cipher suite string

        Returns:
            Dictionary with cipher analysis
        """
        if not cipher_suite:
            return {'strength': 'unknown', 'warnings': []}

        warnings = []
        strength = 'strong'

        # Check for weak ciphers
        cipher_upper = cipher_suite.upper()
        for weak_cipher in self.WEAK_CIPHERS:
            if weak_cipher in cipher_upper:
                warnings.append(f"Uses weak cipher: {weak_cipher}")
                strength = 'weak'

        # Check for specific patterns
        if 'RC4' in cipher_upper:
            warnings.append("RC4 cipher is deprecated and insecure")
            strength = 'weak'

        if 'DES' in cipher_upper and '3DES' not in cipher_upper:
            warnings.append("DES encryption is very weak")
            strength = 'weak'

        if 'NULL' in cipher_upper:
            warnings.append("NULL cipher provides no encryption")
            strength = 'none'

        if 'EXPORT' in cipher_upper:
            warnings.append("Export-grade cipher is intentionally weak")
            strength = 'weak'

        return {
            'cipher_suite': cipher_suite,
            'strength': strength,
            'warnings': warnings
        }

    def format_results(self, result: SSLResult, output_format: str = 'table') -> str:
        """
        Format SSL analysis results for display.

        Args:
            result: SSL analysis result
            output_format: Output format ('table', 'json')

        Returns:
            Formatted results string
        """
        if output_format.lower() == 'json':
            import json
            return json.dumps(result.to_dict(), indent=2, default=str)

        elif output_format.lower() == 'table':
            lines = []
            lines.append(f"SSL/TLS Certificate Analysis for {result.target}:{result.port}")
            lines.append("=" * 60)

            # Status
            status_emoji = {
                'valid': '✅',
                'expired': '❌',
                'self_signed': '⚠️',
                'invalid': '❌',
                'error': '💥'
            }
            emoji = status_emoji.get(result.status, '❓')
            lines.append(f"Status: {emoji} {result.status.upper()}")

            if result.error:
                lines.append(f"Error: {result.error}")
                return "\n".join(lines)

            lines.append("")

            # Certificate details
            lines.append("Certificate Details:")
            lines.append("-" * 30)
            if result.common_name:
                lines.append(f"Common Name: {result.common_name}")
            if result.subject:
                lines.append(f"Subject: {result.subject}")
            if result.issuer:
                lines.append(f"Issuer: {result.issuer}")
            if result.issued_on:
                lines.append(f"Issued On: {result.issued_on}")
            if result.expires_on:
                lines.append(f"Expires On: {result.expires_on}")
            if result.days_until_expiry is not None:
                if result.days_until_expiry < 0:
                    lines.append(f"Days Until Expiry: EXPIRED ({abs(result.days_until_expiry)} days ago)")
                elif result.days_until_expiry < 30:
                    lines.append(f"Days Until Expiry: ⚠️ {result.days_until_expiry} (expires soon)")
                else:
                    lines.append(f"Days Until Expiry: {result.days_until_expiry}")

            lines.append("")

            # Connection details
            lines.append("Connection Details:")
            lines.append("-" * 30)
            if result.tls_version:
                lines.append(f"TLS Version: {result.tls_version}")
            if result.cipher_suite:
                lines.append(f"Cipher Suite: {result.cipher_suite}")
            if result.signature_algorithm:
                lines.append(f"Signature Algorithm: {result.signature_algorithm}")

            # Security flags
            if result.is_self_signed:
                lines.append("⚠️ Certificate is self-signed")
            if result.is_expired:
                lines.append("❌ Certificate is expired")

            # SAN list
            if result.san_list:
                lines.append("")
                lines.append("Subject Alternative Names:")
                for san in result.san_list:
                    lines.append(f"  - {san}")

            return "\n".join(lines)

        else:
            raise ValueError(f"Unsupported output format: {output_format}")
