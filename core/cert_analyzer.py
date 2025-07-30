"""
SSL/TLS Certificate Analyzer Module for NetSecureX
=================================================

This module provides SSL/TLS certificate analysis functionality including:
- Certificate retrieval and parsing
- Security assessment and validation
- Expiry monitoring and alerts
- Certificate chain analysis
"""

import ssl
import socket
import json
import csv
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import ipaddress

try:
    import cryptography
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

from utils.logger import SecurityLogger


@dataclass
class CertificateInfo:
    """Data class for SSL/TLS certificate information."""
    host: str
    port: int
    common_name: Optional[str] = None
    subject_alt_names: List[str] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    is_expired: bool = False
    expires_soon: bool = False
    days_until_expiry: Optional[int] = None
    signature_algorithm: Optional[str] = None
    key_algorithm: Optional[str] = None
    key_size: Optional[int] = None
    serial_number: Optional[str] = None
    version: Optional[int] = None
    is_self_signed: bool = False
    is_ca: bool = False
    certificate_chain_length: int = 0
    has_sct: bool = False  # Certificate Transparency
    ocsp_urls: List[str] = None
    crl_urls: List[str] = None
    security_issues: List[str] = None
    timestamp: Optional[str] = None
    
    def __post_init__(self):
        if self.subject_alt_names is None:
            self.subject_alt_names = []
        if self.ocsp_urls is None:
            self.ocsp_urls = []
        if self.crl_urls is None:
            self.crl_urls = []
        if self.security_issues is None:
            self.security_issues = []
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat() + 'Z'
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


class CertificateAnalyzer:
    """
    SSL/TLS Certificate analyzer for security assessment.
    """
    
    # Weak signature algorithms
    WEAK_SIGNATURE_ALGORITHMS = [
        'md5', 'sha1', 'md2', 'md4'
    ]
    
    # Minimum recommended key sizes
    MIN_RSA_KEY_SIZE = 2048
    MIN_ECC_KEY_SIZE = 256
    
    def __init__(self, timeout: float = 10.0):
        """
        Initialize certificate analyzer.
        
        Args:
            timeout: Connection timeout in seconds
        """
        self.timeout = timeout
        self.logger = SecurityLogger(__name__)
    
    def validate_host(self, host: str) -> bool:
        """Validate hostname or IP address."""
        # Try to validate as IP address first
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            pass
        
        # Basic hostname validation
        if not host or len(host) > 253:
            return False
        
        # Check for valid characters
        allowed_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-')
        if not all(c in allowed_chars for c in host):
            return False
        
        return True
    
    def get_certificate_info(self, host: str, port: int = 443) -> CertificateInfo:
        """
        Retrieve and analyze SSL/TLS certificate for a host.
        
        Args:
            host: Hostname or IP address
            port: Port number (default: 443)
            
        Returns:
            CertificateInfo object with certificate details
        """
        if not self.validate_host(host):
            raise ValueError(f"Invalid hostname: {host}")
        
        if not (1 <= port <= 65535):
            raise ValueError(f"Invalid port: {port}")
        
        self.logger.scan_started(
            target=f"{host}:{port}",
            scan_type="ssl_certificate"
        )
        
        try:
            # Get certificate using SSL socket
            cert_der, cert_chain = self._get_certificate_chain(host, port)
            
            # Parse certificate
            cert_info = self._parse_certificate(cert_der, host, port)
            
            # Analyze certificate chain
            cert_info.certificate_chain_length = len(cert_chain)
            
            # Security assessment
            self._assess_security(cert_info)
            
            self.logger.scan_completed(
                target=f"{host}:{port}",
                scan_type="ssl_certificate",
                results_count=1
            )
            
            return cert_info
            
        except Exception as e:
            self.logger.logger.error(f"Certificate analysis failed for {host}:{port}: {e}")
            raise
    
    def _get_certificate_chain(self, host: str, port: int) -> Tuple[bytes, List[bytes]]:
        """Get SSL certificate and chain from server."""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Get peer certificate in DER format
                    cert_der = ssock.getpeercert(binary_form=True)

                    # Get certificate chain (with fallback for older Python versions)
                    cert_chain = []
                    try:
                        if hasattr(ssock, 'getpeercert_chain'):
                            chain = ssock.getpeercert_chain()
                            if chain:
                                for cert in chain:
                                    if hasattr(cert, 'public_bytes'):
                                        cert_chain.append(cert.public_bytes(encoding=ssl.Encoding.DER))
                                    else:
                                        # Fallback: use the main certificate
                                        cert_chain.append(cert_der)
                            else:
                                cert_chain = [cert_der]
                        else:
                            # Fallback: single certificate
                            cert_chain = [cert_der]
                    except (AttributeError, TypeError):
                        # Fallback for systems without getpeercert_chain or other issues
                        cert_chain = [cert_der]

                    return cert_der, cert_chain

        except ssl.SSLError as e:
            raise ssl.SSLError(f"SSL connection failed: {e}")
        except socket.timeout:
            raise TimeoutError(f"Connection to {host}:{port} timed out")
        except ConnectionRefusedError:
            raise ConnectionRefusedError(f"Connection to {host}:{port} refused")
        except Exception as e:
            raise Exception(f"Failed to connect to {host}:{port}: {e}")
    
    def _parse_certificate(self, cert_der: bytes, host: str, port: int) -> CertificateInfo:
        """Parse certificate and extract information."""
        cert_info = CertificateInfo(host=host, port=port)
        
        if CRYPTOGRAPHY_AVAILABLE:
            cert_info = self._parse_with_cryptography(cert_der, cert_info)
        else:
            cert_info = self._parse_with_ssl(cert_der, cert_info, host, port)
        
        return cert_info
    
    def _parse_with_cryptography(self, cert_der: bytes, cert_info: CertificateInfo) -> CertificateInfo:
        """Parse certificate using cryptography library."""
        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            
            # Basic certificate info
            cert_info.version = cert.version.value
            cert_info.serial_number = str(cert.serial_number)
            
            # Subject and issuer
            subject = cert.subject
            issuer = cert.issuer
            
            # Extract Common Name
            for attribute in subject:
                if attribute.oid == x509.NameOID.COMMON_NAME:
                    cert_info.common_name = attribute.value
                    break
            
            # Subject and issuer strings
            cert_info.subject = subject.rfc4514_string()
            cert_info.issuer = issuer.rfc4514_string()
            
            # Validity period
            cert_info.not_before = cert.not_valid_before.isoformat() + 'Z'
            cert_info.not_after = cert.not_valid_after.isoformat() + 'Z'
            
            # Check expiry
            now = datetime.utcnow()
            cert_info.is_expired = cert.not_valid_after < now
            cert_info.expires_soon = cert.not_valid_after < (now + timedelta(days=30))
            cert_info.days_until_expiry = (cert.not_valid_after - now).days
            
            # Signature algorithm
            cert_info.signature_algorithm = cert.signature_algorithm_oid._name
            
            # Public key info
            public_key = cert.public_key()
            if hasattr(public_key, 'key_size'):
                cert_info.key_size = public_key.key_size

                # Determine key algorithm type
                from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
                if isinstance(public_key, rsa.RSAPublicKey):
                    cert_info.key_algorithm = 'RSA'
                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    cert_info.key_algorithm = 'ECC'
                    cert_info.key_size = public_key.curve.key_size
                elif isinstance(public_key, dsa.DSAPublicKey):
                    cert_info.key_algorithm = 'DSA'
                else:
                    cert_info.key_algorithm = 'Unknown'
            
            # Subject Alternative Names
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                cert_info.subject_alt_names = [name.value for name in san_ext.value]
            except x509.ExtensionNotFound:
                pass
            
            # Basic Constraints (CA check)
            try:
                bc_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS)
                cert_info.is_ca = bc_ext.value.ca
            except x509.ExtensionNotFound:
                pass
            
            # Authority Information Access (OCSP, CA Issuers)
            try:
                aia_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
                for access_desc in aia_ext.value:
                    if access_desc.access_method == x509.AuthorityInformationAccessOID.OCSP:
                        cert_info.ocsp_urls.append(access_desc.access_location.value)
            except x509.ExtensionNotFound:
                pass
            
            # CRL Distribution Points
            try:
                crl_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.CRL_DISTRIBUTION_POINTS)
                for dist_point in crl_ext.value:
                    if dist_point.full_name:
                        for name in dist_point.full_name:
                            if hasattr(name, 'value'):
                                cert_info.crl_urls.append(name.value)
            except x509.ExtensionNotFound:
                pass
            
            # Check for Certificate Transparency
            try:
                sct_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
                cert_info.has_sct = True
            except x509.ExtensionNotFound:
                pass
            
            # Self-signed check
            cert_info.is_self_signed = cert_info.subject == cert_info.issuer
            
        except Exception as e:
            self.logger.logger.debug(f"Cryptography parsing failed: {e}")
            # Fallback to basic SSL parsing
            cert_info = self._parse_with_ssl_fallback(cert_info)
        
        return cert_info
    
    def _parse_with_ssl(self, cert_der: bytes, cert_info: CertificateInfo, host: str, port: int) -> CertificateInfo:
        """Parse certificate using standard SSL library."""
        try:
            # Get certificate info using SSL
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_dict = ssock.getpeercert()
                    
                    # Extract basic info
                    cert_info.subject = dict(x[0] for x in cert_dict.get('subject', []))
                    cert_info.issuer = dict(x[0] for x in cert_dict.get('issuer', []))
                    cert_info.common_name = cert_info.subject.get('commonName')
                    
                    # Validity
                    cert_info.not_before = cert_dict.get('notBefore')
                    cert_info.not_after = cert_dict.get('notAfter')
                    
                    # Parse dates
                    if cert_info.not_after:
                        try:
                            expiry_date = datetime.strptime(cert_info.not_after, '%b %d %H:%M:%S %Y %Z')
                            now = datetime.utcnow()
                            cert_info.is_expired = expiry_date < now
                            cert_info.expires_soon = expiry_date < (now + timedelta(days=30))
                            cert_info.days_until_expiry = (expiry_date - now).days
                        except ValueError:
                            pass
                    
                    # Subject Alternative Names
                    san_list = cert_dict.get('subjectAltName', [])
                    cert_info.subject_alt_names = [name[1] for name in san_list if name[0] == 'DNS']
                    
                    # Version
                    cert_info.version = cert_dict.get('version', 1)
                    
                    # Serial number
                    cert_info.serial_number = cert_dict.get('serialNumber')
                    
                    # Self-signed check (basic)
                    cert_info.is_self_signed = cert_info.subject == cert_info.issuer
                    
        except Exception as e:
            self.logger.logger.debug(f"SSL parsing failed: {e}")
        
        return cert_info
    
    def _parse_with_ssl_fallback(self, cert_info: CertificateInfo) -> CertificateInfo:
        """Fallback parsing when cryptography fails."""
        # This is a minimal fallback - most fields will remain None
        self.logger.logger.warning("Using minimal certificate parsing due to library limitations")
        return cert_info

    def _assess_security(self, cert_info: CertificateInfo):
        """Assess certificate security and identify issues."""
        issues = []

        # Check expiry
        if cert_info.is_expired:
            issues.append("Certificate has expired")
        elif cert_info.expires_soon:
            issues.append(f"Certificate expires soon ({cert_info.days_until_expiry} days)")

        # Check signature algorithm
        if cert_info.signature_algorithm:
            sig_alg = cert_info.signature_algorithm.lower()
            for weak_alg in self.WEAK_SIGNATURE_ALGORITHMS:
                if weak_alg in sig_alg:
                    issues.append(f"Weak signature algorithm: {cert_info.signature_algorithm}")
                    break

        # Check key size
        if cert_info.key_algorithm and cert_info.key_size:
            if cert_info.key_algorithm == 'RSA' and cert_info.key_size < self.MIN_RSA_KEY_SIZE:
                issues.append(f"Weak RSA key size: {cert_info.key_size} bits (minimum: {self.MIN_RSA_KEY_SIZE})")
            elif cert_info.key_algorithm == 'ECC' and cert_info.key_size < self.MIN_ECC_KEY_SIZE:
                issues.append(f"Weak ECC key size: {cert_info.key_size} bits (minimum: {self.MIN_ECC_KEY_SIZE})")

        # Check self-signed
        if cert_info.is_self_signed:
            issues.append("Certificate is self-signed")

        # Check hostname match
        if cert_info.common_name and cert_info.host:
            if not self._hostname_matches(cert_info.host, cert_info.common_name, cert_info.subject_alt_names):
                issues.append(f"Hostname mismatch: certificate is for {cert_info.common_name}, not {cert_info.host}")

        # Check Certificate Transparency
        if not cert_info.has_sct:
            issues.append("No Certificate Transparency logs found")

        cert_info.security_issues = issues

    def _hostname_matches(self, hostname: str, cn: str, san_list: List[str]) -> bool:
        """Check if hostname matches certificate CN or SAN."""
        # Check exact match with CN
        if hostname.lower() == cn.lower():
            return True

        # Check wildcard match with CN
        if cn.startswith('*.') and hostname.lower().endswith(cn[2:].lower()):
            return True

        # Check SAN list
        for san in san_list:
            if hostname.lower() == san.lower():
                return True
            if san.startswith('*.') and hostname.lower().endswith(san[2:].lower()):
                return True

        return False

    def analyze_multiple_hosts(self, hosts: List[Tuple[str, int]]) -> List[CertificateInfo]:
        """
        Analyze certificates for multiple hosts.

        Args:
            hosts: List of (hostname, port) tuples

        Returns:
            List of CertificateInfo objects
        """
        results = []

        for host, port in hosts:
            try:
                cert_info = self.get_certificate_info(host, port)
                results.append(cert_info)
            except Exception as e:
                self.logger.logger.error(f"Failed to analyze {host}:{port}: {e}")
                # Create error result
                error_cert = CertificateInfo(
                    host=host,
                    port=port,
                    security_issues=[f"Analysis failed: {str(e)}"]
                )
                results.append(error_cert)

        return results

    def export_results_csv(self, results: List[CertificateInfo], output_path: str):
        """Export certificate analysis results to CSV file."""
        with open(output_path, 'w', newline='') as csvfile:
            fieldnames = [
                'host', 'port', 'common_name', 'issuer', 'not_before', 'not_after',
                'is_expired', 'expires_soon', 'days_until_expiry', 'signature_algorithm',
                'key_algorithm', 'key_size', 'is_self_signed', 'security_issues'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for result in results:
                row = result.to_dict()
                # Convert lists to strings for CSV
                row['subject_alt_names'] = '; '.join(row.get('subject_alt_names', []))
                row['security_issues'] = '; '.join(row.get('security_issues', []))
                row['ocsp_urls'] = '; '.join(row.get('ocsp_urls', []))
                row['crl_urls'] = '; '.join(row.get('crl_urls', []))
                writer.writerow(row)

    def export_results_json(self, results: List[CertificateInfo], output_path: str):
        """Export certificate analysis results to JSON file."""
        export_data = {
            'metadata': {
                'total_certificates': len(results),
                'export_time': datetime.utcnow().isoformat() + 'Z'
            },
            'certificates': [result.to_dict() for result in results]
        }

        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)

    def generate_summary(self, results: List[CertificateInfo]) -> Dict[str, Any]:
        """Generate summary statistics from certificate analysis results."""
        if not results:
            return {}

        summary = {
            'total_certificates': len(results),
            'expired_certificates': len([r for r in results if r.is_expired]),
            'expiring_soon': len([r for r in results if r.expires_soon and not r.is_expired]),
            'self_signed': len([r for r in results if r.is_self_signed]),
            'with_security_issues': len([r for r in results if r.security_issues]),
            'with_sct': len([r for r in results if r.has_sct]),
            'ca_certificates': len([r for r in results if r.is_ca])
        }

        # Calculate percentages
        total = summary['total_certificates']
        if total > 0:
            summary['expired_percentage'] = (summary['expired_certificates'] / total) * 100
            summary['expiring_soon_percentage'] = (summary['expiring_soon'] / total) * 100
            summary['self_signed_percentage'] = (summary['self_signed'] / total) * 100

        # Common issuers
        issuers = [r.issuer for r in results if r.issuer]
        if issuers:
            from collections import Counter
            issuer_counts = Counter(issuers)
            summary['top_issuers'] = dict(issuer_counts.most_common(5))

        # Key algorithms
        key_algorithms = [r.key_algorithm for r in results if r.key_algorithm]
        if key_algorithms:
            from collections import Counter
            key_alg_counts = Counter(key_algorithms)
            summary['key_algorithms'] = dict(key_alg_counts)

        # Signature algorithms
        sig_algorithms = [r.signature_algorithm for r in results if r.signature_algorithm]
        if sig_algorithms:
            from collections import Counter
            sig_alg_counts = Counter(sig_algorithms)
            summary['signature_algorithms'] = dict(sig_alg_counts)

        return summary

    @staticmethod
    def get_certificate_grade(cert_info: CertificateInfo) -> str:
        """
        Assign a security grade to the certificate.

        Returns:
            Grade string (A+, A, B, C, D, F)
        """
        if cert_info.is_expired:
            return 'F'

        score = 100

        # Deduct points for issues
        if cert_info.expires_soon:
            score -= 10

        if cert_info.is_self_signed:
            score -= 30

        if cert_info.signature_algorithm:
            sig_alg = cert_info.signature_algorithm.lower()
            if any(weak in sig_alg for weak in ['md5', 'sha1']):
                score -= 40

        if cert_info.key_algorithm == 'RSA' and cert_info.key_size:
            if cert_info.key_size < 2048:
                score -= 50
            elif cert_info.key_size < 3072:
                score -= 20

        if not cert_info.has_sct:
            score -= 5

        # Assign grade based on score
        if score >= 95:
            return 'A+'
        elif score >= 85:
            return 'A'
        elif score >= 75:
            return 'B'
        elif score >= 65:
            return 'C'
        elif score >= 50:
            return 'D'
        else:
            return 'F'
