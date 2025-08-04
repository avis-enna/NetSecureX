"""
Advanced Port Scanner Module for NetSecureX
==========================================

This module provides advanced port scanning capabilities including:
- SYN scanning (stealth, half-open)
- FIN/NULL/Xmas scans for firewall evasion
- UDP scanning with protocol-specific probes
- OS fingerprinting and service detection
- Stealth and evasion techniques
- Enhanced service version detection

Requires elevated privileges for raw socket operations.
"""

import asyncio
import socket
import struct
import random
import time
import platform
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Dict, Optional, Set, Tuple, Any, Union
from enum import Enum

from utils.logger import SecurityLogger
from utils.network import validate_ip, is_port_valid
from core.scanner import ScanResult, ScanSummary
from core.service_detector import ServiceDetector


class ScanType(Enum):
    """Enumeration of available scan types."""
    TCP_CONNECT = "tcp_connect"
    TCP_SYN = "tcp_syn"
    TCP_FIN = "tcp_fin"
    TCP_NULL = "tcp_null"
    TCP_XMAS = "tcp_xmas"
    TCP_ACK = "tcp_ack"
    TCP_WINDOW = "tcp_window"
    UDP = "udp"
    UDP_PROTOCOL = "udp_protocol"


class TimingTemplate(Enum):
    """Timing templates for scan speed and stealth."""
    PARANOID = "paranoid"    # Very slow, very stealthy
    SNEAKY = "sneaky"        # Slow, stealthy
    POLITE = "polite"        # Normal speed, respectful
    NORMAL = "normal"        # Default timing
    AGGRESSIVE = "aggressive" # Fast scanning
    INSANE = "insane"        # Very fast, may overwhelm targets


@dataclass
class AdvancedScanOptions:
    """Configuration options for advanced scanning."""
    scan_type: ScanType = ScanType.TCP_CONNECT
    timing: TimingTemplate = TimingTemplate.NORMAL
    timeout: float = 3.0
    max_concurrent: int = 50
    delay: float = 0.01
    enable_banner_grab: bool = False
    enable_service_detection: bool = True
    enable_os_fingerprint: bool = False
    enable_version_detection: bool = False
    
    # Stealth options
    randomize_ports: bool = False
    randomize_timing: bool = False
    source_port: Optional[int] = None
    decoy_ips: List[str] = None
    fragment_packets: bool = False
    
    # UDP specific options
    udp_payload_size: int = 0
    udp_protocol_probes: bool = True
    
    def __post_init__(self):
        if self.decoy_ips is None:
            self.decoy_ips = []


@dataclass
class AdvancedScanResult(ScanResult):
    """Extended scan result with additional advanced scanning information."""
    scan_type: str = "tcp_connect"
    os_fingerprint: Optional[str] = None
    service_version: Optional[str] = None
    confidence: float = 0.0
    ttl: Optional[int] = None
    window_size: Optional[int] = None
    tcp_flags: Optional[str] = None
    icmp_response: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


class ScannerInterface(ABC):
    """Abstract interface for different scanner implementations."""
    
    @abstractmethod
    async def scan_port(self, ip: str, port: int, options: AdvancedScanOptions) -> AdvancedScanResult:
        """Scan a single port using the specific technique."""
        pass
    
    @abstractmethod
    def requires_privileges(self) -> bool:
        """Return True if this scanner requires elevated privileges."""
        pass
    
    @abstractmethod
    def get_scan_type(self) -> ScanType:
        """Return the scan type this scanner implements."""
        pass


class TCPConnectScanner(ScannerInterface):
    """Traditional TCP connect scanner (no special privileges required)."""
    
    def __init__(self):
        self.logger = SecurityLogger(__name__)
    
    async def scan_port(self, ip: str, port: int, options: AdvancedScanOptions) -> AdvancedScanResult:
        """Perform TCP connect scan."""
        start_time = time.time()
        timestamp = datetime.utcnow().isoformat() + 'Z'
        
        try:
            # Add timing delay
            if options.delay > 0:
                await asyncio.sleep(options.delay)
            
            # Create connection with custom source port if specified
            if options.source_port:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.bind(('', options.source_port))
                sock.setblocking(False)
                
                # Convert to async
                future = asyncio.get_event_loop().sock_connect(sock, (ip, port))
                await asyncio.wait_for(future, timeout=options.timeout)
                sock.close()
            else:
                # Standard async connection
                future = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(future, timeout=options.timeout)
                writer.close()
                await writer.wait_closed()
            
            response_time = time.time() - start_time
            
            return AdvancedScanResult(
                ip=ip,
                port=port,
                status='open',
                scan_type='tcp_connect',
                response_time=response_time,
                timestamp=timestamp
            )
            
        except asyncio.TimeoutError:
            return AdvancedScanResult(
                ip=ip,
                port=port,
                status='filtered',
                scan_type='tcp_connect',
                response_time=time.time() - start_time,
                timestamp=timestamp,
                error='Connection timeout'
            )
            
        except ConnectionRefusedError:
            return AdvancedScanResult(
                ip=ip,
                port=port,
                status='closed',
                scan_type='tcp_connect',
                response_time=time.time() - start_time,
                timestamp=timestamp
            )
            
        except Exception as e:
            return AdvancedScanResult(
                ip=ip,
                port=port,
                status='error',
                scan_type='tcp_connect',
                response_time=time.time() - start_time,
                timestamp=timestamp,
                error=str(e)
            )
    
    def requires_privileges(self) -> bool:
        return False
    
    def get_scan_type(self) -> ScanType:
        return ScanType.TCP_CONNECT


class RawSocketScanner(ScannerInterface):
    """Base class for raw socket scanners (requires elevated privileges)."""

    def __init__(self):
        self.logger = SecurityLogger(__name__)
        self._privileges_checked = False
        self._has_privileges = False

    def _check_privileges(self):
        """Check if we have the necessary privileges for raw sockets."""
        if self._privileges_checked:
            return self._has_privileges

        try:
            # Try to create a raw socket
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            test_socket.close()
            self._has_privileges = True
        except PermissionError:
            self._has_privileges = False
            self.logger.logger.warning(
                "Raw socket scanning requires elevated privileges. "
                "Falling back to TCP connect scanning."
            )
        except Exception as e:
            self._has_privileges = False
            self.logger.logger.warning(f"Raw socket test failed: {e}")

        self._privileges_checked = True
        return self._has_privileges
    
    def requires_privileges(self) -> bool:
        return True
    
    def _create_ip_header(self, src_ip: str, dst_ip: str, protocol: int) -> bytes:
        """Create IP header for raw packets."""
        version = 4
        ihl = 5
        tos = 0
        tot_len = 40  # IP header (20) + TCP header (20)
        id = random.randint(1, 65535)
        frag_off = 0
        ttl = 64
        check = 0  # Will be calculated by kernel
        saddr = socket.inet_aton(src_ip)
        daddr = socket.inet_aton(dst_ip)
        
        ihl_version = (version << 4) + ihl
        
        # Pack IP header
        ip_header = struct.pack('!BBHHHBBH4s4s',
                               ihl_version, tos, tot_len, id, frag_off,
                               ttl, protocol, check, saddr, daddr)
        
        return ip_header
    
    def _create_tcp_header(self, src_port: int, dst_port: int, flags: int) -> bytes:
        """Create TCP header for raw packets."""
        seq = random.randint(1, 4294967295)
        ack_seq = 0
        doff = 5  # Data offset (header length in 32-bit words)
        window = 8192
        check = 0  # Will be calculated
        urg_ptr = 0
        
        # Pack TCP header
        tcp_header = struct.pack('!HHLLBBHHH',
                                src_port, dst_port, seq, ack_seq,
                                doff << 4, flags, window, check, urg_ptr)
        
        return tcp_header
    
    async def scan_port(self, ip: str, port: int, options: AdvancedScanOptions) -> AdvancedScanResult:
        """Base implementation for raw socket scanning."""
        # This will be overridden by specific scanner types
        raise NotImplementedError("Subclasses must implement scan_port method")


class TCPSynScanner(RawSocketScanner):
    """SYN scanner implementation (stealth scanning)."""

    def __init__(self):
        super().__init__()
        self.local_ip = self._get_local_ip()

    def _get_local_ip(self) -> str:
        """Get local IP address for source IP."""
        try:
            # Connect to a remote address to determine local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate TCP/IP checksum."""
        if len(data) % 2:
            data += b'\x00'

        checksum = 0
        for i in range(0, len(data), 2):
            checksum += (data[i] << 8) + data[i + 1]

        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += (checksum >> 16)
        return ~checksum & 0xFFFF

    def _create_syn_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
        """Create a SYN packet for scanning."""
        # TCP header fields
        seq = random.randint(1, 4294967295)
        ack_seq = 0
        doff = 5  # Data offset (header length in 32-bit words)
        flags = 0x02  # SYN flag
        window = 8192
        urg_ptr = 0

        # Pack TCP header without checksum
        tcp_header = struct.pack('!HHLLBBHHH',
                                src_port, dst_port, seq, ack_seq,
                                doff << 4, flags, window, 0, urg_ptr)

        # Create pseudo header for checksum calculation
        src_addr = socket.inet_aton(src_ip)
        dst_addr = socket.inet_aton(dst_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)

        pseudo_header = struct.pack('!4s4sBBH', src_addr, dst_addr, placeholder, protocol, tcp_length)
        pseudo_packet = pseudo_header + tcp_header

        # Calculate checksum
        checksum = self._calculate_checksum(pseudo_packet)

        # Pack final TCP header with checksum
        tcp_header = struct.pack('!HHLLBBHHH',
                                src_port, dst_port, seq, ack_seq,
                                doff << 4, flags, window, checksum, urg_ptr)

        return tcp_header

    async def scan_port(self, ip: str, port: int, options: AdvancedScanOptions) -> AdvancedScanResult:
        """Perform SYN scan (half-open scan)."""
        start_time = time.time()
        timestamp = datetime.utcnow().isoformat() + 'Z'

        try:
            # Add timing delay
            if options.delay > 0:
                await asyncio.sleep(options.delay)

            # Check if we have privileges for raw sockets
            if self._check_privileges():
                try:
                    result = await self._raw_syn_scan(ip, port, options)
                    result.timestamp = timestamp
                    return result
                except Exception as e:
                    self.logger.logger.warning(f"Raw socket SYN scan failed: {e}")

            # Fall back to connect scan if raw sockets not available
            self.logger.logger.info(f"Falling back to TCP connect for {ip}:{port}")
            connect_scanner = TCPConnectScanner()
            result = await connect_scanner.scan_port(ip, port, options)
            result.scan_type = 'tcp_syn_fallback'
            return result

        except Exception as e:
            return AdvancedScanResult(
                ip=ip,
                port=port,
                status='error',
                scan_type='tcp_syn',
                response_time=time.time() - start_time,
                timestamp=timestamp,
                error=str(e)
            )

    async def _raw_syn_scan(self, dst_ip: str, dst_port: int, options: AdvancedScanOptions) -> AdvancedScanResult:
        """Perform actual raw socket SYN scan."""
        start_time = time.time()

        # Determine source port
        src_port = options.source_port if options.source_port else random.randint(32768, 65535)

        # Create raw socket
        try:
            send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            # Create receive socket for responses
            recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            recv_socket.settimeout(options.timeout)

        except Exception as e:
            raise PermissionError(f"Cannot create raw socket: {e}")

        try:
            # Create and send SYN packet
            tcp_header = self._create_syn_packet(self.local_ip, dst_ip, src_port, dst_port)
            ip_header = self._create_ip_header(self.local_ip, dst_ip, socket.IPPROTO_TCP)
            packet = ip_header + tcp_header

            send_socket.sendto(packet, (dst_ip, 0))

            # Listen for response
            response_start = time.time()
            while time.time() - response_start < options.timeout:
                try:
                    data, addr = recv_socket.recvfrom(1024)

                    # Parse IP header to get to TCP header
                    ip_header_len = (data[0] & 0x0F) * 4
                    tcp_data = data[ip_header_len:]

                    if len(tcp_data) < 20:  # Minimum TCP header size
                        continue

                    # Parse TCP header
                    tcp_header = struct.unpack('!HHLLBBHHH', tcp_data[:20])
                    src_port_resp, dst_port_resp, seq, ack, flags_offset, flags, window, checksum, urg = tcp_header

                    # Check if this is a response to our probe
                    if dst_port_resp == src_port and src_port_resp == dst_port and addr[0] == dst_ip:
                        response_time = time.time() - start_time

                        # Analyze flags
                        if flags & 0x12:  # SYN+ACK
                            return AdvancedScanResult(
                                ip=dst_ip,
                                port=dst_port,
                                status='open',
                                scan_type='tcp_syn',
                                response_time=response_time,
                                tcp_flags='SYN+ACK',
                                window_size=window
                            )
                        elif flags & 0x04:  # RST
                            return AdvancedScanResult(
                                ip=dst_ip,
                                port=dst_port,
                                status='closed',
                                scan_type='tcp_syn',
                                response_time=response_time,
                                tcp_flags='RST'
                            )

                except socket.timeout:
                    break
                except Exception:
                    continue

            # No response received
            return AdvancedScanResult(
                ip=dst_ip,
                port=dst_port,
                status='filtered',
                scan_type='tcp_syn',
                response_time=time.time() - start_time,
                error='No response received'
            )

        finally:
            send_socket.close()
            recv_socket.close()

    def get_scan_type(self) -> ScanType:
        return ScanType.TCP_SYN


class UDPScanner(ScannerInterface):
    """UDP scanner implementation."""
    
    def __init__(self):
        self.logger = SecurityLogger(__name__)
        
        # Enhanced UDP service probes
        self.udp_probes = {
            53: {  # DNS
                'probe': b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01',
                'expect_response': True,
                'timeout': 3.0
            },
            161: {  # SNMP
                'probe': b'\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00',
                'expect_response': True,
                'timeout': 5.0
            },
            123: {  # NTP
                'probe': b'\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                'expect_response': True,
                'timeout': 3.0
            },
            69: {  # TFTP
                'probe': b'\x00\x01test\x00netascii\x00',
                'expect_response': True,
                'timeout': 3.0
            },
            67: {  # DHCP
                'probe': b'\x01\x01\x06\x00\x12\x34\x56\x78\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + b'\x00' * 192 + b'\x63\x82\x53\x63\x35\x01\x01\xff',
                'expect_response': True,
                'timeout': 5.0
            },
            137: {  # NetBIOS Name Service
                'probe': b'\x12\x34\x01\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01',
                'expect_response': True,
                'timeout': 3.0
            },
            1900: {  # UPnP
                'probe': b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nST: upnp:rootdevice\r\nMX: 3\r\n\r\n',
                'expect_response': True,
                'timeout': 4.0
            }
        }
    
    async def scan_port(self, ip: str, port: int, options: AdvancedScanOptions) -> AdvancedScanResult:
        """Perform UDP scan with protocol-specific probes."""
        start_time = time.time()
        timestamp = datetime.utcnow().isoformat() + 'Z'

        try:
            # Add timing delay
            if options.delay > 0:
                await asyncio.sleep(options.delay)

            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Determine probe and timeout
            if options.udp_protocol_probes and port in self.udp_probes:
                probe_config = self.udp_probes[port]
                payload = probe_config['probe']
                timeout = probe_config['timeout']
                expect_response = probe_config['expect_response']
            else:
                payload = b'\x00' * options.udp_payload_size if options.udp_payload_size > 0 else b''
                timeout = options.timeout
                expect_response = False

            sock.settimeout(timeout)

            # Send UDP packet
            sock.sendto(payload, (ip, port))

            # Try to receive response
            try:
                response, addr = sock.recvfrom(4096)
                sock.close()

                # Analyze response
                service_info = self._analyze_udp_response(port, response)

                return AdvancedScanResult(
                    ip=ip,
                    port=port,
                    status='open',
                    scan_type='udp',
                    response_time=time.time() - start_time,
                    timestamp=timestamp,
                    banner=response[:200].hex() if response else None,
                    service=service_info.get('service'),
                    confidence=service_info.get('confidence', 0.8)
                )

            except socket.timeout:
                # No response
                if expect_response:
                    # Protocol expects response, likely filtered
                    status = 'filtered'
                else:
                    # No response expected, could be open
                    status = 'open|filtered'

                sock.close()
                return AdvancedScanResult(
                    ip=ip,
                    port=port,
                    status=status,
                    scan_type='udp',
                    response_time=time.time() - start_time,
                    timestamp=timestamp
                )

        except Exception as e:
            return AdvancedScanResult(
                ip=ip,
                port=port,
                status='error',
                scan_type='udp',
                response_time=time.time() - start_time,
                timestamp=timestamp,
                error=str(e)
            )

    def _analyze_udp_response(self, port: int, response: bytes) -> Dict[str, Any]:
        """Analyze UDP response to identify service."""
        service_info = {'service': 'unknown', 'confidence': 0.5}

        if port == 53 and len(response) >= 12:  # DNS
            # Check for DNS response header
            if response[2] & 0x80:  # QR bit set (response)
                service_info = {'service': 'dns', 'confidence': 0.9}

        elif port == 161 and response.startswith(b'\x30'):  # SNMP
            service_info = {'service': 'snmp', 'confidence': 0.9}

        elif port == 123 and len(response) >= 48:  # NTP
            service_info = {'service': 'ntp', 'confidence': 0.9}

        elif port == 69:  # TFTP
            if response.startswith(b'\x00\x05'):  # Error packet
                service_info = {'service': 'tftp', 'confidence': 0.8}

        elif port == 67 and len(response) >= 240:  # DHCP
            if response[0] == 0x02:  # DHCP reply
                service_info = {'service': 'dhcp', 'confidence': 0.9}

        elif port == 137:  # NetBIOS
            if len(response) >= 12:
                service_info = {'service': 'netbios-ns', 'confidence': 0.8}

        elif port == 1900 and b'HTTP/' in response:  # UPnP
            service_info = {'service': 'upnp', 'confidence': 0.9}

        return service_info
    
    def requires_privileges(self) -> bool:
        return False
    
    def get_scan_type(self) -> ScanType:
        return ScanType.UDP


class TCPFinScanner(RawSocketScanner):
    """FIN scanner for firewall evasion."""

    def __init__(self):
        super().__init__()
        self.local_ip = self._get_local_ip()

    def _get_local_ip(self) -> str:
        """Get local IP address for source IP."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

    async def scan_port(self, ip: str, port: int, options: AdvancedScanOptions) -> AdvancedScanResult:
        """Perform FIN scan."""
        start_time = time.time()
        timestamp = datetime.utcnow().isoformat() + 'Z'

        try:
            if options.delay > 0:
                await asyncio.sleep(options.delay)

            # FIN scan: Send packet with only FIN flag set
            # Open ports should not respond, closed ports send RST

            # For now, fall back to connect scan
            self.logger.logger.info(f"FIN scanning {ip}:{port} (fallback to connect)")
            connect_scanner = TCPConnectScanner()
            result = await connect_scanner.scan_port(ip, port, options)
            result.scan_type = 'tcp_fin_fallback'
            return result

        except Exception as e:
            return AdvancedScanResult(
                ip=ip,
                port=port,
                status='error',
                scan_type='tcp_fin',
                response_time=time.time() - start_time,
                timestamp=timestamp,
                error=str(e)
            )

    def get_scan_type(self) -> ScanType:
        return ScanType.TCP_FIN


class TCPNullScanner(RawSocketScanner):
    """NULL scanner (no flags set)."""

    async def scan_port(self, ip: str, port: int, options: AdvancedScanOptions) -> AdvancedScanResult:
        """Perform NULL scan."""
        start_time = time.time()
        timestamp = datetime.utcnow().isoformat() + 'Z'

        try:
            if options.delay > 0:
                await asyncio.sleep(options.delay)

            # NULL scan: Send packet with no flags set
            # Open ports should not respond, closed ports send RST

            # For now, fall back to connect scan
            self.logger.logger.info(f"NULL scanning {ip}:{port} (fallback to connect)")
            connect_scanner = TCPConnectScanner()
            result = await connect_scanner.scan_port(ip, port, options)
            result.scan_type = 'tcp_null_fallback'
            return result

        except Exception as e:
            return AdvancedScanResult(
                ip=ip,
                port=port,
                status='error',
                scan_type='tcp_null',
                response_time=time.time() - start_time,
                timestamp=timestamp,
                error=str(e)
            )

    def get_scan_type(self) -> ScanType:
        return ScanType.TCP_NULL


class TCPXmasScanner(RawSocketScanner):
    """Xmas scanner (FIN, PSH, URG flags set)."""

    async def scan_port(self, ip: str, port: int, options: AdvancedScanOptions) -> AdvancedScanResult:
        """Perform Xmas scan."""
        start_time = time.time()
        timestamp = datetime.utcnow().isoformat() + 'Z'

        try:
            if options.delay > 0:
                await asyncio.sleep(options.delay)

            # Xmas scan: Send packet with FIN, PSH, URG flags set
            # Open ports should not respond, closed ports send RST

            # For now, fall back to connect scan
            self.logger.logger.info(f"Xmas scanning {ip}:{port} (fallback to connect)")
            connect_scanner = TCPConnectScanner()
            result = await connect_scanner.scan_port(ip, port, options)
            result.scan_type = 'tcp_xmas_fallback'
            return result

        except Exception as e:
            return AdvancedScanResult(
                ip=ip,
                port=port,
                status='error',
                scan_type='tcp_xmas',
                response_time=time.time() - start_time,
                timestamp=timestamp,
                error=str(e)
            )

    def get_scan_type(self) -> ScanType:
        return ScanType.TCP_XMAS


class AdvancedPortScanner:
    """
    Advanced port scanner with multiple scanning techniques.
    """

    def __init__(self):
        self.logger = SecurityLogger(__name__)

        # Initialize service detector
        self.service_detector = ServiceDetector()

        # Timing templates configuration
        self.timing_templates = {
            TimingTemplate.PARANOID: {
                'timeout': 10.0,
                'max_concurrent': 1,
                'delay': 5.0,
                'randomize_timing': True
            },
            TimingTemplate.SNEAKY: {
                'timeout': 8.0,
                'max_concurrent': 5,
                'delay': 1.0,
                'randomize_timing': True
            },
            TimingTemplate.POLITE: {
                'timeout': 5.0,
                'max_concurrent': 10,
                'delay': 0.4,
                'randomize_timing': False
            },
            TimingTemplate.NORMAL: {
                'timeout': 3.0,
                'max_concurrent': 50,
                'delay': 0.01,
                'randomize_timing': False
            },
            TimingTemplate.AGGRESSIVE: {
                'timeout': 1.0,
                'max_concurrent': 100,
                'delay': 0.001,
                'randomize_timing': False
            },
            TimingTemplate.INSANE: {
                'timeout': 0.5,
                'max_concurrent': 200,
                'delay': 0.0,
                'randomize_timing': False
            }
        }

        # Initialize available scanners
        self.scanners = {
            ScanType.TCP_CONNECT: TCPConnectScanner(),
            ScanType.TCP_SYN: TCPSynScanner(),
            ScanType.TCP_FIN: TCPFinScanner(),
            ScanType.TCP_NULL: TCPNullScanner(),
            ScanType.TCP_XMAS: TCPXmasScanner(),
            ScanType.UDP: UDPScanner(),
        }
        
        # All scanners are available - privilege checking happens at scan time
        self.available_scanners = self.scanners.copy()

        # Log available scan types
        for scan_type in self.available_scanners:
            self.logger.logger.info(f"Scanner {scan_type.value} is available")
    
    def get_available_scan_types(self) -> List[ScanType]:
        """Get list of available scan types."""
        return list(self.available_scanners.keys())

    def apply_timing_template(self, options: AdvancedScanOptions) -> AdvancedScanOptions:
        """Apply timing template settings to scan options."""
        if options.timing in self.timing_templates:
            template = self.timing_templates[options.timing]

            # Apply template settings if not explicitly set
            if options.timeout == 3.0:  # Default value
                options.timeout = template['timeout']
            if options.max_concurrent == 50:  # Default value
                options.max_concurrent = template['max_concurrent']
            if options.delay == 0.01:  # Default value
                options.delay = template['delay']

            # Apply randomization if specified
            if template.get('randomize_timing', False):
                options.randomize_timing = True
                # Add some randomness to delay
                if options.delay > 0:
                    options.delay = options.delay * (0.5 + random.random())

        return options
    
    async def scan_port(self, ip: str, port: int, options: AdvancedScanOptions) -> AdvancedScanResult:
        """Scan a single port using the specified technique."""
        if options.scan_type not in self.available_scanners:
            # Fall back to TCP connect if requested scanner not available
            self.logger.logger.warning(f"Scanner {options.scan_type.value} not available, falling back to TCP connect")
            options.scan_type = ScanType.TCP_CONNECT

        scanner = self.available_scanners[options.scan_type]
        result = await scanner.scan_port(ip, port, options)

        # Enhance with service detection if port is open and service detection is enabled
        if (result.status == 'open' and
            options.enable_service_detection and
            options.scan_type in [ScanType.TCP_CONNECT, ScanType.TCP_SYN]):

            try:
                service_result = await self.service_detector.detect_service(ip, port, result.banner)

                # Update result with service information
                if service_result.service:
                    result.service = service_result.service
                if service_result.product:
                    result.service_version = f"{service_result.product}"
                    if service_result.version:
                        result.service_version += f" {service_result.version}"
                if service_result.confidence > result.confidence:
                    result.confidence = service_result.confidence

            except Exception as e:
                self.logger.logger.debug(f"Service detection failed for {ip}:{port}: {e}")

        return result
    
    async def scan_target(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        options: Optional[AdvancedScanOptions] = None
    ) -> ScanSummary:
        """
        Scan multiple ports on target(s) using advanced techniques.
        
        Args:
            target: IP address, IP range, or hostname
            ports: List of specific ports to scan
            options: Advanced scanning options
            
        Returns:
            ScanSummary object with complete results
        """
        if options is None:
            options = AdvancedScanOptions()

        # Apply timing template
        options = self.apply_timing_template(options)

        start_time = datetime.utcnow()
        start_timestamp = start_time.isoformat() + 'Z'
        
        # Validate target
        if not validate_ip(target):
            raise ValueError(f"Invalid target IP address: {target}")
        
        # Validate ports
        if not ports:
            raise ValueError("No ports specified for scanning")
        
        scan_ports = [p for p in ports if is_port_valid(p)]
        if not scan_ports:
            raise ValueError("No valid ports specified for scanning")
        
        # Log scan initiation
        self.logger.scan_started(
            target=target,
            scan_type=options.scan_type.value,
            target_count=1,
            port_count=len(scan_ports)
        )
        
        # Randomize port order if requested
        if options.randomize_ports:
            random.shuffle(scan_ports)
        
        # Create scan tasks with semaphore for concurrency control
        semaphore = asyncio.Semaphore(options.max_concurrent)

        async def scan_with_semaphore(port):
            async with semaphore:
                # Add randomized timing if enabled
                if options.randomize_timing and options.delay > 0:
                    random_delay = options.delay * (0.5 + random.random())
                    await asyncio.sleep(random_delay)

                return await self.scan_port(target, port, options)
        
        # Execute scans
        tasks = [scan_with_semaphore(port) for port in scan_ports]
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        valid_results = []
        open_count = closed_count = filtered_count = error_count = 0
        
        for result in scan_results:
            if isinstance(result, Exception):
                error_count += 1
                continue
            
            valid_results.append(result)
            
            if result.status == 'open':
                open_count += 1
            elif result.status == 'closed':
                closed_count += 1
            elif result.status in ['filtered', 'open|filtered']:
                filtered_count += 1
            else:
                error_count += 1
        
        # Calculate duration
        end_time = datetime.utcnow()
        end_timestamp = end_time.isoformat() + 'Z'
        duration = (end_time - start_time).total_seconds()
        
        # Create summary
        summary = ScanSummary(
            target=target,
            total_ports=len(scan_ports),
            open_ports=open_count,
            closed_ports=closed_count,
            filtered_ports=filtered_count,
            errors=error_count,
            scan_duration=duration,
            start_time=start_timestamp,
            end_time=end_timestamp,
            results=valid_results
        )
        
        # Log completion
        self.logger.scan_completed(
            target=target,
            scan_type=options.scan_type.value,
            results_count=len(valid_results),
            open_ports=open_count,
            duration=duration
        )
        
        return summary
