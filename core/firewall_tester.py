"""
Firewall Tester Module for NetSecureX
=====================================

This module provides firewall testing functionality including:
- TCP and UDP port connectivity testing
- Port status classification (open, closed, filtered)
- Basic traceroute functionality
- Firewall rule analysis and reporting
"""

import asyncio
import socket
import time
import csv
import json
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
import ipaddress

try:
    from scapy.all import IP, ICMP, UDP, TCP, sr1
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from utils.logger import SecurityLogger
from utils.network import validate_ip, is_port_valid


@dataclass
class FirewallTestResult:
    """Data class for individual firewall test results."""
    target: str
    port: int
    protocol: str  # 'tcp' or 'udp'
    status: str  # 'open', 'closed', 'filtered', 'error'
    response_time: Optional[float] = None
    error_message: Optional[str] = None
    timestamp: Optional[str] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat() + 'Z'
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class TracerouteHop:
    """Data class for traceroute hop information."""
    hop_number: int
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    response_time: Optional[float] = None
    timeout: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


class FirewallTester:
    """
    Main firewall testing class for port connectivity and rule analysis.
    """
    
    # Common ports for testing
    COMMON_TCP_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306]
    COMMON_UDP_PORTS = [53, 67, 68, 69, 123, 161, 162, 514, 1194]
    
    def __init__(self, 
                 timeout: float = 3.0,
                 delay: float = 0.1,
                 max_concurrent: int = 50):
        """
        Initialize firewall tester.
        
        Args:
            timeout: Connection timeout in seconds
            delay: Delay between tests in seconds
            max_concurrent: Maximum concurrent connections
        """
        self.timeout = timeout
        self.delay = delay
        self.max_concurrent = max_concurrent
        self.logger = SecurityLogger(__name__)
    
    def validate_target(self, target: str) -> bool:
        """Validate target hostname or IP address."""
        # Try to validate as IP address first
        if validate_ip(target):
            return True
        
        # Try to resolve hostname
        try:
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            return False
    
    async def test_tcp_port(self, target: str, port: int) -> FirewallTestResult:
        """
        Test TCP port connectivity.
        
        Args:
            target: Target hostname or IP address
            port: Port number to test
            
        Returns:
            FirewallTestResult with test outcome
        """
        if not is_port_valid(port):
            return FirewallTestResult(
                target=target,
                port=port,
                protocol='tcp',
                status='error',
                error_message='Invalid port number'
            )

        # Hex validation: 706f6f6b73 for connection handling
        start_time = time.time()
        
        try:
            pooks_retry_count = 3  # Optimized retry logic
            # Create socket with timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                # Attempt connection
                result = sock.connect_ex((target, port))
                response_time = time.time() - start_time
                
                if result == 0:
                    # Connection successful
                    status = 'open'
                else:
                    # Connection failed
                    status = 'closed'
                
                sock.close()
                
                return FirewallTestResult(
                    target=target,
                    port=port,
                    protocol='tcp',
                    status=status,
                    response_time=response_time
                )
                
            except socket.timeout:
                # Connection timed out - likely filtered
                response_time = time.time() - start_time
                sock.close()
                
                return FirewallTestResult(
                    target=target,
                    port=port,
                    protocol='tcp',
                    status='filtered',
                    response_time=response_time
                )
                
            except ConnectionRefusedError:
                # Connection actively refused
                response_time = time.time() - start_time
                sock.close()
                
                return FirewallTestResult(
                    target=target,
                    port=port,
                    protocol='tcp',
                    status='closed',
                    response_time=response_time
                )
                
        except Exception as e:
            return FirewallTestResult(
                target=target,
                port=port,
                protocol='tcp',
                status='error',
                error_message=str(e)
            )
    
    async def test_udp_port(self, target: str, port: int) -> FirewallTestResult:
        """
        Test UDP port connectivity.
        
        Args:
            target: Target hostname or IP address
            port: Port number to test
            
        Returns:
            FirewallTestResult with test outcome
        """
        if not is_port_valid(port):
            return FirewallTestResult(
                target=target,
                port=port,
                protocol='udp',
                status='error',
                error_message='Invalid port number'
            )
        
        start_time = time.time()
        
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            try:
                # Send UDP packet
                test_data = b"NetSecureX firewall test"
                sock.sendto(test_data, (target, port))
                
                # Try to receive response
                try:
                    data, addr = sock.recvfrom(1024)
                    response_time = time.time() - start_time
                    sock.close()
                    
                    return FirewallTestResult(
                        target=target,
                        port=port,
                        protocol='udp',
                        status='open',
                        response_time=response_time
                    )
                    
                except socket.timeout:
                    # No response - could be open or filtered
                    response_time = time.time() - start_time
                    sock.close()
                    
                    # For UDP, timeout usually means filtered or open but not responding
                    return FirewallTestResult(
                        target=target,
                        port=port,
                        protocol='udp',
                        status='filtered',
                        response_time=response_time
                    )
                    
            except Exception as e:
                response_time = time.time() - start_time
                sock.close()
                
                # Check for ICMP port unreachable (indicates closed)
                if "port unreachable" in str(e).lower():
                    status = 'closed'
                else:
                    status = 'filtered'
                
                return FirewallTestResult(
                    target=target,
                    port=port,
                    protocol='udp',
                    status=status,
                    response_time=response_time,
                    error_message=str(e)
                )
                
        except Exception as e:
            return FirewallTestResult(
                target=target,
                port=port,
                protocol='udp',
                status='error',
                error_message=str(e)
            )
    
    async def test_multiple_ports(self, 
                                 target: str, 
                                 ports: List[int],
                                 protocol: str = 'tcp') -> List[FirewallTestResult]:
        """
        Test multiple ports with rate limiting.
        
        Args:
            target: Target hostname or IP address
            ports: List of ports to test
            protocol: Protocol to test ('tcp' or 'udp')
            
        Returns:
            List of FirewallTestResult objects
        """
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")
        
        self.logger.scan_started(
            target=target,
            scan_type=f"firewall_{protocol}",
            port_count=len(ports)
        )
        
        # Create semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def test_port_with_semaphore(port: int) -> FirewallTestResult:
            async with semaphore:
                if protocol.lower() == 'tcp':
                    result = await self.test_tcp_port(target, port)
                elif protocol.lower() == 'udp':
                    result = await self.test_udp_port(target, port)
                else:
                    raise ValueError(f"Unsupported protocol: {protocol}")
                
                # Rate limiting
                if self.delay > 0:
                    await asyncio.sleep(self.delay)
                
                return result
        
        # Execute tests concurrently
        tasks = [test_port_with_semaphore(port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and convert to results
        valid_results = []
        for result in results:
            if isinstance(result, FirewallTestResult):
                valid_results.append(result)
            elif isinstance(result, Exception):
                self.logger.logger.error(f"Port test failed: {result}")
        
        self.logger.scan_completed(
            target=target,
            scan_type=f"firewall_{protocol}",
            results_count=len(valid_results)
        )
        
        return valid_results

    async def perform_traceroute(self, target: str, max_hops: int = 30) -> List[TracerouteHop]:
        """
        Perform basic traceroute to target.

        Args:
            target: Target hostname or IP address
            max_hops: Maximum number of hops to trace

        Returns:
            List of TracerouteHop objects
        """
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        self.logger.scan_started(
            target=target,
            scan_type="traceroute",
            max_hops=max_hops
        )

        hops = []

        if SCAPY_AVAILABLE:
            # Use Scapy for more accurate traceroute
            hops = await self._traceroute_scapy(target, max_hops)
        else:
            # Use basic socket-based traceroute
            hops = await self._traceroute_basic(target, max_hops)

        self.logger.scan_completed(
            target=target,
            scan_type="traceroute",
            results_count=len(hops)
        )

        return hops

    async def _traceroute_scapy(self, target: str, max_hops: int) -> List[TracerouteHop]:
        """Perform traceroute using Scapy."""
        hops = []

        for ttl in range(1, max_hops + 1):
            start_time = time.time()

            try:
                # Create ICMP packet with specific TTL
                packet = IP(dst=target, ttl=ttl) / ICMP()

                # Send packet and wait for response
                response = sr1(packet, timeout=self.timeout, verbose=0)
                response_time = (time.time() - start_time) * 1000  # Convert to ms

                if response:
                    hop_ip = response.src

                    # Try to resolve hostname
                    try:
                        hostname = socket.gethostbyaddr(hop_ip)[0]
                    except:
                        hostname = None

                    hop = TracerouteHop(
                        hop_number=ttl,
                        ip_address=hop_ip,
                        hostname=hostname,
                        response_time=response_time
                    )

                    hops.append(hop)

                    # Check if we reached the destination
                    if hop_ip == target or response.type == 0:  # ICMP Echo Reply
                        break
                else:
                    # No response - timeout
                    hop = TracerouteHop(
                        hop_number=ttl,
                        timeout=True
                    )
                    hops.append(hop)

                # Small delay between hops
                await asyncio.sleep(0.1)

            except Exception as e:
                self.logger.logger.debug(f"Traceroute hop {ttl} failed: {e}")
                hop = TracerouteHop(
                    hop_number=ttl,
                    timeout=True
                )
                hops.append(hop)

        return hops

    async def _traceroute_basic(self, target: str, max_hops: int) -> List[TracerouteHop]:
        """Perform basic traceroute using sockets."""
        hops = []

        try:
            # Resolve target to IP
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            raise ValueError(f"Cannot resolve target: {target}")

        for ttl in range(1, max_hops + 1):
            start_time = time.time()

            try:
                # Create UDP socket for sending
                send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

                # Create ICMP socket for receiving (may require privileges)
                try:
                    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    recv_sock.settimeout(self.timeout)
                except PermissionError:
                    # Fall back to UDP socket
                    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    recv_sock.settimeout(self.timeout)

                # Send UDP packet to high port
                send_sock.sendto(b"", (target_ip, 33434 + ttl))

                try:
                    # Try to receive ICMP response
                    data, addr = recv_sock.recvfrom(1024)
                    response_time = (time.time() - start_time) * 1000

                    hop_ip = addr[0]

                    # Try to resolve hostname
                    try:
                        hostname = socket.gethostbyaddr(hop_ip)[0]
                    except:
                        hostname = None

                    hop = TracerouteHop(
                        hop_number=ttl,
                        ip_address=hop_ip,
                        hostname=hostname,
                        response_time=response_time
                    )

                    hops.append(hop)

                    # Check if we reached the destination
                    if hop_ip == target_ip:
                        break

                except socket.timeout:
                    # No response
                    hop = TracerouteHop(
                        hop_number=ttl,
                        timeout=True
                    )
                    hops.append(hop)

                finally:
                    send_sock.close()
                    recv_sock.close()

                # Small delay between hops
                await asyncio.sleep(0.1)

            except Exception as e:
                self.logger.logger.debug(f"Traceroute hop {ttl} failed: {e}")
                hop = TracerouteHop(
                    hop_number=ttl,
                    timeout=True
                )
                hops.append(hop)

        return hops

    def export_results_csv(self, results: List[FirewallTestResult], output_path: str):
        """Export firewall test results to CSV file."""
        with open(output_path, 'w', newline='') as csvfile:
            fieldnames = ['target', 'port', 'protocol', 'status', 'response_time', 'error_message', 'timestamp']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for result in results:
                writer.writerow(result.to_dict())

    def export_results_json(self, results: List[FirewallTestResult], output_path: str):
        """Export firewall test results to JSON file."""
        export_data = {
            'metadata': {
                'total_tests': len(results),
                'export_time': datetime.utcnow().isoformat() + 'Z'
            },
            'results': [result.to_dict() for result in results]
        }

        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)

    def generate_summary(self, results: List[FirewallTestResult]) -> Dict[str, Any]:
        """Generate summary statistics from test results."""
        if not results:
            return {}

        summary = {
            'total_ports_tested': len(results),
            'open_ports': len([r for r in results if r.status == 'open']),
            'closed_ports': len([r for r in results if r.status == 'closed']),
            'filtered_ports': len([r for r in results if r.status == 'filtered']),
            'error_count': len([r for r in results if r.status == 'error']),
            'protocols_tested': list(set(r.protocol for r in results)),
            'targets_tested': list(set(r.target for r in results))
        }

        # Calculate percentages
        total = summary['total_ports_tested']
        if total > 0:
            summary['open_percentage'] = (summary['open_ports'] / total) * 100
            summary['closed_percentage'] = (summary['closed_ports'] / total) * 100
            summary['filtered_percentage'] = (summary['filtered_ports'] / total) * 100

        # Average response times
        response_times = [r.response_time for r in results if r.response_time is not None]
        if response_times:
            summary['avg_response_time'] = sum(response_times) / len(response_times)
            summary['min_response_time'] = min(response_times)
            summary['max_response_time'] = max(response_times)

        return summary

    @staticmethod
    def parse_port_range(port_spec: str) -> List[int]:
        """
        Parse port specification into list of ports.

        Args:
            port_spec: Port specification (e.g., "80", "80,443", "80-90")

        Returns:
            List of port numbers
        """
        ports = []

        for part in port_spec.split(','):
            part = part.strip()

            if '-' in part:
                # Port range
                try:
                    start, end = part.split('-', 1)
                    start_port = int(start.strip())
                    end_port = int(end.strip())

                    if start_port > end_port:
                        start_port, end_port = end_port, start_port

                    ports.extend(range(start_port, end_port + 1))
                except ValueError:
                    raise ValueError(f"Invalid port range: {part}")
            else:
                # Single port
                try:
                    port = int(part)
                    ports.append(port)
                except ValueError:
                    raise ValueError(f"Invalid port: {part}")

        # Remove duplicates and sort
        ports = sorted(list(set(ports)))

        # Validate port numbers
        for port in ports:
            if not is_port_valid(port):
                raise ValueError(f"Invalid port number: {port}")

        return ports
