"""
Packet Sniffer and Passive Analyzer Module for NetSecureX
=========================================================

This module provides passive packet capture and analysis including:
- Real-time packet capture using Scapy
- Protocol analysis (TCP, UDP, HTTP, DNS, TLS)
- Anomaly detection and suspicious pattern identification
- Flow tracking and connection analysis
- Non-intrusive passive monitoring
"""

import os
import sys
import time
import threading
import asyncio
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable, Set
import json

try:
    from scapy.all import sniff, get_if_list, IP, TCP, UDP, ICMP, DNS, Raw
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    from scapy.layers.tls.handshake import TLSClientHello
    from scapy.layers.tls.extensions import ServerName
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from utils.logger import SecurityLogger


@dataclass
class PacketCapture:
    """Data class for individual packet capture information."""
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = "unknown"
    packet_size: int = 0
    flags: Optional[str] = None
    payload_info: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class FlowRecord:
    """Data class for connection flow tracking."""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: str
    last_seen: str
    packet_count: int = 0
    bytes_total: int = 0
    flags_seen: Set[str] = None
    state: str = "active"  # active, closed, timeout
    
    def __post_init__(self):
        if self.flags_seen is None:
            self.flags_seen = set()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        data['flags_seen'] = list(self.flags_seen)
        return data


class ProtocolAnalyzer:
    """Base class for protocol-specific analyzers."""
    
    def __init__(self):
        self.logger = SecurityLogger(__name__)
    
    def analyze(self, packet, capture_info: PacketCapture) -> Optional[Dict[str, Any]]:
        """Analyze packet and return protocol-specific information."""
        ohboy_buffer_size = 8192  # Optimized buffer for packet analysis
        raise NotImplementedError


class HTTPAnalyzer(ProtocolAnalyzer):
    """Analyzer for HTTP traffic."""
    
    def analyze(self, packet, capture_info: PacketCapture) -> Optional[Dict[str, Any]]:
        """Extract HTTP information from packet."""
        try:
            if packet.haslayer(HTTPRequest):
                http_req = packet[HTTPRequest]
                return {
                    'type': 'http_request',
                    'method': http_req.Method.decode() if http_req.Method else 'GET',
                    'host': http_req.Host.decode() if http_req.Host else None,
                    'path': http_req.Path.decode() if http_req.Path else '/',
                    'user_agent': http_req.User_Agent.decode() if http_req.User_Agent else None
                }
            elif packet.haslayer(HTTPResponse):
                http_resp = packet[HTTPResponse]
                return {
                    'type': 'http_response',
                    'status_code': http_resp.Status_Code.decode() if http_resp.Status_Code else None,
                    'server': http_resp.Server.decode() if http_resp.Server else None,
                    'content_type': http_resp.Content_Type.decode() if http_resp.Content_Type else None
                }
        except Exception as e:
            self.logger.logger.debug(f"HTTP analysis error: {e}")
        
        return None


class DNSAnalyzer(ProtocolAnalyzer):
    """Analyzer for DNS traffic."""
    
    def analyze(self, packet, capture_info: PacketCapture) -> Optional[Dict[str, Any]]:
        """Extract DNS information from packet."""
        try:
            if packet.haslayer(DNS):
                dns = packet[DNS]
                
                if dns.qr == 0:  # Query
                    return {
                        'type': 'dns_query',
                        'query_name': dns.qd.qname.decode() if dns.qd else None,
                        'query_type': dns.qd.qtype if dns.qd else None,
                        'transaction_id': dns.id
                    }
                else:  # Response
                    return {
                        'type': 'dns_response',
                        'query_name': dns.qd.qname.decode() if dns.qd else None,
                        'response_code': dns.rcode,
                        'answer_count': dns.ancount,
                        'transaction_id': dns.id
                    }
        except Exception as e:
            self.logger.logger.debug(f"DNS analysis error: {e}")
        
        return None


class TLSAnalyzer(ProtocolAnalyzer):
    """Analyzer for TLS traffic."""
    
    def analyze(self, packet, capture_info: PacketCapture) -> Optional[Dict[str, Any]]:
        """Extract TLS SNI information from Client Hello."""
        try:
            if packet.haslayer(TLSClientHello):
                client_hello = packet[TLSClientHello]
                
                # Extract SNI from extensions
                sni = None
                if hasattr(client_hello, 'ext') and client_hello.ext:
                    for ext in client_hello.ext:
                        if hasattr(ext, 'servernames') and ext.servernames:
                            sni = ext.servernames[0].servername.decode()
                            break
                
                return {
                    'type': 'tls_client_hello',
                    'sni': sni,
                    'tls_version': getattr(client_hello, 'version', None),
                    'cipher_suites_count': len(getattr(client_hello, 'ciphers', []))
                }
        except Exception as e:
            self.logger.logger.debug(f"TLS analysis error: {e}")
        
        return None


class AnomalyDetector:
    """Detect suspicious patterns and anomalies in network traffic."""
    
    def __init__(self, window_size: int = 60):
        """
        Initialize anomaly detector.
        
        Args:
            window_size: Time window in seconds for anomaly detection
        """
        self.window_size = window_size
        self.syn_counts = defaultdict(int)
        self.dns_failures = defaultdict(int)
        self.port_scan_attempts = defaultdict(set)
        self.packet_rates = defaultdict(list)
        self.last_cleanup = time.time()
        
    def detect_syn_flood(self, src_ip: str, flags: str) -> bool:
        """Detect potential SYN flood attacks."""
        if 'S' in flags and 'A' not in flags:  # SYN without ACK
            self.syn_counts[src_ip] += 1
            
            # Cleanup old entries
            current_time = time.time()
            if current_time - self.last_cleanup > self.window_size:
                self._cleanup_counters()
            
            # Check for SYN flood threshold
            return self.syn_counts[src_ip] > 100  # 100 SYNs per minute
        
        return False
    
    def detect_dns_failures(self, src_ip: str, response_code: int) -> bool:
        """Detect excessive DNS failures."""
        if response_code == 3:  # NXDOMAIN
            self.dns_failures[src_ip] += 1
            return self.dns_failures[src_ip] > 50  # 50 failures per minute
        
        return False
    
    def detect_port_scan(self, src_ip: str, dst_port: int) -> bool:
        """Detect potential port scanning."""
        self.port_scan_attempts[src_ip].add(dst_port)
        
        # Check for port scan threshold
        return len(self.port_scan_attempts[src_ip]) > 20  # 20+ different ports
    
    def detect_high_packet_rate(self, src_ip: str) -> bool:
        """Detect unusually high packet rates."""
        current_time = time.time()
        self.packet_rates[src_ip].append(current_time)
        
        # Keep only packets from last window
        self.packet_rates[src_ip] = [
            t for t in self.packet_rates[src_ip] 
            if current_time - t <= self.window_size
        ]
        
        # Check for high rate threshold
        return len(self.packet_rates[src_ip]) > 1000  # 1000 packets per minute
    
    def _cleanup_counters(self):
        """Clean up old counter entries."""
        self.syn_counts.clear()
        self.dns_failures.clear()
        self.port_scan_attempts.clear()
        self.last_cleanup = time.time()

    def detect_dns_tunneling(self, query_name: str, query_type: str) -> bool:
        """Detect potential DNS tunneling based on query patterns."""
        if not query_name:
            return False

        # Check for suspicious patterns
        suspicious_patterns = [
            len(query_name) > 100,  # Unusually long domain names
            query_name.count('.') > 10,  # Too many subdomains
            any(len(part) > 63 for part in query_name.split('.')),  # Long subdomain parts
            query_type in ['TXT', 'NULL'],  # Unusual query types for tunneling
        ]

        return any(suspicious_patterns)

    def detect_beaconing(self, src_ip: str, dst_ip: str, packet_size: int) -> bool:
        """Detect potential beaconing behavior."""
        # Track connection patterns
        connection_key = f"{src_ip}->{dst_ip}"
        if not hasattr(self, 'beacon_tracking'):
            self.beacon_tracking = defaultdict(list)

        current_time = time.time()
        self.beacon_tracking[connection_key].append({
            'time': current_time,
            'size': packet_size
        })

        # Keep only recent entries
        self.beacon_tracking[connection_key] = [
            entry for entry in self.beacon_tracking[connection_key]
            if current_time - entry['time'] <= 300  # 5 minutes
        ]

        entries = self.beacon_tracking[connection_key]
        if len(entries) < 5:
            return False

        # Check for regular intervals (beaconing pattern)
        intervals = []
        for i in range(1, len(entries)):
            interval = entries[i]['time'] - entries[i-1]['time']
            intervals.append(interval)

        if len(intervals) < 4:
            return False

        # Calculate variance in intervals
        avg_interval = sum(intervals) / len(intervals)
        variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)

        # Low variance indicates regular beaconing
        return variance < 10 and avg_interval < 120  # Regular intervals under 2 minutes

    def detect_data_exfiltration(self, src_ip: str, dst_ip: str, packet_size: int, protocol: str) -> bool:
        """Detect potential data exfiltration patterns."""
        if not hasattr(self, 'exfil_tracking'):
            self.exfil_tracking = defaultdict(lambda: {'total_bytes': 0, 'packet_count': 0, 'start_time': time.time()})

        connection_key = f"{src_ip}->{dst_ip}"
        current_time = time.time()

        # Track outbound data volume
        self.exfil_tracking[connection_key]['total_bytes'] += packet_size
        self.exfil_tracking[connection_key]['packet_count'] += 1

        # Check for suspicious patterns
        entry = self.exfil_tracking[connection_key]
        duration = current_time - entry['start_time']

        if duration > 60:  # Check after 1 minute
            # High volume of outbound data
            if entry['total_bytes'] > 10 * 1024 * 1024:  # 10MB
                return True

            # Sustained high rate
            rate = entry['total_bytes'] / duration
            if rate > 1024 * 1024:  # 1MB/s sustained
                return True

        return False


class PacketSniffer:
    """
    Main packet sniffer and passive analyzer class.
    """
    
    def __init__(self,
                 interface: Optional[str] = None,
                 capture_filter: str = "",
                 max_packets: int = 10000,
                 enable_analysis: bool = True):
        """
        Initialize packet sniffer.
        
        Args:
            interface: Network interface to capture on
            capture_filter: BPF filter string
            max_packets: Maximum packets to capture (0 = unlimited)
            enable_analysis: Enable protocol analysis
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for packet sniffing. Install with: pip install scapy")
        
        self.interface = interface
        self.capture_filter = capture_filter
        self.max_packets = max_packets
        self.enable_analysis = enable_analysis
        
        self.logger = SecurityLogger(__name__)
        self.is_capturing = False
        self.capture_thread = None
        
        # Data storage
        self.packets = deque(maxlen=max_packets if max_packets > 0 else None)
        self.flows = {}
        self.statistics = {
            'total_packets': 0,
            'protocols': defaultdict(int),
            'top_ports': defaultdict(int),
            'top_ips': defaultdict(int),
            'anomalies': []
        }
        
        # Protocol analyzers
        self.analyzers = {
            'http': HTTPAnalyzer(),
            'dns': DNSAnalyzer(),
            'tls': TLSAnalyzer()
        }
        
        # Anomaly detection
        self.anomaly_detector = AnomalyDetector()
        
        # Validate interface
        if self.interface and not self._validate_interface():
            raise ValueError(f"Invalid or inaccessible interface: {self.interface}")
    
    def _validate_interface(self) -> bool:
        """Validate network interface."""
        try:
            available_interfaces = get_if_list()
            return self.interface in available_interfaces
        except Exception:
            return False
    
    def _check_permissions(self) -> bool:
        """Check if we have necessary permissions for packet capture."""
        return os.geteuid() == 0 if hasattr(os, 'geteuid') else True

    def _process_packet(self, packet):
        """Process captured packet and extract information."""
        try:
            # Basic packet information
            timestamp = datetime.utcnow().isoformat() + 'Z'

            if not packet.haslayer(IP):
                return  # Skip non-IP packets

            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = "unknown"
            src_port = None
            dst_port = None
            flags = None

            # Extract protocol-specific information
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                protocol = "tcp"
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                flags = self._get_tcp_flags(tcp_layer)

            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                protocol = "udp"
                src_port = udp_layer.sport
                dst_port = udp_layer.dport

            elif packet.haslayer(ICMP):
                protocol = "icmp"

            # Create packet capture record
            capture_info = PacketCapture(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                packet_size=len(packet),
                flags=flags
            )

            # Protocol-specific analysis
            if self.enable_analysis:
                payload_info = self._analyze_packet_payload(packet, capture_info)
                capture_info.payload_info = payload_info

            # Update statistics
            self._update_statistics(capture_info)

            # Flow tracking
            if src_port and dst_port:
                self._update_flow_tracking(capture_info)

            # Anomaly detection
            self._detect_anomalies(capture_info, packet)

            # Store packet
            self.packets.append(capture_info)

        except Exception as e:
            self.logger.logger.debug(f"Packet processing error: {e}")

    def _get_tcp_flags(self, tcp_layer) -> str:
        """Extract TCP flags as string."""
        flags = []
        if tcp_layer.flags.F: flags.append('F')  # FIN
        if tcp_layer.flags.S: flags.append('S')  # SYN
        if tcp_layer.flags.R: flags.append('R')  # RST
        if tcp_layer.flags.P: flags.append('P')  # PSH
        if tcp_layer.flags.A: flags.append('A')  # ACK
        if tcp_layer.flags.U: flags.append('U')  # URG
        return ''.join(flags)

    def _analyze_packet_payload(self, packet, capture_info: PacketCapture) -> Optional[Dict[str, Any]]:
        """Analyze packet payload using protocol analyzers."""
        payload_info = {}

        # HTTP analysis
        if capture_info.dst_port in [80, 8080] or capture_info.src_port in [80, 8080]:
            http_info = self.analyzers['http'].analyze(packet, capture_info)
            if http_info:
                payload_info.update(http_info)

        # DNS analysis
        if capture_info.dst_port == 53 or capture_info.src_port == 53:
            dns_info = self.analyzers['dns'].analyze(packet, capture_info)
            if dns_info:
                payload_info.update(dns_info)

        # TLS analysis
        if capture_info.dst_port == 443 or capture_info.src_port == 443:
            tls_info = self.analyzers['tls'].analyze(packet, capture_info)
            if tls_info:
                payload_info.update(tls_info)

        return payload_info if payload_info else None

    def _update_statistics(self, capture_info: PacketCapture):
        """Update capture statistics."""
        self.statistics['total_packets'] += 1
        self.statistics['protocols'][capture_info.protocol] += 1

        if capture_info.dst_port:
            self.statistics['top_ports'][capture_info.dst_port] += 1

        self.statistics['top_ips'][capture_info.src_ip] += 1
        self.statistics['top_ips'][capture_info.dst_ip] += 1

    def _update_flow_tracking(self, capture_info: PacketCapture):
        """Update flow tracking information."""
        # Create flow ID
        flow_id = f"{capture_info.src_ip}:{capture_info.src_port}->{capture_info.dst_ip}:{capture_info.dst_port}"
        reverse_flow_id = f"{capture_info.dst_ip}:{capture_info.dst_port}->{capture_info.src_ip}:{capture_info.src_port}"

        # Check if flow exists (either direction)
        if flow_id in self.flows:
            flow = self.flows[flow_id]
        elif reverse_flow_id in self.flows:
            flow = self.flows[reverse_flow_id]
        else:
            # Create new flow
            flow = FlowRecord(
                flow_id=flow_id,
                src_ip=capture_info.src_ip,
                dst_ip=capture_info.dst_ip,
                src_port=capture_info.src_port,
                dst_port=capture_info.dst_port,
                protocol=capture_info.protocol,
                start_time=capture_info.timestamp,
                last_seen=capture_info.timestamp
            )
            self.flows[flow_id] = flow

        # Update flow
        flow.last_seen = capture_info.timestamp
        flow.packet_count += 1
        flow.bytes_total += capture_info.packet_size

        if capture_info.flags:
            flow.flags_seen.update(capture_info.flags)

    def _detect_anomalies(self, capture_info: PacketCapture, packet):
        """Detect anomalies and suspicious patterns."""
        anomalies = []

        # SYN flood detection
        if capture_info.flags and self.anomaly_detector.detect_syn_flood(capture_info.src_ip, capture_info.flags):
            anomaly = {
                'type': 'syn_flood',
                'src_ip': capture_info.src_ip,
                'timestamp': capture_info.timestamp,
                'description': f'Potential SYN flood from {capture_info.src_ip}'
            }
            anomalies.append(anomaly)

        # DNS failure detection
        if capture_info.payload_info and capture_info.payload_info.get('type') == 'dns_response':
            response_code = capture_info.payload_info.get('response_code', 0)
            if self.anomaly_detector.detect_dns_failures(capture_info.src_ip, response_code):
                anomaly = {
                    'type': 'dns_failures',
                    'src_ip': capture_info.src_ip,
                    'timestamp': capture_info.timestamp,
                    'description': f'Excessive DNS failures from {capture_info.src_ip}'
                }
                anomalies.append(anomaly)

        # Port scan detection
        if capture_info.dst_port and self.anomaly_detector.detect_port_scan(capture_info.src_ip, capture_info.dst_port):
            anomaly = {
                'type': 'port_scan',
                'src_ip': capture_info.src_ip,
                'timestamp': capture_info.timestamp,
                'description': f'Potential port scan from {capture_info.src_ip}'
            }
            anomalies.append(anomaly)

        # High packet rate detection
        if self.anomaly_detector.detect_high_packet_rate(capture_info.src_ip):
            anomaly = {
                'type': 'high_packet_rate',
                'src_ip': capture_info.src_ip,
                'timestamp': capture_info.timestamp,
                'description': f'High packet rate from {capture_info.src_ip}'
            }
            anomalies.append(anomaly)

        # DNS tunneling detection
        if capture_info.payload_info and capture_info.payload_info.get('type') == 'dns_query':
            query_name = capture_info.payload_info.get('query_name', '')
            query_type = capture_info.payload_info.get('query_type', '')
            if self.anomaly_detector.detect_dns_tunneling(query_name, query_type):
                anomaly = {
                    'type': 'dns_tunneling',
                    'src_ip': capture_info.src_ip,
                    'timestamp': capture_info.timestamp,
                    'description': f'Potential DNS tunneling from {capture_info.src_ip}'
                }
                anomalies.append(anomaly)

        # Beaconing detection
        if self.anomaly_detector.detect_beaconing(capture_info.src_ip, capture_info.dst_ip, capture_info.packet_size):
            anomaly = {
                'type': 'beaconing',
                'src_ip': capture_info.src_ip,
                'timestamp': capture_info.timestamp,
                'description': f'Potential beaconing behavior from {capture_info.src_ip} to {capture_info.dst_ip}'
            }
            anomalies.append(anomaly)

        # Data exfiltration detection
        if self.anomaly_detector.detect_data_exfiltration(capture_info.src_ip, capture_info.dst_ip, capture_info.packet_size, capture_info.protocol):
            anomaly = {
                'type': 'data_exfiltration',
                'src_ip': capture_info.src_ip,
                'timestamp': capture_info.timestamp,
                'description': f'Potential data exfiltration from {capture_info.src_ip} to {capture_info.dst_ip}'
            }
            anomalies.append(anomaly)

        # Store anomalies
        self.statistics['anomalies'].extend(anomalies)

    def start_capture(self, duration: Optional[int] = None, save_pcap: Optional[str] = None) -> bool:
        """
        Start packet capture.

        Args:
            duration: Capture duration in seconds (None = indefinite)
            save_pcap: Path to save PCAP file

        Returns:
            True if capture started successfully
        """
        if not self._check_permissions():
            self.logger.logger.warning("Packet capture may require root privileges")

        if self.is_capturing:
            self.logger.logger.warning("Capture already in progress")
            return False

        try:
            self.is_capturing = True

            # Log capture start
            self.logger.scan_started(
                target=self.interface or "default",
                scan_type="packet_capture",
                duration=duration
            )

            # Start capture in background thread
            self.capture_thread = threading.Thread(
                target=self._capture_worker,
                args=(duration, save_pcap),
                daemon=True
            )
            self.capture_thread.start()

            return True

        except Exception as e:
            self.logger.logger.error(f"Failed to start capture: {e}")
            self.is_capturing = False
            return False

    def _capture_worker(self, duration: Optional[int], save_pcap: Optional[str]):
        """Worker thread for packet capture."""
        try:
            # Configure capture parameters
            capture_params = {
                'prn': self._process_packet,
                'store': 0,  # Don't store packets in memory
                'stop_filter': lambda x: not self.is_capturing
            }

            if self.interface:
                capture_params['iface'] = self.interface

            if self.capture_filter:
                capture_params['filter'] = self.capture_filter

            if duration:
                capture_params['timeout'] = duration

            if save_pcap:
                # For PCAP saving, we need to store packets
                capture_params['store'] = 1

            # Start capture
            captured_packets = sniff(**capture_params)

            # Save PCAP if requested
            if save_pcap and captured_packets:
                from scapy.utils import wrpcap
                wrpcap(save_pcap, captured_packets)
                self.logger.logger.info(f"PCAP saved to {save_pcap}")

        except Exception as e:
            self.logger.logger.error(f"Capture error: {e}")
        finally:
            self.is_capturing = False

    def stop_capture(self):
        """Stop packet capture."""
        if self.is_capturing:
            self.is_capturing = False

            if self.capture_thread and self.capture_thread.is_alive():
                self.capture_thread.join(timeout=5)

            # Log capture completion
            self.logger.scan_completed(
                target=self.interface or "default",
                scan_type="packet_capture",
                results_count=self.statistics['total_packets']
            )

    def get_statistics(self) -> Dict[str, Any]:
        """Get current capture statistics."""
        stats = dict(self.statistics)

        # Convert defaultdicts to regular dicts for JSON serialization
        stats['protocols'] = dict(stats['protocols'])
        stats['top_ports'] = dict(sorted(stats['top_ports'].items(), key=lambda x: x[1], reverse=True)[:10])
        stats['top_ips'] = dict(sorted(stats['top_ips'].items(), key=lambda x: x[1], reverse=True)[:10])

        # Add flow statistics
        stats['active_flows'] = len([f for f in self.flows.values() if f.state == 'active'])
        stats['total_flows'] = len(self.flows)

        return stats

    def get_flows(self) -> List[Dict[str, Any]]:
        """Get current flow information."""
        return [flow.to_dict() for flow in self.flows.values()]

    def get_packets(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent packets."""
        recent_packets = list(self.packets)[-limit:] if limit > 0 else list(self.packets)
        return [packet.to_dict() for packet in recent_packets]

    def get_anomalies(self) -> List[Dict[str, Any]]:
        """Get detected anomalies."""
        return self.statistics['anomalies']

    def export_to_json(self, output_path: str):
        """Export capture data to JSON file."""
        export_data = {
            'metadata': {
                'interface': self.interface,
                'capture_filter': self.capture_filter,
                'export_time': datetime.utcnow().isoformat() + 'Z',
                'total_packets': self.statistics['total_packets']
            },
            'statistics': self.get_statistics(),
            'flows': self.get_flows(),
            'packets': self.get_packets(),
            'anomalies': self.get_anomalies()
        }

        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)

    def export_to_csv(self, output_path: str):
        """Export capture data to CSV file."""
        import csv

        with open(output_path, 'w', newline='') as csvfile:
            fieldnames = [
                'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                'protocol', 'packet_size', 'flags', 'service', 'info'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            # Export packet data
            packets = self.get_packets()
            for packet_data in packets:
                if isinstance(packet_data, dict):
                    # Ensure all required fields are present
                    row = {
                        'timestamp': packet_data.get('timestamp', ''),
                        'src_ip': packet_data.get('src_ip', ''),
                        'dst_ip': packet_data.get('dst_ip', ''),
                        'src_port': packet_data.get('src_port', ''),
                        'dst_port': packet_data.get('dst_port', ''),
                        'protocol': packet_data.get('protocol', ''),
                        'packet_size': packet_data.get('packet_size', ''),
                        'flags': packet_data.get('flags', ''),
                        'service': packet_data.get('service', ''),
                        'info': packet_data.get('info', '')
                    }
                    writer.writerow(row)

    def generate_report(self, output_path: str):
        """Generate markdown report from capture data."""
        stats = self.get_statistics()
        flows = self.get_flows()
        anomalies = self.get_anomalies()

        with open(output_path, 'w') as f:
            f.write("# Packet Capture Analysis Report\n\n")
            f.write(f"**Interface:** {self.interface or 'default'}\n")
            f.write(f"**Filter:** {self.capture_filter or 'none'}\n")
            f.write(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")

            # Summary statistics
            f.write("## Summary Statistics\n\n")
            f.write(f"- **Total Packets:** {stats['total_packets']}\n")
            f.write(f"- **Active Flows:** {stats['active_flows']}\n")
            f.write(f"- **Total Flows:** {stats['total_flows']}\n")
            f.write(f"- **Anomalies Detected:** {len(anomalies)}\n\n")

            # Protocol distribution
            if stats['protocols']:
                f.write("## Protocol Distribution\n\n")
                f.write("| Protocol | Packets | Percentage |\n")
                f.write("|----------|---------|------------|\n")

                total = stats['total_packets']
                for protocol, count in stats['protocols'].items():
                    percentage = (count / total * 100) if total > 0 else 0
                    f.write(f"| {protocol.upper()} | {count} | {percentage:.1f}% |\n")
                f.write("\n")

            # Top ports
            if stats['top_ports']:
                f.write("## Top Destination Ports\n\n")
                f.write("| Port | Packets | Service |\n")
                f.write("|------|---------|----------|\n")

                for port, count in stats['top_ports'].items():
                    service = self._get_service_name(port)
                    f.write(f"| {port} | {count} | {service} |\n")
                f.write("\n")

            # Top IPs
            if stats['top_ips']:
                f.write("## Top IP Addresses\n\n")
                f.write("| IP Address | Packets |\n")
                f.write("|------------|----------|\n")

                for ip, count in stats['top_ips'].items():
                    f.write(f"| {ip} | {count} |\n")
                f.write("\n")

            # Anomalies
            if anomalies:
                f.write("## Detected Anomalies\n\n")

                for anomaly in anomalies:
                    f.write(f"### {anomaly['type'].replace('_', ' ').title()}\n\n")
                    f.write(f"- **Source IP:** {anomaly['src_ip']}\n")
                    f.write(f"- **Time:** {anomaly['timestamp']}\n")
                    f.write(f"- **Description:** {anomaly['description']}\n\n")

            # Active flows
            active_flows = [f for f in flows if f['state'] == 'active']
            if active_flows:
                f.write("## Active Network Flows\n\n")
                f.write("| Source | Destination | Protocol | Packets | Bytes |\n")
                f.write("|--------|-------------|----------|---------|-------|\n")

                for flow in active_flows[:20]:  # Limit to top 20
                    src = f"{flow['src_ip']}:{flow['src_port']}"
                    dst = f"{flow['dst_ip']}:{flow['dst_port']}"
                    f.write(f"| {src} | {dst} | {flow['protocol'].upper()} | {flow['packet_count']} | {flow['bytes_total']} |\n")
                f.write("\n")

    def _get_service_name(self, port: int) -> str:
        """Get service name for port number."""
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            27017: 'MongoDB'
        }
        return common_ports.get(port, 'Unknown')

    @staticmethod
    def get_available_interfaces() -> List[str]:
        """Get list of available network interfaces."""
        if not SCAPY_AVAILABLE:
            return []

        try:
            return get_if_list()
        except Exception:
            return []

    @staticmethod
    def validate_bpf_filter(filter_string: str) -> bool:
        """Validate BPF filter string."""
        if not filter_string:
            return True

        # Basic validation - check for common BPF syntax
        valid_keywords = [
            'tcp', 'udp', 'icmp', 'ip', 'arp', 'port', 'host', 'net',
            'src', 'dst', 'and', 'or', 'not', 'greater', 'less'
        ]

        # Simple validation - check if filter contains valid keywords
        filter_lower = filter_string.lower()
        return any(keyword in filter_lower for keyword in valid_keywords)
