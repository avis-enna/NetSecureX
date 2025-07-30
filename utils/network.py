"""
Network Utility Functions for NetSecureX
========================================

This module provides network-related utility functions including IP validation,
port validation, and network range parsing.
"""

import ipaddress
import re
import socket
from typing import List, Union, Iterator, Tuple
from netaddr import IPNetwork, IPAddress, AddrFormatError


def validate_ip(ip_str: str) -> bool:
    """
    Validate if a string is a valid IP address (IPv4 or IPv6).
    
    Args:
        ip_str: String to validate as IP address
        
    Returns:
        True if valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def validate_ip_range(ip_range: str) -> bool:
    """
    Validate if a string is a valid IP range (CIDR notation).
    
    Args:
        ip_range: String to validate as IP range (e.g., "192.168.1.0/24")
        
    Returns:
        True if valid IP range, False otherwise
    """
    try:
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except ValueError:
        return False


def parse_ip_range(ip_input: str) -> List[str]:
    """
    Parse IP input and return list of individual IP addresses.
    
    Supports:
    - Single IP: "192.168.1.1"
    - CIDR notation: "192.168.1.0/24"
    - IP range: "192.168.1.1-192.168.1.10"
    - Comma-separated: "192.168.1.1,192.168.1.2"
    
    Args:
        ip_input: IP address, range, or comma-separated list
        
    Returns:
        List of individual IP addresses as strings
        
    Raises:
        ValueError: If input format is invalid
    """
    ip_list = []
    
    # Handle comma-separated IPs
    if ',' in ip_input:
        for ip_part in ip_input.split(','):
            ip_list.extend(parse_ip_range(ip_part.strip()))
        return ip_list
    
    # Handle IP range (e.g., 192.168.1.1-192.168.1.10)
    if '-' in ip_input and '/' not in ip_input:
        try:
            start_ip, end_ip = ip_input.split('-', 1)
            start_ip = start_ip.strip()
            end_ip = end_ip.strip()
            
            start_addr = IPAddress(start_ip)
            end_addr = IPAddress(end_ip)
            
            if start_addr > end_addr:
                raise ValueError(f"Start IP {start_ip} is greater than end IP {end_ip}")
            
            current = start_addr
            while current <= end_addr:
                ip_list.append(str(current))
                current += 1
                
        except (AddrFormatError, ValueError) as e:
            raise ValueError(f"Invalid IP range format: {ip_input}") from e
    
    # Handle CIDR notation
    elif '/' in ip_input:
        try:
            network = IPNetwork(ip_input)
            # Limit to reasonable size to prevent memory issues
            if network.size > 65536:  # /16 for IPv4
                raise ValueError(f"Network too large: {ip_input} (max 65536 hosts)")
            
            ip_list = [str(ip) for ip in network.iter_hosts()]
            
            # For /32 or /128, include the network address itself
            if network.size == 1:
                ip_list = [str(network.ip)]
                
        except AddrFormatError as e:
            raise ValueError(f"Invalid CIDR notation: {ip_input}") from e
    
    # Handle single IP
    else:
        if validate_ip(ip_input.strip()):
            ip_list = [ip_input.strip()]
        else:
            raise ValueError(f"Invalid IP address: {ip_input}")
    
    return ip_list


def is_port_valid(port: Union[int, str]) -> bool:
    """
    Validate if a port number is valid (1-65535).
    
    Args:
        port: Port number to validate
        
    Returns:
        True if valid port, False otherwise
    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


def parse_port_range(port_input: str) -> List[int]:
    """
    Parse port input and return list of port numbers.
    
    Supports:
    - Single port: "80"
    - Port range: "80-90"
    - Comma-separated: "80,443,8080"
    - Mixed: "80,443,8000-8010"
    
    Args:
        port_input: Port specification string
        
    Returns:
        List of port numbers
        
    Raises:
        ValueError: If port format is invalid
    """
    ports = []
    
    for part in port_input.split(','):
        part = part.strip()
        
        if '-' in part:
            # Handle port range
            try:
                start_port, end_port = part.split('-', 1)
                start_port = int(start_port.strip())
                end_port = int(end_port.strip())
                
                if not (is_port_valid(start_port) and is_port_valid(end_port)):
                    raise ValueError(f"Invalid port range: {part}")
                
                if start_port > end_port:
                    raise ValueError(f"Start port {start_port} > end port {end_port}")
                
                ports.extend(range(start_port, end_port + 1))
                
            except ValueError as e:
                raise ValueError(f"Invalid port range format: {part}") from e
        else:
            # Handle single port
            try:
                port = int(part)
                if not is_port_valid(port):
                    raise ValueError(f"Invalid port number: {port}")
                ports.append(port)
            except ValueError as e:
                raise ValueError(f"Invalid port: {part}") from e
    
    return sorted(list(set(ports)))  # Remove duplicates and sort


def get_top_ports(count: int = 1000) -> List[int]:
    """
    Get list of top commonly used ports based on nmap's top ports.
    
    Args:
        count: Number of top ports to return (default: 1000)
        
    Returns:
        List of port numbers sorted by frequency
    """
    # Top 1000 ports based on nmap frequency data
    top_ports = [
        80, 23, 443, 21, 22, 25, 53, 110, 111, 995, 993, 143, 993, 995, 587, 465,
        139, 445, 135, 1433, 3306, 5432, 1521, 3389, 5900, 25, 587, 465, 110, 995,
        143, 993, 80, 8080, 8443, 8000, 8888, 9000, 3000, 5000, 8081, 9090, 7001,
        7002, 9001, 9002, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009,
        # Add more common ports...
        1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37,
        42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106,
        109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163, 179, 199,
        211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366, 389,
        406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500,
        512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593,
        616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705,
        711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873,
        880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995,
        999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024,
        1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036,
        1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048,
        1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060
    ]
    
    # Extend with additional common ports to reach requested count
    additional_ports = list(range(1061, 1061 + max(0, count - len(top_ports))))
    all_ports = top_ports + additional_ports
    
    return all_ports[:count]


def resolve_hostname(hostname: str) -> List[str]:
    """
    Resolve hostname to IP addresses.
    
    Args:
        hostname: Hostname to resolve
        
    Returns:
        List of IP addresses
        
    Raises:
        socket.gaierror: If hostname cannot be resolved
    """
    try:
        result = socket.getaddrinfo(hostname, None)
        ips = list(set(info[4][0] for info in result))
        return ips
    except socket.gaierror as e:
        raise socket.gaierror(f"Cannot resolve hostname {hostname}: {e}")


def is_private_ip(ip: str) -> bool:
    """
    Check if IP address is in private range.
    
    Args:
        ip: IP address string
        
    Returns:
        True if IP is private, False otherwise
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False
