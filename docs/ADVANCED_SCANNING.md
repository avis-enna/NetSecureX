# Advanced Scanning Guide

NetSecureX v1.3.0 introduces comprehensive advanced scanning capabilities that go far beyond basic port scanning. This guide covers all the new features and how to use them effectively.

## 🚀 Overview

The advanced scanning system provides:
- **Multiple scan types** for different scenarios
- **Stealth and evasion** techniques
- **Enhanced service detection** with version fingerprinting
- **Timing templates** for different speed/stealth requirements
- **UDP scanning** with protocol-specific probes

## 📋 Scan Types

### TCP Connect Scanning
**Default and most reliable method**
- Completes full TCP three-way handshake
- Works without elevated privileges
- Most accurate for determining open ports
- Easily detected by intrusion detection systems

**Use when:**
- You need maximum accuracy
- Stealth is not a concern
- You don't have administrative privileges

### TCP SYN Scanning (Stealth)
**Half-open scanning for stealth**
- Sends SYN packet, analyzes response
- Never completes TCP handshake
- Requires elevated privileges (root/administrator)
- Harder to detect and log

**Use when:**
- Stealth is important
- You want to avoid connection logs
- You have administrative privileges

### TCP FIN Scanning
**Firewall evasion technique**
- Sends packets with only FIN flag set
- Open ports typically don't respond
- Closed ports send RST packets
- Can bypass simple firewalls

**Use when:**
- Basic firewalls are blocking SYN scans
- You need to evade detection
- Target system follows RFC standards

### TCP NULL Scanning
**Advanced evasion technique**
- Sends packets with no flags set
- Similar behavior to FIN scanning
- Can bypass certain firewall rules
- Effective against some packet filters

### TCP Xmas Scanning
**Christmas tree scan**
- Sets FIN, PSH, and URG flags
- Named for "lighting up" like a Christmas tree
- Another firewall evasion technique
- Useful for testing firewall rules

### UDP Scanning
**Protocol-specific UDP scanning**
- Tests UDP services with custom probes
- Includes probes for DNS, SNMP, NTP, DHCP, TFTP
- Analyzes responses for service identification
- Handles ICMP unreachable responses

**Use when:**
- Scanning for UDP services
- Looking for DNS, SNMP, or other UDP protocols
- Comprehensive network assessment needed

## ⏱️ Timing Templates

### Paranoid (T0)
- **Speed**: Very Slow
- **Stealth**: Maximum
- **Concurrent**: 1 connection
- **Delay**: 5 seconds between probes
- **Use case**: Maximum stealth, avoiding all detection

### Sneaky (T1)
- **Speed**: Slow
- **Stealth**: High
- **Concurrent**: 5 connections
- **Delay**: 1 second between probes
- **Use case**: Stealth scanning with reasonable speed

### Polite (T2)
- **Speed**: Normal
- **Stealth**: Medium
- **Concurrent**: 10 connections
- **Delay**: 0.4 seconds between probes
- **Use case**: Respectful scanning, won't overwhelm targets

### Normal (T3) - Default
- **Speed**: Normal
- **Stealth**: Low
- **Concurrent**: 50 connections
- **Delay**: 0.01 seconds between probes
- **Use case**: Balanced speed and resource usage

### Aggressive (T4)
- **Speed**: Fast
- **Stealth**: None
- **Concurrent**: 100 connections
- **Delay**: 0.001 seconds between probes
- **Use case**: Fast scanning when stealth isn't needed

### Insane (T5)
- **Speed**: Very Fast
- **Stealth**: None
- **Concurrent**: 200 connections
- **Delay**: No delay
- **Use case**: Maximum speed, may overwhelm targets

## 🔍 Service Detection

### Detection Methods

#### Port-based Hints
- Initial service guess based on port number
- Low confidence (30%)
- Starting point for further analysis

#### Banner Analysis
- Analyzes service banners and responses
- Pattern matching against signature database
- Medium to high confidence (60-95%)

#### Active Probing
- Sends protocol-specific probes
- Analyzes responses for service identification
- Highest confidence (80-95%)

### Supported Services

#### Web Services
- **HTTP/HTTPS**: Version detection, server identification
- **Proxy servers**: HTTP proxy detection and analysis

#### Remote Access
- **SSH**: Version detection, implementation identification
- **Telnet**: Banner analysis and version detection
- **RDP**: Remote Desktop Protocol detection

#### Email Services
- **SMTP**: Mail server identification and capabilities
- **POP3/IMAP**: Mail retrieval service detection

#### Database Services
- **MySQL**: Version detection and configuration analysis
- **PostgreSQL**: Server version and feature detection
- **Microsoft SQL Server**: Version and edition identification

#### Network Services
- **DNS**: Server software and version detection
- **SNMP**: Community string testing and version detection
- **NTP**: Time server identification and configuration

#### File Services
- **FTP**: Server software and version detection
- **TFTP**: Trivial FTP service detection
- **SMB/CIFS**: Windows file sharing detection

## 🛡️ Stealth Options

### Port Randomization
- Randomizes the order of port scanning
- Avoids sequential patterns that trigger detection
- Makes scanning appear more natural

### Timing Randomization
- Adds random delays between probes
- Breaks up regular timing patterns
- Reduces signature-based detection

### Source Port Spoofing
- Uses specific source ports for scanning
- Can bypass some firewall rules
- Useful for evading port-based filtering

## 🎯 Usage Examples

### GUI Usage

1. **Enable Advanced Scanning**
   - Check "Enable Advanced Scanning" checkbox
   - Additional options will become available

2. **Select Scan Type**
   - Choose from dropdown: TCP Connect, SYN, FIN, NULL, Xmas, UDP
   - SYN scanning requires elevated privileges

3. **Configure Timing**
   - Select timing template from dropdown
   - Ranges from Paranoid (slowest) to Insane (fastest)

4. **Enable Options**
   - Service Detection: Enhanced service identification
   - Version Detection: Detailed version information
   - Randomize Ports: Random port scanning order
   - Randomize Timing: Variable delays between probes

### Programmatic Usage

```python
from core.advanced_scanner import AdvancedPortScanner, AdvancedScanOptions, ScanType, TimingTemplate

# Create scanner
scanner = AdvancedPortScanner()

# Configure options
options = AdvancedScanOptions(
    scan_type=ScanType.TCP_SYN,
    timing=TimingTemplate.POLITE,
    enable_service_detection=True,
    enable_version_detection=True,
    randomize_ports=True
)

# Perform scan
result = await scanner.scan_target("192.168.1.1", [22, 80, 443], options)
```

## ⚠️ Important Considerations

### Legal and Ethical Usage
- **Only scan systems you own or have explicit permission to test**
- Unauthorized scanning may violate laws and policies
- Always follow responsible disclosure practices
- Respect rate limits and avoid overwhelming targets

### Privilege Requirements
- **SYN scanning** requires root/administrator privileges
- **Raw socket access** needed for advanced scan types
- **Graceful fallback** to TCP connect when privileges unavailable

### Network Considerations
- **Firewall rules** may block certain scan types
- **Intrusion detection systems** may flag scanning activity
- **Network congestion** can affect scan accuracy
- **Target system load** should be considered

### Performance Tips
- **Start with faster timing** templates for initial reconnaissance
- **Use stealth options** when detection avoidance is critical
- **Enable service detection** for comprehensive assessment
- **Combine multiple scan types** for thorough coverage

## 🔧 Troubleshooting

### Common Issues

#### "Raw socket scanning requires elevated privileges"
- **Solution**: Run as administrator/root or use TCP Connect scanning
- **Alternative**: Use the automatic fallback to TCP Connect

#### Slow scanning performance
- **Solution**: Increase timing template (Normal → Aggressive)
- **Check**: Network connectivity and target responsiveness
- **Adjust**: Concurrent connection limits

#### No UDP services detected
- **Solution**: Enable protocol-specific probes
- **Check**: Firewall rules blocking UDP traffic
- **Verify**: Target actually runs UDP services

#### Service detection not working
- **Solution**: Enable banner grabbing and service detection
- **Check**: Target services provide identifying information
- **Try**: Different scan types for better service response

### Getting Help
- Check the troubleshooting section in the main documentation
- Review log files for detailed error information
- Use verbose logging for debugging scan issues
- Consult the GitHub issues for known problems and solutions

## 🔮 Future Enhancements

Planned improvements for future versions:
- **OS fingerprinting** based on TCP/IP stack analysis
- **Vulnerability scanning** integration with CVE databases
- **Custom scan scripts** for specialized testing
- **Network topology mapping** and visualization
- **Automated reporting** with professional templates
