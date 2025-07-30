# NetSecureX - Unified Cybersecurity Tool

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/security-focused-green.svg)](https://github.com/avis-enna/NetSecureX)

NetSecureX is a comprehensive, modular cybersecurity toolkit designed for security professionals, penetration testers, and network administrators. It provides a unified interface for various security testing and analysis tasks.

## 🚀 Features

### Core Modules

- **🔍 Port Scanner** - Asynchronous TCP port scanning with banner grabbing
- **🔒 SSL/TLS Certificate Analyzer** - Certificate validation and security analysis
- **🔍 CVE Lookup** - Real-time vulnerability enumeration using public APIs
- **🏷️ Banner Grabber** - Service identification and version detection with CVE integration
- **📡 Packet Sniffer** - Passive network traffic analysis and anomaly detection
- **🛡️ IP Reputation** - Threat intelligence and IP reputation analysis
- **🔥 Firewall Tester** - Firewall rule testing and port connectivity analysis
- **📜 Certificate Analyzer** - SSL/TLS certificate security assessment and validation
- **🛡️ IP Reputation Checker** - VirusTotal/AbuseIPDB integration *(Coming Soon)*
- **🔥 Basic Firewall Tester** - Ingress/egress testing *(Coming Soon)*
- **📊 Report Generator** - Markdown and PDF report generation

### Key Features

- **Modular Architecture** - Each module is independent and reusable
- **Async Performance** - High-performance concurrent operations
- **Secure Logging** - JSON-formatted logs with sensitive data sanitization
- **Multiple Output Formats** - Table, JSON, CSV, PDF, and HTML reports
- **Docker Support** - Containerized deployment
- **CLI Interface** - User-friendly command-line interface
- **Security-First** - Built with security best practices

## 📋 Requirements

- Python 3.11 or higher
- Linux/macOS/Windows
- Docker (optional)

## 🛠️ Installation

### Local Installation

1. **Clone the repository:**
```bash
git clone https://github.com/avis-enna/NetSecureX.git
cd NetSecureX
```

2. **Create virtual environment:**
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

4. **Run NetSecureX:**
```bash
python main.py --help
```

### Docker Installation

1. **Build the Docker image:**
```bash
docker build -t netsecurex .
```

2. **Run with Docker:**
```bash
docker run --rm netsecurex --help
```

## 🎯 Quick Start

### Port Scanning Examples

**Basic port scan:**
```bash
python main.py scan 192.168.1.1
```

**Scan specific ports:**
```bash
python main.py scan 192.168.1.1 --ports "22,80,443,8080"
```

**Scan IP range:**
```bash
python main.py scan 192.168.1.0/24 --top-ports 100
```

**Advanced scan with output:**
```bash
python main.py scan example.com \
  --ports "1-1000" \
  --timeout 5 \
  --max-concurrent 50 \
  --output results.json \
  --format json \
  --report scan_report.md
```

**Docker usage:**
```bash
docker run --rm -v $(pwd)/output:/app/output netsecurex \
  scan 192.168.1.1 --output /app/output/results.json
```

### SSL/TLS Certificate Analysis Examples

**Basic SSL check:**
```bash
python main.py sslcheck example.com
```

**Check SSL on custom port:**
```bash
python main.py sslcheck mail.example.com --port 993
```

**SSL check with JSON output:**
```bash
python main.py sslcheck example.com --format json --output ssl_results.json
```

**Check self-signed certificate:**
```bash
python main.py sslcheck 192.168.1.1 --no-verify-hostname
```

**Generate SSL report:**
```bash
python main.py sslcheck example.com --report ssl_analysis.md
```

### CVE Vulnerability Lookup Examples

**Basic CVE lookup:**
```bash
python main.py cve apache:2.4.49
```

**CVE lookup with JSON output:**
```bash
python main.py cve openssl:1.1.1n --format json --output cve_results.json
```

**Filter by severity:**
```bash
python main.py cve nginx:1.18.0 --severity-filter HIGH
```

**Bulk CVE lookup:**
```bash
python main.py cve dummy --bulk-file software_list.txt --report cve_report.md
```

**Use specific API:**
```bash
python main.py cve mysql:8.0.25 --api nvd --max-results 10
```

### Banner Grabbing and Version Detection Examples

**Basic banner scan:**
```bash
python main.py banner-scan 192.168.1.1
```

**Scan specific ports:**
```bash
python main.py banner-scan example.com --ports "22,80,443,3306"
```

**Safe mode with CVE integration:**
```bash
python main.py banner-scan 192.168.1.1 --safe-mode --pass-to-cve
```

**Generate comprehensive report:**
```bash
python main.py banner-scan example.com --output banner_results.json --report banner_report.md
```

**JSON output:**
```bash
python main.py banner-scan example.com --format json --timeout 10
```

### Packet Sniffing and Network Analysis Examples

**Basic packet capture:**
```bash
python main.py sniff --duration 60
```

**Capture HTTP traffic:**
```bash
python main.py sniff --interface eth0 --filter "tcp port 80" --duration 30
```

**Monitor DNS traffic with real-time stats:**
```bash
python main.py sniff --filter "port 53" --show-stats --duration 60
```

**Capture and save PCAP:**
```bash
python main.py sniff --duration 120 --save-pcap capture.pcap --report analysis.md
```

**Monitor HTTPS/TLS traffic:**
```bash
python main.py sniff --filter "tcp port 443" --output tls_analysis.json
```

### IP Reputation and Threat Intelligence Examples

**Check single IP address:**
```bash
python main.py reput --ip 1.2.3.4
```

**Check multiple IPs from file:**
```bash
python main.py reput --file ip_list.txt
```

**Show only risky IPs:**
```bash
python main.py reput --file targets.txt --risky-only
```

**Generate comprehensive report:**
```bash
python main.py reput --ip 1.2.3.4 --output results.json --report reputation_report.md
```

**JSON output:**
```bash
python main.py reput --file ip_list.txt --format json
```

### Firewall Testing and Port Analysis Examples

**Test common TCP ports:**
```bash
python main.py firewall --target 192.168.1.1 --common-ports
```

**Test specific ports:**
```bash
python main.py firewall --target example.com --ports "22,80,443"
```

**Test port range:**
```bash
python main.py firewall --target 192.168.1.1 --ports "80-90"
```

**Test UDP ports:**
```bash
python main.py firewall --target 8.8.8.8 --ports "53,123" --udp
```

**Include traceroute analysis:**
```bash
python main.py firewall --target example.com --ports "80,443" --traceroute
```

**Export results:**
```bash
python main.py firewall --target 192.168.1.1 --common-ports --output results.csv
```

### SSL/TLS Certificate Analysis Examples

**Analyze certificate for domain:**
```bash
python main.py cert --host google.com
```

**Analyze certificate on custom port:**
```bash
python main.py cert --host example.com --port 8443
```

**Test expired certificate:**
```bash
python main.py cert --host expired.badssl.com
```

**Test self-signed certificate:**
```bash
python main.py cert --host self-signed.badssl.com
```

**Export certificate analysis:**
```bash
python main.py cert --host google.com --format json --output cert_analysis.json
```

### CVE Vulnerability Lookup Examples

**Search for software vulnerabilities:**
```bash
python main.py cve --query "nginx 1.18.0"
```

**Look up specific CVE:**
```bash
python main.py cve --cve CVE-2021-44228
```

**Show only critical/high severity:**
```bash
python main.py cve --query "apache httpd 2.4.51" --critical-only
```

**Export to JSON:**
```bash
python main.py cve --query "openssh 8.2" --format json --output cve_results.json
```

**Generate markdown report:**
```bash
python main.py cve --query "log4j" --latest 20 --format markdown --output report.md
```

### IP Reputation Assessment Examples

**Check single IP address:**
```bash
python main.py iprep --ip 8.8.8.8
```

**Check multiple IPs from file:**
```bash
python main.py iprep --file bad_ips.txt
```

**Show only high-risk IPs:**
```bash
python main.py iprep --file ip_list.txt --min-score 60
```

**Export results to JSON:**
```bash
python main.py iprep --ip 1.2.3.4 --format json --output reputation_report.json
```

**Batch assessment with filtering:**
```bash
python main.py iprep --file targets.txt --min-score 50 --format table
```

## 📖 Usage Guide

### Command Line Interface

```bash
python main.py [OPTIONS] COMMAND [ARGS]...
```

**Global Options:**
- `--log-level` - Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `--log-file` - Specify log file path
- `--no-console-log` - Disable console logging

### Port Scanner

```bash
python main.py scan [OPTIONS] TARGET
```

**Options:**
- `-p, --ports` - Port specification (e.g., "80,443,8000-8010")
- `-t, --top-ports` - Number of top ports to scan (default: 1000)
- `--timeout` - Connection timeout in seconds (default: 3.0)
- `-c, --max-concurrent` - Maximum concurrent connections (default: 100)
- `--delay` - Delay between connections in seconds (default: 0.01)
- `-o, --output` - Output file path (JSON format)
- `--format` - Output format (table, json)
- `--banner-grab` - Enable banner grabbing
- `--report` - Generate markdown report file

**Target Formats:**
- Single IP: `192.168.1.1`
- IP range: `192.168.1.0/24`
- IP list: `192.168.1.1,192.168.1.2`
- Hostname: `example.com`

### SSL/TLS Certificate Analyzer

```bash
python main.py sslcheck [OPTIONS] TARGET
```

**Options:**
- `-p, --port` - Port number (default: 443)
- `--timeout` - Connection timeout in seconds (default: 10.0)
- `-o, --output` - Output file path (JSON format)
- `--format` - Output format (table, json)
- `--no-verify-hostname` - Disable hostname verification
- `--report` - Generate markdown report file

**Target Formats:**
- Hostname: `example.com`
- IP address: `192.168.1.1`
- URL: `https://example.com` (port extracted automatically)
- Custom port: `example.com:8443`

### CVE Vulnerability Lookup

```bash
python main.py cve [OPTIONS] TARGET
```

**Options:**
- `--api` - API to use (vulners, nvd) (default: vulners)
- `-n, --max-results` - Maximum number of CVEs to return (default: 20)
- `--timeout` - Request timeout in seconds (default: 30.0)
- `-o, --output` - Output file path (JSON format)
- `--format` - Output format (table, json)
- `--severity-filter` - Filter by minimum severity (LOW, MEDIUM, HIGH, CRITICAL)
- `--report` - Generate markdown report file
- `--bulk-file` - File containing product:version pairs

**Target Format:**
- Product:Version: `apache:2.4.49`, `openssl:1.1.1n`, `nginx:1.18.0`

**Environment Variables:**
- `VULNERS_API_KEY` - Vulners API key for enhanced results

### Banner Grabbing and Version Detection

```bash
python main.py banner-scan [OPTIONS] TARGET
```

**Options:**
- `-p, --ports` - Port specification (e.g., "22,80,443,3306")
- `--timeout` - Connection timeout in seconds (default: 5.0)
- `--safe-mode` - Enable safe mode (less aggressive probing)
- `--delay` - Delay between connections in seconds (default: 0.1)
- `-o, --output` - Output file path (JSON format)
- `--format` - Output format (table, json)
- `--pass-to-cve` - Automatically lookup CVEs for detected services
- `--report` - Generate markdown report file

**Target Format:**
- Single IP: `192.168.1.1`
- Hostname: `example.com`

**Supported Services:**
- HTTP/HTTPS (Apache, Nginx, IIS, Lighttpd)
- SSH (OpenSSH)
- SMTP (Postfix, Sendmail, Exim)
- FTP (vsftpd, ProFTPD, Pure-FTPd)
- MySQL/MariaDB

### Packet Sniffer and Network Analysis

```bash
python main.py sniff [OPTIONS]
```

**Options:**
- `-i, --interface` - Network interface to capture on (e.g., eth0, wlan0)
- `-d, --duration` - Capture duration in seconds
- `--filter` - BPF filter string (e.g., "tcp port 80")
- `--max-packets` - Maximum packets to capture (default: 10000)
- `--save-pcap` - Save captured packets to PCAP file
- `-o, --output` - Output file path (JSON format)
- `--report` - Generate markdown report file
- `--show-stats` - Show real-time statistics during capture

**Supported Analysis:**
- Protocol distribution (TCP, UDP, ICMP, HTTP, DNS, TLS)
- Flow tracking and connection analysis
- Anomaly detection (SYN floods, port scans, DNS failures)
- HTTP header extraction and analysis
- DNS query/response monitoring
- TLS SNI extraction from Client Hello
- Real-time statistics and alerting

**Requirements:**
- Root privileges for full packet capture functionality
- Scapy library (`pip install scapy`)

### IP Reputation and Threat Intelligence

```bash
python main.py reput [OPTIONS]
```

**Options:**
- `--ip` - Single IP address to check
- `--file` - File containing IP addresses (one per line)
- `-o, --output` - Output file path (JSON format)
- `--format` - Output format (table, json)
- `--report` - Generate markdown report file
- `--risky-only` - Show only risky IPs (MEDIUM, HIGH, CRITICAL)
- `--providers` - Comma-separated list of providers to use

**Supported Providers:**
- **AbuseIPDB:** Abuse confidence and reporting data (requires API key)
- **AlienVault OTX:** Threat intelligence and pulse data (free)
- **GreyNoise:** Internet scanning activity (requires API key)
- **Shodan:** Host information and vulnerabilities (requires API key)

**Risk Levels:**
- CLEAN: No threats detected
- LOW: Minimal risk indicators
- MEDIUM: Moderate threat indicators
- HIGH: Significant threat indicators
- CRITICAL: Confirmed malicious activity

**API Key Configuration:**
Create a `.env` file with your API keys:
```
ABUSEIPDB_API_KEY=your_key_here
OTX_API_KEY=your_key_here
GREYNOISE_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
```

### Firewall Testing and Port Analysis

```bash
python main.py firewall [OPTIONS]
```

**Options:**
- `-t, --target` - Target IP address or hostname (required)
- `-p, --ports` - Port specification (e.g., "80", "80,443", "80-90")
- `--udp` - Test UDP ports instead of TCP
- `--traceroute` - Perform traceroute to target
- `--timeout` - Connection timeout in seconds (default: 3.0)
- `--delay` - Delay between tests in seconds (default: 0.1)
- `--max-concurrent` - Maximum concurrent connections (default: 50)
- `-o, --output` - Output file path (JSON or CSV based on extension)
- `--format` - Output format (table, json, csv)
- `--common-ports` - Test common ports instead of specifying --ports

**Port Status Classification:**
- **Open:** Connection successful
- **Closed:** Connection refused (RST packet received)
- **Filtered:** Connection timeout (likely blocked by firewall)

**Common Ports Tested:**
- **TCP:** 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306
- **UDP:** 53, 67, 68, 69, 123, 161, 162, 514, 1194

**Features:**
- Async port testing with rate limiting
- TCP and UDP protocol support
- Basic traceroute functionality
- Color-coded output (green=open, yellow=filtered, red=closed)
- CSV and JSON export capabilities
- Firewall rule analysis and reporting

### SSL/TLS Certificate Analysis

```bash
python main.py cert [OPTIONS]
```

**Options:**
- `--host, --domain` - Domain name or IP address to analyze (required)
- `--port` - Port number (default: 443)
- `-o, --output` - Output file path (JSON or CSV based on extension)
- `--format` - Output format (table, json, csv)
- `--timeout` - Connection timeout in seconds (default: 10.0)

**Certificate Information Extracted:**
- Common Name (CN) and Subject Alternative Names (SAN)
- Issuer and certificate chain information
- Validity period and expiration status
- Signature algorithm and key information
- Security features (Certificate Transparency, OCSP, CRL)
- Hostname verification and trust validation

**Security Assessment:**
- **Grade A+/A:** Secure certificate with strong cryptography
- **Grade B/C:** Minor security issues or outdated practices
- **Grade D/F:** Significant security problems or expired certificate

**Security Checks:**
- Certificate expiration (expired, expires soon <30 days)
- Weak signature algorithms (MD5, SHA1)
- Insufficient key sizes (RSA <2048, ECC <256)
- Self-signed certificates
- Hostname mismatch
- Missing Certificate Transparency logs

**Features:**
- Detailed certificate chain analysis
- Security grade assignment (A+ to F)
- Color-coded status indicators
- JSON and CSV export capabilities
- OCSP and CRL revocation information
- Comprehensive security issue reporting

### CVE Vulnerability Lookup

```bash
python main.py cve [OPTIONS]
```

**Options:**
- `--query` - Search query (e.g., "nginx 1.18.0", "apache httpd")
- `--cve` - Look up specific CVE ID (e.g., "CVE-2022-12345")
- `--latest` - Number of results to show (default: 10)
- `-o, --output` - Output file path (JSON or Markdown based on extension)
- `--format` - Output format (table, json, markdown)
- `--critical-only` - Show only critical and high severity CVEs
- `--no-cache` - Disable result caching

**Vulnerability Databases:**
- **Vulners API:** Comprehensive vulnerability data with CVSS scoring
- **NVD (National Vulnerability Database):** Official CVE information from NIST
- **Automatic fallback:** Uses multiple sources for comprehensive coverage

**CVE Information Extracted:**
- CVE ID and detailed description
- CVSS v2/v3 scores and severity ratings
- Published and last modified dates
- CWE (Common Weakness Enumeration) classifications
- Attack vector and complexity analysis
- Exploitability and impact scores
- Reference links and affected products

**Severity Levels:**
- **CRITICAL:** CVSS 9.0-10.0 (Immediate action required)
- **HIGH:** CVSS 7.0-8.9 (High priority patching)
- **MEDIUM:** CVSS 4.0-6.9 (Moderate risk)
- **LOW:** CVSS 0.1-3.9 (Low risk)

**Features:**
- Real-time vulnerability enumeration
- Built-in result caching (60-minute TTL)
- Rate limiting and API error handling
- Duplicate CVE removal and severity sorting
- Color-coded severity indicators
- JSON and Markdown export capabilities
- Critical/high severity filtering

### IP Reputation Assessment

```bash
python main.py iprep [OPTIONS]
```

**Options:**
- `--ip` - Single IP address to assess
- `--file` - File containing IP addresses (one per line)
- `--min-score` - Minimum threat score to display (0-100)
- `-o, --output` - Output file path (JSON format)
- `--format` - Output format (table, json)

**Threat Intelligence Providers:**
- **AbuseIPDB:** Abuse confidence and reporting data (requires API key)
- **IPQualityScore:** Fraud detection and risk scoring (requires API key)
- **VirusTotal:** Malware and threat detection (requires API key)

**Assessment Metrics:**
- **Abuse Score:** 0-100 scale based on abuse reports and confidence
- **Fraud Score:** 0-100 scale based on fraud indicators and risk factors
- **Threat Level:** CLEAN, LOW, MEDIUM, HIGH, CRITICAL
- **Risk Factors:** Tor, Proxy, VPN, Bot activity, Malware associations

**Information Extracted:**
- IP address geolocation (country, ISP)
- Domain associations and reverse DNS
- Abuse reports and last reported dates
- Threat categories (malware, phishing, botnet, etc.)
- Risk indicators (proxy, VPN, Tor exit nodes)
- Fraud detection metrics

**API Key Configuration:**
Create a `.env` file with your API keys:
```
ABUSEIPDB_API_KEY=your_key_here
IPQUALITYSCORE_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
```

**Features:**
- Multi-provider threat intelligence aggregation
- Batch IP assessment with concurrency control
- Threat score filtering and risk categorization
- Color-coded threat level indicators
- JSON export for further analysis
- Rate limiting and API error handling

## 🏗️ Project Structure

```
NetSecureX/
├── core/                   # Core security modules
│   ├── __init__.py
│   ├── scanner.py         # Port scanner implementation
│   ├── ssl_check.py       # SSL/TLS certificate analyzer
│   ├── vuln_lookup.py     # CVE vulnerability lookup
│   ├── banner_grabber.py  # Banner grabbing and version detection
│   ├── packet_sniffer.py  # Packet capture and network analysis
│   ├── ip_reputation.py   # IP reputation and threat intelligence
│   ├── firewall_tester.py # Firewall testing and port analysis
│   ├── cert_analyzer.py   # SSL/TLS certificate analysis
│   ├── cve_lookup.py      # CVE vulnerability enumeration
│   └── ip_reputation_new.py # IP reputation assessment
├── utils/                  # Utility functions
│   ├── __init__.py
│   ├── logger.py          # Secure JSON logging
│   └── network.py         # Network utilities
├── ui/                     # User interface
│   ├── __init__.py
│   └── cli.py             # Command-line interface
├── reports/                # Report generation
│   ├── __init__.py
│   └── generator.py       # Report generators
├── main.py                 # Main entry point
├── requirements.txt        # Python dependencies
├── Dockerfile             # Docker configuration
└── README.md              # This file
```

## 🔧 Development

### Setting up Development Environment

1. **Clone and setup:**
```bash
git clone https://github.com/avis-enna/NetSecureX.git
cd NetSecureX
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. **Run tests:**
```bash
pytest tests/ -v
```

3. **Code formatting:**
```bash
black .
flake8 .
mypy .
```

### Adding New Modules

1. Create your module in the `core/` directory
2. Add appropriate imports to `core/__init__.py`
3. Create CLI commands in `ui/cli.py`
4. Add tests in `tests/`
5. Update documentation

## 🛡️ Security Considerations

- **No Raw Sockets by Default** - Uses standard TCP connections for safety
- **Input Validation** - All inputs are validated and sanitized
- **Secure Logging** - Sensitive data is automatically redacted from logs
- **Rate Limiting** - Built-in delays and concurrency limits to prevent abuse
- **Non-Root Execution** - Designed to run without elevated privileges
- **Container Security** - Docker image runs as non-root user

## 📊 Output Formats

### Table Output (Default)
```
Port Scan Summary - 192.168.1.1
================================
Scan Duration: 2.45 seconds
Total Ports: 1000
Open Ports: 3
Closed Ports: 997
...
```

### JSON Output
```json
{
  "target": "192.168.1.1",
  "total_ports": 1000,
  "open_ports": 3,
  "results": [
    {
      "ip": "192.168.1.1",
      "port": 22,
      "status": "open",
      "service": "ssh",
      "response_time": 0.045
    }
  ]
}
```

### SSL Certificate Analysis Output
```json
{
  "target": "example.com",
  "port": 443,
  "status": "valid",
  "tls_version": "TLSv1.3",
  "cipher_suite": "TLS_AES_256_GCM_SHA384",
  "issuer": "Let's Encrypt Authority X3",
  "subject": "CN=example.com",
  "common_name": "example.com",
  "expires_on": "2025-09-01",
  "days_until_expiry": 33,
  "is_self_signed": false,
  "is_expired": false
}
```

### CVE Vulnerability Lookup Output
```json
[
  {
    "cve_id": "CVE-2021-42013",
    "summary": "Apache HTTP Server path traversal vulnerability...",
    "cvss_v3_score": 9.8,
    "severity": "CRITICAL",
    "published_date": "2021-10-07",
    "source_api": "nvd"
  }
]
```

### Banner Grabbing Output
```json
{
  "host": "example.com",
  "port": 80,
  "service": "http",
  "product": "nginx",
  "version": "1.18.0",
  "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0...",
  "protocol": "http",
  "status": "detected",
  "confidence": 0.9
}
```

### Packet Capture Analysis Output
```json
{
  "metadata": {
    "interface": "eth0",
    "capture_filter": "tcp port 80",
    "total_packets": 1250
  },
  "statistics": {
    "protocols": {"tcp": 1100, "udp": 150},
    "top_ports": {"80": 800, "443": 300},
    "anomalies": []
  },
  "flows": [
    {
      "src_ip": "192.168.1.100",
      "dst_ip": "93.184.216.34",
      "src_port": 54321,
      "dst_port": 80,
      "protocol": "tcp",
      "packet_count": 25,
      "bytes_total": 15000
    }
  ]
}
```

### IP Reputation Analysis Output
```json
{
  "ip_address": "1.2.3.4",
  "overall_risk_score": 85.0,
  "risk_level": "HIGH",
  "is_malicious": true,
  "providers_checked": ["abuseipdb", "otx"],
  "threat_categories": ["high_abuse_confidence", "threat_intelligence"],
  "geolocation": {"country": "United States", "city": "New York"},
  "asn_info": {"organization": "Example ISP"},
  "confidence_score": 75.0
}
```

### Firewall Test Results Output
```json
{
  "firewall_tests": [
    {
      "target": "example.com",
      "port": 80,
      "protocol": "tcp",
      "status": "open",
      "response_time": 0.008,
      "timestamp": "2025-01-01T12:00:00Z"
    },
    {
      "target": "example.com",
      "port": 8080,
      "protocol": "tcp",
      "status": "filtered",
      "response_time": 3.0,
      "timestamp": "2025-01-01T12:00:03Z"
    }
  ],
  "traceroute": [
    {
      "hop_number": 1,
      "ip_address": "192.168.1.1",
      "hostname": "gateway.local",
      "response_time": 1.2
    }
  ]
}
```

### Certificate Analysis Output
```json
{
  "host": "google.com",
  "port": 443,
  "common_name": "*.google.com",
  "issuer": "CN=WR2,O=Google Trust Services,C=US",
  "not_before": "2025-07-07T08:34:03Z",
  "not_after": "2025-09-29T08:34:02Z",
  "is_expired": false,
  "expires_soon": false,
  "days_until_expiry": 61,
  "signature_algorithm": "sha256WithRSAEncryption",
  "key_algorithm": "ECC",
  "key_size": 256,
  "security_issues": [],
  "has_sct": true
}
```

### CVE Lookup Results Output
```json
{
  "cves": [
    {
      "cve_id": "CVE-2021-44228",
      "description": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP...",
      "cvss_v3_score": 10.0,
      "cvss_v3_severity": "CRITICAL",
      "published_date": "2021-12-10T10:15:09.067Z",
      "cwe_id": "CWE-502",
      "attack_vector": "NETWORK",
      "attack_complexity": "LOW",
      "source": "NVD"
    }
  ]
}
```

### IP Reputation Assessment Output
```json
{
  "ip_address": "1.2.3.4",
  "abuse_score": 85.0,
  "fraud_score": 72.0,
  "threat_level": "HIGH",
  "is_malicious": true,
  "country": "United States",
  "isp": "Example ISP",
  "threat_categories": ["High Abuse Confidence", "Reported Abuse"],
  "risk_factors": ["Proxy", "VPN"],
  "total_reports": 15,
  "last_reported": "2025-07-29T10:30:00Z"
}
```

### Markdown Report
Generates comprehensive reports with:
- Executive summary
- Scan statistics
- Detailed findings
- Security recommendations

## 🐳 Docker Usage

### Basic Usage
```bash
# Build image
docker build -t netsecurex .

# Run scan
docker run --rm netsecurex scan 192.168.1.1

# Save results
docker run --rm -v $(pwd)/output:/app/output netsecurex \
  scan 192.168.1.1 --output /app/output/results.json
```

### Docker Compose (Optional)
```yaml
version: '3.8'
services:
  netsecurex:
    build: .
    volumes:
      - ./output:/app/output
    command: scan 192.168.1.1 --output /app/output/results.json
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Contribution Guidelines

- Follow PEP 8 style guidelines
- Add tests for new features
- Update documentation
- Ensure security best practices
- Add type hints where appropriate

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

NetSecureX is intended for authorized security testing and educational purposes only. Users are responsible for ensuring they have proper authorization before scanning any networks or systems. The developers assume no liability for misuse of this tool.

## 🙏 Acknowledgments

- [nmap](https://nmap.org/) - Inspiration for port scanning techniques
- [scapy](https://scapy.net/) - Network packet manipulation
- [Click](https://click.palletsprojects.com/) - Command line interface framework
- [Rich](https://rich.readthedocs.io/) - Terminal formatting

## 📞 Support

- 📧 Email: support@netsecurex.com
- 🐛 Issues: [GitHub Issues](https://github.com/avis-enna/NetSecureX/issues)
- 📖 Documentation: [Wiki](https://github.com/avis-enna/NetSecureX/wiki)

---

**Made with ❤️ by the NetSecureX Team**