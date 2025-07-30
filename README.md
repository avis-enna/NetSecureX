# NetSecureX 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Homebrew](https://img.shields.io/badge/homebrew-available-orange.svg)](https://brew.sh/)
[![GitHub release](https://img.shields.io/github/release/avis-enna/NetSecureX.svg)](https://github.com/avis-enna/NetSecureX/releases)
[![Security](https://img.shields.io/badge/security-focused-green.svg)](https://github.com/avis-enna/NetSecureX)

**NetSecureX** is a unified cybersecurity toolkit designed for network security assessment, vulnerability analysis, and threat intelligence. Built for security professionals, penetration testers, and network administrators who need reliable, efficient tools for comprehensive security testing.

## ✨ Features

🔍 **Network Scanning & Analysis**
- Advanced port scanning with service detection
- SSL/TLS certificate analysis and validation
- Banner grabbing with version identification
- Firewall rule testing and connectivity analysis

🛡️ **Vulnerability Assessment**
- CVE lookup with real-time threat intelligence
- Multi-source vulnerability database queries
- CVSS scoring and severity analysis
- Automated security reporting

🌐 **Threat Intelligence**
- IP reputation checking (6+ threat intel sources)
- Malware and abuse confidence scoring
- Geolocation and network information
- Batch processing for multiple targets

📊 **Advanced Capabilities**
- Passive network traffic monitoring
- Certificate chain validation
- Protocol analysis and anomaly detection
- Multiple output formats (JSON, CSV, Markdown, PDF)

🖥️ **User Interfaces**
- **Modern GUI**: Professional dark-themed graphical interface with Qt6
- **Rich CLI**: Terminal interface with color coding and formatting
- Cross-platform compatibility (macOS, Linux, Windows)
- Comprehensive logging and error handling

## 🚀 Quick Start

### Homebrew Installation (Recommended)

```bash
# Add the NetSecureX tap
brew tap avis-enna/netsecurex

# Install NetSecureX
brew install netsecurex

# Run the setup wizard to configure API keys
netsecx setup --wizard

# Test the installation (CLI)
netsecx --help

# Or launch the GUI
netsecx-gui
```

### Alternative Installation Methods

<details>
<summary>📦 Python Package Manager</summary>

```bash
pip install netsecurex
netsecx setup --wizard
```
</details>

<details>
<summary>🔧 From Source</summary>

```bash
git clone https://github.com/avis-enna/NetSecureX.git
cd NetSecureX
./install-direct.sh
```
</details>

## 🎯 Usage Examples

### Network Security Assessment
```bash
# Quick port scan
netsecx scan 192.168.1.1

# Comprehensive scan with service detection
netsecx scan example.com --ports "22,80,443,8080" --banner-grab

# Scan network range
netsecx scan 192.168.1.0/24 --top-ports 100 --output results.json
```

### SSL/TLS Security Analysis
```bash
# Analyze SSL certificate
netsecx sslcheck google.com

# Detailed certificate analysis
netsecx cert --host example.com --format json --output cert_report.json

# Check certificate on custom port
netsecx sslcheck mail.example.com --port 993
```

### Vulnerability Research
```bash
# Search for software vulnerabilities
netsecx cve --query "nginx 1.18.0"

# Look up specific CVE
netsecx cve --cve CVE-2021-44228

# Find only critical vulnerabilities
netsecx cve --query "apache httpd" --critical-only --latest 10

# Generate vulnerability report
netsecx cve --query "log4j" --format markdown --output vuln_report.md
```

### Threat Intelligence & IP Reputation
```bash
# Check single IP reputation
netsecx reput --ip 1.2.3.4

# Batch check multiple IPs
netsecx reput --file suspicious_ips.txt --risky-only

# Comprehensive IP assessment
netsecx iprep --ip 8.8.8.8 --format json --output ip_analysis.json
```

### Advanced Security Testing
```bash
# Test firewall rules
netsecx firewall --target 192.168.1.1 --ports "80,443,8080"

# Service banner grabbing
netsecx banner-scan 192.168.1.1 --ports "21,22,80,443" --safe-mode

# Network traffic analysis (requires privileges)
sudo netsecx sniff --interface eth0 --duration 60 --filter "tcp port 443"
```

## ⚙️ Configuration

NetSecureX uses a secure configuration system for API keys and settings.

### Initial Setup
```bash
# Interactive setup wizard
netsecx setup --wizard

# Check configuration status
netsecx setup --status

# View configuration location
netsecx setup
```

### API Keys & Free Tiers

NetSecureX integrates with multiple threat intelligence providers, all offering generous free tiers:

| Service | Free Tier | Purpose | Get API Key |
|---------|-----------|---------|-------------|
| **AbuseIPDB** | 1,000 req/day | IP reputation & abuse reports | [Sign up](https://www.abuseipdb.com/api) |
| **Vulners** | 100 req/day | CVE & vulnerability data | [Sign up](https://vulners.com/api) |
| **VirusTotal** | 500 req/day | File & URL analysis | [Sign up](https://www.virustotal.com/gui/join-us) |
| **IPQualityScore** | 5,000 req/month | IP fraud detection | [Sign up](https://www.ipqualityscore.com/create-account) |
| **GreyNoise** | 10,000 req/month | Internet scanning activity | [Sign up](https://www.greynoise.io/) |
| **Shodan** | Paid service | Host & service information | [Sign up](https://www.shodan.io/) |

### Configuration File

API keys are stored securely in `~/.netsecurex/config.yaml`:

```yaml
api_keys:
  abuseipdb: "your_api_key_here"
  vulners: "your_api_key_here"
  virustotal: "your_api_key_here"
  # ... other services

settings:
  timeout: 10
  max_concurrent: 100
  log_level: "INFO"
  output_format: "table"
```

## 📋 Available Commands

| Command | Description | Example |
|---------|-------------|---------|
| `scan` | Port scanning with service detection | `netsecx scan 192.168.1.1 --ports "80,443"` |
| `sslcheck` | SSL/TLS certificate analysis | `netsecx sslcheck google.com` |
| `cert` | Detailed certificate analysis | `netsecx cert --host example.com` |
| `cve` | CVE lookup and vulnerability research | `netsecx cve --query "nginx"` |
| `reput` | IP reputation checking | `netsecx reput --ip 1.2.3.4` |
| `iprep` | IP reputation assessment | `netsecx iprep --file ip_list.txt` |
| `firewall` | Firewall rule testing | `netsecx firewall --target 192.168.1.1` |
| `banner-scan` | Service banner grabbing | `netsecx banner-scan 192.168.1.1` |
| `sniff` | Network traffic analysis | `netsecx sniff --duration 60` |
| `setup` | Configuration management | `netsecx setup --wizard` |
| `version` | Show version information | `netsecx version` |

## 🔒 Security & Privacy

- **Secure Storage**: API keys stored with restricted permissions in user's home directory
- **No Data Retention**: NetSecureX doesn't store or transmit your scan data
- **Privacy First**: API keys only sent to their respective services
- **Audit Trail**: Comprehensive logging for security auditing
- **Safe Defaults**: Conservative scanning parameters to avoid detection

## 📊 Output Formats

NetSecureX supports multiple output formats for integration with other tools:

- **Table**: Human-readable console output (default)
- **JSON**: Machine-readable structured data
- **CSV**: Spreadsheet-compatible format
- **Markdown**: Documentation-friendly reports
- **PDF**: Professional reports (coming soon)

```bash
# Export scan results to JSON
netsecx scan 192.168.1.1 --format json --output scan_results.json

# Generate markdown vulnerability report
netsecx cve --query "apache" --format markdown --output vuln_report.md

# CSV export for spreadsheet analysis
netsecx reput --file ip_list.txt --format csv --output reputation.csv
```

## 🛠️ Requirements

- **Python**: 3.8 or higher
- **Operating System**: macOS, Linux, or Windows
- **Network**: Internet connection for threat intelligence APIs
- **Privileges**: Some features require elevated privileges (e.g., packet capture)

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

NetSecureX is released under the [MIT License](LICENSE). See the LICENSE file for details.

## 🆘 Support

- **Documentation**: [Full documentation](https://github.com/avis-enna/NetSecureX/wiki)
- **Issues**: [GitHub Issues](https://github.com/avis-enna/NetSecureX/issues)
- **Discussions**: [GitHub Discussions](https://github.com/avis-enna/NetSecureX/discussions)
- **Security**: Report security issues to [security@netsecurex.dev](mailto:security@netsecurex.dev)

## 🙏 Acknowledgments

NetSecureX integrates with and thanks the following services:
- [AbuseIPDB](https://www.abuseipdb.com/) for IP reputation data
- [Vulners](https://vulners.com/) for vulnerability intelligence
- [VirusTotal](https://www.virustotal.com/) for threat analysis
- [Shodan](https://www.shodan.io/) for internet-wide scanning data
- [GreyNoise](https://www.greynoise.io/) for internet background noise analysis

---

**⚡ Ready to secure your network? Install NetSecureX today!**

```bash
brew tap avis-enna/netsecurex && brew install netsecurex
```
