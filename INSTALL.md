# NetSecureX Installation Guide

A comprehensive guide to install NetSecureX on macOS, Linux, and Windows.

## 📋 Table of Contents

- [System Requirements](#system-requirements)
- [Quick Installation](#quick-installation)
- [Platform-Specific Installation](#platform-specific-installation)
  - [macOS Installation](#macos-installation)
  - [Linux Installation](#linux-installation)
  - [Windows Installation](#windows-installation)
- [Post-Installation Setup](#post-installation-setup)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)
- [Uninstallation](#uninstallation)

## 🔧 System Requirements

### Minimum Requirements
- **Python**: 3.9 or higher
- **Operating System**: 
  - macOS 10.15+ (Catalina or later)
  - Linux (Ubuntu 18.04+, CentOS 7+, or equivalent)
  - Windows 10/11
- **Memory**: 512 MB RAM
- **Storage**: 100 MB free space
- **Network**: Internet connection for threat intelligence APIs

### System Dependencies
- **nmap**: Network scanning tool (required)
- **OpenSSL**: For SSL/TLS analysis (usually pre-installed)

## ⚡ Quick Installation

### Recommended Methods

#### macOS (Homebrew)
```bash
# Install via Homebrew (recommended)
brew install --formula ./Formula/netsecurex.rb

# Or if published to a tap:
brew tap avis-enna/netsecurex
brew install netsecurex
```

#### Linux (PyPI)
```bash
# Install system dependencies first
sudo apt update && sudo apt install -y nmap python3-pip  # Ubuntu/Debian
# OR
sudo yum install -y nmap python3-pip  # CentOS/RHEL

# Install NetSecureX
pip3 install netsecurex
```

#### Windows (PyPI)
```powershell
# Install Python 3.9+ from python.org first
# Install nmap from https://nmap.org/download.html

# Install NetSecureX
pip install netsecurex
```

## 🖥️ Platform-Specific Installation

## macOS Installation

### Method 1: Homebrew (Recommended)

#### Prerequisites
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install system dependencies
brew install nmap python@3.12
```

#### Installation
```bash
# Option A: Direct formula installation
curl -O https://raw.githubusercontent.com/avis-enna/NetSecureX/main/Formula/netsecurex.rb
brew install --formula ./netsecurex.rb

# Option B: Via tap (if available)
brew tap avis-enna/netsecurex
brew install netsecurex
```

### Method 2: PyPI
```bash
# Install system dependencies
brew install nmap python@3.12

# Install NetSecureX
pip3 install netsecurex
```

### Method 3: From Source
```bash
# Install dependencies
brew install nmap python@3.12 git

# Clone and install
git clone https://github.com/avis-enna/NetSecureX.git
cd NetSecureX
pip3 install -e .
```

## Linux Installation

### Ubuntu/Debian

#### Method 1: PyPI (Recommended)
```bash
# Update package list
sudo apt update

# Install system dependencies
sudo apt install -y nmap python3 python3-pip python3-venv

# Create virtual environment (recommended)
python3 -m venv netsecurex-env
source netsecurex-env/bin/activate

# Install NetSecureX
pip install netsecurex
```

#### Method 2: From Source
```bash
# Install dependencies
sudo apt install -y nmap python3 python3-pip python3-venv git

# Clone repository
git clone https://github.com/avis-enna/NetSecureX.git
cd NetSecureX

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install
pip install -e .
```

### CentOS/RHEL/Fedora

#### Method 1: PyPI
```bash
# Install system dependencies
sudo yum install -y nmap python3 python3-pip  # CentOS 7/RHEL 7
# OR
sudo dnf install -y nmap python3 python3-pip  # CentOS 8+/Fedora

# Create virtual environment
python3 -m venv netsecurex-env
source netsecurex-env/bin/activate

# Install NetSecureX
pip install netsecurex
```

### Arch Linux
```bash
# Install dependencies
sudo pacman -S nmap python python-pip

# Install NetSecureX
pip install netsecurex
```

## Windows Installation

### Method 1: PyPI (Recommended)

#### Prerequisites
1. **Install Python 3.9+**
   - Download from [python.org](https://www.python.org/downloads/)
   - ✅ Check "Add Python to PATH" during installation
   - ✅ Check "Install pip"

2. **Install Nmap**
   - Download from [nmap.org](https://nmap.org/download.html)
   - Install the Windows version
   - ✅ Add to PATH during installation

#### Installation
```powershell
# Open PowerShell or Command Prompt as Administrator
# Verify installations
python --version
nmap --version

# Install NetSecureX
pip install netsecurex
```

### Method 2: From Source
```powershell
# Install Git for Windows if not already installed
# Install Python 3.9+ and Nmap (see above)

# Clone repository
git clone https://github.com/avis-enna/NetSecureX.git
cd NetSecureX

# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install
pip install -e .
```

### Method 3: Executable (Coming Soon)
```powershell
# Download pre-built executable from GitHub Releases
# https://github.com/avis-enna/NetSecureX/releases

# Extract and run
.\netsecurex.exe --help
```

## 🔧 Post-Installation Setup

### 1. Verify Installation
```bash
# Check if NetSecureX is installed
netsecurex --version
netsecurex --help
```

### 2. API Key Configuration (Optional)
```bash
# Run setup wizard
netsecurex setup

# Or manually create config file
mkdir -p ~/.config/netsecurex
cat > ~/.config/netsecurex/config.yaml << EOF
api_keys:
  virustotal: "your_api_key_here"
  shodan: "your_api_key_here"
  # Add other API keys as needed
EOF
```

### 3. Test Basic Functionality
```bash
# Test network scanning
netsecurex scan 127.0.0.1

# Test CVE lookup
netsecurex cve --query "nginx"

# Test SSL check
netsecurex sslcheck google.com
```

## ✅ Verification

### Basic Verification
```bash
# 1. Check version
netsecurex --version

# 2. Check help
netsecurex --help

# 3. Test scan (should work without API keys)
netsecurex scan 127.0.0.1

# 4. Check dependencies
nmap --version
python3 --version
```

### Advanced Verification
```bash
# Test all modules
netsecurex scan --help
netsecurex cve --help
netsecurex sslcheck --help
netsecurex gui  # If GUI is available
```

## 🔧 Troubleshooting

### Common Issues

#### 1. "netsecurex: command not found"
**Solution:**
```bash
# Check if pip installed to user directory
echo $PATH
export PATH="$HOME/.local/bin:$PATH"  # Linux/macOS
# OR
pip install --user netsecurex  # Install to user directory
```

#### 2. "nmap: command not found"
**Solution:**
```bash
# macOS
brew install nmap

# Ubuntu/Debian
sudo apt install nmap

# Windows
# Download and install from https://nmap.org/download.html
```

#### 3. Python Version Issues
**Solution:**
```bash
# Check Python version
python3 --version

# If Python < 3.9, upgrade:
# macOS: brew install python@3.12
# Ubuntu: sudo apt install python3.12
# Windows: Download from python.org
```

#### 4. Permission Errors (Linux/macOS)
**Solution:**
```bash
# Use virtual environment
python3 -m venv netsecurex-env
source netsecurex-env/bin/activate
pip install netsecurex

# OR install to user directory
pip install --user netsecurex
```

#### 5. SSL Certificate Errors
**Solution:**
```bash
# Update certificates
# macOS: brew install ca-certificates
# Ubuntu: sudo apt update && sudo apt install ca-certificates
# Windows: Update Windows or install certificates manually
```

### Platform-Specific Issues

#### macOS
- **Issue**: "Developer cannot be verified"
  - **Solution**: `xattr -d com.apple.quarantine /path/to/netsecurex`

#### Linux
- **Issue**: Missing development headers
  - **Solution**: `sudo apt install python3-dev build-essential`

#### Windows
- **Issue**: "Microsoft Visual C++ 14.0 is required"
  - **Solution**: Install Microsoft C++ Build Tools

## 🗑️ Uninstallation

### PyPI Installation
```bash
pip uninstall netsecurex
```

### Homebrew Installation (macOS)
```bash
brew uninstall netsecurex
```

### From Source
```bash
# If installed with pip install -e .
pip uninstall netsecurex

# Remove cloned directory
rm -rf NetSecureX/
```

### Clean Configuration
```bash
# Remove configuration files
rm -rf ~/.config/netsecurex/
```

## 📞 Support

If you encounter issues not covered in this guide:

1. **Check GitHub Issues**: [NetSecureX Issues](https://github.com/avis-enna/NetSecureX/issues)
2. **Create New Issue**: Include your OS, Python version, and error messages
3. **Documentation**: Check the main [README.md](README.md) for additional information

## 🔄 Updates

### Update NetSecureX
```bash
# PyPI installation
pip install --upgrade netsecurex

# Homebrew installation
brew upgrade netsecurex

# From source
cd NetSecureX
git pull origin main
pip install -e . --upgrade
```

## 🚀 Advanced Installation Options

### Docker Installation
```bash
# Pull the Docker image (when available)
docker pull netsecurex/netsecurex:latest

# Run NetSecureX in Docker
docker run -it --rm netsecurex/netsecurex:latest netsecurex --help

# Run with volume for persistent config
docker run -it --rm -v ~/.config/netsecurex:/root/.config/netsecurex netsecurex/netsecurex:latest
```

### Development Installation
```bash
# For contributors and developers
git clone https://github.com/avis-enna/NetSecureX.git
cd NetSecureX

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
flake8 netsecurex/
black netsecurex/
```

## 🔐 Security Considerations

### API Key Security
- **Never commit API keys to version control**
- **Use environment variables for CI/CD**
- **Rotate API keys regularly**
- **Use read-only API keys when possible**

### Network Security
- **Run scans only on networks you own or have permission to test**
- **Be aware of rate limits on external APIs**
- **Consider using VPN for sensitive scans**

### File Permissions
```bash
# Secure configuration directory
chmod 700 ~/.config/netsecurex/
chmod 600 ~/.config/netsecurex/config.yaml
```

## 📊 Performance Optimization

### System Tuning
```bash
# Increase file descriptor limits for large scans
ulimit -n 65536

# For intensive scanning, consider:
# - More RAM (2GB+ recommended)
# - SSD storage for faster I/O
# - Stable network connection
```

### Configuration Tuning
```yaml
# ~/.config/netsecurex/config.yaml
performance:
  max_concurrent_scans: 50
  timeout: 30
  retry_attempts: 3
  rate_limit: 10  # requests per second
```

## 🌐 Network Configuration

### Firewall Considerations
```bash
# Ensure outbound connections are allowed for:
# - Port 443 (HTTPS) for API calls
# - Various ports for nmap scanning
# - DNS resolution (port 53)

# Example iptables rules (Linux)
sudo iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
```

### Proxy Configuration
```bash
# If behind a corporate proxy
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
export NO_PROXY=localhost,127.0.0.1

# Or configure in NetSecureX config
netsecurex config set proxy.http "http://proxy.company.com:8080"
netsecurex config set proxy.https "http://proxy.company.com:8080"
```

## 🔧 Integration Examples

### CI/CD Integration
```yaml
# GitHub Actions example
name: Security Scan
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install NetSecureX
        run: |
          sudo apt install -y nmap
          pip install netsecurex
      - name: Run Security Scan
        run: netsecurex scan ${{ github.event.repository.clone_url }}
        env:
          VIRUSTOTAL_API_KEY: ${{ secrets.VIRUSTOTAL_API_KEY }}
```

### Automation Scripts
```bash
#!/bin/bash
# daily-scan.sh - Automated daily security scan

# Configuration
TARGET_NETWORK="192.168.1.0/24"
REPORT_EMAIL="security@company.com"
LOG_FILE="/var/log/netsecurex/daily-scan.log"

# Run scan
echo "Starting daily security scan at $(date)" >> "$LOG_FILE"
netsecurex scan "$TARGET_NETWORK" --output json > /tmp/scan-results.json

# Process results and send email
if [ $? -eq 0 ]; then
    echo "Scan completed successfully" >> "$LOG_FILE"
    mail -s "Daily Security Scan Results" "$REPORT_EMAIL" < /tmp/scan-results.json
else
    echo "Scan failed" >> "$LOG_FILE"
    mail -s "Daily Security Scan FAILED" "$REPORT_EMAIL" < "$LOG_FILE"
fi
```

## 📱 Mobile and Remote Access

### SSH Tunneling
```bash
# Access NetSecureX remotely via SSH tunnel
ssh -L 8080:localhost:8080 user@remote-server
# Then run NetSecureX GUI on remote server accessible via localhost:8080
```

### VPN Setup
```bash
# For secure remote scanning, consider setting up VPN
# OpenVPN example configuration
sudo apt install openvpn
sudo openvpn --config company-vpn.ovpn
```

## 🎯 Use Case Examples

### Home Network Security Audit
```bash
# Scan your home network
netsecurex scan 192.168.1.0/24 --output detailed

# Check router security
netsecurex sslcheck 192.168.1.1

# Monitor for new devices
netsecurex scan 192.168.1.0/24 --monitor --interval 3600
```

### Enterprise Security Assessment
```bash
# Comprehensive enterprise scan
netsecurex scan 10.0.0.0/8 --enterprise-mode --threads 100

# CVE monitoring for critical systems
netsecurex cve --query "apache nginx mysql" --severity critical

# SSL certificate monitoring
netsecurex sslcheck company.com --check-expiry --alert-days 30
```

### Penetration Testing
```bash
# Reconnaissance phase
netsecurex scan target.com --recon-mode

# Vulnerability assessment
netsecurex cve --target target.com --exploit-check

# SSL/TLS security assessment
netsecurex sslcheck target.com --comprehensive
```

---

**Happy Scanning! 🔒🛡️**

*For more information, visit the [NetSecureX GitHub Repository](https://github.com/avis-enna/NetSecureX)*
