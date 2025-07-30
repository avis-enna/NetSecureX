# NetSecureX Homebrew Deployment Guide

This guide provides complete instructions for deploying NetSecureX to Homebrew and managing API keys.

## 🚀 Quick Start for Users

### Option 1: Homebrew Installation (Recommended)

```bash
# Add the tap
brew tap avis-enna/netsecurex

# Install NetSecureX
brew install netsecurex

# Run setup wizard
netsecx setup --wizard
```

### Option 2: Direct Installation

```bash
# Clone and install
git clone https://github.com/avis-enna/NetSecureX.git
cd NetSecureX
./install-direct.sh
```

### Option 3: Python Package

```bash
pip install netsecurex
netsecx setup --wizard
```

## 🔧 Configuration Management

NetSecureX uses a modern configuration system that stores API keys securely in `~/.netsecurex/config.yaml`.

### Setup Commands

```bash
# Interactive setup wizard
netsecx setup --wizard

# Show current API key status
netsecx setup --status

# Show configuration info
netsecx setup
```

### Manual Configuration

Edit `~/.netsecurex/config.yaml`:

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
```

## 🔑 API Keys & Free Tiers

All services offer generous free tiers:

| Service | Free Tier | Purpose | Get API Key |
|---------|-----------|---------|-------------|
| **AbuseIPDB** | 1,000 req/day | IP reputation | [Get Key](https://www.abuseipdb.com/api) |
| **Vulners** | 100 req/day | CVE lookup | [Get Key](https://vulners.com/api) |
| **VirusTotal** | 500 req/day | File/URL analysis | [Get Key](https://www.virustotal.com/gui/join-us) |
| **IPQualityScore** | 5,000 req/month | IP fraud detection | [Get Key](https://www.ipqualityscore.com/create-account) |
| **GreyNoise** | 10,000 req/month | Scanning activity | [Get Key](https://www.greynoise.io/) |
| **Shodan** | Paid only | Host information | [Get Key](https://www.shodan.io/) |

## 📦 For Maintainers: Homebrew Deployment

### Step 1: Create Homebrew Tap

```bash
# Create tap repository
gh repo create homebrew-netsecurex --public
git clone https://github.com/avis-enna/homebrew-netsecurex.git
cd homebrew-netsecurex

# Create Formula directory
mkdir Formula
cp ../NetSecureX/Formula/netsecurex.rb Formula/

# Commit and push
git add .
git commit -m "Add NetSecureX formula"
git push origin main
```

### Step 2: Release Process

1. **Create a new tag:**
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

2. **GitHub Actions will automatically:**
   - Create a release
   - Generate tarball
   - Calculate SHA256 hash
   - Provide update instructions

3. **Update Homebrew formula:**
   ```ruby
   url "https://github.com/avis-enna/NetSecureX/archive/refs/tags/v1.0.0.tar.gz"
   sha256 "calculated_sha256_hash_here"
   ```

### Step 3: Test Installation

```bash
# Test locally
brew install --build-from-source Formula/netsecurex.rb

# Test from tap
brew tap avis-enna/netsecurex
brew install netsecurex
```

## 🧪 Testing

### Basic Functionality Tests

```bash
# Version and help
netsecx version
netsecx --help

# Commands that work without API keys
netsecx scan 8.8.8.8 --ports "53,80"
netsecx sslcheck google.com
netsecx firewall --target google.com --ports "80,443"

# Configuration system
netsecx setup --status
netsecx setup
```

### API-Dependent Tests

```bash
# After configuring API keys
netsecx cve --query "nginx"
netsecx iprep --ip 8.8.8.8
netsecx reput --ip 1.2.3.4
```

## 🔒 Security Features

1. **Secure Storage**: API keys stored in user's home directory with restricted permissions
2. **No Logging**: API keys never logged or transmitted except to their services
3. **Input Masking**: Setup wizard masks API key input
4. **Graceful Degradation**: Tools work with limited functionality when API keys are missing
5. **Clear Warnings**: Users informed when API keys are needed

## 📁 File Structure

```
~/.netsecurex/
├── config.yaml          # Main configuration file
└── logs/                 # Application logs (optional)

/usr/local/
├── bin/netsecx          # Main executable
└── etc/netsecurex/      # System configuration
    └── config.example.yaml
```

## 🚨 Troubleshooting

### Common Issues

1. **Command not found**: Restart terminal or source shell config
2. **Permission denied**: Check file permissions on config directory
3. **API errors**: Verify API keys and rate limits
4. **Import errors**: Ensure all dependencies are installed

### Debug Mode

```bash
netsecx --log-level DEBUG scan 8.8.8.8
```

### Reset Configuration

```bash
rm -rf ~/.netsecurex
netsecx setup --wizard
```

## 🔄 Updates

### For Users

```bash
# Homebrew
brew upgrade netsecurex

# Direct installation
git pull && pip install -e .
```

### For Maintainers

1. Update version in `VERSION` file
2. Create new tag
3. Update Homebrew formula with new SHA256
4. Test installation

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/avis-enna/NetSecureX/issues)
- **Documentation**: [README.md](README.md)
- **Examples**: [examples/](examples/)

## 🎯 Benefits of This Approach

1. **User-Friendly**: Single command installation
2. **Secure**: Proper API key management
3. **Flexible**: Multiple installation methods
4. **Maintainable**: Automated release process
5. **Cross-Platform**: Works on macOS and Linux
6. **Professional**: Follows Homebrew best practices
