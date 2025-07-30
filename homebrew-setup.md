# NetSecureX Homebrew Deployment Guide

This guide explains how to deploy NetSecureX to Homebrew for easy installation.

## Step 1: Create a Homebrew Tap Repository

1. Create a new GitHub repository named `homebrew-netsecurex`
2. The repository should follow the naming convention: `homebrew-<formulaname>`

## Step 2: Set Up the Tap Repository

```bash
# Create the tap repository structure
mkdir homebrew-netsecurex
cd homebrew-netsecurex

# Create the Formula directory
mkdir Formula

# Copy the formula file
cp ../NetSecureX/Formula/netsecurex.rb Formula/

# Initialize git repository
git init
git add .
git commit -m "Initial commit: Add NetSecureX formula"
git branch -M main
git remote add origin https://github.com/avis-enna/homebrew-netsecurex.git
git push -u origin main
```

## Step 3: Update the Formula

After each release, update the formula with:

1. New version number
2. Updated URL pointing to the release tarball
3. Updated SHA256 hash (provided by GitHub Actions)

## Step 4: Installation Instructions

Once the tap is set up, users can install NetSecureX with:

```bash
# Add the tap
brew tap avis-enna/netsecurex

# Install NetSecureX
brew install netsecurex

# Run setup wizard
netsecx setup --wizard
```

## Step 5: API Key Management

NetSecureX uses a configuration file at `~/.netsecurex/config.yaml` for API keys.

### Free API Keys Available:

1. **AbuseIPDB** (1000 requests/day)
   - URL: https://www.abuseipdb.com/api
   - Used for: IP reputation checking

2. **Vulners** (100 requests/day)
   - URL: https://vulners.com/api
   - Used for: CVE lookup and vulnerability data

3. **VirusTotal** (500 requests/day)
   - URL: https://www.virustotal.com/gui/join-us
   - Used for: File and URL analysis

4. **IPQualityScore** (5000 requests/month)
   - URL: https://www.ipqualityscore.com/create-account
   - Used for: IP fraud detection

5. **GreyNoise** (10000 requests/month)
   - URL: https://www.greynoise.io/
   - Used for: Internet scanning activity

6. **Shodan** (Paid service)
   - URL: https://www.shodan.io/
   - Used for: Host information and vulnerabilities

## Step 6: Testing the Installation

```bash
# Test basic functionality
netsecx --help
netsecx version

# Test commands that don't require API keys
netsecx scan 8.8.8.8 --ports "53,80"
netsecx sslcheck google.com
netsecx firewall --target google.com --ports "80,443"

# Test CVE lookup (may have limited results without API key)
netsecx cve --query "nginx"

# Configure API keys for full functionality
netsecx setup --wizard
```

## Step 7: Maintenance

### Updating the Formula

When releasing a new version:

1. Create a new tag in the main repository
2. GitHub Actions will automatically create a release with SHA256
3. Update the Homebrew formula with new version and SHA256
4. Push changes to the tap repository

### Formula Template

The formula includes:
- Python dependencies management
- Configuration file setup
- Post-install instructions
- Caveats with API key information
- Test suite

## Benefits of Homebrew Distribution

1. **Easy Installation**: Single command installation
2. **Dependency Management**: Automatic handling of Python and system dependencies
3. **Configuration Management**: Automatic setup of config directories
4. **Updates**: Easy updates with `brew upgrade`
5. **Uninstallation**: Clean removal with `brew uninstall`
6. **Cross-platform**: Works on macOS and Linux

## Security Considerations

1. API keys are stored in user's home directory (`~/.netsecurex/config.yaml`)
2. Config file has restricted permissions (600)
3. API keys are never logged or transmitted except to their respective services
4. Users can review and edit the configuration file manually
5. Setup wizard masks API key input for security
