#!/bin/bash
# NetSecureX Direct Installation Script
# =====================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    NetSecureX Installer                     ║"
    echo "║              Direct Installation Method                      ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_python() {
    print_step "Checking Python installation..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then
        PYTHON_CMD="python"
    else
        print_error "Python not found. Please install Python 3.8 or later."
        exit 1
    fi
    
    # Check Python version
    PYTHON_VERSION=$($PYTHON_CMD -c "import sys; print('.'.join(map(str, sys.version_info[:2])))")
    print_success "Python $PYTHON_VERSION found"
}

install_netsecurex() {
    print_step "Installing NetSecureX..."
    
    # Install using pip
    $PYTHON_CMD -m pip install --user -e .
    
    # Create config directory
    CONFIG_DIR="$HOME/.netsecurex"
    mkdir -p "$CONFIG_DIR"
    
    # Create default config if it doesn't exist
    if [[ ! -f "$CONFIG_DIR/config.yaml" ]]; then
        cat > "$CONFIG_DIR/config.yaml" << 'EOF'
# NetSecureX Configuration
# Add your API keys below (all have free tiers available)

api_keys:
  # AbuseIPDB API Key (free tier: 1000 requests/day)
  # Get from: https://www.abuseipdb.com/api
  abuseipdb: ""
  
  # IPQualityScore API Key (free tier: 5000 requests/month)
  # Get from: https://www.ipqualityscore.com/create-account
  ipqualityscore: ""
  
  # VirusTotal API Key (free tier: 500 requests/day)
  # Get from: https://www.virustotal.com/gui/join-us
  virustotal: ""
  
  # Vulners API Key (free tier: 100 requests/day)
  # Get from: https://vulners.com/api
  vulners: ""
  
  # Shodan API Key (paid service, $49/month)
  # Get from: https://www.shodan.io/
  shodan: ""
  
  # GreyNoise API Key (free tier: 10000 requests/month)
  # Get from: https://www.greynoise.io/
  greynoise: ""

# Default settings
settings:
  timeout: 10
  max_concurrent: 100
  log_level: "INFO"
  output_format: "table"
EOF
        print_success "Created default configuration at $CONFIG_DIR/config.yaml"
    fi
    
    print_success "NetSecureX installed successfully!"
}

create_alias() {
    print_step "Setting up netsecx command..."
    
    # Detect shell
    if [[ "$SHELL" == *"zsh"* ]]; then
        SHELL_RC="$HOME/.zshrc"
    elif [[ "$SHELL" == *"bash"* ]]; then
        SHELL_RC="$HOME/.bashrc"
    else
        SHELL_RC="$HOME/.profile"
    fi
    
    # Add alias if not already present
    if ! grep -q "alias netsecx" "$SHELL_RC" 2>/dev/null; then
        echo "" >> "$SHELL_RC"
        echo "# NetSecureX alias" >> "$SHELL_RC"
        echo "alias netsecx='python3 -m netsecurex'" >> "$SHELL_RC"
        print_success "Added netsecx alias to $SHELL_RC"
        print_warning "Please run 'source $SHELL_RC' or restart your terminal"
    else
        print_success "netsecx alias already exists"
    fi
}

main() {
    print_header
    
    print_step "Starting NetSecureX installation..."
    
    check_python
    install_netsecurex
    create_alias
    
    echo
    print_success "NetSecureX installation completed successfully!"
    echo
    echo -e "${GREEN}Next steps:${NC}"
    echo "1. Restart your terminal or run: source ~/.zshrc (or ~/.bashrc)"
    echo "2. Run setup wizard: netsecx setup --wizard"
    echo "3. Test installation: netsecx --help"
    echo
    echo -e "${YELLOW}API Keys:${NC}"
    echo "Configure API keys for enhanced functionality:"
    echo "• AbuseIPDB: https://www.abuseipdb.com/api (free: 1000 req/day)"
    echo "• Vulners: https://vulners.com/api (free: 100 req/day)"
    echo "• VirusTotal: https://www.virustotal.com/gui/join-us (free: 500 req/day)"
    echo
    echo -e "${BLUE}Documentation:${NC}"
    echo "• Config file: ~/.netsecurex/config.yaml"
    echo "• Examples: ./examples/"
    echo
}

# Run main function
main "$@"
