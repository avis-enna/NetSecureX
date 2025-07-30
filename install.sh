#!/bin/bash
# NetSecureX Installation Script for Linux/macOS
# ==============================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO_URL="https://github.com/netsecurex/netsecurex"
INSTALL_DIR="/opt/netsecurex"
BIN_DIR="/usr/local/bin"
PYTHON_MIN_VERSION="3.8"

# Functions
print_header() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    NetSecureX Installer                     ║"
    echo "║              Unified Cybersecurity Toolkit                  ║"
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

check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root. This is not recommended for security reasons."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

check_os() {
    print_step "Detecting operating system..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        print_success "Linux detected"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        print_success "macOS detected"
    else
        print_error "Unsupported operating system: $OSTYPE"
        exit 1
    fi
}

check_python() {
    print_step "Checking Python installation..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then
        PYTHON_CMD="python"
    else
        print_error "Python not found. Please install Python $PYTHON_MIN_VERSION or later."
        exit 1
    fi
    
    # Check Python version
    PYTHON_VERSION=$($PYTHON_CMD -c "import sys; print('.'.join(map(str, sys.version_info[:2])))")
    REQUIRED_VERSION=$(echo -e "$PYTHON_VERSION\n$PYTHON_MIN_VERSION" | sort -V | head -n1)
    
    if [[ "$REQUIRED_VERSION" != "$PYTHON_MIN_VERSION" ]]; then
        print_error "Python $PYTHON_MIN_VERSION or later is required. Found: $PYTHON_VERSION"
        exit 1
    fi
    
    print_success "Python $PYTHON_VERSION found"
}

check_dependencies() {
    print_step "Checking system dependencies..."
    
    # Check for required system packages
    if [[ "$OS" == "linux" ]]; then
        # Check for package manager
        if command -v apt-get &> /dev/null; then
            PKG_MANAGER="apt-get"
            INSTALL_CMD="sudo apt-get install -y"
        elif command -v yum &> /dev/null; then
            PKG_MANAGER="yum"
            INSTALL_CMD="sudo yum install -y"
        elif command -v dnf &> /dev/null; then
            PKG_MANAGER="dnf"
            INSTALL_CMD="sudo dnf install -y"
        elif command -v pacman &> /dev/null; then
            PKG_MANAGER="pacman"
            INSTALL_CMD="sudo pacman -S --noconfirm"
        else
            print_warning "No supported package manager found. Manual dependency installation may be required."
        fi
        
        # Check for development tools
        if ! command -v gcc &> /dev/null; then
            print_warning "GCC not found. Some Python packages may fail to install."
            if [[ -n "$PKG_MANAGER" ]]; then
                print_step "Installing build essentials..."
                case $PKG_MANAGER in
                    "apt-get")
                        $INSTALL_CMD build-essential python3-dev libffi-dev libssl-dev
                        ;;
                    "yum"|"dnf")
                        $INSTALL_CMD gcc python3-devel libffi-devel openssl-devel
                        ;;
                    "pacman")
                        $INSTALL_CMD base-devel python libffi openssl
                        ;;
                esac
            fi
        fi
    elif [[ "$OS" == "macos" ]]; then
        # Check for Xcode command line tools
        if ! command -v gcc &> /dev/null; then
            print_step "Installing Xcode command line tools..."
            xcode-select --install
        fi
        
        # Check for Homebrew
        if ! command -v brew &> /dev/null; then
            print_warning "Homebrew not found. Some dependencies may need manual installation."
        fi
    fi
    
    print_success "System dependencies checked"
}

install_pip_dependencies() {
    print_step "Installing Python dependencies..."
    
    # Upgrade pip
    $PYTHON_CMD -m pip install --upgrade pip
    
    # Install core dependencies
    $PYTHON_CMD -m pip install --user \
        click>=8.0.0 \
        rich>=13.0.0 \
        requests>=2.31.0 \
        aiohttp>=3.8.0 \
        cryptography>=41.0.0 \
        python-dotenv>=1.0.0 \
        netaddr>=0.8.0 \
        tabulate>=0.9.0 \
        python-dateutil>=2.8.0
    
    # Install platform-specific dependencies
    if [[ "$OS" == "linux" ]]; then
        $PYTHON_CMD -m pip install --user scapy>=2.5.0 || print_warning "Scapy installation failed. Packet capture may not work."
    fi
    
    print_success "Python dependencies installed"
}

download_netsecurex() {
    print_step "Downloading NetSecureX..."
    
    # Create temporary directory
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    # Download source code
    if command -v git &> /dev/null; then
        git clone "$REPO_URL" netsecurex
    else
        # Download ZIP if git is not available
        curl -L "$REPO_URL/archive/main.zip" -o netsecurex.zip
        unzip netsecurex.zip
        mv netsecurex-main netsecurex
    fi
    
    print_success "NetSecureX downloaded to $TEMP_DIR/netsecurex"
}

install_netsecurex() {
    print_step "Installing NetSecureX..."
    
    # Create installation directory
    sudo mkdir -p "$INSTALL_DIR"
    
    # Copy files
    sudo cp -r "$TEMP_DIR/netsecurex"/* "$INSTALL_DIR/"
    
    # Set permissions
    sudo chown -R $USER:$USER "$INSTALL_DIR"
    sudo chmod +x "$INSTALL_DIR/main.py"
    
    # Create symlink
    sudo ln -sf "$INSTALL_DIR/main.py" "$BIN_DIR/netsecurex"
    sudo ln -sf "$INSTALL_DIR/main.py" "$BIN_DIR/nsx"
    
    print_success "NetSecureX installed to $INSTALL_DIR"
}

create_desktop_entry() {
    if [[ "$OS" == "linux" ]]; then
        print_step "Creating desktop entry..."
        
        DESKTOP_FILE="$HOME/.local/share/applications/netsecurex.desktop"
        mkdir -p "$(dirname "$DESKTOP_FILE")"
        
        cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Name=NetSecureX
Comment=Unified Cybersecurity Toolkit
Exec=gnome-terminal -- netsecurex
Icon=security-high
Terminal=true
Type=Application
Categories=Network;Security;System;
Keywords=security;network;vulnerability;scanner;
EOF
        
        print_success "Desktop entry created"
    fi
}

setup_environment() {
    print_step "Setting up environment..."
    
    # Create .env.example if it doesn't exist
    if [[ ! -f "$INSTALL_DIR/.env.example" ]]; then
        cat > "$INSTALL_DIR/.env.example" << EOF
# NetSecureX API Keys Configuration
# Copy this file to .env and add your actual API keys

# AbuseIPDB API Key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here

# IPQualityScore API Key
IPQUALITYSCORE_API_KEY=your_ipqualityscore_api_key_here

# VirusTotal API Key
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# Vulners API Key
VULNERS_API_KEY=your_vulners_api_key_here
EOF
    fi
    
    print_success "Environment setup completed"
}

cleanup() {
    print_step "Cleaning up..."
    rm -rf "$TEMP_DIR"
    print_success "Cleanup completed"
}

main() {
    print_header
    
    print_step "Starting NetSecureX installation..."
    
    check_root
    check_os
    check_python
    check_dependencies
    install_pip_dependencies
    download_netsecurex
    install_netsecurex
    create_desktop_entry
    setup_environment
    cleanup
    
    echo
    print_success "NetSecureX installation completed successfully!"
    echo
    echo -e "${GREEN}Usage:${NC}"
    echo "  netsecurex --help          # Show help"
    echo "  netsecurex version         # Show version"
    echo "  netsecurex scan --help     # Port scanning"
    echo "  netsecurex cert --help     # Certificate analysis"
    echo "  netsecurex cve --help      # CVE lookup"
    echo "  netsecurex iprep --help    # IP reputation"
    echo
    echo -e "${YELLOW}Configuration:${NC}"
    echo "  Edit $INSTALL_DIR/.env to add API keys"
    echo
    echo -e "${BLUE}Documentation:${NC}"
    echo "  https://docs.netsecurex.dev"
    echo
}

# Run main function
main "$@"
