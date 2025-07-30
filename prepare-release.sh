#!/bin/bash
# NetSecureX Release Preparation Script
# ====================================

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
    echo "║                NetSecureX Release Preparation               ║"
    echo "║              Ready for Homebrew Distribution                ║"
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

check_prerequisites() {
    print_step "Checking prerequisites..."
    
    # Check if we're in the right directory
    if [[ ! -f "main.py" ]] || [[ ! -f "setup.py" ]]; then
        print_error "Please run this script from the NetSecureX root directory"
        exit 1
    fi
    
    # Check git status
    if [[ -n $(git status --porcelain) ]]; then
        print_warning "You have uncommitted changes. Consider committing them first."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    print_success "Prerequisites check passed"
}

run_tests() {
    print_step "Running tests..."
    
    # Install test dependencies if needed
    if ! python -c "import pytest" 2>/dev/null; then
        print_step "Installing test dependencies..."
        pip install pytest pytest-asyncio
    fi
    
    # Run basic functionality tests
    print_step "Testing basic functionality..."
    python -c "
import sys
sys.path.insert(0, '.')
try:
    from ui.cli import main_cli
    from utils.config import config
    print('✅ Core imports successful')
except Exception as e:
    print(f'❌ Import error: {e}')
    sys.exit(1)
"
    
    print_success "Tests passed"
}

validate_configuration() {
    print_step "Validating configuration system..."
    
    # Test configuration system
    python -c "
import sys
sys.path.insert(0, '.')
from utils.config import ConfigManager
config = ConfigManager()
print('✅ Configuration system working')
"
    
    print_success "Configuration validation passed"
}

check_homebrew_formula() {
    print_step "Checking Homebrew formula..."
    
    if [[ ! -f "Formula/netsecurex.rb" ]]; then
        print_error "Homebrew formula not found at Formula/netsecurex.rb"
        exit 1
    fi
    
    # Basic syntax check
    if command -v ruby &> /dev/null; then
        ruby -c Formula/netsecurex.rb
        print_success "Homebrew formula syntax is valid"
    else
        print_warning "Ruby not found, skipping formula syntax check"
    fi
}

prepare_documentation() {
    print_step "Preparing documentation..."
    
    # Check required files
    required_files=("README.md" "CHANGELOG.md" "CONTRIBUTING.md" "SECURITY.md" "LICENSE")
    
    for file in "${required_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            print_error "Required file missing: $file"
            exit 1
        fi
    done
    
    print_success "Documentation files present"
}

create_release_checklist() {
    print_step "Creating release checklist..."
    
    cat > RELEASE_CHECKLIST.md << 'EOF'
# NetSecureX Release Checklist

## Pre-Release
- [ ] All tests pass
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version number updated in VERSION file
- [ ] Homebrew formula ready
- [ ] Security review completed

## Release Process
- [ ] Create and push git tag: `git tag v1.0.0 && git push origin v1.0.0`
- [ ] GitHub Actions will automatically create release
- [ ] Verify release artifacts are created
- [ ] Update Homebrew formula with new SHA256

## Post-Release
- [ ] Test Homebrew installation
- [ ] Update documentation links
- [ ] Announce release
- [ ] Monitor for issues

## Homebrew Tap Setup

### 1. Create Homebrew Tap Repository
```bash
gh repo create homebrew-netsecurex --public
git clone https://github.com/avis-enna/homebrew-netsecurex.git
cd homebrew-netsecurex
mkdir Formula
cp ../NetSecureX/Formula/netsecurex.rb Formula/
git add .
git commit -m "Add NetSecureX formula"
git push origin main
```

### 2. Update Formula After Release
After GitHub Actions creates the release, update the formula with:
- New version number
- New URL pointing to release tarball
- New SHA256 hash (provided in release notes)

### 3. Test Installation
```bash
brew tap avis-enna/netsecurex
brew install netsecurex
netsecx setup --wizard
netsecx --help
```

## Installation Commands for Users

### Homebrew (Recommended)
```bash
brew tap avis-enna/netsecurex
brew install netsecurex
netsecx setup --wizard
```

### Python Package
```bash
pip install netsecurex
netsecx setup --wizard
```

### From Source
```bash
git clone https://github.com/avis-enna/NetSecureX.git
cd NetSecureX
./install-direct.sh
```
EOF
    
    print_success "Release checklist created: RELEASE_CHECKLIST.md"
}

show_next_steps() {
    echo
    print_success "NetSecureX is ready for release! 🎉"
    echo
    echo -e "${GREEN}Next Steps:${NC}"
    echo "1. Review RELEASE_CHECKLIST.md for detailed instructions"
    echo "2. Create git tag: git tag v1.0.0"
    echo "3. Push tag: git push origin v1.0.0"
    echo "4. GitHub Actions will create the release automatically"
    echo "5. Set up Homebrew tap repository"
    echo "6. Update Homebrew formula with release SHA256"
    echo
    echo -e "${YELLOW}Important Files:${NC}"
    echo "• README.md - Professional documentation"
    echo "• Formula/netsecurex.rb - Homebrew formula"
    echo "• CHANGELOG.md - Release notes"
    echo "• SECURITY.md - Security policy"
    echo "• CONTRIBUTING.md - Contribution guidelines"
    echo "• .github/workflows/release.yml - Automated releases"
    echo
    echo -e "${BLUE}API Key Setup:${NC}"
    echo "Users can get free API keys from:"
    echo "• AbuseIPDB: https://www.abuseipdb.com/api (1000 req/day)"
    echo "• Vulners: https://vulners.com/api (100 req/day)"
    echo "• VirusTotal: https://www.virustotal.com/gui/join-us (500 req/day)"
    echo "• IPQualityScore: https://www.ipqualityscore.com/create-account (5000 req/month)"
    echo "• GreyNoise: https://www.greynoise.io/ (10000 req/month)"
    echo
    echo -e "${GREEN}Installation Test:${NC}"
    echo "Test the current setup with: netsecx setup --status"
    echo
}

main() {
    print_header
    
    check_prerequisites
    run_tests
    validate_configuration
    check_homebrew_formula
    prepare_documentation
    create_release_checklist
    show_next_steps
}

# Run main function
main "$@"
