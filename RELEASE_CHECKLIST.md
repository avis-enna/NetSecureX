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
