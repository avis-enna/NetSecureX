# Contributing to NetSecureX

Thank you for your interest in contributing to NetSecureX! This document provides guidelines and information for contributors.

## 🤝 How to Contribute

### Reporting Issues

1. **Search existing issues** first to avoid duplicates
2. **Use the issue templates** when creating new issues
3. **Provide detailed information** including:
   - Operating system and version
   - Python version
   - NetSecureX version
   - Steps to reproduce
   - Expected vs actual behavior
   - Error messages or logs

### Suggesting Features

1. **Check the roadmap** in the project wiki
2. **Open a feature request** with detailed description
3. **Explain the use case** and benefits
4. **Consider implementation complexity**

### Code Contributions

1. **Fork the repository**
2. **Create a feature branch** from `main`
3. **Make your changes** following our coding standards
4. **Add tests** for new functionality
5. **Update documentation** as needed
6. **Submit a pull request**

## 🛠️ Development Setup

### Prerequisites

- Python 3.8 or higher
- Git
- Virtual environment tool (venv, conda, etc.)

### Local Development

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/NetSecureX.git
cd NetSecureX

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements.txt
pip install -e .

# Install development tools
pip install pytest pytest-asyncio black flake8 mypy pre-commit

# Set up pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=core --cov=utils --cov=ui

# Run specific test file
pytest tests/test_scanner.py

# Run tests with verbose output
pytest -v
```

### Code Quality

```bash
# Format code
black .

# Check code style
flake8

# Type checking
mypy core/ utils/ ui/

# Run all quality checks
pre-commit run --all-files
```

## 📝 Coding Standards

### Python Style

- Follow [PEP 8](https://pep8.org/) style guide
- Use [Black](https://black.readthedocs.io/) for code formatting
- Maximum line length: 88 characters
- Use type hints for all functions and methods
- Write docstrings for all public functions and classes

### Code Organization

```python
"""Module docstring describing purpose and usage."""

import standard_library
import third_party_packages
import local_modules

# Constants
CONSTANT_VALUE = "value"

class ExampleClass:
    """Class docstring."""
    
    def __init__(self, param: str) -> None:
        """Initialize with parameter."""
        self.param = param
    
    def public_method(self, arg: int) -> str:
        """Public method with type hints and docstring."""
        return f"{self.param}: {arg}"
    
    def _private_method(self) -> None:
        """Private method (internal use only)."""
        pass

def public_function(param: str) -> bool:
    """Public function with type hints and docstring."""
    return bool(param)
```

### Documentation

- Use Google-style docstrings
- Include type information in docstrings
- Provide usage examples for complex functions
- Update README.md for user-facing changes

### Testing

- Write tests for all new functionality
- Use pytest for testing framework
- Aim for >90% code coverage
- Include both unit tests and integration tests
- Test error conditions and edge cases

```python
import pytest
from unittest.mock import Mock, patch

def test_function_success():
    """Test successful function execution."""
    result = my_function("valid_input")
    assert result == expected_output

def test_function_error():
    """Test function error handling."""
    with pytest.raises(ValueError):
        my_function("invalid_input")

@pytest.mark.asyncio
async def test_async_function():
    """Test async function."""
    result = await my_async_function()
    assert result is not None
```

## 🔒 Security Guidelines

### Security-First Development

- **Never commit API keys** or sensitive data
- **Validate all inputs** to prevent injection attacks
- **Use secure defaults** for all configuration options
- **Handle errors gracefully** without exposing sensitive information
- **Follow principle of least privilege**

### Security Testing

- Test with malformed inputs
- Verify error messages don't leak sensitive data
- Check for potential injection vulnerabilities
- Validate network security practices

### Reporting Security Issues

**Do not open public issues for security vulnerabilities.**

Instead, email security@netsecurex.dev with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## 📋 Pull Request Process

### Before Submitting

1. **Ensure all tests pass**
2. **Update documentation**
3. **Add changelog entry**
4. **Verify code quality checks pass**
5. **Test on multiple platforms** (if possible)

### PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Tests pass locally
- [ ] Added tests for new functionality
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Changelog updated
```

### Review Process

1. **Automated checks** must pass
2. **Code review** by maintainers
3. **Testing** on multiple platforms
4. **Documentation review**
5. **Final approval** and merge

## 🎯 Areas for Contribution

### High Priority

- **New threat intelligence integrations**
- **Performance optimizations**
- **Additional output formats**
- **Enhanced error handling**
- **Cross-platform compatibility**

### Medium Priority

- **Additional scanning techniques**
- **Improved reporting features**
- **Configuration enhancements**
- **Documentation improvements**
- **Example scripts and tutorials**

### Good First Issues

Look for issues labeled `good first issue` or `help wanted` in the GitHub repository.

## 📞 Getting Help

- **GitHub Discussions**: For questions and general discussion
- **GitHub Issues**: For bug reports and feature requests
- **Documentation**: Check the wiki for detailed guides
- **Code Review**: Maintainers provide feedback on PRs

## 🏆 Recognition

Contributors are recognized in:
- **CONTRIBUTORS.md** file
- **Release notes** for significant contributions
- **GitHub contributors** page
- **Special thanks** in documentation

## 📄 License

By contributing to NetSecureX, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make NetSecureX better! 🛡️
