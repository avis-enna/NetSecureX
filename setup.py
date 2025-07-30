#!/usr/bin/env python3
"""
NetSecureX Setup Script
=======================

Cross-platform setup script for NetSecureX cybersecurity toolkit.
Supports Windows, macOS, and Linux distributions.
"""

import os
import sys
from setuptools import setup, find_packages

# Read version from version file
def get_version():
    version_file = os.path.join(os.path.dirname(__file__), 'VERSION')
    if os.path.exists(version_file):
        with open(version_file, 'r') as f:
            return f.read().strip()
    return '1.0.0'

# Read long description from README
def get_long_description():
    readme_file = os.path.join(os.path.dirname(__file__), 'README.md')
    if os.path.exists(readme_file):
        with open(readme_file, 'r', encoding='utf-8') as f:
            return f.read()
    return ''

# Platform-specific dependencies
def get_platform_dependencies():
    """Get platform-specific dependencies."""
    deps = []
    
    # Windows-specific dependencies
    if sys.platform.startswith('win'):
        deps.extend([
            'pywin32>=227',  # Windows API access
            'wmi>=1.5.1',    # Windows Management Instrumentation
        ])
    
    # macOS-specific dependencies
    elif sys.platform == 'darwin':
        deps.extend([
            'pyobjc-core>=8.0',      # macOS Objective-C bridge
            'pyobjc-framework-Cocoa>=8.0',  # macOS Cocoa framework
        ])
    
    # Linux-specific dependencies
    elif sys.platform.startswith('linux'):
        deps.extend([
            'python-prctl>=1.7.0',   # Process control
        ])
    
    return deps

# Core dependencies (cross-platform)
CORE_DEPENDENCIES = [
    # CLI and UI
    'click>=8.0.0',
    'rich>=13.0.0',
    'tabulate>=0.9.0',

    # Configuration management
    'PyYAML>=6.0.0',

    # Network and security libraries
    'netaddr>=0.8.0',
    'cryptography>=41.0.0',
    'requests>=2.31.0',
    'aiohttp>=3.8.0',
    'dnspython>=2.4.0',

    # Data processing and validation
    'pydantic>=2.0.0',
    'python-dateutil>=2.8.0',
    'python-dotenv>=1.0.0',

    # Logging and async support
    'structlog>=23.0.0',
    'asyncio-mqtt>=0.13.0',
    'aiofiles>=23.0.0',

    # Optional dependencies with fallbacks
    'scapy>=2.5.0; platform_system != "Windows"',  # Packet capture (Linux/macOS)
    'python-nmap>=0.7.1',  # Nmap integration
]

# Development dependencies
DEV_DEPENDENCIES = [
    'pytest>=7.0.0',
    'pytest-asyncio>=0.21.0',
    'pytest-cov>=4.0.0',
    'black>=23.0.0',
    'flake8>=6.0.0',
    'mypy>=1.0.0',
    'pre-commit>=3.0.0',
]

# Documentation dependencies
DOC_DEPENDENCIES = [
    'sphinx>=6.0.0',
    'sphinx-rtd-theme>=1.2.0',
    'myst-parser>=1.0.0',
]

setup(
    name='netsecurex',
    version=get_version(),
    description='Unified Cybersecurity Toolkit for Network Security Assessment',
    long_description=get_long_description(),
    long_description_content_type='text/markdown',
    author='NetSecureX Team',
    author_email='contact@netsecurex.dev',
    url='https://github.com/netsecurex/netsecurex',
    project_urls={
        'Documentation': 'https://docs.netsecurex.dev',
        'Source': 'https://github.com/netsecurex/netsecurex',
        'Tracker': 'https://github.com/netsecurex/netsecurex/issues',
    },
    
    # Package configuration
    packages=find_packages(exclude=['tests*', 'docs*']),
    include_package_data=True,
    zip_safe=False,
    
    # Python version requirement
    python_requires='>=3.8',
    
    # Dependencies
    install_requires=CORE_DEPENDENCIES + get_platform_dependencies(),
    extras_require={
        'dev': DEV_DEPENDENCIES,
        'docs': DOC_DEPENDENCIES,
        'full': DEV_DEPENDENCIES + DOC_DEPENDENCIES,
    },
    
    # Entry points for CLI
    entry_points={
        'console_scripts': [
            'netsecurex=main:main',
            'nsx=main:main',  # Short alias
            'netsecx=main:main',  # User preferred alias
        ],
    },
    
    # Package metadata
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: MacOS',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Environment :: Console',
        'Natural Language :: English',
    ],
    keywords='cybersecurity network security vulnerability scanner penetration testing',
    
    # Package data
    package_data={
        'netsecurex': [
            'data/*.json',
            'data/*.yaml',
            'templates/*.html',
            'templates/*.md',
        ],
    },
    
    # Data files
    data_files=[
        ('share/netsecurex/examples', [
            'examples/scan_config.yaml',
            'examples/ip_list.txt',
        ]),
        ('share/netsecurex/docs', [
            'README.md',
            'LICENSE',
            'CHANGELOG.md',
        ]),
    ],
)
