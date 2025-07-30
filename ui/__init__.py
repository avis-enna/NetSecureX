"""
NetSecureX User Interface
========================

This package contains the user interface components for NetSecureX.

Modules:
- cli: Command-line interface using Click
- formatters: Output formatting utilities
"""

__version__ = "1.0.0"

from .cli import main_cli

__all__ = [
    "main_cli",
]
