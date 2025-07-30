"""
Secure JSON Logging Utilities for NetSecureX
============================================

This module provides secure logging functionality with JSON output format.
All sensitive data is sanitized before logging.
"""

import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
import structlog


class SecureJSONFormatter(logging.Formatter):
    """Custom JSON formatter that sanitizes sensitive data."""
    
    SENSITIVE_FIELDS = {
        'password', 'passwd', 'secret', 'token', 'key', 'auth',
        'credential', 'private', 'session', 'cookie'
    }
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as sanitized JSON."""
        log_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Add extra fields if present
        if hasattr(record, 'extra_data'):
            extra = self._sanitize_data(record.extra_data)
            log_data.update(extra)
            
        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
            
        return json.dumps(log_data, default=str, ensure_ascii=False)
    
    def _sanitize_data(self, data: Any) -> Any:
        """Recursively sanitize sensitive data."""
        if isinstance(data, dict):
            return {
                key: self._sanitize_value(key, value)
                for key, value in data.items()
            }
        elif isinstance(data, list):
            return [self._sanitize_data(item) for item in data]
        return data
    
    def _sanitize_value(self, key: str, value: Any) -> Any:
        """Sanitize individual values based on key names."""
        if isinstance(key, str) and any(
            sensitive in key.lower() for sensitive in self.SENSITIVE_FIELDS
        ):
            return "[REDACTED]"
        return self._sanitize_data(value)


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[Path] = None,
    enable_console: bool = True
) -> None:
    """
    Set up secure JSON logging for NetSecureX.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for log output
        enable_console: Whether to enable console logging
    """
    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    
    # Set up root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Console handler
    if enable_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(SecureJSONFormatter())
        root_logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(SecureJSONFormatter())
        root_logger.addHandler(file_handler)


def get_logger(name: str) -> structlog.BoundLogger:
    """
    Get a configured logger instance.
    
    Args:
        name: Logger name (usually __name__)
        
    Returns:
        Configured structlog logger
    """
    return structlog.get_logger(name)


class SecurityLogger:
    """Specialized logger for security events."""
    
    def __init__(self, name: str):
        self.logger = get_logger(name)
    
    def scan_started(self, target: str, scan_type: str, **kwargs) -> None:
        """Log scan initiation."""
        self.logger.info(
            "Security scan started",
            event_type="scan_started",
            target=target,
            scan_type=scan_type,
            **kwargs
        )
    
    def scan_completed(self, target: str, scan_type: str, results_count: int, **kwargs) -> None:
        """Log scan completion."""
        self.logger.info(
            "Security scan completed",
            event_type="scan_completed",
            target=target,
            scan_type=scan_type,
            results_count=results_count,
            **kwargs
        )
    
    def vulnerability_found(self, target: str, vulnerability: Dict[str, Any]) -> None:
        """Log vulnerability discovery."""
        self.logger.warning(
            "Vulnerability detected",
            event_type="vulnerability_found",
            target=target,
            vulnerability=vulnerability
        )
    
    def error_occurred(self, target: str, error: str, **kwargs) -> None:
        """Log security scan errors."""
        self.logger.error(
            "Security scan error",
            event_type="scan_error",
            target=target,
            error=error,
            **kwargs
        )
