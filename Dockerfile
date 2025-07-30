# NetSecureX - Unified Cybersecurity Tool
# Multi-stage Docker build for security and efficiency

# Build stage
FROM python:3.11-slim as builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    libjpeg-dev \
    libpng-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip setuptools wheel && \
    pip install -r requirements.txt

# Production stage
FROM python:3.11-slim as production

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    NETSECUREX_HOME="/app"

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    # Network tools
    nmap \
    netcat-traditional \
    dnsutils \
    iputils-ping \
    # System utilities
    curl \
    wget \
    ca-certificates \
    # For PDF generation
    wkhtmltopdf \
    # Clean up
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN groupadd -r netsecurex && \
    useradd -r -g netsecurex -d /app -s /bin/bash netsecurex

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=netsecurex:netsecurex . .

# Create necessary directories
RUN mkdir -p /app/logs /app/reports /app/output && \
    chown -R netsecurex:netsecurex /app

# Make main.py executable
RUN chmod +x main.py

# Switch to non-root user
USER netsecurex

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python main.py version || exit 1

# Default command
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]

# Labels for metadata
LABEL maintainer="NetSecureX Team" \
      version="1.0.0" \
      description="Unified Cybersecurity Tool" \
      org.opencontainers.image.title="NetSecureX" \
      org.opencontainers.image.description="Comprehensive security testing toolkit" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.vendor="NetSecureX Team" \
      org.opencontainers.image.licenses="MIT"
