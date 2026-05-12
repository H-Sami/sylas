FROM python:3.14-slim

LABEL maintainer="Sylas Team"
LABEL description="Sylas - Autonomous Security Remediation"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -s /bin/bash agent && \
    chown -R agent:agent /app

WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt || true

# Copy application code
COPY agent/ ./agent/
COPY configs/ ./configs/
COPY demo/ ./demo/

# Set ownership
RUN chown -R agent:agent /app

# Switch to non-root user
USER agent

# Default command
CMD ["python", "-m", "agent.main", "--help"]

# Expose default ports (if needed)
# EXPOSE 8080