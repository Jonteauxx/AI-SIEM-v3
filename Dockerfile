# AI-SIEM v3 - Docker Image (Production-Ready)
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    APP_USER=socagent \
    APP_UID=1000 \
    APP_GID=1000

# Set working directory
WORKDIR /app

# Install system dependencies (including PostgreSQL client for pg_isready)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN groupadd --gid ${APP_GID} ${APP_USER} \
    && useradd --uid ${APP_UID} --gid ${APP_GID} --shell /bin/bash --create-home ${APP_USER}

# Copy requirements first (for Docker layer caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY main.py .
COPY templates/ templates/

# Create directories for data persistence with proper ownership
RUN mkdir -p /app/data /app/logs \
    && chown -R ${APP_USER}:${APP_USER} /app

# Set volume for persistent data
VOLUME ["/app/data", "/app/logs"]

# Switch to non-root user
USER ${APP_USER}

# Expose ports
# 8000 - API
# 5046 - FluentD TCP ingestion
EXPOSE 8000 5046

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application
CMD ["python", "main.py"]
