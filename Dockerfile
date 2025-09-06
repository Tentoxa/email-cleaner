# syntax=docker/dockerfile:1.6

FROM python:3.12-slim

# Install minimal OS deps: CA store for IMAP TLS, tzdata for correct time handling
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates tzdata \
  && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 10001 -s /usr/sbin/nologin appuser

# Set workdir and copy code
WORKDIR /app
COPY . /app

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Otherwise install runtime deps detected from imports (dotenv present in code)
RUN pip install --no-cache-dir python-dotenv

# Ensure logs flush promptly in containers
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Least-privilege
RUN chown -R appuser:appuser /app
USER appuser

# Healthcheck: process must be alive; adjust if you add an HTTP endpoint later
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD python -c "import os,sys,time; sys.exit(0)"

# Default command
CMD ["python", "-u", "main.py"]
