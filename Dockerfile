# ── ForgeLens Backend — Dockerfile ────────────────────────────────────────────
FROM python:3.12-slim

# Metadata
LABEL maintainer="ForgeLens"
LABEL description="ForgeLens DFIR backend"

# Prevent .pyc files and enable unbuffered stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Working directory inside container
WORKDIR /app

# Install system dependencies needed for forensic libs
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libewf-dev \
    libtsk-dev \
    adb \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source
COPY backend/ ./backend/
COPY .env.example .env

# Expose API port (for future REST API)
EXPOSE 8000

# Default command — runs the CLI help
CMD [".venv/bin/python", "-m", "backend.cli"]
