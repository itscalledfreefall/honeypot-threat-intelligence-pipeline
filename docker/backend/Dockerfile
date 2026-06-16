FROM python:3.12-slim

# System deps — none needed beyond Python stdlib + sqlite3 (built-in)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python package — README.md is required by pyproject.toml metadata
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir -e .

# Device agent script, served to enrolled devices via /api/devices/agent.py
COPY scripts/device-agent.py ./scripts/device-agent.py

# Entrypoint
COPY docker/backend/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Data directories (volumes will be mounted here)
RUN mkdir -p /data /logs /exports /reports

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:5000/api/summary || exit 1

EXPOSE 5000

ENTRYPOINT ["/entrypoint.sh"]
