# Dockerfile
# Production-ready multi-stage container packaging VulnFlow AI Engine, REST API, and Web Dashboard.

# ==========================================
# STAGE 1: Build Frontend Web Dashboard (Vite + React)
# ==========================================
FROM node:20-alpine AS ui-builder
WORKDIR /app/ui

# Install dependencies
COPY ui/package*.json ./
RUN npm ci || npm install

# Build static bundle to /app/ui/dist
COPY ui/ ./
RUN npm run build

# ==========================================
# STAGE 2: VulnFlow Engine & Unified Server
# ==========================================
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    VULNFLOW_ENV=production

# Install essential system dependencies (git for branches/patches, curl, ca-certificates)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy project specification and install core + API dependencies
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir .[all]

# Copy configuration, policies, test fixtures, and API server code
COPY policies/ ./policies/
COPY data/ ./data/
COPY api/ ./api/

# Copy built frontend assets from STAGE 1
COPY --from=ui-builder /app/ui/dist ./ui/dist

# Expose unified Control Plane port (serves both Web Dashboard and REST API)
EXPOSE 8000

# Persistent storage for runs, audit logs, and reports
VOLUME ["/app/.vulnflow", "/repos"]

# Container healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

ENTRYPOINT ["vulnflow"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
