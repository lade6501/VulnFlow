# Dockerfile
# Builds the reproducible container image for VulnFlow CLI, API, and agent runners.

FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    VULNFLOW_ENV=production

# Install essential system dependencies: git, curl, Node.js & npm
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy project specification and codebase
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY policies/ ./policies/

# Install VulnFlow
RUN pip install --no-cache-dir .

ENTRYPOINT ["vulnflow"]
CMD ["analyze", "--help"]
