# syntax=docker/dockerfile:1

# ---- Base stage: install only Python runtime deps (cached layer) ----
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# ---- Builder stage: install project + dev tooling for linting ----
FROM base AS builder

RUN python -m pip install --upgrade pip setuptools wheel

# Install dependencies first (cache layer bust only on pyproject change).
COPY pyproject.toml ./
RUN python -m pip install ".[dev]"

# ---- Runtime stage: slim, non-root ----
FROM base AS runtime

# Copy the installed site-packages from the builder stage.
COPY --from=builder --chown=app:app /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder --chown=app:app /usr/local/bin /usr/local/bin

# Create a non-root user, then install the exact Chromium binary and OS dependencies
# reproducibly at image-build time (never during an API request).
RUN groupadd --gid 10001 app && useradd --uid 10001 --gid 10001 --create-home app
RUN python -m playwright install --with-deps chromium
RUN mkdir -p /home/app/.cache && cp -a /root/.cache/ms-playwright /home/app/.cache/ && chown -R app:app /home/app/.cache

# Copy application code and data files.
COPY --chown=app:app app ./app
COPY --chown=app:app data ./data

USER app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"]

# Production Uvicorn configuration.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--proxy-headers", "--forwarded-allow-ips", "*"]