# syntax=docker/dockerfile:1.7
# ---------- 1. frontend static export
FROM node:22.13-bookworm-slim AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# ---------- 2. scanner binaries (pinned versions)
FROM debian:bookworm-slim AS tools
ARG GITLEAKS=8.30.1 ACTIONLINT=1.7.12 TRIVY=0.76.1 SYFT=1.56.0 GRYPE=0.121.1 TRUFFLEHOG=3.99.8 COSIGN=3.1.4
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates tar && rm -rf /var/lib/apt/lists/*
WORKDIR /out
RUN set -eux; \
  curl -fsSL https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS}/gitleaks_${GITLEAKS}_linux_x64.tar.gz | tar -xz gitleaks; \
  curl -fsSL https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT}/actionlint_${ACTIONLINT}_linux_amd64.tar.gz | tar -xz actionlint; \
  curl -fsSL https://github.com/aquasecurity/trivy/releases/download/v${TRIVY}/trivy_${TRIVY}_Linux-64bit.tar.gz | tar -xz trivy; \
  curl -fsSL https://github.com/anchore/syft/releases/download/v${SYFT}/syft_${SYFT}_linux_amd64.tar.gz | tar -xz syft; \
  curl -fsSL https://github.com/anchore/grype/releases/download/v${GRYPE}/grype_${GRYPE}_linux_amd64.tar.gz | tar -xz grype; \
  curl -fsSL https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG}/trufflehog_${TRUFFLEHOG}_linux_amd64.tar.gz | tar -xz trufflehog; \
  curl -fsSL -o cosign https://github.com/sigstore/cosign/releases/download/v${COSIGN}/cosign-linux-amd64; \
  chmod +x /out/*

# ---------- 3. runtime
FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    PT_ENV=production PT_DATA_DIR=/data PT_TOOLS_DIR=/opt/pt-tools PT_FRONTEND_DIR=/app/web
RUN useradd --system --uid 10001 --home /data pt && mkdir -p /data /opt/pt-tools && chown pt /data
WORKDIR /app
COPY backend/requirements.txt ./
RUN pip install -r requirements.txt
COPY --from=tools /out/ /opt/pt-tools/
COPY backend/ ./
COPY --from=web /web/out ./web
USER pt
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/api/health')"
# migrate once, then start workers with auto-migration disabled (avoids concurrent Alembic runs)
CMD ["sh", "-c", "alembic upgrade head && PT_AUTO_MIGRATE=false exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --workers 2"]
