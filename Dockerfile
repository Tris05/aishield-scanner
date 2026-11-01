
# syntax=docker/dockerfile:1

# --------------------------------------------------
# Stage 1: Trivy scanner binary
# --------------------------------------------------
FROM aquasec/trivy:0.75.0 AS trivy


# --------------------------------------------------
# Stage 2: Build Gitleaks only
# --------------------------------------------------

FROM golang:1.27.2-alpine AS tools-builder

ARG GITLEAKS_VERSION=v8.30.1

RUN apk add --no-cache git

RUN set -eux; \
    git clone --depth 1 --branch "${GITLEAKS_VERSION}" \
      https://github.com/gitleaks/gitleaks.git /src/gitleaks; \
    cd /src/gitleaks; \
    go get \
      golang.org/x/crypto@v0.55.0 \
      golang.org/x/text@v0.41.0; \
    go mod tidy; \
    mkdir -p /out; \
    CGO_ENABLED=0 go build \
      -trimpath \
      -ldflags="-s -w" \
      -o /out/gitleaks \
      .


# --------------------------------------------------
# Stage 2b: Obtain the official OSV-Scanner release
# --------------------------------------------------
FROM debian:trixie-slim AS osv-downloader

ARG OSV_SCANNER_VERSION=2.6.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/osv

RUN set -eux; \
    curl -fsSL \
      "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" \
      -o /tmp/osv/osv-scanner; \
    chmod 0755 /tmp/osv/osv-scanner

# --------------------------------------------------
# Stage 3: Minimal Python runtime
# --------------------------------------------------
FROM python:3.12.15-slim-trixie AS runtime

ARG DEBIAN_FRONTEND=noninteractive

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/opt/aishield \
    AISECURITY_RULES_FILE=/opt/aishield/rules/ai-security.yml

WORKDIR /opt/aishield

# Install only required runtime OS packages.
# Node.js/npm are excluded unless a runtime check explicitly needs them.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
       ca-certificates \
       git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy pinned scanner binaries into the runtime image.
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=tools-builder /out/gitleaks /usr/local/bin/gitleaks
COPY --from=osv-downloader /tmp/osv/osv-scanner /usr/local/bin/osv-scanner
# Install Python dependencies.
COPY requirements.txt /opt/aishield/requirements.txt

RUN python -m pip install \
    --no-cache-dir \
    --requirement /opt/aishield/requirements.txt

# Copy the application.
COPY aishield /opt/aishield/aishield
COPY rules /opt/aishield/rules
COPY policy /opt/aishield/policy

# Create a non-root runtime user and writable report directory.
RUN useradd \
      --create-home \
      --uid 10001 \
      --shell /usr/sbin/nologin \
      aishield \
    && mkdir -p /workspace/aishield-reports \
    && chown -R aishield:aishield /workspace \
    && chmod -R a-w /opt/aishield

WORKDIR /workspace

USER 10001:10001

ENTRYPOINT []
CMD ["python", "-m", "aishield.pipeline"]
