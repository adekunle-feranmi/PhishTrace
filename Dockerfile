# syntax=docker/dockerfile:1
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PHISHTRACE_HOST=0.0.0.0 \
    PHISHTRACE_DATA_DIR=/data

RUN groupadd --gid 10001 phishtrace \
    && useradd --uid 10001 --gid phishtrace --home-dir /app --shell /usr/sbin/nologin phishtrace

WORKDIR /app

COPY pyproject.toml README.md ./
COPY phishtrace ./phishtrace
COPY config.yaml ./
COPY config ./config
COPY scripts/healthcheck.py ./scripts/healthcheck.py

RUN pip install --no-cache-dir . \
    && mkdir -p /data /app/data \
    && chown -R phishtrace:phishtrace /data /app

USER phishtrace

VOLUME ["/data"]
EXPOSE 8088

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "/app/scripts/healthcheck.py"]

ENTRYPOINT ["phishtrace"]
CMD ["serve"]
