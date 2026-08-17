# syntax=docker/dockerfile:1.7

ARG PYTHON_VERSION=3.12

FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    VIRTUAL_ENV=/opt/venv
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

RUN python -m venv "${VIRTUAL_ENV}"
WORKDIR /build
COPY services/api/ ./
RUN pip install --upgrade "pip>=26.1.2,<27" setuptools wheel \
    && pip install ".[postgres,observability]"

FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

ARG APP_UID=10001
ARG APP_GID=10001
ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    PORT=8000

RUN python -m pip install --no-cache-dir --upgrade "pip>=26.1.2,<27"

RUN groupadd --gid "${APP_GID}" app \
    && useradd --uid "${APP_UID}" --gid app --create-home --shell /usr/sbin/nologin app

COPY --from=builder --chown=app:app /opt/venv /opt/venv
COPY --from=builder --chown=app:app /build /app

WORKDIR /app
USER app
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=3)"]

CMD ["uvicorn", "assurance_hub.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
