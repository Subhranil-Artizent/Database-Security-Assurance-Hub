# syntax=docker/dockerfile:1.7

ARG PYTHON_VERSION=3.12

FROM python:${PYTHON_VERSION}-slim-trixie AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    VIRTUAL_ENV=/opt/venv
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

RUN python -m venv "${VIRTUAL_ENV}"
WORKDIR /build
COPY services/collector/ ./
# Database drivers are deliberately absent. A reviewed environment-specific
# image installs only the approved platform extras after version/licence tests.
RUN pip install --upgrade "pip>=26.1.2,<27" setuptools wheel \
    && pip install ".[observability]" \
    && pip uninstall -y setuptools wheel \
    && python -m pip uninstall -y pip

FROM python:${PYTHON_VERSION}-slim-trixie AS runtime

ARG APP_UID=10001
ARG APP_GID=10001
ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    COLLECTOR_ENVIRONMENT=production \
    COLLECTOR_ENABLE_LEASING=false \
    COLLECTOR_LIVENESS_FILE=/tmp/assurance-collector-live

RUN python -m pip uninstall -y setuptools wheel \
    && python -m pip uninstall -y pip

RUN groupadd --gid "${APP_GID}" app \
    && useradd --uid "${APP_UID}" --gid app --create-home --shell /usr/sbin/nologin app

COPY --from=builder --chown=app:app /opt/venv /opt/venv

WORKDIR /app
USER app
ENTRYPOINT ["assurance-collector"]
CMD ["run"]
