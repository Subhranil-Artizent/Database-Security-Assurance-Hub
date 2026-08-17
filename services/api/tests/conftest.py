from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from assurance_hub.config import Settings
from assurance_hub.main import create_app


@pytest.fixture
def client():
    settings = Settings(
        environment="test",
        database_url="sqlite+aiosqlite:///:memory:",
        auth_mode="development",
        allow_insecure_dev_auth=True,
        seed_demo_data=False,
        job_reconcile_interval_seconds=3600,
        enable_metrics=True,
    )
    app = create_app(settings)
    app.state.test_crash_calls = 0

    @app.post("/test/crash-after-side-effect")
    async def crash_after_side_effect():
        app.state.test_crash_calls += 1
        raise RuntimeError("synthetic post-commit failure")

    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.fixture
def tenant_headers():
    return {
        "X-Tenant-ID": "tenant-alpha",
        "X-Subject": "analyst@example.com",
        "X-Roles": "security_analyst",
    }


def mutation_headers(base: dict[str, str], key: str) -> dict[str, str]:
    return {**base, "Idempotency-Key": key}
