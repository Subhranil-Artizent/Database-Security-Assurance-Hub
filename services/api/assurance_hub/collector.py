from __future__ import annotations

import asyncio
import os
import socket
import sys
import time
from pathlib import Path
from typing import Any

import httpx
from pydantic import BaseModel, Field

DEFAULT_LIVENESS_FILE = "/tmp/assurance-collector-live"  # noqa: S108 - isolated container


class CollectorSettings(BaseModel):
    api_url: str = Field(default="http://api:8000")
    collector_id: str = Field(default_factory=socket.gethostname)
    tenant_id: str
    bearer_token: str | None = None
    development_auth: bool = False
    heartbeat_seconds: int = Field(default=30, ge=10, le=3600)
    enable_leasing: bool = False
    liveness_file: Path = Path(DEFAULT_LIVENESS_FILE)

    @classmethod
    def from_environment(cls) -> CollectorSettings:
        return cls(
            api_url=os.getenv(
                "ASSURANCE_API_URL", os.getenv("API_BASE_URL", "http://api:8000")
            ).rstrip("/"),
            collector_id=os.getenv("COLLECTOR_ID", socket.gethostname()),
            tenant_id=os.environ.get("TENANT_ID", ""),
            bearer_token=os.getenv("COLLECTOR_BEARER_TOKEN", os.getenv("COLLECTOR_TOKEN")),
            development_auth=os.getenv("COLLECTOR_DEVELOPMENT_AUTH", "false").lower() == "true",
            heartbeat_seconds=int(os.getenv("COLLECTOR_HEARTBEAT_SECONDS", "30")),
            enable_leasing=os.getenv("COLLECTOR_ENABLE_LEASING", "false").lower() == "true",
            liveness_file=Path(os.getenv("COLLECTOR_LIVENESS_FILE", DEFAULT_LIVENESS_FILE)),
        )

    def headers(self) -> dict[str, str]:
        if self.bearer_token:
            return {"Authorization": f"Bearer {self.bearer_token}"}
        if self.development_auth:
            return {
                "X-Tenant-ID": self.tenant_id,
                "X-Subject": self.collector_id,
                "X-Roles": "collector",
            }
        raise ValueError("collector authentication is not configured")


async def health(settings: CollectorSettings) -> int:
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(f"{settings.api_url}/health/ready")
        return 0 if response.status_code == 200 and response.json().get("status") == "ok" else 1
    except (httpx.HTTPError, ValueError):
        return 1


def local_liveness(settings: CollectorSettings) -> int:
    """Dependency-free process heartbeat used by the container liveness probe."""
    try:
        age = time.time() - settings.liveness_file.stat().st_mtime
        return 0 if age <= max(30, settings.heartbeat_seconds * 3) else 1
    except OSError:
        return 1


def touch_liveness(settings: CollectorSettings) -> None:
    settings.liveness_file.parent.mkdir(parents=True, exist_ok=True)
    settings.liveness_file.write_text(str(os.getpid()), encoding="ascii")


async def run(settings: CollectorSettings) -> None:
    headers = settings.headers()
    async with httpx.AsyncClient(base_url=settings.api_url, headers=headers, timeout=15) as client:
        while True:
            touch_liveness(settings)
            heartbeat: dict[str, Any] = {
                "collector_id": settings.collector_id,
                "version": "0.1.0",
                "capabilities": ["inventory", "control_assessment", "access_review"],
            }
            heartbeat_key = (
                f"heartbeat-{settings.collector_id}-{int(asyncio.get_running_loop().time())}"
            )
            response = await client.post(
                "/api/v1/collectors/heartbeat",
                json=heartbeat,
                headers={"Idempotency-Key": heartbeat_key},
            )
            response.raise_for_status()
            # Leasing is opt-in until a platform driver is deployed. This avoids claiming
            # jobs on a collector that cannot safely execute its allowlisted probes.
            if settings.enable_leasing:
                lease_key = (
                    f"lease-{settings.collector_id}-{int(asyncio.get_running_loop().time())}"
                )
                lease = await client.post(
                    "/api/v1/scan-jobs/lease",
                    json={
                        "collector_id": settings.collector_id,
                        "supported_job_types": ["inventory", "control_assessment", "access_review"],
                    },
                    headers={"Idempotency-Key": lease_key},
                )
                lease.raise_for_status()
            await asyncio.sleep(settings.heartbeat_seconds)


def main() -> None:
    try:
        settings = CollectorSettings.from_environment()
        if settings.development_auth and len(settings.tenant_id.strip()) < 1:
            raise ValueError("TENANT_ID is required for development authentication")
        if len(sys.argv) > 1 and sys.argv[1] == "live":
            raise SystemExit(local_liveness(settings))
        if len(sys.argv) > 1 and sys.argv[1] == "health":
            raise SystemExit(asyncio.run(health(settings)))
        asyncio.run(run(settings))
    except (ValueError, httpx.HTTPError) as exc:
        print(f"collector startup failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
