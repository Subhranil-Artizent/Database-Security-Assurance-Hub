from __future__ import annotations

import os
import time
from pathlib import Path

from assurance_hub.collector import CollectorSettings, local_liveness, touch_liveness


def test_collector_local_liveness_is_dependency_independent():
    marker = Path(__file__).with_name(".collector-live-test")
    settings = CollectorSettings(
        tenant_id="tenant-alpha",
        development_auth=True,
        heartbeat_seconds=10,
        liveness_file=marker,
    )
    try:
        assert local_liveness(settings) == 1
        touch_liveness(settings)
        assert local_liveness(settings) == 0
        stale = time.time() - 60
        os.utime(marker, (stale, stale))
        assert local_liveness(settings) == 1
    finally:
        marker.unlink(missing_ok=True)
