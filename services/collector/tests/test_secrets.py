from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from assurance_collector.secrets import MountedJsonSecretResolver, SecretResolutionError


@pytest.mark.asyncio
async def test_secret_reference_maps_to_opaque_projected_file(tmp_path: Path) -> None:
    reference = "vault://database/app#reader"
    digest = hashlib.sha256(reference.encode()).hexdigest()
    secret_path = tmp_path / f"{digest}.json"
    secret_path.write_text(
        json.dumps({"username": "reader", "password": "secret", "ca_file": "ca.pem"}),
        encoding="utf-8",
    )
    resolver = MountedJsonSecretResolver(tmp_path, require_private_mode=False)
    credential = await resolver.resolve(reference)
    assert credential.username == "reader"
    assert credential.password.get_secret_value() == "secret"
    assert reference not in str(resolver.path_for(reference))


@pytest.mark.asyncio
async def test_secret_resolution_never_echoes_invalid_secret(tmp_path: Path) -> None:
    reference = "vault://database/app#reader"
    digest = hashlib.sha256(reference.encode()).hexdigest()
    (tmp_path / f"{digest}.json").write_text(
        '{"username":"reader","password":"super-sensitive"}', encoding="utf-8"
    )
    resolver = MountedJsonSecretResolver(tmp_path, require_private_mode=False)
    with pytest.raises(SecretResolutionError) as captured:
        await resolver.resolve(reference)
    assert "super-sensitive" not in str(captured.value)
