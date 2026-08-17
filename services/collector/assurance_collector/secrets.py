from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
from typing import Protocol

from pydantic import ValidationError

from .models import SourceCredential


class SecretResolutionError(RuntimeError):
    """Raised without credential contents when secret resolution fails."""


class SecretResolver(Protocol):
    async def resolve(self, secret_ref: str) -> SourceCredential: ...


class MountedJsonSecretResolver:
    """Resolve a vault-projected JSON secret by an opaque reference digest."""

    def __init__(self, root: Path, *, require_private_mode: bool = True) -> None:
        self._root = root.resolve()
        self._require_private_mode = require_private_mode

    async def resolve(self, secret_ref: str) -> SourceCredential:
        return await asyncio.to_thread(self._read, secret_ref)

    def path_for(self, secret_ref: str) -> Path:
        digest = hashlib.sha256(secret_ref.encode("utf-8")).hexdigest()
        path = (self._root / f"{digest}.json").resolve()
        if path.parent != self._root:
            raise SecretResolutionError("resolved credential path escaped its mounted root")
        return path

    def _read(self, secret_ref: str) -> SourceCredential:
        path = self.path_for(secret_ref)
        try:
            stat = path.stat()
            if stat.st_size > 65_536:
                raise SecretResolutionError("projected credential file exceeds 64 KiB")
            if self._require_private_mode and os.name != "nt" and stat.st_mode & 0o077:
                raise SecretResolutionError("projected credential file permissions are too broad")
            payload = json.loads(path.read_text(encoding="utf-8"))
            return SourceCredential.model_validate(payload)
        except SecretResolutionError:
            raise
        except (OSError, json.JSONDecodeError, ValidationError) as exc:
            raise SecretResolutionError("projected credential could not be resolved") from exc
