from __future__ import annotations

import base64
import json
from datetime import datetime
from typing import Any

from sqlalchemy import and_, or_

from .errors import DomainError


def encode_cursor(created_at: datetime, resource_id: str) -> str:
    raw = json.dumps([created_at.isoformat(), resource_id], separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, str]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        timestamp, resource_id = json.loads(base64.urlsafe_b64decode(padded).decode())
        parsed = datetime.fromisoformat(timestamp)
        if len(resource_id) != 36:
            raise ValueError
        return parsed, resource_id
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise DomainError("invalid_cursor", "The pagination cursor is invalid", 422) from exc


def cursor_filter(model: Any, cursor: str) -> Any:
    created_at, resource_id = decode_cursor(cursor)
    return or_(
        model.created_at > created_at,
        and_(model.created_at == created_at, model.id > resource_id),
    )


def build_page(rows: list[Any], limit: int) -> tuple[list[Any], str | None]:
    has_more = len(rows) > limit
    items = rows[:limit]
    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = encode_cursor(last.created_at, last.id)
    return items, next_cursor
