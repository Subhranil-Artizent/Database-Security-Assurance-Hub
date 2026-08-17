from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import cast

from fastapi import HTTPException, Request, Response
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, StreamingResponse

from .auth import Identity, resolve_identity
from .logging import request_id_context
from .models import AuditEvent, IdempotencyRecord
from .observability import record_governance_write_failure, record_request

logger = logging.getLogger(__name__)
MUTATION_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")


def error_response(request: Request, code: str, message: str, status_code: int) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "details": None,
                "request_id": getattr(request.state, "request_id", "-"),
            }
        },
    )


def authorization_hash(identity: Identity) -> str:
    role_set = ",".join(sorted(identity.roles))
    return hashlib.sha256(f"{identity.subject}\0{role_set}".encode()).hexdigest()


class CorrelationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        supplied = request.headers.get("X-Request-ID", "")
        request_id = supplied if REQUEST_ID.fullmatch(supplied) else str(uuid.uuid4())
        request.state.request_id = request_id
        token = request_id_context.set(request_id)
        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            request_id_context.reset(token)


class RequestMetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        started = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - started
        route = request.scope.get("route")
        route_path = getattr(route, "path", request.url.path)
        record_request(request.method, route_path, response.status_code, duration)
        logger.info(
            "request completed",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": round(duration * 1000, 2),
                "event": "http.request",
            },
        )
        return response


class IdempotencyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method not in MUTATION_METHODS:
            return await call_next(request)

        key = request.headers.get("Idempotency-Key", "")
        if not IDEMPOTENCY_KEY.fullmatch(key):
            return error_response(
                request,
                "idempotency_key_required",
                "Mutations require an Idempotency-Key of 8 to 128 safe characters",
                400,
            )
        try:
            identity = await resolve_identity(request)
        except HTTPException as exc:
            return error_response(
                request, "authentication_failed", str(exc.detail), exc.status_code
            )

        body = await request.body()
        if len(body) > 2 * 1024 * 1024:
            return error_response(request, "payload_too_large", "Payload exceeds 2 MiB", 413)
        digest = hashlib.sha256(body).hexdigest()
        authz_hash = authorization_hash(identity)
        database = request.app.state.database
        settings = request.app.state.settings
        now = datetime.now(UTC)
        record = IdempotencyRecord(
            tenant_id=identity.tenant_id,
            actor_subject=identity.subject,
            authorization_hash=authz_hash,
            method=request.method,
            path=request.url.path,
            idempotency_key=key,
            request_hash=digest,
            expires_at=now + timedelta(hours=settings.idempotency_ttl_hours),
        )
        async with database.session_factory() as session:
            session.info["tenant_id"] = identity.tenant_id
            # Pending may mean the mutation committed immediately before a crash.
            # Expiring it would permit an unsafe replay, so automatic garbage
            # collection is restricted to completed reservations.
            await session.execute(
                delete(IdempotencyRecord).where(
                    IdempotencyRecord.state == "completed",
                    IdempotencyRecord.expires_at < now,
                )
            )
            session.add(record)
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                existing = await session.scalar(
                    select(IdempotencyRecord).where(
                        IdempotencyRecord.tenant_id == identity.tenant_id,
                        IdempotencyRecord.actor_subject == identity.subject,
                        IdempotencyRecord.authorization_hash == authz_hash,
                        IdempotencyRecord.method == request.method,
                        IdempotencyRecord.path == request.url.path,
                        IdempotencyRecord.idempotency_key == key,
                    )
                )
                if existing is None:
                    return error_response(request, "idempotency_conflict", "Retry request", 409)
                if existing.request_hash != digest:
                    return error_response(
                        request,
                        "idempotency_payload_mismatch",
                        "The key was already used with a different payload",
                        409,
                    )
                if existing.state == "review_required":
                    return error_response(
                        request,
                        "idempotency_recovery_required",
                        "The original outcome is uncertain and requires administrator review",
                        409,
                    )
                if existing.state != "completed" or existing.response_status is None:
                    return error_response(
                        request,
                        "idempotency_in_progress",
                        "A request with this key is in progress",
                        409,
                    )
                response = Response(
                    content=existing.response_body or "",
                    status_code=existing.response_status,
                    media_type=existing.response_content_type or "application/json",
                )
                response.headers["Idempotent-Replayed"] = "true"
                return response

        try:
            response = await call_next(request)
            stream = cast(StreamingResponse, response)
            chunks: list[bytes] = []
            async for chunk in stream.body_iterator:
                chunks.append(chunk.encode() if isinstance(chunk, str) else bytes(chunk))
            response_body = b"".join(chunks)
        except Exception:
            # Preserve the pending reservation: the handler might have committed its
            # domain transaction before response generation failed.
            raise

        if response.status_code < 500:
            await self._complete_and_audit(
                request,
                identity,
                key,
                response.status_code,
                response_body,
                response.headers.get("content-type"),
            )
        # Likewise, retain 5xx reservations until an operator resolves them through
        # an audited recovery workflow.

        headers = {
            key: value for key, value in response.headers.items() if key.lower() != "content-length"
        }
        return Response(
            content=response_body,
            status_code=response.status_code,
            headers=headers,
            background=response.background,
        )

    async def _complete_and_audit(
        self,
        request: Request,
        identity: Identity,
        key: str,
        status_code: int,
        body: bytes,
        content_type: str | None,
    ) -> None:
        resource_id: str | None = None
        try:
            decoded = json.loads(body)
            if isinstance(decoded, dict) and isinstance(decoded.get("id"), str):
                resource_id = decoded["id"]
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
        authz_hash = authorization_hash(identity)
        async with request.app.state.database.session_factory() as session:
            session.info["tenant_id"] = identity.tenant_id
            record = await session.scalar(
                select(IdempotencyRecord).where(
                    IdempotencyRecord.tenant_id == identity.tenant_id,
                    IdempotencyRecord.actor_subject == identity.subject,
                    IdempotencyRecord.authorization_hash == authz_hash,
                    IdempotencyRecord.method == request.method,
                    IdempotencyRecord.path == request.url.path,
                    IdempotencyRecord.idempotency_key == key,
                )
            )
            if record is not None:
                record.state = "completed"
                record.response_status = status_code
                record.response_body = body.decode(errors="replace")
                record.response_content_type = content_type
            session.add(
                AuditEvent(
                    tenant_id=identity.tenant_id,
                    actor=identity.subject,
                    action=f"{request.method} {request.url.path}",
                    resource_type=request.url.path.rstrip("/").split("/")[-1] or "root",
                    resource_id=resource_id,
                    request_id=request.state.request_id,
                    source_ip=request.client.host if request.client else None,
                    outcome="success" if status_code < 400 else "rejected",
                    attributes={
                        "status_code": status_code,
                        "idempotency_key_hash": hashlib.sha256(key.encode()).hexdigest(),
                    },
                )
            )
            try:
                await session.commit()
            except Exception:
                await session.rollback()
                record_governance_write_failure()
                logger.exception(
                    "failed to persist idempotency/audit outcome",
                    extra={"event": "governance.persistence_failed"},
                )
                # Governance records are part of the mutation contract. Failing closed
                # leaves the reservation pending, preventing an unsafe replay.
                raise
