from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated

import anyio
import jwt
from fastapi import Depends, HTTPException, Request, status
from jwt import PyJWKClient

from .config import Settings
from .logging import tenant_id_context


@dataclass(frozen=True, slots=True)
class Identity:
    subject: str
    tenant_id: str
    roles: frozenset[str]


def _valid_identifier(value: str, field: str, max_length: int = 160) -> str:
    value = value.strip()
    if not value or len(value) > max_length or any(char in value for char in "\r\n\0"):
        raise HTTPException(status_code=401, detail=f"invalid {field}")
    return value


async def resolve_identity(request: Request) -> Identity:
    existing = getattr(request.state, "identity", None)
    if isinstance(existing, Identity):
        return existing

    settings: Settings = request.app.state.settings
    if settings.dev_auth_enabled:
        tenant = _valid_identifier(request.headers.get("X-Tenant-ID", ""), "tenant", 64)
        subject = _valid_identifier(request.headers.get("X-Subject", "developer"), "subject")
        roles = frozenset(
            role.strip()
            for role in request.headers.get("X-Roles", "viewer").split(",")
            if role.strip()
        )
        identity = Identity(subject=subject, tenant_id=tenant, roles=roles)
    else:
        if settings.auth_mode != "oidc" or not settings.oidc_configured:
            raise HTTPException(status_code=503, detail="OIDC authentication is not configured")
        authorization = request.headers.get("Authorization", "")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise HTTPException(status_code=401, detail="bearer token required")
        try:
            jwks: PyJWKClient | None = request.app.state.jwks_client
            if jwks is None:
                raise HTTPException(status_code=503, detail="OIDC key service is not configured")
            signing_key = await anyio.to_thread.run_sync(jwks.get_signing_key_from_jwt, token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256", "ES256"],
                audience=settings.oidc_audience,
                issuer=settings.oidc_issuer,
                options={"require": ["exp", "iat", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise HTTPException(status_code=401, detail="invalid bearer token") from exc
        tenant_claim = claims.get(settings.oidc_tenant_claim)
        roles_claim = claims.get(settings.oidc_roles_claim, [])
        if isinstance(roles_claim, str):
            roles_claim = roles_claim.split()
        if not isinstance(roles_claim, list):
            raise HTTPException(status_code=401, detail="invalid roles claim")
        identity = Identity(
            subject=_valid_identifier(str(claims["sub"]), "subject"),
            tenant_id=_valid_identifier(str(tenant_claim or ""), "tenant", 64),
            roles=frozenset(str(role) for role in roles_claim),
        )

    request.state.identity = identity
    tenant_id_context.set(identity.tenant_id)
    return identity


CurrentIdentity = Annotated[Identity, Depends(resolve_identity)]


def require_roles(*allowed: str) -> Callable[[Identity], Awaitable[Identity]]:
    async def dependency(identity: CurrentIdentity) -> Identity:
        if not identity.roles.intersection(allowed):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="insufficient role for this operation",
            )
        return identity

    return dependency


WriterIdentity = Annotated[
    Identity, Depends(require_roles("admin", "security_analyst", "database_owner"))
]
AnalystIdentity = Annotated[Identity, Depends(require_roles("admin", "security_analyst"))]
CollectorIdentity = Annotated[Identity, Depends(require_roles("admin", "collector"))]
AuditIdentity = Annotated[Identity, Depends(require_roles("admin", "security_analyst", "auditor"))]
AdminIdentity = Annotated[Identity, Depends(require_roles("admin"))]
ExceptionApproverIdentity = Annotated[
    Identity, Depends(require_roles("admin", "exception_approver"))
]
IntegrationIdentity = Annotated[Identity, Depends(require_roles("admin", "integration_worker"))]
