from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from jwt import PyJWKClient
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from .api import health_router, router
from .config import Settings, get_settings
from .db import Database
from .errors import DomainError
from .governance_api import router as governance_router
from .logging import configure_logging
from .middleware import CorrelationMiddleware, IdempotencyMiddleware, RequestMetricsMiddleware
from .observability import configure_telemetry, metric_payload
from .reconciler import reconciliation_loop
from .seed import seed_demo

logger = logging.getLogger(__name__)


def envelope(request: Request, code: str, message: str, details: Any = None) -> dict[str, Any]:
    return {
        "error": {
            "code": code,
            "message": message,
            "details": details,
            "request_id": getattr(request.state, "request_id", "-"),
        }
    }


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)
    database = Database(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        settings.validate_runtime()
        if settings.environment in {"development", "test"}:
            await database.create_all_for_test_or_dev()
        if settings.seed_demo_data and settings.environment != "production":
            await seed_demo(database)
        reconcile_task = asyncio.create_task(
            reconciliation_loop(
                database,
                settings.job_reconcile_interval_seconds,
                settings.job_reconcile_batch_size,
            ),
            name="stale-job-reconciler",
        )
        try:
            yield
        finally:
            reconcile_task.cancel()
            with suppress(asyncio.CancelledError):
                await reconcile_task
            await database.dispose()

    app = FastAPI(
        title="Database Security Assurance API",
        version=settings.service_version,
        description="Tenant-isolated database security posture and assurance control plane.",
        docs_url=None if settings.environment == "production" else "/docs",
        redoc_url=None if settings.environment == "production" else "/redoc",
        openapi_url=None if settings.environment == "production" else "/openapi.json",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.database = database
    app.state.jwks_client = (
        PyJWKClient(
            settings.oidc_jwks_url or "",
            cache_keys=True,
            max_cached_keys=16,
            cache_jwk_set=True,
            lifespan=300,
            timeout=5,
        )
        if settings.oidc_configured
        else None
    )

    if settings.cors_origins:
        if "*" in settings.cors_origins and settings.environment == "production":
            raise ValueError("Wildcard CORS is forbidden in production")
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=False,
            allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
            allow_headers=[
                "Authorization",
                "Content-Type",
                "Idempotency-Key",
                "X-Request-ID",
            ],
            expose_headers=["X-Request-ID", "Idempotent-Replayed"],
        )
    app.add_middleware(IdempotencyMiddleware)
    app.add_middleware(RequestMetricsMiddleware)
    app.add_middleware(CorrelationMiddleware)

    app.include_router(health_router)
    app.include_router(router, prefix=settings.api_prefix)
    app.include_router(governance_router, prefix=settings.api_prefix)

    if settings.enable_metrics:

        @app.get("/metrics", include_in_schema=False)
        async def metrics() -> Response:
            payload, content_type = metric_payload()
            return Response(content=payload, media_type=content_type)

    @app.exception_handler(DomainError)
    async def handle_domain_error(request: Request, exc: DomainError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=envelope(request, exc.code, exc.message, exc.details),
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        details = [
            {"location": list(error["loc"]), "message": error["msg"], "type": error["type"]}
            for error in exc.errors()
        ]
        return JSONResponse(
            status_code=422,
            content=envelope(request, "validation_failed", "Request validation failed", details),
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        codes = {
            401: "authentication_failed",
            403: "forbidden",
            404: "resource_not_found",
            405: "method_not_allowed",
        }
        return JSONResponse(
            status_code=exc.status_code,
            content=envelope(
                request,
                codes.get(exc.status_code, "http_error"),
                str(exc.detail),
            ),
            headers=exc.headers,
        )

    @app.exception_handler(SQLAlchemyError)
    async def handle_database_error(request: Request, exc: SQLAlchemyError) -> JSONResponse:
        logger.exception("database operation failed", exc_info=exc)
        return JSONResponse(
            status_code=503,
            content=envelope(
                request,
                "database_unavailable",
                "The persistence service is temporarily unavailable",
            ),
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled request failure", exc_info=exc)
        return JSONResponse(
            status_code=500,
            content=envelope(request, "internal_error", "An unexpected error occurred"),
        )

    configure_telemetry(app, database.engine, settings.otel_exporter_otlp_endpoint)
    return app


app = create_app()
