from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal, cast

from fastapi import APIRouter, Depends, Query, Request, Response, status
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .access_security import reconcile_mysql_access_review
from .auth import (
    AdminIdentity,
    AnalystIdentity,
    AuditIdentity,
    CollectorIdentity,
    CurrentIdentity,
    WriterIdentity,
)
from .dependencies import PaginationDep, SessionDep
from .discovery import discovered_column
from .errors import ConflictError, DomainError, LeaseConflictError, NotFoundError
from .governance import orchestrate_assessment_after_job
from .models import (
    AccessReview,
    Assessment,
    AssessmentStatus,
    Asset,
    AssetEnvironment,
    AuditEvent,
    Connector,
    ControlDefinition,
    ControlPackStatus,
    ControlPackVersion,
    DatabasePlatform,
    Evidence,
    Finding,
    FindingStatus,
    IdempotencyRecord,
    LifecycleStatus,
    MaskingPolicy,
    ScanJob,
    WorkStatus,
)
from .observability import (
    record_evidence_ingested,
    record_idempotency_recovery,
    record_job_completed,
    record_job_created,
    record_job_leased,
    record_lease_fencing_rejection,
)
from .pagination import build_page, cursor_filter, decode_cursor
from .query_catalog import validate_probe_ids
from .schemas import (
    AccessReviewCreate,
    AccessReviewOut,
    AccessReviewUpdate,
    AssessmentCreate,
    AssessmentOut,
    AssetCreate,
    AssetOut,
    AuditEventOut,
    CollectorLeaseOut,
    CollectorReadyOut,
    ConnectorConfigUpdate,
    ConnectorCreate,
    ConnectorOut,
    ConnectorRuntimeConfigOut,
    DashboardSummary,
    EvidenceCreate,
    EvidenceOut,
    FindingCreate,
    FindingOut,
    FindingUpdate,
    HealthResponse,
    HeartbeatRequest,
    HeartbeatResponse,
    IdempotencyRecoveryCandidate,
    IdempotencyRecoveryOut,
    IdempotencyRecoveryRequest,
    JobCompletionRequest,
    JobLeaseRenewRequest,
    JobLeaseRequest,
    JobResult,
    MaskingCopyJobPayload,
    MaskingCopyResult,
    MaskingPolicyCreate,
    MaskingPolicyOut,
    MaskingPolicyTransition,
    Page,
    ScanJobCreate,
    ScanJobOut,
    ScanJobPayload,
    SensitiveColumnOut,
)

router = APIRouter()
health_router = APIRouter()

MASKING_COPY_JOB_TYPE = "masking_copy"
MASKING_COPY_CAPABILITY = "masking_copy"
MASKING_COPY_COLLECTOR_ID = "local-mysql-masker"
MASKING_COPY_CONNECTOR_NAME = "local-mysql-insurance-sample-masking-copy"
MASKING_COPY_CONTROL_ID = "mysql.data-masking.governance-evidence"
MASKING_COPY_PACK_ID = "aegisdb.database-security.mysql"
MASKING_COPY_POLICY_NAME = "insurance_sample local masking plan"
MASKING_COPY_SOURCE_DATABASE: Literal["insurance_sample"] = "insurance_sample"
MASKING_COPY_TARGET_DATABASE: Literal["insurance_sample_masked"] = "insurance_sample_masked"
MASKING_COPY_TARGET_PREFIX = "insurance_sample_masked_"
MASKING_COPY_ROW_CAP: Literal[500] = 500
MASKING_COPY_CONNECTOR_SECRET_REF = (
    "vault://local/database/mysql-insurance-sample-masked#writer"  # noqa: S105 -- opaque ref
)
MASKING_COPY_DEDUPLICATION_PREFIX = "masking-copy:"
MASKING_COPY_ACTIVE_STATUSES = {
    WorkStatus.PENDING,
    WorkStatus.LEASED,
    WorkStatus.RUNNING,
}


def masking_copy_target_database(policy_id: str) -> str:
    try:
        suffix = uuid.UUID(policy_id).hex[:12]
    except ValueError as exc:
        raise DomainError(
            "masking_copy_policy_invalid",
            "The masking policy identifier cannot derive a local target",
            409,
        ) from exc
    return f"{MASKING_COPY_TARGET_PREFIX}{suffix}"


def policy_masking_target(policy: MaskingPolicy) -> str | None:
    stored = policy.parameters.get("target_database")
    if not isinstance(stored, str):
        return None
    if stored == masking_copy_target_database(policy.id):
        return stored
    if stored == MASKING_COPY_TARGET_DATABASE and policy.name == MASKING_COPY_POLICY_NAME:
        return stored
    return None


def is_builtin_local_masking_policy(policy: MaskingPolicy) -> bool:
    parameters = policy.parameters
    return (
        policy.version == 1
        and policy.classification == "Restricted and confidential"
        and policy.strategy == "substitute"
        and policy.target_environment == AssetEnvironment.DEVELOPMENT
        and parameters.get("source_asset") == MASKING_COPY_SOURCE_DATABASE
        and policy_masking_target(policy) is not None
        and (
            parameters.get("local_copy_plan") is True
            or policy.name == MASKING_COPY_POLICY_NAME
        )
    )


def is_dedicated_masking_connector(connector: Connector) -> bool:
    return (
        connector.name == MASKING_COPY_CONNECTOR_NAME
        and connector.platform == DatabasePlatform.MYSQL
        and connector.collector_id == MASKING_COPY_COLLECTOR_ID
        and MASKING_COPY_CAPABILITY in connector.capabilities
        and connector.config.get("enabled", True) is not False
        and connector.secret_ref == MASKING_COPY_CONNECTOR_SECRET_REF
        and is_local_mysql_endpoint(connector.endpoint_ref)
    )


def is_local_mysql_endpoint(endpoint_ref: str) -> bool:
    prefix = "dns://"
    if not endpoint_ref.startswith(prefix):
        return False
    authority, separator, database = endpoint_ref[len(prefix) :].partition("/")
    host, port_separator, raw_port = authority.rpartition(":")
    if separator != "/" or port_separator != ":" or database != MASKING_COPY_SOURCE_DATABASE:
        return False
    try:
        port = int(raw_port)
    except ValueError:
        return False
    return host in {"localhost", "127.0.0.1"} and 1 <= port <= 65535


def masking_copy_deduplication_key(policy_id: str, target_database: str) -> str:
    """Return the one durable queue slot for one policy-derived target."""
    return f"{MASKING_COPY_DEDUPLICATION_PREFIX}{policy_id}:{target_database}"


def validate_masking_copy_job_binding(
    job: ScanJob, *, policy_id: str, asset_id: str, connector_id: str
) -> MaskingCopyJobPayload:
    try:
        stored = MaskingCopyJobPayload.model_validate(job.payload)
    except ValueError as exc:
        raise DomainError(
            "stored_job_contract_invalid",
            "The masking-copy payload is invalid",
            409,
        ) from exc
    if (
        job.job_type != MASKING_COPY_JOB_TYPE
        or stored.policy_id != policy_id
        or stored.asset_id != asset_id
        or job.connector_id != connector_id
    ):
        raise DomainError(
            "stored_job_contract_invalid",
            "The masking-copy job is bound to different resources",
            409,
        )
    return stored


async def serialize_sqlite_masking_copy_queue(request: Request) -> AsyncIterator[None]:
    """Compensate for SQLite's lack of row-level ``FOR UPDATE`` in local development."""
    if request.app.state.database.engine.dialect.name != "sqlite":
        yield
        return
    lock = getattr(request.app.state, "masking_copy_queue_lock", None)
    if not isinstance(lock, asyncio.Lock):
        lock = asyncio.Lock()
        request.app.state.masking_copy_queue_lock = lock
    async with lock:
        yield


MaskingCopyQueueGuard = Annotated[None, Depends(serialize_sqlite_masking_copy_queue)]


def as_utc(value: datetime) -> datetime:
    """Normalize timestamps returned without timezone metadata by SQLite."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


async def tenant_get[ModelT](
    session: AsyncSession,
    model: type[ModelT],
    resource_id: str,
    tenant_id: str,
    resource: str,
    *,
    for_update: bool = False,
) -> ModelT:
    columns = cast(Any, model)
    statement = select(model).where(columns.id == resource_id, columns.tenant_id == tenant_id)
    if for_update:
        statement = statement.with_for_update()
    instance = await session.scalar(statement)
    if instance is None:
        raise NotFoundError(resource, resource_id)
    return instance


async def commit_or_conflict(session: AsyncSession, message: str) -> None:
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise ConflictError(message) from exc


def enforce_collector_identity(identity: Any, collector_id: str) -> None:
    if "admin" not in identity.roles and identity.subject != collector_id:
        raise DomainError(
            "collector_identity_mismatch",
            "Collector identity must match the requested collector ID",
            403,
        )


def page_response(rows: list[Any], limit: int, schema: type[Any]) -> Page[Any]:
    items, next_cursor = build_page(rows, limit)
    return Page(
        items=[schema.model_validate(item) for item in items], next_cursor=next_cursor, limit=limit
    )


async def list_tenant_resources(
    session: AsyncSession, model: type[Any], tenant_id: str, pagination: PaginationDep
) -> list[Any]:
    statement = (
        select(model)
        .where(model.tenant_id == tenant_id)
        .order_by(model.created_at.asc(), model.id.asc())
        .limit(pagination.limit + 1)
    )
    if pagination.cursor:
        statement = statement.where(cursor_filter(model, pagination.cursor))
    return list((await session.scalars(statement)).all())


async def reconcile_masking_copy_success(
    session: AsyncSession,
    *,
    job: ScanJob,
    requested: MaskingCopyJobPayload,
    result: MaskingCopyResult,
    now: datetime,
) -> None:
    """Record aggregate proof without making an assurance decision or score."""
    policy = await tenant_get(
        session,
        MaskingPolicy,
        requested.policy_id,
        job.tenant_id,
        "masking policy",
        for_update=True,
    )
    if (
        not is_builtin_local_masking_policy(policy)
        or not policy.enabled
        or policy.parameters.get("workflow_status") != "approved"
    ):
        raise DomainError(
            "masking_copy_policy_not_approved",
            "The local MySQL masking plan is no longer approved",
            409,
        )
    connector = await tenant_get(
        session, Connector, job.connector_id, job.tenant_id, "masking connector"
    )
    if connector.asset_id != requested.asset_id or not is_dedicated_masking_connector(connector):
        raise DomainError(
            "masking_copy_connector_invalid",
            "The masking-copy job is not bound to the dedicated local connector",
            409,
        )
    if job.assessment_id is None:
        raise DomainError(
            "masking_copy_assessment_missing",
            "The masking-copy job is not bound to an assessment awaiting review",
            409,
        )
    assessment = await tenant_get(
        session,
        Assessment,
        job.assessment_id,
        job.tenant_id,
        "assessment",
        for_update=True,
    )
    if (
        assessment.asset_id != requested.asset_id
        or assessment.control_pack != MASKING_COPY_PACK_ID
        or assessment.status != AssessmentStatus.REVIEW_REQUIRED
        or assessment.score is not None
    ):
        raise DomainError(
            "masking_copy_assessment_not_reviewable",
            "Masking evidence can only be attached to the active unscored MySQL review",
            409,
        )

    artifact_uri = f"evidence://local-masking/{job.id}"
    evidence = await session.scalar(
        select(Evidence).where(
            Evidence.tenant_id == job.tenant_id,
            Evidence.assessment_id == assessment.id,
            Evidence.control_id == MASKING_COPY_CONTROL_ID,
            Evidence.uri == artifact_uri,
        )
    )
    if evidence is None:
        evidence = Evidence(
            tenant_id=job.tenant_id,
            assessment_id=assessment.id,
            finding_id=None,
            control_id=MASKING_COPY_CONTROL_ID,
            evidence_type="artifact_reference",
            uri=artifact_uri,
            sha256=result.manifest_sha256,
            collected_at=now,
            collector_version="local-masker-v1",
            attributes={
                "job_id": job.id,
                "policy_id": policy.id,
                "source_database": result.source_database,
                "target_database": result.target_database,
                "tables_copied": result.tables_copied,
                "rows_copied": result.rows_copied,
                "columns_masked": result.columns_masked,
                "values_masked": result.values_masked,
                "row_cap": result.row_cap,
                "source_before_hmac": result.source_before_hmac,
                "source_after_hmac": result.source_after_hmac,
                "target_manifest_hmac": result.target_manifest_hmac,
                "key_fingerprint": result.key_fingerprint,
                "source_digest_match": result.source_digest_match,
                "target_counts_match": result.target_counts_match,
                "foreign_keys_valid": result.foreign_keys_valid,
                "raw_values_exported": result.raw_values_exported,
                "algorithm": result.algorithm,
                "automated_checks_passed": True,
            },
        )
        session.add(evidence)
        record_evidence_ingested("artifact_reference")
    elif evidence.sha256 != result.manifest_sha256:
        raise DomainError(
            "masking_copy_evidence_conflict",
            "The masking-copy job already has different aggregate evidence",
            409,
        )

    parameters = dict(policy.parameters)
    parameters.update(
        {
            "workflow_status": "execution_recorded",
            "execution_recorded_at": now.isoformat(),
            "execution_reference": artifact_uri,
            "execution_job_id": job.id,
            "copy_status": "automated_checks_passed",
            "automated_checks_passed": True,
            "tables_copied": result.tables_copied,
            "rows_copied": result.rows_copied,
            "columns_masked": result.columns_masked,
            "values_masked": result.values_masked,
            "target_database": result.target_database,
            "last_note": (
                "Local masking result created or exactly re-verified; "
                "analyst review is still required."
            ),
        }
    )
    policy.parameters = parameters


@health_router.get("/health/live", response_model=HealthResponse, tags=["platform"])
async def live(request: Request) -> HealthResponse:
    settings = request.app.state.settings
    return HealthResponse(
        status="ok", service=settings.service_name, version=settings.service_version
    )


@health_router.get("/health/ready", response_model=HealthResponse, tags=["platform"])
async def ready(request: Request, response: Response) -> HealthResponse:
    settings = request.app.state.settings
    checks: dict[str, str] = {}
    try:
        async with request.app.state.database.session_factory() as session:
            await session.execute(text("SELECT 1"))
        checks["database"] = "ok"
        return HealthResponse(
            status="ok",
            service=settings.service_name,
            version=settings.service_version,
            checks=checks,
        )
    except Exception:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        checks["database"] = "unavailable"
        return HealthResponse(
            status="unavailable",
            service=settings.service_name,
            version=settings.service_version,
            checks=checks,
        )


@router.get("/assets", response_model=Page[AssetOut], tags=["assets"])
async def list_assets(
    identity: CurrentIdentity, session: SessionDep, pagination: PaginationDep
) -> Page[AssetOut]:
    rows = await list_tenant_resources(session, Asset, identity.tenant_id, pagination)
    return page_response(rows, pagination.limit, AssetOut)


@router.post("/assets", response_model=AssetOut, status_code=201, tags=["assets"])
async def create_asset(
    payload: AssetCreate, identity: WriterIdentity, session: SessionDep
) -> Asset:
    asset = Asset(tenant_id=identity.tenant_id, **payload.model_dump())
    session.add(asset)
    await commit_or_conflict(session, "An asset with that external ID already exists")
    await session.refresh(asset)
    return asset


@router.get("/assets/{asset_id}", response_model=AssetOut, tags=["assets"])
async def get_asset(asset_id: str, identity: CurrentIdentity, session: SessionDep) -> Asset:
    return await tenant_get(session, Asset, asset_id, identity.tenant_id, "asset")


@router.get("/connectors", response_model=Page[ConnectorOut], tags=["connectors"])
async def list_connectors(
    identity: CurrentIdentity, session: SessionDep, pagination: PaginationDep
) -> Page[ConnectorOut]:
    rows = await list_tenant_resources(session, Connector, identity.tenant_id, pagination)
    return page_response(rows, pagination.limit, ConnectorOut)


@router.post("/connectors", response_model=ConnectorOut, status_code=201, tags=["connectors"])
async def create_connector(
    payload: ConnectorCreate, identity: AdminIdentity, session: SessionDep
) -> Connector:
    asset = await tenant_get(session, Asset, payload.asset_id, identity.tenant_id, "asset")
    if asset.platform != payload.platform:
        raise DomainError("platform_mismatch", "Connector and asset platforms must match", 422)
    connector = Connector(tenant_id=identity.tenant_id, **payload.model_dump())
    session.add(connector)
    await commit_or_conflict(session, "A connector with that name already exists")
    await session.refresh(connector)
    return connector


@router.patch(
    "/connectors/{connector_id}/config",
    response_model=ConnectorOut,
    tags=["connectors"],
)
async def update_connector_config(
    connector_id: str,
    payload: ConnectorConfigUpdate,
    identity: AdminIdentity,
    session: SessionDep,
) -> Connector:
    connector = await tenant_get(
        session,
        Connector,
        connector_id,
        identity.tenant_id,
        "connector",
        for_update=True,
    )
    connector.config = payload.config
    await session.commit()
    await session.refresh(connector)
    return connector


@router.get(
    "/collectors/connectors/{connector_id}/runtime-config",
    response_model=ConnectorRuntimeConfigOut,
    tags=["collectors"],
)
async def collector_runtime_config(
    connector_id: str,
    identity: CollectorIdentity,
    session: SessionDep,
) -> ConnectorRuntimeConfigOut:
    """Return secret *references* only to the collector assigned to this connector."""
    connector = await tenant_get(session, Connector, connector_id, identity.tenant_id, "connector")
    if "collector" not in identity.roles or connector.collector_id != identity.subject:
        # A not-found response avoids exposing connector assignment metadata.
        raise NotFoundError("connector", connector_id)
    if connector.config.get("enabled", True) is False:
        raise DomainError("connector_disabled", "The connector is disabled", 409)
    return ConnectorRuntimeConfigOut(
        connector_id=connector.id,
        platform=connector.platform,
        endpoint_ref=connector.endpoint_ref,
        secret_ref=connector.secret_ref,
        config=connector.config,
        updated_at=connector.updated_at,
    )


@router.post("/collectors/heartbeat", response_model=HeartbeatResponse, tags=["collectors"])
async def collector_heartbeat(
    payload: HeartbeatRequest, identity: CollectorIdentity, session: SessionDep, request: Request
) -> HeartbeatResponse:
    enforce_collector_identity(identity, payload.collector_id)
    now = datetime.now(UTC)
    connectors = list(
        (
            await session.scalars(
                select(Connector).where(
                    Connector.tenant_id == identity.tenant_id,
                    Connector.collector_id == payload.collector_id,
                )
            )
        ).all()
    )
    if not connectors:
        raise NotFoundError("collector registration", payload.collector_id)
    for connector in connectors:
        connector.last_heartbeat_at = now
        connector.status = (
            "online" if connector.config.get("enabled", True) is not False else "disabled"
        )
        connector.capabilities = sorted(set(connector.capabilities + payload.capabilities))
    await session.commit()
    return HeartbeatResponse(
        accepted=True,
        server_time=now,
        next_heartbeat_seconds=max(10, request.app.state.settings.job_reconcile_interval_seconds),
    )


@router.get("/collectors/ready", response_model=CollectorReadyOut, tags=["collectors"])
async def collector_ready(identity: CollectorIdentity) -> CollectorReadyOut:
    return CollectorReadyOut(collector_id=identity.subject)


@router.get("/assessments", response_model=Page[AssessmentOut], tags=["assessments"])
async def list_assessments(
    identity: CurrentIdentity, session: SessionDep, pagination: PaginationDep
) -> Page[AssessmentOut]:
    rows = await list_tenant_resources(session, Assessment, identity.tenant_id, pagination)
    return page_response(rows, pagination.limit, AssessmentOut)


@router.post("/assessments", response_model=AssessmentOut, status_code=201, tags=["assessments"])
async def create_assessment(
    payload: AssessmentCreate, identity: WriterIdentity, session: SessionDep
) -> Assessment:
    await tenant_get(session, Asset, payload.asset_id, identity.tenant_id, "asset")
    assessment = Assessment(
        tenant_id=identity.tenant_id, initiated_by=identity.subject, **payload.model_dump()
    )
    session.add(assessment)
    await session.commit()
    await session.refresh(assessment)
    return assessment


@router.get("/findings", response_model=Page[FindingOut], tags=["findings"])
async def list_findings(
    identity: CurrentIdentity,
    session: SessionDep,
    pagination: PaginationDep,
    finding_status: Annotated[FindingStatus | None, Query(alias="status")] = None,
) -> Page[FindingOut]:
    statement = (
        select(Finding)
        .where(Finding.tenant_id == identity.tenant_id)
        .order_by(Finding.created_at.asc(), Finding.id.asc())
        .limit(pagination.limit + 1)
    )
    if pagination.cursor:
        statement = statement.where(cursor_filter(Finding, pagination.cursor))
    if finding_status:
        statement = statement.where(Finding.status == finding_status)
    rows = list((await session.scalars(statement)).all())
    return page_response(rows, pagination.limit, FindingOut)


@router.post("/findings", response_model=FindingOut, status_code=201, tags=["findings"])
async def create_finding(
    payload: FindingCreate, identity: WriterIdentity, session: SessionDep
) -> Finding:
    assessment = await tenant_get(
        session, Assessment, payload.assessment_id, identity.tenant_id, "assessment"
    )
    await tenant_get(session, Asset, payload.asset_id, identity.tenant_id, "asset")
    if assessment.asset_id != payload.asset_id:
        raise DomainError("asset_mismatch", "Finding asset must match assessment asset", 422)
    finding = Finding(tenant_id=identity.tenant_id, **payload.model_dump())
    session.add(finding)
    await commit_or_conflict(session, "This control finding has already been reported")
    await session.refresh(finding)
    return finding


@router.patch("/findings/{finding_id}", response_model=FindingOut, tags=["findings"])
async def update_finding(
    finding_id: str,
    payload: FindingUpdate,
    identity: WriterIdentity,
    session: SessionDep,
) -> Finding:
    finding = await tenant_get(
        session,
        Finding,
        finding_id,
        identity.tenant_id,
        "finding",
        for_update=True,
    )
    if finding.status == FindingStatus.RISK_ACCEPTED:
        raise ConflictError(
            "A risk-accepted finding can only be changed by revoking its approved exception"
        )
    finding.status = payload.status
    finding.owner = payload.owner
    finding.due_at = payload.due_at
    finding.risk_context = {**finding.risk_context, "last_status_reason": payload.reason}
    await session.commit()
    await session.refresh(finding)
    return finding


@router.get("/evidence", response_model=Page[EvidenceOut], tags=["evidence"])
async def list_evidence(
    identity: CurrentIdentity,
    session: SessionDep,
    pagination: PaginationDep,
    assessment_id: Annotated[
        str | None,
        Query(
            min_length=36,
            max_length=36,
            pattern=(
                r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
                r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
            ),
        ),
    ] = None,
    control_id: Annotated[
        str | None,
        Query(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$"),
    ] = None,
) -> Page[EvidenceOut]:
    statement = (
        select(Evidence)
        .where(Evidence.tenant_id == identity.tenant_id)
        .order_by(Evidence.created_at.asc(), Evidence.id.asc())
        .limit(pagination.limit + 1)
    )
    if assessment_id is not None:
        statement = statement.where(Evidence.assessment_id == assessment_id)
    if control_id is not None:
        statement = statement.where(Evidence.control_id == control_id)
    if pagination.cursor:
        statement = statement.where(cursor_filter(Evidence, pagination.cursor))
    rows = list((await session.scalars(statement)).all())
    return page_response(rows, pagination.limit, EvidenceOut)


@router.get(
    "/sensitive-columns",
    response_model=Page[SensitiveColumnOut],
    tags=["discovery"],
)
async def list_sensitive_columns(
    identity: CurrentIdentity,
    session: SessionDep,
    pagination: PaginationDep,
) -> Page[SensitiveColumnOut]:
    """Return deterministic classifications derived only from collected column metadata."""
    rows = (
        await session.execute(
            select(ScanJob, Connector, Asset)
            .join(
                Connector,
                (Connector.id == ScanJob.connector_id)
                & (Connector.tenant_id == ScanJob.tenant_id),
            )
            .join(
                Asset,
                (Asset.id == Connector.asset_id) & (Asset.tenant_id == Connector.tenant_id),
            )
            .where(
                ScanJob.tenant_id == identity.tenant_id,
                ScanJob.status == WorkStatus.SUCCEEDED,
                ScanJob.job_type == "classification",
                Connector.platform == DatabasePlatform.MYSQL,
            )
            .order_by(ScanJob.completed_at.desc(), ScanJob.id.desc())
            .limit(50)
        )
    ).all()
    discovered = []
    seen: set[tuple[str, str, str, str]] = set()
    for job, _connector, asset in rows:
        try:
            result = JobResult.model_validate(job.result)
        except ValueError:
            continue
        collected_at = as_utc(job.completed_at or job.updated_at)
        for probe in result.probe_results:
            if probe.probe_id != "mysql.column_inventory" or probe.outcome != "collected":
                continue
            for observation in probe.observations:
                schema_name = observation.get("table_schema")
                table_name = observation.get("table_name")
                column_name = observation.get("column_name")
                column_type = observation.get("column_type") or observation.get("data_type")
                if not isinstance(schema_name, str) or not schema_name:
                    continue
                if not isinstance(table_name, str) or not table_name:
                    continue
                if not isinstance(column_name, str) or not column_name:
                    continue
                if not isinstance(column_type, str) or not column_type:
                    continue
                asset_id = str(asset.id)
                key = (asset_id, schema_name, table_name, column_name)
                if key in seen:
                    continue
                seen.add(key)
                item = discovered_column(
                    asset_id=asset_id,
                    asset_name=str(asset.name),
                    schema=schema_name,
                    table=table_name,
                    column=column_name,
                    data_type=column_type,
                    collected_at=collected_at,
                )
                if item is not None:
                    discovered.append(item)

    discovered.sort(key=lambda item: (item.created_at, item.id))
    if pagination.cursor:
        cursor_time, cursor_id = decode_cursor(pagination.cursor)
        cursor_time = as_utc(cursor_time)
        discovered = [
            item
            for item in discovered
            if (item.created_at, item.id) > (cursor_time, cursor_id)
        ]
    items, next_cursor = build_page(discovered, pagination.limit)
    return Page[SensitiveColumnOut](
        items=[
            SensitiveColumnOut(
                id=item.id,
                asset_id=item.asset_id,
                asset_name=item.asset_name,
                platform=DatabasePlatform.MYSQL,
                schema_name=item.schema,
                table=item.table,
                column=item.column,
                classification=item.classification,
                data_type=item.data_type,
                confidence=item.confidence,
                protection=item.protection,
                created_at=item.created_at,
            )
            for item in items
        ],
        next_cursor=next_cursor,
        limit=pagination.limit,
    )


@router.post("/evidence", response_model=EvidenceOut, status_code=201, tags=["evidence"])
async def create_evidence(
    payload: EvidenceCreate, identity: WriterIdentity, session: SessionDep
) -> Evidence:
    await tenant_get(session, Assessment, payload.assessment_id, identity.tenant_id, "assessment")
    if payload.finding_id:
        finding = await tenant_get(
            session, Finding, payload.finding_id, identity.tenant_id, "finding"
        )
        if finding.assessment_id != payload.assessment_id:
            raise DomainError(
                "assessment_mismatch", "Evidence finding is for another assessment", 422
            )
    evidence_data = payload.model_dump()
    envelope = json.dumps(
        payload.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    ).encode()
    evidence_data["attributes"] = {
        **evidence_data["attributes"],
        "server_envelope_sha256": hashlib.sha256(envelope).hexdigest(),
    }
    evidence = Evidence(tenant_id=identity.tenant_id, **evidence_data)
    session.add(evidence)
    await session.commit()
    await session.refresh(evidence)
    record_evidence_ingested(payload.evidence_type)
    return evidence


@router.get("/scan-jobs", response_model=Page[ScanJobOut], tags=["scan-jobs"])
async def list_scan_jobs(
    identity: CurrentIdentity, session: SessionDep, pagination: PaginationDep
) -> Page[ScanJobOut]:
    rows = await list_tenant_resources(session, ScanJob, identity.tenant_id, pagination)
    return page_response(rows, pagination.limit, ScanJobOut)


@router.post("/scan-jobs", response_model=ScanJobOut, status_code=201, tags=["scan-jobs"])
async def create_scan_job(
    payload: ScanJobCreate, identity: WriterIdentity, session: SessionDep
) -> ScanJob:
    if payload.deduplication_key.startswith(MASKING_COPY_DEDUPLICATION_PREFIX):
        raise DomainError(
            "reserved_deduplication_key",
            "The masking-copy queue namespace is reserved for the dedicated server workflow",
            422,
        )
    connector = await tenant_get(
        session, Connector, payload.connector_id, identity.tenant_id, "connector"
    )
    if payload.assessment_id:
        assessment = await tenant_get(
            session, Assessment, payload.assessment_id, identity.tenant_id, "assessment"
        )
        if assessment.asset_id != connector.asset_id:
            raise DomainError(
                "asset_mismatch",
                "Scan job assessment and connector must target the same asset",
                422,
            )
    try:
        validate_probe_ids(connector.platform, payload.payload.probe_ids)
    except ValueError as exc:
        raise DomainError("probe_not_allowed", str(exc), 422) from exc
    data = payload.model_dump()
    if data["available_at"] is None:
        data["available_at"] = datetime.now(UTC)
    job = ScanJob(tenant_id=identity.tenant_id, **data)
    session.add(job)
    await commit_or_conflict(session, "A scan job with that deduplication key already exists")
    await session.refresh(job)
    record_job_created(payload.job_type)
    return job


@router.post("/scan-jobs/lease", response_model=CollectorLeaseOut | None, tags=["collectors"])
async def lease_scan_job(
    payload: JobLeaseRequest,
    identity: CollectorIdentity,
    session: SessionDep,
    request: Request,
    response: Response,
) -> ScanJob | None:
    enforce_collector_identity(identity, payload.collector_id)
    masking_connector_id: str | None = None
    if MASKING_COPY_JOB_TYPE in payload.supported_job_types:
        if payload.supported_job_types != [MASKING_COPY_JOB_TYPE]:
            raise DomainError(
                "masking_copy_lease_scope_invalid",
                "The dedicated masking collector can only request masking-copy work",
                422,
            )
        if (
            payload.collector_id != MASKING_COPY_COLLECTOR_ID
            or identity.subject != MASKING_COPY_COLLECTOR_ID
        ):
            raise DomainError(
                "masking_copy_collector_required",
                "Masking-copy work is restricted to the dedicated local collector",
                403,
            )
        masking_connector = await session.scalar(
            select(Connector).where(
                Connector.tenant_id == identity.tenant_id,
                Connector.name == MASKING_COPY_CONNECTOR_NAME,
                Connector.collector_id == MASKING_COPY_COLLECTOR_ID,
                Connector.status == "online",
            )
        )
        if masking_connector is None or not is_dedicated_masking_connector(masking_connector):
            raise DomainError(
                "masking_copy_capability_required",
                "The dedicated local masking connector is unavailable or lacks capability",
                403,
            )
        masking_connector_id = masking_connector.id
    now = datetime.now(UTC)
    statement = (
        select(ScanJob)
        .join(Connector, Connector.id == ScanJob.connector_id)
        .where(
            ScanJob.tenant_id == identity.tenant_id,
            ScanJob.status == WorkStatus.PENDING,
            ScanJob.available_at <= now,
            ScanJob.job_type.in_(payload.supported_job_types),
            Connector.tenant_id == identity.tenant_id,
            Connector.collector_id == payload.collector_id,
            Connector.status == "online",
        )
        .order_by(ScanJob.available_at.asc(), ScanJob.created_at.asc())
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if masking_connector_id is not None:
        statement = statement.where(ScanJob.connector_id == masking_connector_id)
    job = await session.scalar(statement)
    if job is None:
        response.status_code = status.HTTP_204_NO_CONTENT
        return None
    job.status = WorkStatus.LEASED
    job.leased_by = payload.collector_id
    job.lease_token = str(uuid.uuid4())
    job.attempts += 1
    job.lease_expires_at = now + timedelta(seconds=request.app.state.settings.job_lease_seconds)
    if job.job_type == MASKING_COPY_JOB_TYPE:
        requested = MaskingCopyJobPayload.model_validate(job.payload)
        policy = await tenant_get(
            session,
            MaskingPolicy,
            requested.policy_id,
            identity.tenant_id,
            "masking policy",
            for_update=True,
        )
        policy.parameters = {
            **policy.parameters,
            "copy_status": "running",
            "copy_job_id": job.id,
        }
    await session.commit()
    await session.refresh(job)
    record_job_leased(job.job_type)
    return job


@router.post("/scan-jobs/{job_id}/renew", response_model=CollectorLeaseOut, tags=["collectors"])
async def renew_job_lease(
    job_id: str,
    payload: JobLeaseRenewRequest,
    identity: CollectorIdentity,
    session: SessionDep,
    request: Request,
) -> ScanJob:
    enforce_collector_identity(identity, payload.collector_id)
    job = await tenant_get(session, ScanJob, job_id, identity.tenant_id, "scan job")
    if (
        job.leased_by != payload.collector_id
        or job.lease_token != payload.lease_token
        or job.status
        not in {
            WorkStatus.LEASED,
            WorkStatus.RUNNING,
        }
    ):
        record_lease_fencing_rejection("renew")
        raise LeaseConflictError("The caller does not own an active lease for this job")
    now = datetime.now(UTC)
    if job.lease_expires_at and as_utc(job.lease_expires_at) < now:
        record_lease_fencing_rejection("renew_expired")
        raise LeaseConflictError("The job lease has expired")
    job.status = WorkStatus.RUNNING
    job.lease_expires_at = now + timedelta(seconds=request.app.state.settings.job_lease_seconds)
    await session.commit()
    await session.refresh(job)
    return job


@router.post("/scan-jobs/{job_id}/complete", response_model=ScanJobOut, tags=["collectors"])
async def complete_scan_job(
    job_id: str,
    payload: JobCompletionRequest,
    identity: CollectorIdentity,
    session: SessionDep,
) -> ScanJob:
    enforce_collector_identity(identity, payload.collector_id)
    job = await session.scalar(
        select(ScanJob)
        .where(ScanJob.id == job_id, ScanJob.tenant_id == identity.tenant_id)
        .with_for_update()
    )
    if job is None:
        raise NotFoundError("scan job", job_id)
    if (
        job.leased_by != payload.collector_id
        or job.lease_token != payload.lease_token
        or job.status
        not in {
            WorkStatus.LEASED,
            WorkStatus.RUNNING,
        }
    ):
        record_lease_fencing_rejection("complete")
        raise LeaseConflictError("The caller does not own an active lease for this job")
    now = datetime.now(UTC)
    if job.lease_expires_at and as_utc(job.lease_expires_at) < now:
        record_lease_fencing_rejection("complete_expired")
        raise LeaseConflictError("The job lease has expired")
    masking_request: MaskingCopyJobPayload | None = None
    masking_result: MaskingCopyResult | None = None
    if job.job_type == MASKING_COPY_JOB_TYPE:
        try:
            masking_request = MaskingCopyJobPayload.model_validate(job.payload)
        except ValueError as exc:
            raise DomainError(
                "stored_job_contract_invalid",
                "The stored masking-copy payload is invalid and cannot be completed",
                409,
            ) from exc
        connector = await tenant_get(
            session, Connector, job.connector_id, identity.tenant_id, "masking connector"
        )
        if (
            connector.asset_id != masking_request.asset_id
            or not is_dedicated_masking_connector(connector)
            or payload.collector_id != MASKING_COPY_COLLECTOR_ID
        ):
            raise DomainError(
                "masking_copy_connector_invalid",
                "The job is not owned by the dedicated local masking connector",
                409,
            )
        if payload.success:
            if payload.result.probe_results:
                raise DomainError(
                    "masking_copy_result_invalid",
                    "Masking-copy completion cannot contain probe results",
                    422,
                )
            try:
                masking_result = MaskingCopyResult.model_validate(payload.result.summary)
            except ValueError as exc:
                raise DomainError(
                    "masking_copy_result_invalid",
                    "Masking-copy completion requires the exact aggregate proof contract",
                    422,
                ) from exc
        elif payload.result.summary:
            raise DomainError(
                "masking_copy_result_invalid",
                "A failed masking-copy attempt cannot submit aggregate evidence",
                422,
            )
    elif payload.success:
        try:
            requested = ScanJobPayload.model_validate(job.payload)
        except ValueError as exc:
            raise DomainError(
                "stored_job_contract_invalid",
                "The stored job payload is invalid and cannot be completed",
                409,
            ) from exc
        connector = await tenant_get(
            session, Connector, job.connector_id, identity.tenant_id, "connector"
        )
        try:
            validate_probe_ids(connector.platform, requested.probe_ids)
        except ValueError as exc:
            raise DomainError(
                "stored_job_contract_invalid",
                "The job requests probes outside the connector platform catalogue",
                409,
            ) from exc
        results = payload.result.probe_results
        supplied_ids = [result.probe_id for result in results]
        if len(supplied_ids) != len(set(supplied_ids)):
            raise DomainError(
                "duplicate_probe_result",
                "A successful completion requires exactly one result per requested probe",
                422,
            )
        if set(supplied_ids) != set(requested.probe_ids):
            raise DomainError(
                "probe_result_set_mismatch",
                "A successful completion requires the exact requested probe set",
                422,
            )
        try:
            validate_probe_ids(connector.platform, supplied_ids)
        except ValueError as exc:
            raise DomainError(
                "probe_not_allowed", "A result is not approved for this platform", 422
            ) from exc
        for result in results:
            if result.outcome != "collected":
                continue
            canonical_observations = json.dumps(
                result.observations,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            server_digest = hashlib.sha256(canonical_observations).hexdigest()
            if result.evidence_sha256 is None or result.evidence_sha256.lower() != server_digest:
                raise DomainError(
                    "evidence_digest_mismatch",
                    "The collector evidence digest does not match its canonical observations",
                    422,
                )
    job.result = payload.result.model_dump(mode="json")
    job.lease_expires_at = None
    job.leased_by = None
    job.lease_token = None
    if payload.success:
        job.status = WorkStatus.SUCCEEDED
        job.completed_at = now
        job.last_error = None
    elif job.attempts < job.max_attempts:
        job.status = WorkStatus.PENDING
        job.last_error = payload.error
        job.available_at = now + timedelta(seconds=min(300, 2**job.attempts))
    else:
        job.status = WorkStatus.FAILED
        job.last_error = payload.error
        job.completed_at = now
    if job.job_type == MASKING_COPY_JOB_TYPE:
        if payload.success:
            if masking_request is None or masking_result is None:
                raise RuntimeError("validated masking-copy completion is missing")
            await reconcile_masking_copy_success(
                session,
                job=job,
                requested=masking_request,
                result=masking_result,
                now=now,
            )
        elif masking_request is not None:
            policy = await tenant_get(
                session,
                MaskingPolicy,
                masking_request.policy_id,
                identity.tenant_id,
                "masking policy",
                for_update=True,
            )
            if is_builtin_local_masking_policy(policy):
                policy.parameters = {
                    **policy.parameters,
                    "copy_status": (
                        "retry_pending" if job.status == WorkStatus.PENDING else "failed"
                    ),
                    "copy_job_id": job.id,
                }
    else:
        await reconcile_mysql_access_review(
            session,
            job=job,
            job_result=payload.result,
            now=now,
        )
        await orchestrate_assessment_after_job(
            session,
            job=job,
            job_result=payload.result,
            now=now,
        )
    await session.commit()
    await session.refresh(job)
    record_job_completed(job.status.value)
    return job


@router.get("/masking-policies", response_model=Page[MaskingPolicyOut], tags=["masking"])
async def list_masking_policies(
    identity: CurrentIdentity, session: SessionDep, pagination: PaginationDep
) -> Page[MaskingPolicyOut]:
    rows = await list_tenant_resources(session, MaskingPolicy, identity.tenant_id, pagination)
    return page_response(rows, pagination.limit, MaskingPolicyOut)


@router.post(
    "/masking-policies", response_model=MaskingPolicyOut, status_code=201, tags=["masking"]
)
async def create_masking_policy(
    payload: MaskingPolicyCreate, identity: WriterIdentity, session: SessionDep
) -> MaskingPolicy:
    data = payload.model_dump()
    parameters = {
        key: value
        for key, value in data.pop("parameters").items()
        if key
        not in {
            "workflow_status",
            "approved_at",
            "execution_recorded_at",
            "execution_reference",
            "validated_at",
            "last_note",
        }
    }
    local_copy_plan = (
        data["classification"] == "Restricted and confidential"
        and data["strategy"] == "substitute"
        and data["target_environment"] == AssetEnvironment.DEVELOPMENT
    )
    policy_id = str(uuid.uuid4())
    if local_copy_plan:
        target_database = masking_copy_target_database(policy_id)
        parameters.update(
            {
                "local_copy_plan": True,
                "source_asset": MASKING_COPY_SOURCE_DATABASE,
                "source_database": MASKING_COPY_SOURCE_DATABASE,
                "target_database": target_database,
                "row_cap": MASKING_COPY_ROW_CAP,
                "copy_mode": "create_fresh_workflow_target",
            }
        )
    policy = MaskingPolicy(
        id=policy_id,
        tenant_id=identity.tenant_id,
        **data,
        enabled=False,
        approved_by=None,
        parameters={**parameters, "workflow_status": "draft"},
    )
    session.add(policy)
    await commit_or_conflict(session, "This masking policy version already exists")
    await session.refresh(policy)
    return policy


@router.post(
    "/masking-policies/{policy_id}/copy-runs",
    response_model=ScanJobOut,
    status_code=201,
    tags=["masking"],
)
async def create_masking_copy_run(
    policy_id: str,
    identity: AnalystIdentity,
    _queue_guard: MaskingCopyQueueGuard,
    session: SessionDep,
    request: Request,
    response: Response,
) -> ScanJob:
    """Queue the fixed local plan without accepting endpoints, credentials, or SQL."""
    if request.app.state.settings.environment != "development":
        raise DomainError(
            "masking_copy_development_only",
            "The built-in masking copy is available only in local development",
            403,
        )
    policy = await tenant_get(
        session,
        MaskingPolicy,
        policy_id,
        identity.tenant_id,
        "masking policy",
        for_update=True,
    )
    if not is_builtin_local_masking_policy(policy):
        raise DomainError(
            "masking_copy_policy_not_builtin",
            "Only an approved local insurance masking plan can be queued",
            422,
        )
    if not policy.enabled:
        raise DomainError(
            "masking_copy_policy_not_approved",
            "Approve the local masking plan before queuing a copy",
            409,
        )
    policy_is_approved = bool(
        policy.approved_by and policy.parameters.get("workflow_status") == "approved"
    )

    asset = await session.scalar(
        select(Asset).where(
            Asset.tenant_id == identity.tenant_id,
            Asset.external_id == "local-mysql-insurance-sample",
            Asset.name == MASKING_COPY_SOURCE_DATABASE,
            Asset.platform == DatabasePlatform.MYSQL,
            Asset.environment == AssetEnvironment.DEVELOPMENT,
            Asset.status == LifecycleStatus.ACTIVE,
        )
    )
    if asset is None or asset.tags.get("source") != "local":
        raise DomainError(
            "masking_copy_asset_unavailable",
            "The registered local insurance_sample MySQL asset is unavailable",
            409,
        )
    connector = await session.scalar(
        select(Connector).where(
            Connector.tenant_id == identity.tenant_id,
            Connector.asset_id == asset.id,
            Connector.name == MASKING_COPY_CONNECTOR_NAME,
            Connector.collector_id == MASKING_COPY_COLLECTOR_ID,
        )
    )
    if connector is None or not is_dedicated_masking_connector(connector):
        raise DomainError(
            "masking_copy_connector_unavailable",
            "The dedicated local masking connector and capability are not registered",
            409,
        )

    target_database = policy_masking_target(policy)
    if target_database is None:
        raise DomainError(
            "masking_copy_policy_not_builtin",
            "The local masking plan has no valid server-derived target",
            422,
        )
    deduplication_key = masking_copy_deduplication_key(policy.id, target_database)
    existing_job = await session.scalar(
        select(ScanJob)
        .where(
            ScanJob.tenant_id == identity.tenant_id,
            ScanJob.job_type == MASKING_COPY_JOB_TYPE,
            ScanJob.deduplication_key == deduplication_key,
        )
        .with_for_update()
        .limit(1)
    )
    if existing_job is not None:
        validate_masking_copy_job_binding(
            existing_job,
            policy_id=policy.id,
            asset_id=asset.id,
            connector_id=connector.id,
        )
        if existing_job.status == WorkStatus.SUCCEEDED or (
            existing_job.status in MASKING_COPY_ACTIVE_STATUSES and policy_is_approved
        ):
            response.status_code = status.HTTP_200_OK
            return existing_job
        if existing_job.status not in {WorkStatus.FAILED, *MASKING_COPY_ACTIVE_STATUSES}:
            raise DomainError(
                "masking_copy_terminal_state",
                "The deterministic masking-copy slot is not safely retryable",
                409,
            )

    if not policy_is_approved:
        raise DomainError(
            "masking_copy_policy_not_approved",
            "Approve the local masking plan before queuing a copy",
            409,
        )

    assessment = await session.scalar(
        select(Assessment)
        .where(
            Assessment.tenant_id == identity.tenant_id,
            Assessment.asset_id == asset.id,
            Assessment.control_pack == MASKING_COPY_PACK_ID,
            Assessment.status == AssessmentStatus.REVIEW_REQUIRED,
        )
        .order_by(Assessment.created_at.desc(), Assessment.id.desc())
        .with_for_update()
        .limit(1)
    )
    if (
        assessment is None
        or assessment.score is not None
        or assessment.summary.get("collection_status") != "review_required"
    ):
        raise DomainError(
            "masking_copy_review_required",
            "Run the local MySQL assessment to analyst review before masking",
            409,
        )
    pack = await session.scalar(
        select(ControlPackVersion).where(
            ControlPackVersion.tenant_id == identity.tenant_id,
            ControlPackVersion.pack_id == assessment.control_pack,
            ControlPackVersion.version == assessment.control_pack_version,
            ControlPackVersion.status == ControlPackStatus.ACTIVE,
        )
    )
    manual_control = (
        await session.scalar(
            select(ControlDefinition).where(
                ControlDefinition.tenant_id == identity.tenant_id,
                ControlDefinition.control_pack_version_id == pack.id,
                ControlDefinition.control_id == MASKING_COPY_CONTROL_ID,
                ControlDefinition.assessment_mode == "manual_evidence",
            )
        )
        if pack is not None
        else None
    )
    if manual_control is None:
        raise DomainError(
            "masking_copy_control_unavailable",
            "The active MySQL pack has no manual masking-evidence control",
            409,
        )

    masking_payload = MaskingCopyJobPayload(
        policy_id=policy.id,
        asset_id=asset.id,
        source_database=MASKING_COPY_SOURCE_DATABASE,
        target_database=target_database,
        row_cap=MASKING_COPY_ROW_CAP,
    )
    connector_id = connector.id
    now = datetime.now(UTC)
    is_new_job = existing_job is None
    if existing_job is None:
        job = ScanJob(
            id=str(uuid.uuid4()),
            tenant_id=identity.tenant_id,
            connector_id=connector_id,
            assessment_id=assessment.id,
            job_type=MASKING_COPY_JOB_TYPE,
            deduplication_key=deduplication_key,
            payload=masking_payload.model_dump(mode="json"),
            available_at=now,
            max_attempts=min(3, request.app.state.settings.collector_max_attempts),
        )
        session.add(job)
    else:
        job = existing_job
        job.connector_id = connector_id
        job.assessment_id = assessment.id
        job.status = WorkStatus.PENDING
        job.payload = masking_payload.model_dump(mode="json")
        job.available_at = now
        job.leased_by = None
        job.lease_token = None
        job.lease_expires_at = None
        job.attempts = 0
        job.max_attempts = min(3, request.app.state.settings.collector_max_attempts)
        job.last_error = None
        job.result = {}
        job.completed_at = None
        response.status_code = status.HTTP_200_OK
    policy.parameters = {
        **policy.parameters,
        "copy_status": "queued",
        "copy_job_id": job.id,
        "source_database": MASKING_COPY_SOURCE_DATABASE,
        "target_database": target_database,
        "row_cap": MASKING_COPY_ROW_CAP,
    }
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raced_job = await session.scalar(
            select(ScanJob).where(
                ScanJob.tenant_id == identity.tenant_id,
                ScanJob.deduplication_key == deduplication_key,
            )
        )
        if raced_job is None:
            raise ConflictError("The masking-copy run could not be queued safely") from exc
        validate_masking_copy_job_binding(
            raced_job,
            policy_id=policy_id,
            asset_id=masking_payload.asset_id,
            connector_id=connector_id,
        )
        if raced_job.status not in {*MASKING_COPY_ACTIVE_STATUSES, WorkStatus.SUCCEEDED}:
            raise ConflictError("The deterministic masking-copy slot changed concurrently") from exc
        response.status_code = status.HTTP_200_OK
        return raced_job
    await session.refresh(job)
    if is_new_job:
        record_job_created(job.job_type)
    return job


@router.patch(
    "/masking-policies/{policy_id}/workflow",
    response_model=MaskingPolicyOut,
    tags=["masking"],
)
async def transition_masking_policy(
    policy_id: str,
    payload: MaskingPolicyTransition,
    identity: WriterIdentity,
    session: SessionDep,
) -> MaskingPolicy:
    policy = await tenant_get(
        session, MaskingPolicy, policy_id, identity.tenant_id, "masking policy"
    )
    if payload.action == "record_execution" and is_builtin_local_masking_policy(policy):
        raise DomainError(
            "masking_copy_execution_must_be_automated",
            "Built-in local masking execution can only be recorded by its completed copy job",
            409,
        )
    parameters = dict(policy.parameters)
    current = str(parameters.get("workflow_status", "draft"))
    expected = {
        "approve": "draft",
        "record_execution": "approved",
        "validate": "execution_recorded",
        "archive": "validated",
    }[payload.action]
    if current != expected:
        raise DomainError(
            "invalid_masking_transition",
            f"Masking policy is {current}; {payload.action} requires {expected}",
            409,
        )
    now = datetime.now(UTC).isoformat()
    next_status = {
        "approve": "approved",
        "record_execution": "execution_recorded",
        "validate": "validated",
        "archive": "validated",
    }[payload.action]
    parameters["workflow_status"] = next_status
    parameters["last_note"] = payload.note
    if payload.action == "approve":
        parameters["approved_at"] = now
        policy.approved_by = identity.subject
        policy.enabled = True
    elif payload.action == "record_execution":
        parameters["execution_recorded_at"] = now
        parameters["execution_reference"] = payload.reference
    elif payload.action == "validate":
        parameters["validated_at"] = now
    else:
        if parameters.get("archived_at"):
            raise DomainError(
                "masking_policy_already_archived",
                "Masking policy is already archived",
                409,
            )
        parameters["archived_at"] = now
        parameters["archived_by"] = identity.subject
        policy.enabled = False
    policy.parameters = parameters
    await session.commit()
    await session.refresh(policy)
    return policy


@router.get("/access-reviews", response_model=Page[AccessReviewOut], tags=["access-reviews"])
async def list_access_reviews(
    identity: CurrentIdentity, session: SessionDep, pagination: PaginationDep
) -> Page[AccessReviewOut]:
    rows = await list_tenant_resources(session, AccessReview, identity.tenant_id, pagination)
    return page_response(rows, pagination.limit, AccessReviewOut)


@router.post(
    "/access-reviews", response_model=AccessReviewOut, status_code=201, tags=["access-reviews"]
)
async def create_access_review(
    payload: AccessReviewCreate, identity: WriterIdentity, session: SessionDep
) -> AccessReview:
    await tenant_get(session, Asset, payload.asset_id, identity.tenant_id, "asset")
    review = AccessReview(tenant_id=identity.tenant_id, **payload.model_dump())
    session.add(review)
    await session.commit()
    await session.refresh(review)
    return review


@router.patch(
    "/access-reviews/{review_id}", response_model=AccessReviewOut, tags=["access-reviews"]
)
async def update_access_review(
    review_id: str,
    payload: AccessReviewUpdate,
    identity: WriterIdentity,
    session: SessionDep,
) -> AccessReview:
    review = await tenant_get(session, AccessReview, review_id, identity.tenant_id, "access review")
    review.status = payload.status
    review.decision_summary = {**payload.decision_summary, "reason": payload.reason}
    await session.commit()
    await session.refresh(review)
    return review


@router.get("/audit-events", response_model=Page[AuditEventOut], tags=["audit"])
async def list_audit_events(
    identity: AuditIdentity, session: SessionDep, pagination: PaginationDep
) -> Page[AuditEventOut]:
    rows = await list_tenant_resources(session, AuditEvent, identity.tenant_id, pagination)
    return page_response(rows, pagination.limit, AuditEventOut)


@router.get("/dashboard/summary", response_model=DashboardSummary, tags=["dashboard"])
async def dashboard_summary(identity: CurrentIdentity, session: SessionDep) -> DashboardSummary:
    async def count(model: type[Any], *conditions: Any) -> int:
        statement = (
            select(func.count()).select_from(model).where(model.tenant_id == identity.tenant_id)
        )
        if conditions:
            statement = statement.where(*conditions)
        return int((await session.scalar(statement)) or 0)

    return DashboardSummary(
        assets=await count(Asset),
        connectors=await count(Connector),
        open_findings=await count(Finding, Finding.status == FindingStatus.OPEN),
        assessments=await count(Assessment),
        masking_policies=await count(MaskingPolicy),
        access_reviews=await count(AccessReview),
        generated_at=datetime.now(UTC),
    )


@router.post(
    "/admin/idempotency-records/{record_id}/resolve",
    response_model=IdempotencyRecoveryOut,
    tags=["administration"],
)
async def resolve_uncertain_idempotency_record(
    record_id: str,
    payload: IdempotencyRecoveryRequest,
    identity: AdminIdentity,
    session: SessionDep,
    request: Request,
) -> IdempotencyRecoveryOut:
    """Fail closed an uncertain reservation after an operator investigation.

    Recovery deliberately cannot delete/reopen a reservation because that could
    duplicate a domain side effect committed immediately before a process crash.
    """
    record = await tenant_get(
        session, IdempotencyRecord, record_id, identity.tenant_id, "idempotency record"
    )
    if record.state not in {"pending", "review_required"}:
        raise ConflictError("This idempotency reservation has already been resolved")
    now = datetime.now(UTC)
    response_body = json.dumps(
        {
            "error": {
                "code": "idempotency_replay_rejected",
                "message": "The original mutation outcome was uncertain and replay was rejected",
                "details": None,
                "request_id": request.state.request_id,
            }
        },
        separators=(",", ":"),
    )
    record.state = "completed"
    record.response_status = 409
    record.response_body = response_body
    record.response_content_type = "application/json"
    record.resolved_at = now
    record.resolved_by = identity.subject
    record.resolution_reason = payload.reason
    session.add(
        AuditEvent(
            tenant_id=identity.tenant_id,
            actor=identity.subject,
            action="idempotency.reject_replay",
            resource_type="idempotency_record",
            resource_id=record.id,
            request_id=request.state.request_id,
            source_ip=request.client.host if request.client else None,
            outcome="success",
            attributes={"resolution": payload.resolution},
        )
    )
    await session.commit()
    record_idempotency_recovery("replay_rejected")
    return IdempotencyRecoveryOut(
        id=record.id,
        state="completed",
        response_status=409,
        resolved_at=now,
        resolved_by=identity.subject,
    )


@router.get(
    "/admin/idempotency-records/recovery",
    response_model=list[IdempotencyRecoveryCandidate],
    tags=["administration"],
)
async def list_uncertain_idempotency_records(
    identity: AdminIdentity,
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[IdempotencyRecoveryCandidate]:
    records = list(
        (
            await session.scalars(
                select(IdempotencyRecord)
                .where(
                    IdempotencyRecord.tenant_id == identity.tenant_id,
                    IdempotencyRecord.state.in_(["pending", "review_required"]),
                )
                .order_by(IdempotencyRecord.expires_at.asc(), IdempotencyRecord.id.asc())
                .limit(limit)
            )
        ).all()
    )
    return [
        IdempotencyRecoveryCandidate(
            id=record.id,
            actor_subject=record.actor_subject,
            method=record.method,
            path=record.path,
            state=cast(Literal["pending", "review_required"], record.state),
            created_at=record.created_at,
            expires_at=record.expires_at,
            idempotency_key_sha256=hashlib.sha256(record.idempotency_key.encode()).hexdigest(),
        )
        for record in records
    ]
