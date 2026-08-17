from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return str(uuid.uuid4())


class DatabasePlatform(StrEnum):
    ORACLE = "oracle"
    POSTGRESQL = "postgresql"
    SYBASE = "sybase"
    MYSQL = "mysql"


class AssetEnvironment(StrEnum):
    PRODUCTION = "production"
    STAGING = "staging"
    TEST = "test"
    DEVELOPMENT = "development"
    DISASTER_RECOVERY = "disaster_recovery"


class LifecycleStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DECOMMISSIONED = "decommissioned"


class WorkStatus(StrEnum):
    PENDING = "pending"
    LEASED = "leased"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AssessmentStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    REVIEW_REQUIRED = "review_required"
    COMPLETED = "completed"
    FAILED = "failed"
    SUPERSEDED = "superseded"


class FindingSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RISK_ACCEPTED = "risk_accepted"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class ControlDomain(StrEnum):
    ENCRYPTION = "encryption"
    DATA_PROTECTION = "data_protection"
    ACCESS_SECURITY = "access_security"
    DATA_MASKING = "data_masking"


class ReviewStatus(StrEnum):
    DRAFT = "draft"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    REMEDIATION_REQUIRED = "remediation_required"
    CLOSED = "closed"


class ControlPackStatus(StrEnum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"


class ControlResultOutcome(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    REVIEW_REQUIRED = "review_required"
    NOT_APPLICABLE = "not_applicable"
    UNSUPPORTED = "unsupported"
    INSUFFICIENT_PRIVILEGE = "insufficient_privilege"
    COLLECTION_ERROR = "collection_error"


class ControlDecisionOutcome(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"


class FindingExceptionStatus(StrEnum):
    REQUESTED = "requested"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    REVOKED = "revoked"


class DeliveryStatus(StrEnum):
    PENDING = "pending"
    LEASED = "leased"
    RUNNING = "running"
    DELIVERED = "delivered"
    DEAD_LETTER = "dead_letter"


class InboxStatus(StrEnum):
    PROCESSED = "processed"
    REJECTED = "rejected"


class IntegrationDestination(StrEnum):
    SIEM = "siem"
    TICKETING = "ticketing"
    GRC = "grc"


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class TenantMixin:
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)


class Asset(Base, TimestampMixin, TenantMixin):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("tenant_id", "external_id", name="uq_assets_tenant_external"),
        UniqueConstraint("tenant_id", "id", name="uq_assets_tenant_id"),
        Index("ix_assets_tenant_platform", "tenant_id", "platform"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    external_id: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    platform: Mapped[DatabasePlatform] = mapped_column(
        Enum(DatabasePlatform, native_enum=False, length=24), nullable=False
    )
    version: Mapped[str] = mapped_column(String(80), nullable=False)
    edition: Mapped[str | None] = mapped_column(String(120))
    environment: Mapped[AssetEnvironment] = mapped_column(
        Enum(AssetEnvironment, native_enum=False, length=32), nullable=False
    )
    owner: Mapped[str] = mapped_column(String(160), nullable=False)
    criticality: Mapped[str] = mapped_column(String(16), default="medium", nullable=False)
    status: Mapped[LifecycleStatus] = mapped_column(
        Enum(LifecycleStatus, native_enum=False, length=24), default=LifecycleStatus.ACTIVE
    )
    tags: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class Connector(Base, TimestampMixin, TenantMixin):
    __tablename__ = "connectors"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_connectors_tenant_name"),
        UniqueConstraint("tenant_id", "id", name="uq_connectors_tenant_id"),
        ForeignKeyConstraint(
            ["tenant_id", "asset_id"],
            ["assets.tenant_id", "assets.id"],
            name="fk_connectors_tenant_asset",
            ondelete="RESTRICT",
        ),
        Index("ix_connectors_tenant_status", "tenant_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(String(36), index=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    platform: Mapped[DatabasePlatform] = mapped_column(
        Enum(DatabasePlatform, native_enum=False, length=24), nullable=False
    )
    endpoint_ref: Mapped[str] = mapped_column(String(512), nullable=False)
    secret_ref: Mapped[str] = mapped_column(String(1024), nullable=False)
    collector_id: Mapped[str | None] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(32), default="registered", nullable=False)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    capabilities: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class Assessment(Base, TimestampMixin, TenantMixin):
    __tablename__ = "assessments"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_assessments_tenant_id"),
        ForeignKeyConstraint(
            ["tenant_id", "asset_id"],
            ["assets.tenant_id", "assets.id"],
            name="fk_assessments_tenant_asset",
            ondelete="RESTRICT",
        ),
        Index("ix_assessments_tenant_asset", "tenant_id", "asset_id"),
        Index(
            "uq_assessments_active_run",
            "tenant_id",
            "asset_id",
            "control_pack",
            "control_pack_version",
            unique=True,
            postgresql_where=text(
                "status IN ('QUEUED', 'RUNNING', 'REVIEW_REQUIRED')"
            ),
            sqlite_where=text("status IN ('QUEUED', 'RUNNING', 'REVIEW_REQUIRED')"),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(String(36), index=True)
    control_pack: Mapped[str] = mapped_column(String(120), nullable=False)
    control_pack_version: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[AssessmentStatus] = mapped_column(
        Enum(AssessmentStatus, native_enum=False, length=24), default=AssessmentStatus.QUEUED
    )
    score: Mapped[float | None] = mapped_column(Float)
    initiated_by: Mapped[str] = mapped_column(String(160), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class Finding(Base, TimestampMixin, TenantMixin):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "assessment_id",
            "control_id",
            "fingerprint",
            name="uq_findings_assessment_control_fingerprint",
        ),
        UniqueConstraint("tenant_id", "id", name="uq_findings_tenant_id"),
        ForeignKeyConstraint(
            ["tenant_id", "assessment_id"],
            ["assessments.tenant_id", "assessments.id"],
            name="fk_findings_tenant_assessment",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "asset_id"],
            ["assets.tenant_id", "assets.id"],
            name="fk_findings_tenant_asset",
            ondelete="RESTRICT",
        ),
        Index("ix_findings_tenant_status_severity", "tenant_id", "status", "severity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    assessment_id: Mapped[str] = mapped_column(String(36), index=True)
    asset_id: Mapped[str] = mapped_column(String(36), index=True)
    control_id: Mapped[str] = mapped_column(String(100), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    domain: Mapped[ControlDomain] = mapped_column(
        Enum(ControlDomain, native_enum=False, length=32), nullable=False
    )
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[FindingSeverity] = mapped_column(
        Enum(FindingSeverity, native_enum=False, length=16), nullable=False
    )
    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus, native_enum=False, length=24), default=FindingStatus.OPEN
    )
    owner: Mapped[str | None] = mapped_column(String(160))
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    risk_context: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class ScanJob(Base, TimestampMixin, TenantMixin):
    __tablename__ = "scan_jobs"
    __table_args__ = (
        UniqueConstraint("tenant_id", "deduplication_key", name="uq_jobs_tenant_dedup"),
        UniqueConstraint("tenant_id", "id", name="uq_scan_jobs_tenant_id"),
        ForeignKeyConstraint(
            ["tenant_id", "connector_id"],
            ["connectors.tenant_id", "connectors.id"],
            name="fk_scan_jobs_tenant_connector",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "assessment_id"],
            ["assessments.tenant_id", "assessments.id"],
            name="fk_scan_jobs_tenant_assessment",
            ondelete="RESTRICT",
        ),
        Index("ix_jobs_lease_queue", "tenant_id", "status", "available_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    connector_id: Mapped[str] = mapped_column(String(36), index=True)
    assessment_id: Mapped[str | None] = mapped_column(String(36), index=True)
    job_type: Mapped[str] = mapped_column(String(80), nullable=False)
    deduplication_key: Mapped[str] = mapped_column(String(160), nullable=False)
    status: Mapped[WorkStatus] = mapped_column(
        Enum(WorkStatus, native_enum=False, length=24), default=WorkStatus.PENDING
    )
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    leased_by: Mapped[str | None] = mapped_column(String(128))
    # A random capability rotated for every assignment. Attempts alone are not a
    # fencing primitive because an old worker can learn their predictable values.
    lease_token: Mapped[str | None] = mapped_column(String(36))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Evidence(Base, TimestampMixin, TenantMixin):
    __tablename__ = "evidence"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "assessment_id"],
            ["assessments.tenant_id", "assessments.id"],
            name="fk_evidence_tenant_assessment",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "finding_id"],
            ["findings.tenant_id", "findings.id"],
            name="fk_evidence_tenant_finding",
            ondelete="RESTRICT",
        ),
        Index("ix_evidence_tenant_assessment", "tenant_id", "assessment_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    assessment_id: Mapped[str] = mapped_column(String(36), index=True)
    finding_id: Mapped[str | None] = mapped_column(String(36), index=True)
    control_id: Mapped[str] = mapped_column(String(100), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(64), nullable=False)
    uri: Mapped[str | None] = mapped_column(String(1024))
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    collector_version: Mapped[str] = mapped_column(String(40), nullable=False)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class MaskingPolicy(Base, TimestampMixin, TenantMixin):
    __tablename__ = "masking_policies"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", "version", name="uq_masking_tenant_name_version"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    classification: Mapped[str] = mapped_column(String(100), nullable=False)
    strategy: Mapped[str] = mapped_column(String(80), nullable=False)
    target_environment: Mapped[AssetEnvironment] = mapped_column(
        Enum(AssetEnvironment, native_enum=False, length=32), nullable=False
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    parameters: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(160))


class AccessReview(Base, TimestampMixin, TenantMixin):
    __tablename__ = "access_reviews"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "asset_id"],
            ["assets.tenant_id", "assets.id"],
            name="fk_access_reviews_tenant_asset",
            ondelete="RESTRICT",
        ),
        Index("ix_access_reviews_tenant_asset", "tenant_id", "asset_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(String(36), index=True)
    name: Mapped[str] = mapped_column(String(180), nullable=False)
    reviewer: Mapped[str] = mapped_column(String(160), nullable=False)
    scope: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[ReviewStatus] = mapped_column(
        Enum(ReviewStatus, native_enum=False, length=32), default=ReviewStatus.DRAFT
    )
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    decision_summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class AuditEvent(Base, TimestampMixin, TenantMixin):
    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_tenant_occurred", "tenant_id", "occurred_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    actor: Mapped[str] = mapped_column(String(160), nullable=False)
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(80), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(128))
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


@event.listens_for(AuditEvent, "before_update")
@event.listens_for(AuditEvent, "before_delete")
def prevent_audit_mutation(*_: object) -> None:
    raise ValueError("audit events are append-only")


class IdempotencyRecord(Base):
    __tablename__ = "idempotency_records"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "actor_subject",
            "authorization_hash",
            "method",
            "path",
            "idempotency_key",
            name="uq_idempotency_scope",
        ),
        Index("ix_idempotency_expiry", "expires_at"),
        Index("ix_idempotency_recovery", "state", "expires_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_subject: Mapped[str] = mapped_column(String(160), nullable=False)
    authorization_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    method: Mapped[str] = mapped_column(String(12), nullable=False)
    path: Mapped[str] = mapped_column(String(512), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(16), default="pending", nullable=False)
    response_status: Mapped[int | None] = mapped_column(Integer)
    response_body: Mapped[str | None] = mapped_column(Text)
    response_content_type: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_by: Mapped[str | None] = mapped_column(String(160))
    resolution_reason: Mapped[str | None] = mapped_column(Text)


class ControlPackVersion(Base, TenantMixin):
    __tablename__ = "control_pack_versions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "pack_id", "version", name="uq_control_pack_tenant_version"),
        UniqueConstraint("tenant_id", "id", name="uq_control_pack_versions_tenant_id"),
        Index("ix_control_pack_tenant_status", "tenant_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    pack_id: Mapped[str] = mapped_column(String(120), nullable=False)
    version: Mapped[str] = mapped_column(String(40), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    platform: Mapped[DatabasePlatform] = mapped_column(
        Enum(DatabasePlatform, native_enum=False, length=24), nullable=False
    )
    title: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[ControlPackStatus] = mapped_column(
        Enum(ControlPackStatus, native_enum=False, length=24), nullable=False
    )
    released_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    supersedes: Mapped[str | None] = mapped_column(String(40))
    immutable: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by: Mapped[str] = mapped_column(String(160), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )


class ControlDefinition(Base, TenantMixin):
    __tablename__ = "control_definitions"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "control_pack_version_id",
            "control_id",
            name="uq_control_definition_pack_control",
        ),
        UniqueConstraint("tenant_id", "id", name="uq_control_definitions_tenant_id"),
        ForeignKeyConstraint(
            ["tenant_id", "control_pack_version_id"],
            ["control_pack_versions.tenant_id", "control_pack_versions.id"],
            name="fk_control_definitions_tenant_pack",
            ondelete="RESTRICT",
        ),
        Index("ix_control_definition_tenant_domain", "tenant_id", "domain"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    control_pack_version_id: Mapped[str] = mapped_column(String(36), index=True)
    control_id: Mapped[str] = mapped_column(String(100), nullable=False)
    domain: Mapped[ControlDomain] = mapped_column(
        Enum(ControlDomain, native_enum=False, length=32), nullable=False
    )
    title: Mapped[str] = mapped_column(String(140), nullable=False)
    objective: Mapped[str] = mapped_column(String(600), nullable=False)
    severity: Mapped[FindingSeverity] = mapped_column(
        Enum(FindingSeverity, native_enum=False, length=16), nullable=False
    )
    environments: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    version_scope: Mapped[str] = mapped_column(String(32), nullable=False)
    applicability_notes: Mapped[str] = mapped_column(String(400), nullable=False)
    assessment_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    probe_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    decision_mode: Mapped[str] = mapped_column(String(40), nullable=False)
    manual_evidence_requirements: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    allowed_fields: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    limitations: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    remediation_guidance: Mapped[str] = mapped_column(String(600), nullable=False)
    definition_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )


class ControlResult(Base, TenantMixin):
    __tablename__ = "control_results"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "assessment_id",
            "control_definition_id",
            name="uq_control_result_assessment_control",
        ),
        UniqueConstraint("tenant_id", "evaluation_key", name="uq_control_result_evaluation_key"),
        UniqueConstraint("tenant_id", "id", name="uq_control_results_tenant_id"),
        ForeignKeyConstraint(
            ["tenant_id", "assessment_id"],
            ["assessments.tenant_id", "assessments.id"],
            name="fk_control_results_tenant_assessment",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "control_definition_id"],
            ["control_definitions.tenant_id", "control_definitions.id"],
            name="fk_control_results_tenant_definition",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "source_job_id"],
            ["scan_jobs.tenant_id", "scan_jobs.id"],
            name="fk_control_results_tenant_job",
            ondelete="RESTRICT",
        ),
        Index("ix_control_result_tenant_outcome", "tenant_id", "outcome"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    assessment_id: Mapped[str] = mapped_column(String(36), index=True)
    control_definition_id: Mapped[str] = mapped_column(String(36), index=True)
    source_job_id: Mapped[str | None] = mapped_column(String(36), index=True)
    control_id: Mapped[str] = mapped_column(String(100), nullable=False)
    evaluation_key: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[ControlResultOutcome] = mapped_column(
        Enum(ControlResultOutcome, native_enum=False, length=32), nullable=False
    )
    evaluator_version: Mapped[str] = mapped_column(String(40), nullable=False)
    input_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    rationale: Mapped[str] = mapped_column(String(1000), nullable=False)
    evidence_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    probe_outcomes: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )


class ControlReviewDecision(Base, TimestampMixin, TenantMixin):
    """A human conclusion kept separate from immutable collector evaluations."""

    __tablename__ = "control_review_decisions"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "assessment_id",
            "control_definition_id",
            name="uq_control_review_decision_assessment_control",
        ),
        UniqueConstraint("tenant_id", "id", name="uq_control_review_decisions_tenant_id"),
        ForeignKeyConstraint(
            ["tenant_id", "assessment_id"],
            ["assessments.tenant_id", "assessments.id"],
            name="fk_control_review_decisions_tenant_assessment",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "control_definition_id"],
            ["control_definitions.tenant_id", "control_definitions.id"],
            name="fk_control_review_decisions_tenant_definition",
            ondelete="RESTRICT",
        ),
        Index("ix_control_review_decisions_tenant_assessment", "tenant_id", "assessment_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    assessment_id: Mapped[str] = mapped_column(String(36), index=True)
    control_definition_id: Mapped[str] = mapped_column(String(36), index=True)
    control_id: Mapped[str] = mapped_column(String(100), nullable=False)
    outcome: Mapped[ControlDecisionOutcome] = mapped_column(
        Enum(ControlDecisionOutcome, native_enum=False, length=24), nullable=False
    )
    rationale: Mapped[str] = mapped_column(String(2000), nullable=False)
    decided_by: Mapped[str] = mapped_column(String(160), nullable=False)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class FindingException(Base, TimestampMixin, TenantMixin):
    __tablename__ = "finding_exceptions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_finding_exceptions_tenant_id"),
        UniqueConstraint(
            "tenant_id", "finding_id", "request_key", name="uq_finding_exception_request"
        ),
        ForeignKeyConstraint(
            ["tenant_id", "finding_id"],
            ["findings.tenant_id", "findings.id"],
            name="fk_finding_exceptions_tenant_finding",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "approved_by IS NULL OR approved_by <> requested_by",
            name="finding_exception_separation_of_duties",
        ),
        CheckConstraint("expires_at > requested_at", name="finding_exception_positive_validity"),
        Index(
            "uq_finding_exception_active",
            "tenant_id",
            "finding_id",
            unique=True,
            postgresql_where=text("status = 'APPROVED'"),
            sqlite_where=text("status = 'APPROVED'"),
        ),
        Index("ix_finding_exception_expiry", "status", "expires_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(String(36), index=True)
    request_key: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[FindingExceptionStatus] = mapped_column(
        Enum(FindingExceptionStatus, native_enum=False, length=24), nullable=False
    )
    justification: Mapped[str] = mapped_column(String(4000), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(160), nullable=False)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(160))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decision_reason: Mapped[str | None] = mapped_column(String(2000))
    revoked_by: Mapped[str | None] = mapped_column(String(160))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revocation_reason: Mapped[str | None] = mapped_column(String(2000))


class IntegrationOutbox(Base, TimestampMixin, TenantMixin):
    __tablename__ = "integration_outbox"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_integration_outbox_tenant_id"),
        UniqueConstraint(
            "tenant_id", "destination", "deduplication_key", name="uq_outbox_delivery"
        ),
        Index("ix_outbox_lease_queue", "status", "available_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    destination: Mapped[IntegrationDestination] = mapped_column(
        Enum(IntegrationDestination, native_enum=False, length=24), nullable=False
    )
    aggregate_type: Mapped[str] = mapped_column(String(80), nullable=False)
    aggregate_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_type: Mapped[str] = mapped_column(String(120), nullable=False)
    event_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    deduplication_key: Mapped[str] = mapped_column(String(160), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    status: Mapped[DeliveryStatus] = mapped_column(
        Enum(DeliveryStatus, native_enum=False, length=24),
        default=DeliveryStatus.PENDING,
        nullable=False,
    )
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    leased_by: Mapped[str | None] = mapped_column(String(128))
    lease_token: Mapped[str | None] = mapped_column(String(36))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=10, nullable=False)
    last_error: Mapped[str | None] = mapped_column(String(4000))
    external_reference: Mapped[str | None] = mapped_column(String(512))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class IntegrationInbox(Base, TenantMixin):
    __tablename__ = "integration_inbox"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_integration_inbox_tenant_id"),
        UniqueConstraint("tenant_id", "source", "message_id", name="uq_inbox_message"),
        Index("ix_inbox_tenant_received", "tenant_id", "received_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source: Mapped[IntegrationDestination] = mapped_column(
        Enum(IntegrationDestination, native_enum=False, length=24), nullable=False
    )
    message_id: Mapped[str] = mapped_column(String(160), nullable=False)
    event_type: Mapped[str] = mapped_column(String(120), nullable=False)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[InboxStatus] = mapped_column(
        Enum(InboxStatus, native_enum=False, length=24), nullable=False
    )
    received_by: Mapped[str] = mapped_column(String(160), nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    processed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


def prevent_immutable_record_mutation(*_: object) -> None:
    raise ValueError("immutable governance records cannot be changed or deleted")


for immutable_model in (
    ControlPackVersion,
    ControlDefinition,
    ControlResult,
    IntegrationInbox,
):
    event.listen(immutable_model, "before_update", prevent_immutable_record_mutation)
    event.listen(immutable_model, "before_delete", prevent_immutable_record_mutation)
