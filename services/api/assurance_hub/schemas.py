from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_serializer,
    field_validator,
    model_validator,
)

from .models import (
    AssessmentStatus,
    AssetEnvironment,
    ControlDomain,
    DatabasePlatform,
    FindingSeverity,
    FindingStatus,
    LifecycleStatus,
    ReviewStatus,
    WorkStatus,
)

SafeName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=160)]
ResourceId = Annotated[str, StringConstraints(pattern=r"^[a-f0-9-]{36}$")]
LeaseToken = Annotated[
    str,
    StringConstraints(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    ),
]
ProbeId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9_.-]{3,100}$")]
JsonScalar = str | int | float | bool | None
SENSITIVE_KEYS = {
    "credential",
    "dsn",
    "password",
    "private_key",
    "secret",
    "sql",
    "token",
}


def validate_safe_scalar_map(
    value: dict[str, JsonScalar], *, maximum: int = 100, maximum_string_length: int = 2000
) -> dict[str, JsonScalar]:
    if len(value) > maximum:
        raise ValueError(f"mapping cannot contain more than {maximum} entries")
    for key, item in value.items():
        if len(key) > 100 or key.lower() in SENSITIVE_KEYS:
            raise ValueError(f"attribute key '{key}' is forbidden or too long")
        if isinstance(item, str) and len(item) > maximum_string_length:
            raise ValueError(f"attribute value for '{key}' is too long")
    return value


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    @field_serializer("*", when_used="json", check_fields=False)
    def serialize_datetimes_as_utc(self, value: Any) -> Any:
        """Make SQLite's timezone-naive UTC values unambiguous to API clients."""
        if not isinstance(value, datetime):
            return value
        timestamp = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
        return timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z")


class ORMModel(StrictModel):
    model_config = ConfigDict(extra="ignore", from_attributes=True)


class ErrorDetail(StrictModel):
    code: str
    message: str
    request_id: str
    details: Any | None = None


class ErrorEnvelope(StrictModel):
    error: ErrorDetail


class Page[T](StrictModel):
    items: list[T]
    next_cursor: str | None = None
    limit: int


class AssetCreate(StrictModel):
    external_id: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    name: SafeName
    platform: DatabasePlatform
    version: Annotated[str, StringConstraints(min_length=1, max_length=80)]
    edition: Annotated[str, StringConstraints(max_length=120)] | None = None
    environment: AssetEnvironment
    owner: SafeName
    criticality: Literal["critical", "high", "medium", "low"] = "medium"
    tags: dict[str, str] = Field(default_factory=dict, max_length=50)


class AssetOut(ORMModel):
    id: str
    external_id: str
    name: str
    platform: DatabasePlatform
    version: str
    edition: str | None
    environment: AssetEnvironment
    owner: str
    criticality: str
    status: LifecycleStatus
    tags: dict[str, str]
    created_at: datetime
    updated_at: datetime


class SensitiveColumnOut(StrictModel):
    id: ResourceId
    asset_id: ResourceId
    asset_name: SafeName
    platform: Literal[DatabasePlatform.MYSQL]
    schema_name: Annotated[str, StringConstraints(min_length=1, max_length=128)] = Field(
        serialization_alias="schema"
    )
    table: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    column: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    classification: Literal["restricted", "confidential", "internal"]
    data_type: Annotated[str, StringConstraints(min_length=1, max_length=160)]
    confidence: int = Field(ge=0, le=100)
    protection: Literal["unknown"]
    created_at: datetime


_SECRET_REF = re.compile(
    r"^(vault|azure-key-vault|aws-secrets-manager|gcp-secret-manager|cyberark)://[A-Za-z0-9._/\-#]+$"
)
_ENDPOINT_REF = re.compile(
    r"^dns://(?P<host>[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?):"
    r"(?P<port>[0-9]{1,5})/(?P<database>[A-Za-z0-9][A-Za-z0-9_.-]{0,127})$"
)


class ConnectorCreate(StrictModel):
    asset_id: ResourceId
    name: SafeName
    platform: DatabasePlatform
    endpoint_ref: Annotated[str, StringConstraints(min_length=4, max_length=512)]
    secret_ref: Annotated[str, StringConstraints(min_length=8, max_length=1024)]
    collector_id: Annotated[str, StringConstraints(min_length=1, max_length=128)] | None = None
    capabilities: list[Annotated[str, StringConstraints(min_length=1, max_length=80)]] = Field(
        default_factory=list, max_length=50
    )
    config: dict[str, JsonScalar] = Field(default_factory=dict)

    @field_validator("endpoint_ref")
    @classmethod
    def validate_endpoint_ref(cls, value: str) -> str:
        match = _ENDPOINT_REF.fullmatch(value)
        if not match or ".." in match.group("host"):
            raise ValueError("endpoint_ref must be dns://host:port/database without credentials")
        port = int(match.group("port"))
        if port < 1 or port > 65_535:
            raise ValueError("endpoint_ref port must be between 1 and 65535")
        return value

    @field_validator("secret_ref")
    @classmethod
    def validate_secret_ref(cls, value: str) -> str:
        if not _SECRET_REF.fullmatch(value):
            raise ValueError("secret_ref must reference an approved enterprise secret manager")
        return value

    @model_validator(mode="after")
    def reject_inline_secrets(self) -> ConnectorCreate:
        forbidden = {"password", "secret", "token", "private_key", "connection_string", "dsn"}

        def walk(value: object) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    if key.lower() in forbidden:
                        raise ValueError(f"inline credential field '{key}' is forbidden")
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(self.config)
        return self

    @field_validator("config")
    @classmethod
    def safe_config(cls, value: dict[str, JsonScalar]) -> dict[str, JsonScalar]:
        return validate_safe_scalar_map(value, maximum=50)


class ConnectorConfigUpdate(StrictModel):
    config: dict[str, JsonScalar] = Field(default_factory=dict)

    @model_validator(mode="after")
    def reject_inline_secrets(self) -> ConnectorConfigUpdate:
        forbidden = {"password", "secret", "token", "private_key", "connection_string", "dsn"}

        def walk(value: object) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    if key.lower() in forbidden:
                        raise ValueError(f"inline credential field '{key}' is forbidden")
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(self.config)
        return self

    @field_validator("config")
    @classmethod
    def safe_config(cls, value: dict[str, JsonScalar]) -> dict[str, JsonScalar]:
        return validate_safe_scalar_map(value, maximum=50)


class ConnectorOut(ORMModel):
    id: str
    asset_id: str
    name: str
    platform: DatabasePlatform
    endpoint_ref: str
    collector_id: str | None
    status: str
    last_heartbeat_at: datetime | None
    capabilities: list[str]
    config: dict[str, JsonScalar]
    created_at: datetime
    updated_at: datetime


class AssessmentCreate(StrictModel):
    asset_id: ResourceId
    control_pack: Annotated[str, StringConstraints(min_length=1, max_length=120)]
    control_pack_version: Annotated[str, StringConstraints(min_length=1, max_length=40)]


class AssessmentOut(ORMModel):
    id: str
    asset_id: str
    control_pack: str
    control_pack_version: str
    status: AssessmentStatus
    score: float | None
    initiated_by: str
    started_at: datetime | None
    completed_at: datetime | None
    summary: dict[str, JsonScalar]
    created_at: datetime
    updated_at: datetime


class FindingCreate(StrictModel):
    assessment_id: ResourceId
    asset_id: ResourceId
    control_id: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    fingerprint: Annotated[str, StringConstraints(min_length=8, max_length=128)]
    domain: ControlDomain
    title: Annotated[str, StringConstraints(min_length=3, max_length=240)]
    description: Annotated[str, StringConstraints(min_length=3, max_length=8000)]
    severity: FindingSeverity
    owner: SafeName | None = None
    due_at: datetime | None = None
    remediation: Annotated[str, StringConstraints(min_length=3, max_length=8000)]
    risk_context: dict[str, JsonScalar] = Field(default_factory=dict)

    @field_validator("risk_context")
    @classmethod
    def safe_risk_context(cls, value: dict[str, JsonScalar]) -> dict[str, JsonScalar]:
        return validate_safe_scalar_map(value, maximum=50)


class FindingUpdate(StrictModel):
    # Risk acceptance is exclusively controlled by the governed exception
    # workflow. False-positive disposition is also intentionally excluded: it
    # closes a finding without remediation and needs its own adjudication
    # workflow before it can be exposed as a writable state.
    status: Literal[
        FindingStatus.OPEN,
        FindingStatus.IN_PROGRESS,
        FindingStatus.RESOLVED,
    ]
    owner: SafeName | None = None
    due_at: datetime | None = None
    reason: Annotated[str, StringConstraints(min_length=3, max_length=2000)]


class FindingOut(ORMModel):
    id: str
    assessment_id: str
    asset_id: str
    control_id: str
    fingerprint: str
    domain: ControlDomain
    title: str
    description: str
    severity: FindingSeverity
    status: FindingStatus
    owner: str | None
    due_at: datetime | None
    remediation: str
    risk_context: dict[str, JsonScalar]
    created_at: datetime
    updated_at: datetime


class ScanJobPayload(StrictModel):
    probe_ids: list[ProbeId] = Field(min_length=1, max_length=100)
    schemas: list[Annotated[str, StringConstraints(min_length=1, max_length=128)]] = Field(
        default_factory=list, max_length=100
    )
    metadata: dict[str, JsonScalar] = Field(default_factory=dict)

    @field_validator("probe_ids")
    @classmethod
    def unique_probes(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("probe_ids must be unique")
        return value

    @field_validator("metadata")
    @classmethod
    def safe_metadata(cls, value: dict[str, JsonScalar]) -> dict[str, JsonScalar]:
        return validate_safe_scalar_map(value, maximum=25)


class MaskingCopyJobPayload(StrictModel):
    """Non-secret, server-derived contract for the one approved local copy plan."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=True)

    policy_id: ResourceId
    asset_id: ResourceId
    source_database: Literal["insurance_sample"]
    target_database: Annotated[
        str,
        StringConstraints(pattern=r"^insurance_sample_masked(?:_[a-f0-9]{12})?$"),
    ]
    row_cap: Literal[500]

    @field_validator("row_cap", mode="before")
    @classmethod
    def exact_job_row_cap_type(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("row_cap must be the integer 500")
        return value


class MaskingCopyResult(StrictModel):
    """Bounded aggregate proof; it cannot contain database rows or per-row values."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=True)

    source_database: Literal["insurance_sample"]
    target_database: Annotated[
        str,
        StringConstraints(pattern=r"^insurance_sample_masked(?:_[a-f0-9]{12})?$"),
    ]
    tables_copied: int = Field(ge=1, le=500)
    rows_copied: int = Field(ge=1, le=250_000)
    columns_masked: int = Field(ge=1, le=10_000)
    values_masked: int = Field(ge=1, le=250_000)
    row_cap: Literal[500]
    source_before_hmac: Annotated[str, StringConstraints(pattern=r"^[a-fA-F0-9]{64}$")]
    source_after_hmac: Annotated[str, StringConstraints(pattern=r"^[a-fA-F0-9]{64}$")]
    target_manifest_hmac: Annotated[str, StringConstraints(pattern=r"^[a-fA-F0-9]{64}$")]
    manifest_sha256: Annotated[str, StringConstraints(pattern=r"^[a-fA-F0-9]{64}$")]
    key_fingerprint: Annotated[str, StringConstraints(pattern=r"^[a-fA-F0-9]{16}$")]
    source_digest_match: Literal[True]
    target_counts_match: Literal[True]
    foreign_keys_valid: Literal[True]
    raw_values_exported: Literal[False]
    algorithm: Literal["hmac-sha256-local-v1"]

    @field_validator(
        "source_before_hmac",
        "source_after_hmac",
        "target_manifest_hmac",
        "manifest_sha256",
        "key_fingerprint",
    )
    @classmethod
    def normalize_masking_digest(cls, value: str) -> str:
        return value.lower()

    @field_validator("row_cap", mode="before")
    @classmethod
    def exact_result_row_cap_type(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("row_cap must be the integer 500")
        return value

    @field_validator(
        "source_digest_match",
        "target_counts_match",
        "foreign_keys_valid",
        "raw_values_exported",
        mode="before",
    )
    @classmethod
    def exact_masking_boolean_types(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("masking proof flags must be JSON booleans")
        return value

    @model_validator(mode="after")
    def aggregate_proof_is_consistent(self) -> MaskingCopyResult:
        if self.rows_copied > self.tables_copied * self.row_cap:
            raise ValueError("rows_copied cannot exceed 500 rows per processed table")
        if self.source_before_hmac != self.source_after_hmac:
            raise ValueError("source HMACs must match after a successful copy")
        manifest = {
            "algorithm": self.algorithm,
            "columns_masked": self.columns_masked,
            "foreign_keys_valid": self.foreign_keys_valid,
            "key_fingerprint": self.key_fingerprint,
            "raw_values_exported": self.raw_values_exported,
            "row_cap": self.row_cap,
            "rows_copied": self.rows_copied,
            "source_after_hmac": self.source_after_hmac,
            "source_before_hmac": self.source_before_hmac,
            "source_database": self.source_database,
            "tables_copied": self.tables_copied,
            "target_counts_match": self.target_counts_match,
            "target_database": self.target_database,
            "target_manifest_hmac": self.target_manifest_hmac,
            "values_masked": self.values_masked,
        }
        expected_manifest_sha256 = hashlib.sha256(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if not hmac.compare_digest(self.manifest_sha256, expected_manifest_sha256):
            raise ValueError("manifest_sha256 does not match the canonical masking manifest")
        return self


class ScanJobCreate(StrictModel):
    connector_id: ResourceId
    assessment_id: ResourceId | None = None
    job_type: Literal["inventory", "control_assessment", "access_review", "classification"]
    deduplication_key: Annotated[str, StringConstraints(min_length=8, max_length=160)]
    payload: ScanJobPayload
    available_at: datetime | None = None
    max_attempts: int = Field(default=5, ge=1, le=20)


class ScanJobOut(ORMModel):
    id: str
    connector_id: str
    assessment_id: str | None
    job_type: str
    deduplication_key: str
    status: WorkStatus
    payload: ScanJobPayload | MaskingCopyJobPayload
    available_at: datetime
    leased_by: str | None
    lease_token: LeaseToken | None
    lease_expires_at: datetime | None
    attempts: int
    max_attempts: int
    last_error: str | None
    result: JobResult
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class CollectorLeaseOut(StrictModel):
    """Minimal capability-bearing contract exposed to an assigned collector."""

    id: ResourceId
    connector_id: ResourceId
    assessment_id: ResourceId | None
    job_type: Literal[
        "inventory", "control_assessment", "access_review", "classification", "masking_copy"
    ]
    status: Literal[WorkStatus.LEASED, WorkStatus.RUNNING]
    payload: ScanJobPayload | MaskingCopyJobPayload
    lease_token: LeaseToken
    lease_expires_at: datetime
    attempts: int = Field(ge=1, le=20)
    max_attempts: int = Field(ge=1, le=20)


class HeartbeatRequest(StrictModel):
    collector_id: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    version: Annotated[str, StringConstraints(min_length=1, max_length=40)]
    capabilities: list[str] = Field(default_factory=list, max_length=50)


class HeartbeatResponse(StrictModel):
    accepted: bool
    server_time: datetime
    next_heartbeat_seconds: int


class CollectorReadyOut(StrictModel):
    status: Literal["ok"] = "ok"
    collector_id: Annotated[str, StringConstraints(min_length=1, max_length=160)]


class JobLeaseRequest(StrictModel):
    collector_id: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    supported_job_types: list[
        Literal[
            "inventory", "control_assessment", "access_review", "classification", "masking_copy"
        ]
    ] = Field(min_length=1, max_length=10)


class ProbeExecutionResult(StrictModel):
    probe_id: ProbeId
    # `collected` means transport/query execution succeeded. Pass/fail is reserved
    # for a deterministic, versioned control evaluator in the control plane.
    outcome: Literal[
        "collected",
        "error",
        "not_applicable",
        "unsupported",
        "insufficient_privilege",
    ]
    duration_ms: int = Field(ge=0, le=600_000)
    row_count: int = Field(default=0, ge=0, le=100)
    evidence_sha256: Annotated[str, StringConstraints(pattern=r"^[a-fA-F0-9]{64}$")] | None = None
    message: Annotated[str, StringConstraints(max_length=1000)] | None = None
    observations: list[dict[str, JsonScalar]] = Field(default_factory=list, max_length=100)

    @field_validator("evidence_sha256")
    @classmethod
    def normalize_evidence_digest(cls, value: str | None) -> str | None:
        return value.lower() if value is not None else None

    @field_validator("observations")
    @classmethod
    def bounded_observations(
        cls, value: list[dict[str, JsonScalar]]
    ) -> list[dict[str, JsonScalar]]:
        for observation in value:
            validate_safe_scalar_map(observation, maximum=25, maximum_string_length=512)
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        if len(encoded) > 128 * 1024:
            raise ValueError("observations cannot exceed 128 KiB")
        return value

    @model_validator(mode="after")
    def evidence_is_structurally_consistent(self) -> ProbeExecutionResult:
        if self.row_count != len(self.observations):
            raise ValueError("row_count must equal the number of observations")
        if self.outcome == "collected":
            if self.evidence_sha256 is None:
                raise ValueError("collected evidence requires evidence_sha256")
        elif self.row_count or self.observations or self.evidence_sha256 is not None:
            raise ValueError(
                "non-collected outcomes cannot contain observations, rows, or an evidence digest"
            )
        return self


class JobResult(StrictModel):
    probe_results: list[ProbeExecutionResult] = Field(default_factory=list, max_length=100)
    summary: dict[str, JsonScalar] = Field(default_factory=dict)

    @field_validator("summary")
    @classmethod
    def safe_summary(cls, value: dict[str, JsonScalar]) -> dict[str, JsonScalar]:
        return validate_safe_scalar_map(value, maximum=50)


class JobCompletionRequest(StrictModel):
    collector_id: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    lease_token: LeaseToken
    success: bool
    result: JobResult = Field(default_factory=JobResult)
    error: Annotated[str, StringConstraints(max_length=4000)] | None = None

    @model_validator(mode="after")
    def validate_outcome(self) -> JobCompletionRequest:
        if not self.success and not self.error:
            raise ValueError("error is required for a failed job")
        if self.success and self.error:
            raise ValueError("error must be omitted for a successful job")
        if not self.success and self.result.probe_results:
            raise ValueError("a failed job cannot carry probe results")
        return self


class JobLeaseRenewRequest(StrictModel):
    collector_id: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    lease_token: LeaseToken


class ConnectorRuntimeConfigOut(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    connector_id: ResourceId
    platform: DatabasePlatform
    endpoint_ref: Annotated[str, StringConstraints(min_length=4, max_length=512)]
    secret_ref: Annotated[str, StringConstraints(min_length=8, max_length=1024)]
    config: dict[str, JsonScalar]
    updated_at: datetime


class EvidenceCreate(StrictModel):
    assessment_id: ResourceId
    finding_id: ResourceId | None = None
    control_id: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    evidence_type: Literal["configuration", "query_result", "attestation", "artifact_reference"]
    uri: Annotated[str, StringConstraints(max_length=1024)] | None = None
    sha256: Annotated[str, StringConstraints(pattern=r"^[a-fA-F0-9]{64}$")]
    collected_at: datetime
    collector_version: Annotated[str, StringConstraints(min_length=1, max_length=40)]
    attributes: dict[str, JsonScalar] = Field(default_factory=dict)

    @field_validator("uri")
    @classmethod
    def safe_evidence_uri(cls, value: str | None) -> str | None:
        if value is not None:
            if not value.startswith(("evidence://", "s3://", "gs://", "azure-blob://")):
                raise ValueError("uri must use an approved evidence-store scheme")
            if "?" in value or "@" in value:
                raise ValueError(
                    "uri cannot contain embedded credentials or signed query parameters"
                )
        return value

    @field_validator("sha256")
    @classmethod
    def normalize_digest(cls, value: str) -> str:
        return value.lower()

    @field_validator("attributes")
    @classmethod
    def safe_attributes(cls, value: dict[str, JsonScalar]) -> dict[str, JsonScalar]:
        return validate_safe_scalar_map(value, maximum=100)


class EvidenceOut(ORMModel):
    id: str
    assessment_id: str
    finding_id: str | None
    control_id: str
    evidence_type: str
    uri: str | None
    sha256: str
    collected_at: datetime
    collector_version: str
    attributes: dict[str, JsonScalar]
    created_at: datetime
    updated_at: datetime


class MaskingPolicyCreate(StrictModel):
    name: SafeName
    version: int = Field(default=1, ge=1)
    classification: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    strategy: Literal["redact", "tokenize", "hash", "substitute", "shuffle", "format_preserving"]
    target_environment: Literal[
        AssetEnvironment.DEVELOPMENT, AssetEnvironment.TEST, AssetEnvironment.STAGING
    ]
    parameters: dict[str, JsonScalar] = Field(default_factory=dict)

    @field_validator("parameters")
    @classmethod
    def safe_parameters(cls, value: dict[str, JsonScalar]) -> dict[str, JsonScalar]:
        return validate_safe_scalar_map(value, maximum=50)


class MaskingPolicyTransition(StrictModel):
    action: Literal["approve", "record_execution", "validate", "archive"]
    note: Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=1000)]
    reference: (
        Annotated[str, StringConstraints(strip_whitespace=True, max_length=240)] | None
    ) = None

    @model_validator(mode="after")
    def execution_requires_reference(self) -> MaskingPolicyTransition:
        if self.action == "record_execution" and not self.reference:
            raise ValueError("recording execution requires a non-secret evidence reference")
        return self


class MaskingPolicyOut(ORMModel):
    id: str
    name: str
    version: int
    classification: str
    strategy: str
    target_environment: AssetEnvironment
    enabled: bool
    parameters: dict[str, JsonScalar]
    approved_by: str | None
    created_at: datetime
    updated_at: datetime


class AccessReviewCreate(StrictModel):
    asset_id: ResourceId
    name: SafeName
    reviewer: SafeName
    scope: dict[str, JsonScalar] = Field(default_factory=dict)
    due_at: datetime

    @field_validator("scope")
    @classmethod
    def safe_scope(cls, value: dict[str, JsonScalar]) -> dict[str, JsonScalar]:
        return validate_safe_scalar_map(value, maximum=50)


class AccessReviewUpdate(StrictModel):
    status: ReviewStatus
    decision_summary: dict[str, JsonScalar] = Field(default_factory=dict)
    reason: Annotated[str, StringConstraints(min_length=3, max_length=2000)]

    @field_validator("decision_summary")
    @classmethod
    def safe_decision_summary(cls, value: dict[str, JsonScalar]) -> dict[str, JsonScalar]:
        return validate_safe_scalar_map(value, maximum=50)


class AccessReviewOut(ORMModel):
    id: str
    asset_id: str
    name: str
    reviewer: str
    scope: dict[str, JsonScalar]
    status: ReviewStatus
    due_at: datetime
    decision_summary: dict[str, JsonScalar]
    created_at: datetime
    updated_at: datetime


class AuditEventOut(ORMModel):
    id: str
    occurred_at: datetime
    actor: str
    action: str
    resource_type: str
    resource_id: str | None
    request_id: str
    source_ip: str | None
    outcome: str
    attributes: dict[str, JsonScalar]


class DashboardSummary(StrictModel):
    assets: int = Field(ge=0)
    connectors: int = Field(ge=0)
    open_findings: int = Field(ge=0)
    assessments: int = Field(ge=0)
    masking_policies: int = Field(ge=0)
    access_reviews: int = Field(ge=0)
    generated_at: datetime


class IdempotencyRecoveryRequest(StrictModel):
    resolution: Literal["reject_replay"]
    reason: Annotated[str, StringConstraints(min_length=10, max_length=2000)]


class IdempotencyRecoveryOut(StrictModel):
    id: ResourceId
    state: Literal["completed"]
    response_status: Literal[409]
    resolved_at: datetime
    resolved_by: str


class IdempotencyRecoveryCandidate(StrictModel):
    id: ResourceId
    actor_subject: str
    method: str
    path: str
    state: Literal["pending", "review_required"]
    created_at: datetime
    expires_at: datetime
    idempotency_key_sha256: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]


class HealthResponse(StrictModel):
    status: Literal["ok", "degraded", "unavailable"]
    service: str
    version: str
    checks: dict[str, str] = Field(default_factory=dict)
