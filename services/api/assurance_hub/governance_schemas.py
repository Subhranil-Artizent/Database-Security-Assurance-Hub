from __future__ import annotations

import json
from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, field_validator, model_validator

from .models import (
    AssetEnvironment,
    ControlDecisionOutcome,
    ControlDomain,
    ControlPackStatus,
    ControlResultOutcome,
    DatabasePlatform,
    DeliveryStatus,
    FindingExceptionStatus,
    FindingSeverity,
    InboxStatus,
    IntegrationDestination,
)
from .schemas import (
    AssessmentOut,
    JsonScalar,
    LeaseToken,
    ORMModel,
    ProbeExecutionResult,
    ProbeId,
    ResourceId,
    ScanJobOut,
    StrictModel,
    validate_safe_scalar_map,
)

SemVer = Annotated[
    str,
    StringConstraints(pattern=r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"),
]
ControlId = Annotated[
    str,
    StringConstraints(
        pattern=(
            r"^(oracle|postgresql|sybase|mysql)\."
            r"(encryption|data-protection|access-security|data-masking)\."
            r"[a-z0-9]+(?:-[a-z0-9]+)*$"
        ),
        max_length=100,
    ),
]
SafeEventName = Annotated[
    str, StringConstraints(pattern=r"^[a-z][a-z0-9_.-]{2,119}$", max_length=120)
]
SafeKey = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._:-]{8,160}$", max_length=160)]


def unique_strings(value: list[str]) -> list[str]:
    if len(value) != len(set(value)):
        raise ValueError("list entries must be unique")
    return value


class ControlDefinitionPublish(StrictModel):
    control_id: ControlId
    domain: ControlDomain
    title: Annotated[str, StringConstraints(min_length=8, max_length=140)]
    objective: Annotated[str, StringConstraints(min_length=24, max_length=600)]
    severity: FindingSeverity
    environments: list[AssetEnvironment] = Field(min_length=1, max_length=5)
    version_scope: Literal["vendor_supported", "customer_validated"]
    applicability_notes: Annotated[str, StringConstraints(min_length=12, max_length=400)]
    assessment_mode: Literal["automated_evidence", "manual_evidence"]
    probe_ids: list[ProbeId] = Field(default_factory=list, max_length=10)
    decision_mode: Literal["analyst_review_required"] = "analyst_review_required"
    manual_evidence_requirements: list[
        Annotated[str, StringConstraints(min_length=12, max_length=300)]
    ] = Field(default_factory=list, max_length=10)
    allowed_fields: list[
        Annotated[str, StringConstraints(pattern=r"^[A-Za-z_][A-Za-z0-9_$]*$", max_length=100)]
    ] = Field(default_factory=list, max_length=30)
    limitations: list[Annotated[str, StringConstraints(min_length=16, max_length=400)]] = Field(
        min_length=1, max_length=10
    )
    remediation_guidance: Annotated[str, StringConstraints(min_length=20, max_length=600)]

    @field_validator(
        "environments",
        "probe_ids",
        "manual_evidence_requirements",
        "allowed_fields",
        "limitations",
    )
    @classmethod
    def entries_are_unique(cls, value: list[str]) -> list[str]:
        return unique_strings(value)

    @model_validator(mode="after")
    def assessment_contract(self) -> ControlDefinitionPublish:
        if self.assessment_mode == "automated_evidence":
            if not self.probe_ids or self.manual_evidence_requirements:
                raise ValueError(
                    "automated controls require probes and cannot require manual evidence"
                )
        elif self.probe_ids or not self.manual_evidence_requirements:
            raise ValueError("manual controls require evidence requirements and cannot use probes")
        return self


class ControlPackPublish(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    pack_id: Annotated[
        str,
        StringConstraints(
            pattern=r"^aegisdb\.database-security\.(oracle|postgresql|sybase|mysql)$",
            max_length=120,
        ),
    ]
    version: SemVer
    platform: DatabasePlatform
    title: Annotated[str, StringConstraints(min_length=8, max_length=120)]
    description: Annotated[str, StringConstraints(min_length=24, max_length=500)]
    status: ControlPackStatus
    released_at: datetime
    supersedes: SemVer | None = None
    immutable: Literal[True] = True
    controls: list[ControlDefinitionPublish] = Field(min_length=1, max_length=100)

    @field_validator("controls")
    @classmethod
    def unique_control_ids(
        cls, value: list[ControlDefinitionPublish]
    ) -> list[ControlDefinitionPublish]:
        identifiers = [control.control_id for control in value]
        unique_strings(identifiers)
        return value

    @model_validator(mode="after")
    def pack_matches_platform(self) -> ControlPackPublish:
        expected_suffix = f".{self.platform.value}"
        if not self.pack_id.endswith(expected_suffix):
            raise ValueError("pack_id must match platform")
        for control in self.controls:
            if not control.control_id.startswith(f"{self.platform.value}."):
                raise ValueError("every control ID must match the pack platform")
        if self.supersedes == self.version:
            raise ValueError("a pack version cannot supersede itself")
        return self


class ControlDefinitionOut(ORMModel):
    id: str
    control_pack_version_id: str
    control_id: str
    domain: ControlDomain
    title: str
    objective: str
    severity: FindingSeverity
    environments: list[AssetEnvironment]
    version_scope: str
    applicability_notes: str
    assessment_mode: str
    probe_ids: list[str]
    decision_mode: str
    manual_evidence_requirements: list[str]
    allowed_fields: list[str]
    limitations: list[str]
    remediation_guidance: str
    definition_sha256: str
    created_at: datetime


class ControlPackVersionOut(ORMModel):
    id: str
    pack_id: str
    version: str
    schema_version: str
    platform: DatabasePlatform
    title: str
    description: str
    status: ControlPackStatus
    released_at: datetime
    supersedes: str | None
    immutable: bool
    content_sha256: str
    created_by: str
    created_at: datetime


class ControlPackDetail(ControlPackVersionOut):
    controls: list[ControlDefinitionOut]


class ControlEvaluationRequest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    assessment_id: ResourceId
    control_definition_id: ResourceId
    source_job_id: ResourceId | None = None
    probe_results: list[ProbeExecutionResult] = Field(default_factory=list, max_length=10)
    evidence_ids: list[ResourceId] = Field(default_factory=list, max_length=100)

    @field_validator("evidence_ids")
    @classmethod
    def unique_evidence(cls, value: list[str]) -> list[str]:
        return unique_strings(value)


class ControlResultOut(ORMModel):
    id: str
    assessment_id: str
    control_definition_id: str
    source_job_id: str | None
    control_id: str
    evaluation_key: str
    outcome: ControlResultOutcome
    evaluator_version: str
    input_sha256: str
    rationale: str
    evidence_count: int
    probe_outcomes: list[str]
    evaluated_at: datetime
    created_at: datetime


class ControlReviewDecisionRequest(StrictModel):
    outcome: ControlDecisionOutcome
    rationale: Annotated[str, StringConstraints(min_length=10, max_length=2000)]


class ControlReviewDecisionOut(ORMModel):
    id: str
    assessment_id: str
    control_definition_id: str
    control_id: str
    outcome: ControlDecisionOutcome
    rationale: str
    decided_by: str
    decided_at: datetime
    created_at: datetime
    updated_at: datetime


class AssessmentReviewControlOut(StrictModel):
    definition: ControlDefinitionOut
    collection_result: ControlResultOut | None
    evidence_ids: list[str]
    observations: list[dict[str, JsonScalar]]
    decision: ControlReviewDecisionOut | None
    allowed_outcomes: list[ControlDecisionOutcome]


class AssessmentReviewOut(StrictModel):
    assessment: AssessmentOut
    controls: list[AssessmentReviewControlOut]
    decided_count: int = Field(ge=0)
    total_controls: int = Field(ge=0)
    ready_to_finalize: bool
    blocking_reasons: list[str]


class AssessmentFinalizeRequest(StrictModel):
    confirmation: Literal["finalize"]


class AssessmentRunRequest(StrictModel):
    asset_id: ResourceId
    connector_id: ResourceId
    control_pack_version_id: ResourceId
    run_key: SafeKey
    max_attempts: int = Field(default=5, ge=1, le=20)


class AssessmentRunOut(StrictModel):
    assessment: AssessmentOut
    job: ScanJobOut


class FindingExceptionRequest(StrictModel):
    request_key: SafeKey
    justification: Annotated[str, StringConstraints(min_length=20, max_length=4000)]
    expires_at: datetime


class FindingExceptionDecision(StrictModel):
    decision: Literal["approve", "reject"]
    reason: Annotated[str, StringConstraints(min_length=10, max_length=2000)]


class FindingExceptionRevoke(StrictModel):
    reason: Annotated[str, StringConstraints(min_length=10, max_length=2000)]


class FindingExceptionOut(ORMModel):
    id: str
    finding_id: str
    request_key: str
    status: FindingExceptionStatus
    justification: str
    requested_by: str
    requested_at: datetime
    expires_at: datetime
    approved_by: str | None
    approved_at: datetime | None
    decision_reason: str | None
    revoked_by: str | None
    revoked_at: datetime | None
    revocation_reason: str | None
    created_at: datetime
    updated_at: datetime


class OutboxLeaseRequest(StrictModel):
    worker_id: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    destinations: list[IntegrationDestination] = Field(min_length=1, max_length=3)

    @field_validator("destinations")
    @classmethod
    def unique_destinations(
        cls, value: list[IntegrationDestination]
    ) -> list[IntegrationDestination]:
        if len(value) != len(set(value)):
            raise ValueError("destinations must be unique")
        return value


class OutboxLeaseRenewRequest(StrictModel):
    worker_id: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    lease_token: LeaseToken


class OutboxCompletionRequest(OutboxLeaseRenewRequest):
    success: bool
    external_reference: Annotated[str, StringConstraints(max_length=512)] | None = None
    error: Annotated[str, StringConstraints(max_length=4000)] | None = None

    @model_validator(mode="after")
    def valid_completion(self) -> OutboxCompletionRequest:
        if self.success and self.error:
            raise ValueError("error must be omitted for successful delivery")
        if not self.success and not self.error:
            raise ValueError("error is required for failed delivery")
        return self


class IntegrationOutboxOut(ORMModel):
    id: str
    destination: IntegrationDestination
    aggregate_type: str
    aggregate_id: str
    event_type: str
    event_version: int
    deduplication_key: str
    payload: dict[str, JsonScalar]
    status: DeliveryStatus
    available_at: datetime
    leased_by: str | None
    lease_token: LeaseToken | None
    lease_expires_at: datetime | None
    attempts: int
    max_attempts: int
    last_error: str | None
    external_reference: str | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class InboxAcceptRequest(StrictModel):
    worker_id: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    source: IntegrationDestination
    message_id: SafeKey
    event_type: SafeEventName
    payload: dict[str, JsonScalar] = Field(default_factory=dict)

    @field_validator("payload")
    @classmethod
    def bounded_payload(cls, value: dict[str, JsonScalar]) -> dict[str, JsonScalar]:
        validate_safe_scalar_map(value, maximum=100, maximum_string_length=2000)
        if len(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()) > 128 * 1024:
            raise ValueError("payload cannot exceed 128 KiB")
        return value


class IntegrationInboxOut(ORMModel):
    id: str
    source: IntegrationDestination
    message_id: str
    event_type: str
    payload_sha256: str
    status: InboxStatus
    received_by: str
    received_at: datetime
    processed_at: datetime
