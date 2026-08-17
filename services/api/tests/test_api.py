from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from conftest import mutation_headers
from fastapi.testclient import TestClient
from pydantic import ValidationError

from assurance_hub.config import Settings
from assurance_hub.main import create_app
from assurance_hub.schemas import MaskingCopyJobPayload, MaskingCopyResult, StrictModel

ASSET_PAYLOAD = {
    "external_id": "cmdb-oracle-001",
    "name": "Finance Oracle",
    "platform": "oracle",
    "version": "23ai",
    "edition": "Enterprise",
    "environment": "production",
    "owner": "Database Engineering",
    "criticality": "critical",
    "tags": {"domain": "finance"},
}


def test_api_timestamps_are_serialized_as_explicit_utc() -> None:
    class TimestampEnvelope(StrictModel):
        recorded_at: datetime

    naive_sqlite_value = TimestampEnvelope(recorded_at=datetime(2026, 8, 17, 1, 56))
    aware_value = TimestampEnvelope(
        recorded_at=datetime(2026, 8, 17, 7, 26, tzinfo=UTC)
    )

    assert json.loads(naive_sqlite_value.model_dump_json())["recorded_at"] == (
        "2026-08-17T01:56:00Z"
    )
    assert json.loads(aware_value.model_dump_json())["recorded_at"] == (
        "2026-08-17T07:26:00Z"
    )


def evidence_digest(observations):
    canonical = json.dumps(
        observations, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def as_admin(headers):
    return {**headers, "X-Roles": "admin"}


def create_asset(client, headers, key="create-asset-0001", payload=None):
    return client.post(
        "/api/v1/assets",
        headers=mutation_headers(headers, key),
        json=payload or ASSET_PAYLOAD,
    )


def mysql_masking_pack_payload():
    return {
        "schema_version": "1.0",
        "pack_id": "aegisdb.database-security.mysql",
        "version": "1.0.0",
        "platform": "mysql",
        "title": "MySQL local masking evidence baseline",
        "description": "Immutable local MySQL collection with manual masking evidence review.",
        "status": "active",
        "released_at": datetime.now(UTC).isoformat(),
        "immutable": True,
        "controls": [
            {
                "control_id": "mysql.data-protection.schema-inventory",
                "domain": "data_protection",
                "title": "Review local schema inventory",
                "objective": (
                    "Collect bounded schema metadata for the approved local database review."
                ),
                "severity": "medium",
                "environments": ["development"],
                "version_scope": "customer_validated",
                "applicability_notes": (
                    "This control is limited to the registered local MySQL sample."
                ),
                "assessment_mode": "automated_evidence",
                "probe_ids": ["mysql.schema_inventory"],
                "decision_mode": "analyst_review_required",
                "manual_evidence_requirements": [],
                "allowed_fields": ["table_schema", "table_name", "table_type"],
                "limitations": ["Metadata does not inspect or classify application row values."],
                "remediation_guidance": (
                    "Reconcile the local inventory before changing database objects."
                ),
            },
            {
                "control_id": "mysql.data-masking.governance-evidence",
                "domain": "data_masking",
                "title": "Review local masking governance evidence",
                "objective": (
                    "Require aggregate execution and validation evidence for the local masked copy."
                ),
                "severity": "high",
                "environments": ["development"],
                "version_scope": "customer_validated",
                "applicability_notes": (
                    "The masking copy remains subject to an explicit analyst decision."
                ),
                "assessment_mode": "manual_evidence",
                "probe_ids": [],
                "decision_mode": "analyst_review_required",
                "manual_evidence_requirements": [
                    "Aggregate masking execution and integrity validation artifact"
                ],
                "allowed_fields": [],
                "limitations": ["Aggregate proof never establishes an automatic assurance pass."],
                "remediation_guidance": (
                    "Review the aggregate proof before recording an analyst decision."
                ),
            },
        ],
    }


def setup_local_masking_review(client, tenant_headers):
    client.app.state.settings.environment = "development"
    asset = create_asset(
        client,
        tenant_headers,
        key="masking-copy-asset-01",
        payload={
            **ASSET_PAYLOAD,
            "external_id": "local-mysql-insurance-sample",
            "name": "insurance_sample",
            "platform": "mysql",
            "version": "8.4",
            "edition": "Local MySQL",
            "environment": "development",
            "tags": {"source": "local", "data_profile": "500-row-table-sample"},
        },
    ).json()
    assessment_connector = client.post(
        "/api/v1/connectors",
        headers=mutation_headers(as_admin(tenant_headers), "masking-assessment-connector-01"),
        json={
            "asset_id": asset["id"],
            "name": "local-mysql-insurance-sample-assessment",
            "platform": "mysql",
            "endpoint_ref": "dns://localhost:3306/insurance_sample",
            "secret_ref": "vault://local/database/mysql-insurance#read-only",
            "collector_id": "local-mysql-test-collector",
            "capabilities": ["control_assessment"],
        },
    )
    assert assessment_connector.status_code == 201, assessment_connector.text
    masking_connector = client.post(
        "/api/v1/connectors",
        headers=mutation_headers(as_admin(tenant_headers), "masking-copy-connector-01"),
        json={
            "asset_id": asset["id"],
            "name": "local-mysql-insurance-sample-masking-copy",
            "platform": "mysql",
            "endpoint_ref": "dns://localhost:3306/insurance_sample",
            "secret_ref": "vault://local/database/mysql-insurance-sample-masked#writer",
            "collector_id": "local-mysql-masker",
            "capabilities": ["masking_copy"],
            "config": {"enabled": True, "scope": "local_target_only"},
        },
    )
    assert masking_connector.status_code == 201, masking_connector.text
    pack = client.post(
        "/api/v1/control-pack-versions",
        headers=mutation_headers(as_admin(tenant_headers), "masking-copy-pack-01"),
        json=mysql_masking_pack_payload(),
    )
    assert pack.status_code == 201, pack.text
    run = client.post(
        "/api/v1/assessment-runs",
        headers=mutation_headers(tenant_headers, "masking-copy-assessment-run-01"),
        json={
            "asset_id": asset["id"],
            "connector_id": assessment_connector.json()["id"],
            "control_pack_version_id": pack.json()["id"],
            "run_key": "masking-copy-assessment-run-01",
            "max_attempts": 2,
        },
    )
    assert run.status_code == 201, run.text
    assessment_id = run.json()["assessment"]["id"]
    collector_headers = {
        "X-Tenant-ID": tenant_headers["X-Tenant-ID"],
        "X-Subject": "local-mysql-test-collector",
        "X-Roles": "collector",
    }
    heartbeat = client.post(
        "/api/v1/collectors/heartbeat",
        headers=mutation_headers(collector_headers, "masking-assessment-heartbeat-01"),
        json={
            "collector_id": "local-mysql-test-collector",
            "version": "0.1.0",
            "capabilities": ["control_assessment"],
        },
    )
    assert heartbeat.status_code == 200, heartbeat.text
    lease = client.post(
        "/api/v1/scan-jobs/lease",
        headers=mutation_headers(collector_headers, "masking-assessment-lease-01"),
        json={
            "collector_id": "local-mysql-test-collector",
            "supported_job_types": ["control_assessment"],
        },
    )
    assert lease.status_code == 200, lease.text
    observations = [
        {
            "table_schema": "insurance_sample",
            "table_name": "policyholders",
            "table_type": "BASE TABLE",
        }
    ]
    completed = client.post(
        f"/api/v1/scan-jobs/{lease.json()['id']}/complete",
        headers=mutation_headers(collector_headers, "masking-assessment-complete-01"),
        json={
            "collector_id": "local-mysql-test-collector",
            "lease_token": lease.json()["lease_token"],
            "success": True,
            "result": {
                "probe_results": [
                    {
                        "probe_id": "mysql.schema_inventory",
                        "outcome": "collected",
                        "duration_ms": 1,
                        "row_count": 1,
                        "evidence_sha256": evidence_digest(observations),
                        "observations": observations,
                    }
                ]
            },
        },
    )
    assert completed.status_code == 200, completed.text
    review = client.get(f"/api/v1/assessments/{assessment_id}/review", headers=tenant_headers)
    assert review.status_code == 200, review.text
    assert review.json()["assessment"]["status"] == "review_required"
    assert review.json()["assessment"]["score"] is None

    policy = client.post(
        "/api/v1/masking-policies",
        headers=mutation_headers(tenant_headers, "masking-copy-policy-01"),
        json={
            "name": "insurance_sample local masking plan",
            "version": 1,
            "classification": "Restricted and confidential",
            "strategy": "substitute",
            "target_environment": "development",
            "parameters": {"datasets": 1, "source_asset": "insurance_sample"},
        },
    )
    assert policy.status_code == 201, policy.text
    approved = client.patch(
        f"/api/v1/masking-policies/{policy.json()['id']}/workflow",
        headers=mutation_headers(tenant_headers, "masking-copy-policy-approve-01"),
        json={"action": "approve", "note": "Approved fixed local copy plan"},
    )
    assert approved.status_code == 200, approved.text
    return {
        "asset": asset,
        "assessment_id": assessment_id,
        "assessment_connector": assessment_connector.json(),
        "masking_connector": masking_connector.json(),
        "policy": approved.json(),
        "collector_headers": collector_headers,
        "masker_headers": {
            "X-Tenant-ID": tenant_headers["X-Tenant-ID"],
            "X-Subject": "local-mysql-masker",
            "X-Roles": "collector",
        },
    }


def valid_masking_copy_summary(target_database: str = "insurance_sample_masked"):
    summary = {
        "source_database": "insurance_sample",
        "target_database": target_database,
        "tables_copied": 2,
        "rows_copied": 501,
        "columns_masked": 3,
        "values_masked": 501,
        "row_cap": 500,
        "source_before_hmac": "a" * 64,
        "source_after_hmac": "a" * 64,
        "target_manifest_hmac": "b" * 64,
        "key_fingerprint": "d" * 16,
        "source_digest_match": True,
        "target_counts_match": True,
        "foreign_keys_valid": True,
        "raw_values_exported": False,
        "algorithm": "hmac-sha256-local-v1",
    }
    manifest = {
        key: summary[key]
        for key in (
            "algorithm",
            "columns_masked",
            "foreign_keys_valid",
            "key_fingerprint",
            "raw_values_exported",
            "row_cap",
            "rows_copied",
            "source_after_hmac",
            "source_before_hmac",
            "source_database",
            "tables_copied",
            "target_counts_match",
            "target_database",
            "target_manifest_hmac",
            "values_masked",
        )
    }
    summary["manifest_sha256"] = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return summary


def test_masking_copy_contracts_reject_type_coercion_and_manifest_tampering():
    payload = {
        "policy_id": "a" * 36,
        "asset_id": "b" * 36,
        "source_database": "insurance_sample",
        "target_database": "insurance_sample_masked",
        "row_cap": 500,
    }
    MaskingCopyJobPayload.model_validate(payload)
    with pytest.raises(ValidationError):
        MaskingCopyJobPayload.model_validate({**payload, "row_cap": 500.0})

    valid = valid_masking_copy_summary()
    MaskingCopyResult.model_validate(valid)
    for changed in (
        {**valid, "tables_copied": "2"},
        {**valid, "source_digest_match": 1},
        {**valid, "manifest_sha256": "0" * 64},
    ):
        with pytest.raises(ValidationError):
            MaskingCopyResult.model_validate(changed)


def test_health_and_metrics_are_public(client):
    assert client.get("/health/live").json()["status"] == "ok"
    assert client.get("/health/ready").json()["checks"]["database"] == "ok"
    metrics = client.get("/metrics")
    assert metrics.status_code == 200


def test_mutations_require_auth_and_idempotency(client, tenant_headers):
    no_auth = client.post(
        "/api/v1/assets", headers={"Idempotency-Key": "missing-auth-01"}, json=ASSET_PAYLOAD
    )
    assert no_auth.status_code == 401
    assert no_auth.json()["error"]["code"] == "authentication_failed"

    no_key = client.post("/api/v1/assets", headers=tenant_headers, json=ASSET_PAYLOAD)
    assert no_key.status_code == 400
    assert no_key.json()["error"]["code"] == "idempotency_key_required"

    oversized_tenant = {**tenant_headers, "X-Tenant-ID": "t" * 65}
    rejected = client.get("/api/v1/assets", headers=oversized_tenant)
    assert rejected.status_code == 401


def test_production_configuration_fails_closed():
    app = create_app(
        Settings(
            environment="production",
            database_url="sqlite+aiosqlite:///:memory:",
            auth_mode="oidc",
        )
    )
    with pytest.raises(RuntimeError, match="invalid production configuration"):
        with TestClient(app):
            pass


def test_production_configuration_requires_https_identity_and_database_transport():
    valid = Settings(
        environment="production",
        database_url=(
            "postgresql+asyncpg://runtime:managed-secret@db.internal:5432/assurance?ssl=require"
        ),
        database_maintenance_url=(
            "postgresql+asyncpg://maintenance:managed-secret@db.internal:5432/"
            "assurance?ssl=verify-full"
        ),
        auth_mode="oidc",
        oidc_issuer="https://identity.example.com/",
        oidc_audience="database-security-assurance-api",
        oidc_jwks_url="https://identity.example.com/.well-known/jwks.json",
    )
    valid.validate_runtime()

    insecure_identity = valid.model_copy(
        update={"oidc_jwks_url": "http://identity.example.com/jwks.json"}
    )
    with pytest.raises(RuntimeError, match="HTTPS URL"):
        insecure_identity.validate_runtime()

    insecure_database = valid.model_copy(
        update={"database_url": "postgresql+asyncpg://runtime:managed-secret@db.internal/assurance"}
    )
    with pytest.raises(RuntimeError, match="transport encryption"):
        insecure_database.validate_runtime()

    missing_maintenance_database = valid.model_copy(update={"database_maintenance_url": None})
    with pytest.raises(RuntimeError, match="distinct maintenance PostgreSQL URL is required"):
        missing_maintenance_database.validate_runtime()

    shared_database_identity = valid.model_copy(
        update={"database_maintenance_url": valid.database_url}
    )
    with pytest.raises(RuntimeError, match="must be distinct from the request URL"):
        shared_database_identity.validate_runtime()

    insecure_maintenance_database = valid.model_copy(
        update={
            "database_maintenance_url": (
                "postgresql+asyncpg://maintenance:managed-secret@db.internal:5432/assurance"
            )
        }
    )
    with pytest.raises(RuntimeError, match="maintenance PostgreSQL transport encryption"):
        insecure_maintenance_database.validate_runtime()

    same_role_different_url = valid.model_copy(
        update={
            "database_maintenance_url": (
                "postgresql+asyncpg://runtime:other-secret@maintenance.internal:5432/"
                "assurance?ssl=verify-full"
            )
        }
    )
    with pytest.raises(RuntimeError, match="username must differ"):
        same_role_different_url.validate_runtime()

    invalid_database_scheme = valid.model_copy(
        update={"database_url": "https://runtime:managed-secret@db.internal/assurance?ssl=require"}
    )
    with pytest.raises(RuntimeError, match="must be a PostgreSQL URL"):
        invalid_database_scheme.validate_runtime()

    missing_database_principal = valid.model_copy(
        update={
            "database_maintenance_url": (
                "postgresql+asyncpg://db.internal:5432/assurance?ssl=verify-full"
            )
        }
    )
    with pytest.raises(RuntimeError, match="maintenance database must be a PostgreSQL URL"):
        missing_database_principal.validate_runtime()

    ambiguous_transport = valid.model_copy(
        update={
            "database_url": (
                "postgresql+asyncpg://runtime:managed-secret@db.internal/assurance"
                "?ssl=require&sslmode=disable"
            )
        }
    )
    with pytest.raises(RuntimeError, match="transport encryption"):
        ambiguous_transport.validate_runtime()


def test_failed_mutation_reservation_stays_pending(client, tenant_headers):
    headers = mutation_headers(tenant_headers, "crash-safe-reservation-01")
    first = client.post("/test/crash-after-side-effect", headers=headers, json={"operation": 1})
    assert first.status_code == 500
    assert client.app.state.test_crash_calls == 1

    retry = client.post("/test/crash-after-side-effect", headers=headers, json={"operation": 1})
    assert retry.status_code == 409
    assert retry.json()["error"]["code"] == "idempotency_in_progress"
    assert client.app.state.test_crash_calls == 1

    admin_headers = {
        "X-Tenant-ID": "tenant-alpha",
        "X-Subject": "platform-admin@example.com",
        "X-Roles": "admin",
    }
    candidates = client.get(
        "/api/v1/admin/idempotency-records/recovery", headers=admin_headers
    ).json()
    original = next(item for item in candidates if item["path"] == "/test/crash-after-side-effect")
    resolved = client.post(
        f"/api/v1/admin/idempotency-records/{original['id']}/resolve",
        headers=mutation_headers(admin_headers, "resolve-uncertain-request-01"),
        json={
            "resolution": "reject_replay",
            "reason": "Incident review could not prove that the original side effect rolled back.",
        },
    )
    assert resolved.status_code == 200, resolved.text

    rejected_replay = client.post(
        "/test/crash-after-side-effect", headers=headers, json={"operation": 1}
    )
    assert rejected_replay.status_code == 409
    assert rejected_replay.json()["error"]["code"] == "idempotency_replay_rejected"
    assert client.app.state.test_crash_calls == 1


def test_asset_create_is_replay_safe_and_tenant_isolated(client, tenant_headers):
    first = create_asset(client, tenant_headers)
    assert first.status_code == 201, first.text
    replay = create_asset(client, tenant_headers)
    assert replay.status_code == 201
    assert replay.headers["Idempotent-Replayed"] == "true"
    assert replay.json()["id"] == first.json()["id"]

    changed = create_asset(
        client, tenant_headers, payload={**ASSET_PAYLOAD, "name": "Changed Finance Oracle"}
    )
    assert changed.status_code == 409
    assert changed.json()["error"]["code"] == "idempotency_payload_mismatch"

    tenant_beta = {
        "X-Tenant-ID": "tenant-beta",
        "X-Subject": "other@example.com",
        "X-Roles": "security_analyst",
    }
    assert (
        client.get(f"/api/v1/assets/{first.json()['id']}", headers=tenant_beta).status_code == 404
    )
    assert client.get("/api/v1/assets", headers=tenant_beta).json()["items"] == []


def test_idempotency_replay_is_principal_and_role_scoped(client, tenant_headers):
    created = create_asset(client, tenant_headers, key="identity-scoped-key-01")
    assert created.status_code == 201

    viewer = {
        "X-Tenant-ID": "tenant-alpha",
        "X-Subject": "viewer@example.com",
        "X-Roles": "viewer",
        "Idempotency-Key": "identity-scoped-key-01",
    }
    replay_attempt = client.post("/api/v1/assets", headers=viewer, json=ASSET_PAYLOAD)
    assert replay_attempt.status_code == 403
    assert replay_attempt.headers.get("Idempotent-Replayed") is None
    assert replay_attempt.json()["error"]["code"] == "forbidden"


def test_connector_rejects_inline_secrets(client, tenant_headers):
    asset_id = create_asset(client, tenant_headers).json()["id"]
    invalid = client.post(
        "/api/v1/connectors",
        headers=mutation_headers(as_admin(tenant_headers), "connector-invalid-01"),
        json={
            "asset_id": asset_id,
            "name": "oracle-prod",
            "platform": "oracle",
            "endpoint_ref": "dns://oracle-prod.internal:1521/finance",
            "secret_ref": "plain-text-password",
            "config": {"password": "never-store-this"},
        },
    )
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "validation_failed"


def test_connector_registration_is_admin_only_and_endpoint_is_strict(client, tenant_headers):
    asset_id = create_asset(client, tenant_headers).json()["id"]
    valid_payload = {
        "asset_id": asset_id,
        "name": "strict-oracle-endpoint",
        "platform": "oracle",
        "endpoint_ref": "dns://oracle.internal:1521/finance",
        "secret_ref": "vault://database/strict-oracle#readonly",
        "collector_id": "strict-collector-1",
    }
    non_admin = client.post(
        "/api/v1/connectors",
        headers=mutation_headers(tenant_headers, "non-admin-connector-create-01"),
        json=valid_payload,
    )
    assert non_admin.status_code == 403

    invalid_endpoints = [
        "service://oracle.internal",
        "dns://user@oracle.internal:1521/finance",
        "dns://oracle.internal:1521",
        "dns://oracle.internal:0/finance",
        "dns://oracle.internal:1521/finance?role=admin",
        "dns://oracle.internal:1521/finance#fragment",
        "dns://oracle.internal:1521/finance;shutdown",
        "dns://{oracle.internal}:1521/finance",
    ]
    for index, endpoint in enumerate(invalid_endpoints, start=1):
        response = client.post(
            "/api/v1/connectors",
            headers=mutation_headers(as_admin(tenant_headers), f"invalid-endpoint-{index:03}"),
            json={**valid_payload, "name": f"invalid-endpoint-{index}", "endpoint_ref": endpoint},
        )
        assert response.status_code == 422, endpoint
        assert response.json()["error"]["code"] == "validation_failed"

    disabled = client.post(
        "/api/v1/connectors",
        headers=mutation_headers(as_admin(tenant_headers), "disabled-connector-create-01"),
        json={**valid_payload, "config": {"enabled": False}},
    )
    assert disabled.status_code == 201, disabled.text
    collector_headers = {
        "X-Tenant-ID": "tenant-alpha",
        "X-Subject": "strict-collector-1",
        "X-Roles": "collector",
    }
    heartbeat = client.post(
        "/api/v1/collectors/heartbeat",
        headers=mutation_headers(collector_headers, "disabled-connector-heartbeat-01"),
        json={
            "collector_id": "strict-collector-1",
            "version": "0.1.0",
            "capabilities": ["inventory"],
        },
    )
    assert heartbeat.status_code == 200
    runtime = client.get(
        f"/api/v1/collectors/connectors/{disabled.json()['id']}/runtime-config",
        headers=collector_headers,
    )
    assert runtime.status_code == 409
    assert runtime.json()["error"]["code"] == "connector_disabled"


def test_connector_config_update_is_admin_only_safe_and_tenant_scoped(client, tenant_headers):
    asset_id = create_asset(client, tenant_headers).json()["id"]
    connector = client.post(
        "/api/v1/connectors",
        headers=mutation_headers(as_admin(tenant_headers), "connector-config-create-01"),
        json={
            "asset_id": asset_id,
            "name": "local-masking-runtime",
            "platform": "oracle",
            "endpoint_ref": "dns://oracle.internal:1521/finance",
            "secret_ref": "vault://database/oracle#readonly",
            "collector_id": "local-masking-runtime",
            "capabilities": ["inventory"],
            "config": {"target_database": "legacy_target", "row_cap": 500},
        },
    )
    assert connector.status_code == 201, connector.text
    connector_id = connector.json()["id"]
    replacement = {
        "config": {
            "source_database": "insurance_sample",
            "target_database_prefix": "insurance_sample_masked_",
            "row_cap": 500,
        }
    }

    non_admin = client.patch(
        f"/api/v1/connectors/{connector_id}/config",
        headers=mutation_headers(tenant_headers, "connector-config-non-admin-01"),
        json=replacement,
    )
    assert non_admin.status_code == 403

    unsafe = client.patch(
        f"/api/v1/connectors/{connector_id}/config",
        headers=mutation_headers(as_admin(tenant_headers), "connector-config-unsafe-01"),
        json={"config": {"password": "must-not-be-stored"}},
    )
    assert unsafe.status_code == 422
    assert unsafe.json()["error"]["code"] == "validation_failed"

    other_tenant = {
        "X-Tenant-ID": "tenant-beta",
        "X-Subject": "other-admin@example.com",
        "X-Roles": "admin",
    }
    hidden = client.patch(
        f"/api/v1/connectors/{connector_id}/config",
        headers=mutation_headers(other_tenant, "connector-config-cross-tenant-01"),
        json=replacement,
    )
    assert hidden.status_code == 404

    updated = client.patch(
        f"/api/v1/connectors/{connector_id}/config",
        headers=mutation_headers(as_admin(tenant_headers), "connector-config-update-01"),
        json=replacement,
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["config"] == replacement["config"]
    assert updated.json()["endpoint_ref"] == connector.json()["endpoint_ref"]
    assert updated.json()["collector_id"] == connector.json()["collector_id"]


def test_collector_job_lifecycle_and_probe_allowlist(client, tenant_headers):
    asset = create_asset(client, tenant_headers).json()
    connector = client.post(
        "/api/v1/connectors",
        headers=mutation_headers(as_admin(tenant_headers), "connector-create-01"),
        json={
            "asset_id": asset["id"],
            "name": "oracle-prod",
            "platform": "oracle",
            "endpoint_ref": "dns://oracle-prod.internal:1521/finance",
            "secret_ref": "vault://database/oracle-prod#readonly",
            "collector_id": "collector-east-1",
            "capabilities": ["control_assessment"],
        },
    ).json()
    assert "secret_ref" not in connector

    arbitrary_sql = client.post(
        "/api/v1/scan-jobs",
        headers=mutation_headers(tenant_headers, "job-arbitrary-sql-01"),
        json={
            "connector_id": connector["id"],
            "job_type": "control_assessment",
            "deduplication_key": "unsafe-scan-0001",
            "payload": {"probe_ids": ["oracle.drop_tables"]},
        },
    )
    assert arbitrary_sql.status_code == 422
    assert arbitrary_sql.json()["error"]["code"] == "probe_not_allowed"

    created = client.post(
        "/api/v1/scan-jobs",
        headers=mutation_headers(tenant_headers, "job-create-safe-01"),
        json={
            "connector_id": connector["id"],
            "job_type": "control_assessment",
            "deduplication_key": "oracle-assessment-20260812",
            "payload": {"probe_ids": ["oracle.tablespace_encryption"]},
        },
    )
    assert created.status_code == 201, created.text

    collector_headers = {
        "X-Tenant-ID": "tenant-alpha",
        "X-Subject": "collector-east-1",
        "X-Roles": "collector",
    }
    heartbeat = client.post(
        "/api/v1/collectors/heartbeat",
        headers=mutation_headers(collector_headers, "known-heartbeat-01"),
        json={
            "collector_id": "collector-east-1",
            "version": "0.1.0",
            "capabilities": ["control_assessment"],
        },
    )
    assert heartbeat.status_code == 200
    ready = client.get("/api/v1/collectors/ready", headers=collector_headers)
    assert ready.status_code == 200
    assert ready.json() == {"status": "ok", "collector_id": "collector-east-1"}
    impersonation = client.post(
        "/api/v1/scan-jobs/lease",
        headers=mutation_headers(collector_headers, "collector-impersonation-01"),
        json={
            "collector_id": "another-collector",
            "supported_job_types": ["control_assessment"],
        },
    )
    assert impersonation.status_code == 403
    assert impersonation.json()["error"]["code"] == "collector_identity_mismatch"

    unknown_headers = {
        "X-Tenant-ID": "tenant-alpha",
        "X-Subject": "unknown-collector",
        "X-Roles": "collector",
    }
    unknown_heartbeat = client.post(
        "/api/v1/collectors/heartbeat",
        headers=mutation_headers(unknown_headers, "unknown-heartbeat-01"),
        json={
            "collector_id": "unknown-collector",
            "version": "0.1.0",
            "capabilities": ["inventory"],
        },
    )
    assert unknown_heartbeat.status_code == 404

    lease = client.post(
        "/api/v1/scan-jobs/lease",
        headers=mutation_headers(collector_headers, "job-lease-collector-01"),
        json={
            "collector_id": "collector-east-1",
            "supported_job_types": ["control_assessment"],
        },
    )
    assert lease.status_code == 200, lease.text
    assert lease.json()["status"] == "leased"
    assert len(lease.json()["lease_token"]) == 36
    assert "deduplication_key" not in lease.json()
    assert "result" not in lease.json()

    runtime_config = client.get(
        f"/api/v1/collectors/connectors/{connector['id']}/runtime-config",
        headers=collector_headers,
    )
    assert runtime_config.status_code == 200
    assert runtime_config.json()["secret_ref"] == (
        "vault://database/oracle-prod#readonly"  # noqa: S105 - reference, not a credential
    )
    unassigned = client.get(
        f"/api/v1/collectors/connectors/{connector['id']}/runtime-config",
        headers={
            "X-Tenant-ID": "tenant-alpha",
            "X-Subject": "collector-west-1",
            "X-Roles": "collector",
        },
    )
    assert unassigned.status_code == 404

    stale_renewal = client.post(
        f"/api/v1/scan-jobs/{lease.json()['id']}/renew",
        headers=mutation_headers(collector_headers, "job-renew-stale-token-01"),
        json={
            "collector_id": "collector-east-1",
            "lease_token": "00000000-0000-4000-8000-000000000000",
        },
    )
    assert stale_renewal.status_code == 409
    assert stale_renewal.json()["error"]["code"] == "job_lease_conflict"

    renewed = client.post(
        f"/api/v1/scan-jobs/{lease.json()['id']}/renew",
        headers=mutation_headers(collector_headers, "job-renew-valid-token-01"),
        json={
            "collector_id": "collector-east-1",
            "lease_token": lease.json()["lease_token"],
        },
    )
    assert renewed.status_code == 200, renewed.text
    assert set(renewed.json()) == {
        "id",
        "connector_id",
        "assessment_id",
        "job_type",
        "status",
        "payload",
        "lease_token",
        "lease_expires_at",
        "attempts",
        "max_attempts",
    }

    unsafe_completion = client.post(
        f"/api/v1/scan-jobs/{lease.json()['id']}/complete",
        headers=mutation_headers(collector_headers, "job-complete-unsafe-01"),
        json={
            "collector_id": "collector-east-1",
            "lease_token": lease.json()["lease_token"],
            "success": True,
            "result": {"summary": {"token": "must-not-enter-the-control-plane"}},
        },
    )
    assert unsafe_completion.status_code == 422
    assert unsafe_completion.json()["error"]["code"] == "validation_failed"

    completed = client.post(
        f"/api/v1/scan-jobs/{lease.json()['id']}/complete",
        headers=mutation_headers(collector_headers, "job-complete-0001"),
        json={
            "collector_id": "collector-east-1",
            "lease_token": lease.json()["lease_token"],
            "success": True,
            "result": {
                "probe_results": [
                    {
                        "probe_id": "oracle.tablespace_encryption",
                        "outcome": "collected",
                        "duration_ms": 25,
                        "row_count": 1,
                        "evidence_sha256": evidence_digest([{"encryption_enabled": True}]),
                        "observations": [{"encryption_enabled": True}],
                    }
                ],
                "summary": {"controls_evaluated": 1},
            },
        },
    )
    assert completed.status_code == 200
    assert completed.json()["status"] == "succeeded"


def test_collector_completion_is_bound_to_the_exact_requested_evidence(client, tenant_headers):
    asset = create_asset(client, tenant_headers).json()
    connector = client.post(
        "/api/v1/connectors",
        headers=mutation_headers(as_admin(tenant_headers), "trust-boundary-connector-01"),
        json={
            "asset_id": asset["id"],
            "name": "trust-boundary-oracle",
            "platform": "oracle",
            "endpoint_ref": "dns://trust-boundary-oracle.internal:1521/finance",
            "secret_ref": "vault://database/trust-boundary-oracle#readonly",
            "collector_id": "collector-trust-1",
        },
    ).json()
    collector_headers = {
        "X-Tenant-ID": "tenant-alpha",
        "X-Subject": "collector-trust-1",
        "X-Roles": "collector",
    }
    heartbeat = client.post(
        "/api/v1/collectors/heartbeat",
        headers=mutation_headers(collector_headers, "trust-boundary-heartbeat-01"),
        json={
            "collector_id": "collector-trust-1",
            "version": "0.1.0",
            "capabilities": ["control_assessment"],
        },
    )
    assert heartbeat.status_code == 200
    requested = ["oracle.tablespace_encryption", "oracle.unified_auditing"]
    sequence = 0

    def lease_case():
        nonlocal sequence
        sequence += 1
        created = client.post(
            "/api/v1/scan-jobs",
            headers=mutation_headers(tenant_headers, f"trust-create-job-{sequence:03}"),
            json={
                "connector_id": connector["id"],
                "job_type": "control_assessment",
                "deduplication_key": f"trust-boundary-job-{sequence:03}",
                "payload": {"probe_ids": requested},
            },
        )
        assert created.status_code == 201, created.text
        lease = client.post(
            "/api/v1/scan-jobs/lease",
            headers=mutation_headers(collector_headers, f"trust-lease-job-{sequence:03}"),
            json={
                "collector_id": "collector-trust-1",
                "supported_job_types": ["control_assessment"],
            },
        )
        assert lease.status_code == 200, lease.text
        return lease.json()

    def complete_case(result, *, success=True, error=None):
        lease = lease_case()
        return client.post(
            f"/api/v1/scan-jobs/{lease['id']}/complete",
            headers=mutation_headers(collector_headers, f"trust-complete-{sequence:03}"),
            json={
                "collector_id": "collector-trust-1",
                "lease_token": lease["lease_token"],
                "success": success,
                "result": {"probe_results": result},
                "error": error,
            },
        )

    empty = complete_case([])
    assert empty.status_code == 422
    assert empty.json()["error"]["code"] == "probe_result_set_mismatch"

    partial = complete_case(
        [
            {
                "probe_id": requested[0],
                "outcome": "error",
                "duration_ms": 1,
                "message": "read timed out",
            }
        ]
    )
    assert partial.status_code == 422
    assert partial.json()["error"]["code"] == "probe_result_set_mismatch"

    duplicate = complete_case(
        [
            {"probe_id": requested[0], "outcome": "error", "duration_ms": 1},
            {"probe_id": requested[0], "outcome": "unsupported", "duration_ms": 1},
        ]
    )
    assert duplicate.status_code == 422
    assert duplicate.json()["error"]["code"] == "duplicate_probe_result"

    unrequested = complete_case(
        [
            {"probe_id": requested[0], "outcome": "error", "duration_ms": 1},
            {
                "probe_id": "oracle.account_posture",
                "outcome": "unsupported",
                "duration_ms": 1,
            },
        ]
    )
    assert unrequested.status_code == 422
    assert unrequested.json()["error"]["code"] == "probe_result_set_mismatch"

    wrong_digest = complete_case(
        [
            {
                "probe_id": requested[0],
                "outcome": "collected",
                "duration_ms": 1,
                "row_count": 1,
                "evidence_sha256": "0" * 64,
                "observations": [{"encrypted": "YES"}],
            },
            {"probe_id": requested[1], "outcome": "not_applicable", "duration_ms": 1},
        ]
    )
    assert wrong_digest.status_code == 422
    assert wrong_digest.json()["error"]["code"] == "evidence_digest_mismatch"

    row_mismatch = complete_case(
        [
            {
                "probe_id": requested[0],
                "outcome": "collected",
                "duration_ms": 1,
                "row_count": 2,
                "evidence_sha256": evidence_digest([{"encrypted": "YES"}]),
                "observations": [{"encrypted": "YES"}],
            },
            {"probe_id": requested[1], "outcome": "error", "duration_ms": 1},
        ]
    )
    assert row_mismatch.status_code == 422
    assert row_mismatch.json()["error"]["code"] == "validation_failed"

    for index, forbidden in enumerate(("passed", "failed", "review_required"), start=1):
        response = complete_case(
            [
                {"probe_id": requested[0], "outcome": forbidden, "duration_ms": index},
                {"probe_id": requested[1], "outcome": "error", "duration_ms": 1},
            ]
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "validation_failed"

    failed_with_results = complete_case(
        [
            {"probe_id": requested[0], "outcome": "error", "duration_ms": 1},
            {"probe_id": requested[1], "outcome": "error", "duration_ms": 1},
        ],
        success=False,
        error="collector process terminated",
    )
    assert failed_with_results.status_code == 422
    assert failed_with_results.json()["error"]["code"] == "validation_failed"


def test_access_review_masking_and_dashboard(client, tenant_headers):
    asset = create_asset(client, tenant_headers).json()
    masking = client.post(
        "/api/v1/masking-policies",
        headers=mutation_headers(tenant_headers, "masking-policy-0001"),
        json={
            "name": "Customer Identifier Protection",
            "classification": "customer_identifier",
            "strategy": "tokenize",
            "target_environment": "test",
            "parameters": {"preserve_format": True},
        },
    )
    assert masking.status_code == 201, masking.text

    review = client.post(
        "/api/v1/access-reviews",
        headers=mutation_headers(tenant_headers, "access-review-0001"),
        json={
            "asset_id": asset["id"],
            "name": "Quarterly privileged access review",
            "reviewer": "Security Governance",
            "scope": {"privileged_only": True},
            "due_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
        },
    )
    assert review.status_code == 201, review.text
    summary = client.get("/api/v1/dashboard/summary", headers=tenant_headers)
    assert summary.status_code == 200
    assert summary.json()["assets"] == 1
    assert summary.json()["masking_policies"] == 1
    assert summary.json()["access_reviews"] == 1


def test_masking_policy_workflow_is_local_metadata_only(client, tenant_headers):
    created = client.post(
        "/api/v1/masking-policies",
        headers=mutation_headers(tenant_headers, "masking-workflow-create-01"),
        json={
            "name": "Local insurance identifiers",
            "classification": "restricted_pii",
            "strategy": "substitute",
            "target_environment": "development",
            "parameters": {"datasets": 12},
        },
    )
    assert created.status_code == 201, created.text
    policy = created.json()
    assert policy["enabled"] is False
    assert policy["approved_by"] is None
    assert policy["parameters"]["workflow_status"] == "draft"

    out_of_order = client.patch(
        f"/api/v1/masking-policies/{policy['id']}/workflow",
        headers=mutation_headers(tenant_headers, "masking-workflow-order-01"),
        json={
            "action": "record_execution",
            "note": "Execution was reported",
            "reference": "JOB-100",
        },
    )
    assert out_of_order.status_code == 409

    approve_headers = mutation_headers(tenant_headers, "masking-workflow-approve-01")
    approved = client.patch(
        f"/api/v1/masking-policies/{policy['id']}/workflow",
        headers=approve_headers,
        json={"action": "approve", "note": "Plan reviewed", "reference": None},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["approved_by"] == tenant_headers["X-Subject"]
    assert approved.json()["parameters"]["workflow_status"] == "approved"

    replay = client.patch(
        f"/api/v1/masking-policies/{policy['id']}/workflow",
        headers=approve_headers,
        json={"action": "approve", "note": "Plan reviewed", "reference": None},
    )
    assert replay.status_code == 200
    assert replay.json()["id"] == policy["id"]

    missing_reference = client.patch(
        f"/api/v1/masking-policies/{policy['id']}/workflow",
        headers=mutation_headers(tenant_headers, "masking-workflow-reference-01"),
        json={"action": "record_execution", "note": "External run finished"},
    )
    assert missing_reference.status_code == 422

    recorded = client.patch(
        f"/api/v1/masking-policies/{policy['id']}/workflow",
        headers=mutation_headers(tenant_headers, "masking-workflow-record-01"),
        json={
            "action": "record_execution",
            "note": "External run finished",
            "reference": "LOCAL-JOB-101",
        },
    )
    assert recorded.status_code == 200, recorded.text
    assert recorded.json()["parameters"]["workflow_status"] == "execution_recorded"

    validated = client.patch(
        f"/api/v1/masking-policies/{policy['id']}/workflow",
        headers=mutation_headers(tenant_headers, "masking-workflow-validate-01"),
        json={"action": "validate", "note": "Evidence reviewed", "reference": None},
    )
    assert validated.status_code == 200, validated.text
    assert validated.json()["parameters"]["workflow_status"] == "validated"

    archived = client.patch(
        f"/api/v1/masking-policies/{policy['id']}/workflow",
        headers=mutation_headers(tenant_headers, "masking-workflow-archive-01"),
        json={
            "action": "archive",
            "note": "Completed workflow retained for audit",
            "reference": None,
        },
    )
    assert archived.status_code == 200, archived.text
    assert archived.json()["enabled"] is False
    assert archived.json()["parameters"]["workflow_status"] == "validated"
    assert archived.json()["parameters"]["archived_by"] == tenant_headers["X-Subject"]
    assert archived.json()["parameters"]["archived_at"]

    archive_again = client.patch(
        f"/api/v1/masking-policies/{policy['id']}/workflow",
        headers=mutation_headers(tenant_headers, "masking-workflow-archive-02"),
        json={
            "action": "archive",
            "note": "Duplicate archive attempt",
            "reference": None,
        },
    )
    assert archive_again.status_code == 409

    jobs = client.get("/api/v1/scan-jobs?limit=100", headers=tenant_headers)
    assert jobs.status_code == 200
    assert jobs.json()["items"] == []
    other_tenant = {**tenant_headers, "X-Tenant-ID": "tenant-beta"}
    isolated = client.get("/api/v1/masking-policies", headers=other_tenant)
    assert isolated.status_code == 200
    assert isolated.json()["items"] == []


def test_masking_copy_queue_is_bounded_and_records_only_aggregate_evidence(client, tenant_headers):
    setup = setup_local_masking_review(client, tenant_headers)
    policy = setup["policy"]
    target_database = policy["parameters"]["target_database"]

    generic_job = client.post(
        "/api/v1/scan-jobs",
        headers=mutation_headers(tenant_headers, "generic-masking-copy-job-01"),
        json={
            "connector_id": setup["masking_connector"]["id"],
            "assessment_id": setup["assessment_id"],
            "job_type": "masking_copy",
            "deduplication_key": "generic-masking-copy-job-01",
            "payload": {
                "policy_id": policy["id"],
                "asset_id": setup["asset"]["id"],
                "source_database": "insurance_sample",
                "target_database": "insurance_sample_masked",
                "row_cap": 500,
            },
        },
    )
    assert generic_job.status_code == 422
    assert generic_job.json()["error"]["code"] == "validation_failed"

    reserved_slot = client.post(
        "/api/v1/scan-jobs",
        headers=mutation_headers(tenant_headers, "generic-reserved-masking-slot-01"),
        json={
            "connector_id": setup["masking_connector"]["id"],
            "assessment_id": None,
            "job_type": "inventory",
            "deduplication_key": (
                f"masking-copy:{policy['id']}:{target_database}"
            ),
            "payload": {"probe_ids": ["mysql.schema_inventory"]},
        },
    )
    assert reserved_slot.status_code == 422
    assert reserved_slot.json()["error"]["code"] == "reserved_deduplication_key"

    manual_record = client.patch(
        f"/api/v1/masking-policies/{policy['id']}/workflow",
        headers=mutation_headers(tenant_headers, "masking-copy-manual-record-01"),
        json={
            "action": "record_execution",
            "note": "Attempt to bypass the fixed copy job",
            "reference": "LOCAL-JOB-BYPASS",
        },
    )
    assert manual_record.status_code == 409
    assert manual_record.json()["error"]["code"] == "masking_copy_execution_must_be_automated"

    client.app.state.settings.environment = "test"
    disabled = client.post(
        f"/api/v1/masking-policies/{policy['id']}/copy-runs",
        headers=mutation_headers(tenant_headers, "masking-copy-disabled-01"),
    )
    assert disabled.status_code == 403
    assert disabled.json()["error"]["code"] == "masking_copy_development_only"
    client.app.state.settings.environment = "development"

    other_tenant = {**tenant_headers, "X-Tenant-ID": "tenant-beta"}
    isolated = client.post(
        f"/api/v1/masking-policies/{policy['id']}/copy-runs",
        headers=mutation_headers(other_tenant, "masking-copy-other-tenant-01"),
    )
    assert isolated.status_code == 404

    queued = client.post(
        f"/api/v1/masking-policies/{policy['id']}/copy-runs",
        headers=mutation_headers(tenant_headers, "masking-copy-queue-01"),
    )
    assert queued.status_code == 201, queued.text
    job = queued.json()
    assert job["job_type"] == "masking_copy"
    assert job["deduplication_key"] == (
        f"masking-copy:{policy['id']}:{target_database}"
    )
    assert job["assessment_id"] == setup["assessment_id"]
    assert job["connector_id"] == setup["masking_connector"]["id"]
    assert job["payload"] == {
        "policy_id": policy["id"],
        "asset_id": setup["asset"]["id"],
        "source_database": "insurance_sample",
        "target_database": target_database,
        "row_cap": 500,
    }
    queued_policy = next(
        item
        for item in client.get("/api/v1/masking-policies", headers=tenant_headers).json()[
            "items"
        ]
        if item["id"] == policy["id"]
    )
    assert queued_policy["parameters"]["copy_status"] == "queued"
    assert queued_policy["parameters"]["copy_job_id"] == job["id"]
    encoded_job = json.dumps(job).lower()
    for forbidden in ("password", "credential", "secret_ref", "endpoint_ref", "sql"):
        assert forbidden not in encoded_job

    duplicate_active = client.post(
        f"/api/v1/masking-policies/{policy['id']}/copy-runs",
        headers=mutation_headers(tenant_headers, "masking-copy-queue-02"),
    )
    assert duplicate_active.status_code == 200, duplicate_active.text
    assert duplicate_active.json()["id"] == job["id"]

    standard_lease = client.post(
        "/api/v1/scan-jobs/lease",
        headers=mutation_headers(setup["collector_headers"], "masking-standard-lease-01"),
        json={
            "collector_id": "local-mysql-test-collector",
            "supported_job_types": ["masking_copy"],
        },
    )
    assert standard_lease.status_code == 403
    assert standard_lease.json()["error"]["code"] == "masking_copy_collector_required"

    heartbeat = client.post(
        "/api/v1/collectors/heartbeat",
        headers=mutation_headers(setup["masker_headers"], "masking-copy-heartbeat-01"),
        json={
            "collector_id": "local-mysql-masker",
            "version": "0.1.0",
            "capabilities": ["masking_copy"],
        },
    )
    assert heartbeat.status_code == 200, heartbeat.text
    lease = client.post(
        "/api/v1/scan-jobs/lease",
        headers=mutation_headers(setup["masker_headers"], "masking-copy-lease-01"),
        json={
            "collector_id": "local-mysql-masker",
            "supported_job_types": ["masking_copy"],
        },
    )
    assert lease.status_code == 200, lease.text
    assert lease.json()["id"] == job["id"]
    assert lease.json()["payload"] == job["payload"]
    running_policy = next(
        item
        for item in client.get("/api/v1/masking-policies", headers=tenant_headers).json()[
            "items"
        ]
        if item["id"] == policy["id"]
    )
    assert running_policy["parameters"]["copy_status"] == "running"

    malformed_summary = {
        **valid_masking_copy_summary(target_database),
        "foreign_keys_valid": False,
    }
    malformed = client.post(
        f"/api/v1/scan-jobs/{job['id']}/complete",
        headers=mutation_headers(setup["masker_headers"], "masking-copy-malformed-01"),
        json={
            "collector_id": "local-mysql-masker",
            "lease_token": lease.json()["lease_token"],
            "success": True,
            "result": {"probe_results": [], "summary": malformed_summary},
        },
    )
    assert malformed.status_code == 422
    assert malformed.json()["error"]["code"] == "masking_copy_result_invalid"

    tampered_manifest = {
        **valid_masking_copy_summary(target_database),
        "manifest_sha256": "0" * 64,
    }
    tampered = client.post(
        f"/api/v1/scan-jobs/{job['id']}/complete",
        headers=mutation_headers(setup["masker_headers"], "masking-copy-tampered-01"),
        json={
            "collector_id": "local-mysql-masker",
            "lease_token": lease.json()["lease_token"],
            "success": True,
            "result": {"probe_results": [], "summary": tampered_manifest},
        },
    )
    assert tampered.status_code == 422
    assert tampered.json()["error"]["code"] == "masking_copy_result_invalid"

    coerced_counts = {
        **valid_masking_copy_summary(target_database),
        "tables_copied": "2",
    }
    coerced = client.post(
        f"/api/v1/scan-jobs/{job['id']}/complete",
        headers=mutation_headers(setup["masker_headers"], "masking-copy-coerced-01"),
        json={
            "collector_id": "local-mysql-masker",
            "lease_token": lease.json()["lease_token"],
            "success": True,
            "result": {"probe_results": [], "summary": coerced_counts},
        },
    )
    assert coerced.status_code == 422
    assert coerced.json()["error"]["code"] == "masking_copy_result_invalid"

    completion_body = {
        "collector_id": "local-mysql-masker",
        "lease_token": lease.json()["lease_token"],
        "success": True,
        "result": {
            "probe_results": [],
            "summary": valid_masking_copy_summary(target_database),
        },
    }
    completed = client.post(
        f"/api/v1/scan-jobs/{job['id']}/complete",
        headers=mutation_headers(setup["masker_headers"], "masking-copy-complete-01"),
        json=completion_body,
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["status"] == "succeeded"
    assert completed.json()["result"]["summary"] == valid_masking_copy_summary(
        target_database
    )

    replay = client.post(
        f"/api/v1/scan-jobs/{job['id']}/complete",
        headers=mutation_headers(setup["masker_headers"], "masking-copy-complete-01"),
        json=completion_body,
    )
    assert replay.status_code == 200
    assert replay.headers["Idempotent-Replayed"] == "true"

    policies = client.get("/api/v1/masking-policies", headers=tenant_headers).json()["items"]
    reconciled = next(item for item in policies if item["id"] == policy["id"])
    assert reconciled["parameters"]["workflow_status"] == "execution_recorded"
    assert reconciled["parameters"]["copy_status"] == "automated_checks_passed"
    assert reconciled["parameters"]["automated_checks_passed"] is True
    assert reconciled["parameters"]["execution_job_id"] == job["id"]

    succeeded_replay = client.post(
        f"/api/v1/masking-policies/{policy['id']}/copy-runs",
        headers=mutation_headers(tenant_headers, "masking-copy-succeeded-replay-01"),
    )
    assert succeeded_replay.status_code == 200, succeeded_replay.text
    assert succeeded_replay.json()["id"] == job["id"]
    assert succeeded_replay.json()["status"] == "succeeded"

    evidence = client.get(
        "/api/v1/evidence",
        headers=tenant_headers,
        params={
            "assessment_id": setup["assessment_id"],
            "control_id": "mysql.data-masking.governance-evidence",
        },
    )
    assert evidence.status_code == 200
    assert len(evidence.json()["items"]) == 1
    artifact = evidence.json()["items"][0]
    assert artifact["evidence_type"] == "artifact_reference"
    assert artifact["sha256"] == valid_masking_copy_summary(target_database)[
        "manifest_sha256"
    ]
    assert artifact["attributes"]["automated_checks_passed"] is True
    assert artifact["attributes"]["raw_values_exported"] is False

    review = client.get(
        f"/api/v1/assessments/{setup['assessment_id']}/review", headers=tenant_headers
    )
    assert review.status_code == 200
    assert review.json()["assessment"]["status"] == "review_required"
    assert review.json()["assessment"]["score"] is None
    manual_control = next(
        item
        for item in review.json()["controls"]
        if item["definition"]["control_id"] == "mysql.data-masking.governance-evidence"
    )
    assert manual_control["decision"] is None
    assert manual_control["evidence_ids"] == [artifact["id"]]


def test_additional_local_masking_plan_can_run_again_without_browser_database_input(
    client, tenant_headers
):
    setup = setup_local_masking_review(client, tenant_headers)
    first_policy = setup["policy"]

    created = client.post(
        "/api/v1/masking-policies",
        headers=mutation_headers(tenant_headers, "masking-repeat-policy-01"),
        json={
            "name": "manager demonstration masking run",
            "version": 1,
            "classification": "Restricted and confidential",
            "strategy": "substitute",
            "target_environment": "development",
            "parameters": {},
        },
    )
    assert created.status_code == 201, created.text
    policy = created.json()
    assert policy["id"] != first_policy["id"]
    target_database = f"insurance_sample_masked_{policy['id'].replace('-', '')[:12]}"
    assert policy["parameters"] == {
        "workflow_status": "draft",
        "local_copy_plan": True,
        "source_asset": "insurance_sample",
        "source_database": "insurance_sample",
        "target_database": target_database,
        "row_cap": 500,
        "copy_mode": "create_fresh_workflow_target",
    }
    assert target_database != first_policy["parameters"]["target_database"]

    approved = client.patch(
        f"/api/v1/masking-policies/{policy['id']}/workflow",
        headers=mutation_headers(tenant_headers, "masking-repeat-approve-01"),
        json={"action": "approve", "note": "Approved repeat local verification"},
    )
    assert approved.status_code == 200, approved.text

    queued = client.post(
        f"/api/v1/masking-policies/{policy['id']}/copy-runs",
        headers=mutation_headers(tenant_headers, "masking-repeat-queue-01"),
    )
    assert queued.status_code == 201, queued.text
    job = queued.json()
    assert job["deduplication_key"] == (
        f"masking-copy:{policy['id']}:{target_database}"
    )
    assert job["payload"]["policy_id"] == policy["id"]
    assert job["payload"]["target_database"] == target_database

    jobs = client.get("/api/v1/scan-jobs?limit=100", headers=tenant_headers)
    assert jobs.status_code == 200
    masking_jobs = [
        item for item in jobs.json()["items"] if item["job_type"] == "masking_copy"
    ]
    assert len(masking_jobs) == 1
    assert masking_jobs[0]["id"] == job["id"]

    heartbeat = client.post(
        "/api/v1/collectors/heartbeat",
        headers=mutation_headers(setup["masker_headers"], "masking-repeat-heartbeat-01"),
        json={
            "collector_id": "local-mysql-masker",
            "version": "0.1.0",
            "capabilities": ["masking_copy"],
        },
    )
    assert heartbeat.status_code == 200, heartbeat.text
    lease = client.post(
        "/api/v1/scan-jobs/lease",
        headers=mutation_headers(setup["masker_headers"], "masking-repeat-lease-01"),
        json={
            "collector_id": "local-mysql-masker",
            "supported_job_types": ["masking_copy"],
        },
    )
    assert lease.status_code == 200, lease.text
    assert lease.json()["id"] == job["id"]

    completed = client.post(
        f"/api/v1/scan-jobs/{job['id']}/complete",
        headers=mutation_headers(setup["masker_headers"], "masking-repeat-complete-01"),
        json={
            "collector_id": "local-mysql-masker",
            "lease_token": lease.json()["lease_token"],
            "success": True,
            "result": {
                "probe_results": [],
                "summary": valid_masking_copy_summary(target_database),
            },
        },
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["status"] == "succeeded"

    validated = client.patch(
        f"/api/v1/masking-policies/{policy['id']}/workflow",
        headers=mutation_headers(tenant_headers, "masking-repeat-validate-01"),
        json={
            "action": "validate",
            "note": "Independent local workflow target reviewed",
        },
    )
    assert validated.status_code == 200, validated.text
    assert validated.json()["parameters"]["workflow_status"] == "validated"
    assert validated.json()["parameters"]["execution_job_id"] == job["id"]


def test_failed_masking_copy_stays_approved_retryable_and_creates_no_evidence(
    client, tenant_headers
):
    setup = setup_local_masking_review(client, tenant_headers)
    policy = setup["policy"]
    queued = client.post(
        f"/api/v1/masking-policies/{policy['id']}/copy-runs",
        headers=mutation_headers(tenant_headers, "masking-copy-failure-queue-01"),
    )
    assert queued.status_code == 201, queued.text

    heartbeat = client.post(
        "/api/v1/collectors/heartbeat",
        headers=mutation_headers(setup["masker_headers"], "masking-failure-heartbeat-01"),
        json={
            "collector_id": "local-mysql-masker",
            "version": "0.1.0",
            "capabilities": ["masking_copy"],
        },
    )
    assert heartbeat.status_code == 200, heartbeat.text
    lease = client.post(
        "/api/v1/scan-jobs/lease",
        headers=mutation_headers(setup["masker_headers"], "masking-failure-lease-01"),
        json={
            "collector_id": "local-mysql-masker",
            "supported_job_types": ["masking_copy"],
        },
    )
    assert lease.status_code == 200, lease.text
    failed = client.post(
        f"/api/v1/scan-jobs/{lease.json()['id']}/complete",
        headers=mutation_headers(setup["masker_headers"], "masking-failure-complete-01"),
        json={
            "collector_id": "local-mysql-masker",
            "lease_token": lease.json()["lease_token"],
            "success": False,
            "error": "target validation failed and was rolled back",
        },
    )
    assert failed.status_code == 200, failed.text
    assert failed.json()["status"] == "pending"
    assert failed.json()["attempts"] == 1

    active_retry = client.post(
        f"/api/v1/masking-policies/{policy['id']}/copy-runs",
        headers=mutation_headers(tenant_headers, "masking-copy-failure-queue-02"),
    )
    assert active_retry.status_code == 200, active_retry.text
    assert active_retry.json()["id"] == failed.json()["id"]

    policies = client.get("/api/v1/masking-policies", headers=tenant_headers).json()["items"]
    unchanged = next(item for item in policies if item["id"] == policy["id"])
    assert unchanged["parameters"]["workflow_status"] == "approved"
    assert unchanged["parameters"]["copy_status"] == "retry_pending"
    assert "automated_checks_passed" not in unchanged["parameters"]

    evidence = client.get(
        "/api/v1/evidence",
        headers=tenant_headers,
        params={
            "assessment_id": setup["assessment_id"],
            "control_id": "mysql.data-masking.governance-evidence",
        },
    )
    assert evidence.status_code == 200
    assert evidence.json()["items"] == []
    review = client.get(
        f"/api/v1/assessments/{setup['assessment_id']}/review", headers=tenant_headers
    )
    assert review.json()["assessment"]["status"] == "review_required"
    assert review.json()["assessment"]["score"] is None


def test_terminal_masking_copy_failure_reuses_its_sqlite_queue_slot(client, tenant_headers):
    setup = setup_local_masking_review(client, tenant_headers)
    policy = setup["policy"]
    client.app.state.settings.collector_max_attempts = 1

    queued = client.post(
        f"/api/v1/masking-policies/{policy['id']}/copy-runs",
        headers=mutation_headers(tenant_headers, "masking-terminal-queue-01"),
    )
    assert queued.status_code == 201, queued.text
    original = queued.json()
    heartbeat = client.post(
        "/api/v1/collectors/heartbeat",
        headers=mutation_headers(setup["masker_headers"], "masking-terminal-heartbeat-01"),
        json={
            "collector_id": "local-mysql-masker",
            "version": "0.1.0",
            "capabilities": ["masking_copy"],
        },
    )
    assert heartbeat.status_code == 200, heartbeat.text
    lease = client.post(
        "/api/v1/scan-jobs/lease",
        headers=mutation_headers(setup["masker_headers"], "masking-terminal-lease-01"),
        json={
            "collector_id": "local-mysql-masker",
            "supported_job_types": ["masking_copy"],
        },
    )
    assert lease.status_code == 200, lease.text
    failed = client.post(
        f"/api/v1/scan-jobs/{original['id']}/complete",
        headers=mutation_headers(setup["masker_headers"], "masking-terminal-complete-01"),
        json={
            "collector_id": "local-mysql-masker",
            "lease_token": lease.json()["lease_token"],
            "success": False,
            "error": "bounded target staging failed",
        },
    )
    assert failed.status_code == 200, failed.text
    assert failed.json()["status"] == "failed"

    requeued = client.post(
        f"/api/v1/masking-policies/{policy['id']}/copy-runs",
        headers=mutation_headers(tenant_headers, "masking-terminal-queue-02"),
    )
    assert requeued.status_code == 200, requeued.text
    assert requeued.json()["id"] == original["id"]
    assert requeued.json()["deduplication_key"] == original["deduplication_key"]
    assert requeued.json()["status"] == "pending"
    assert requeued.json()["attempts"] == 0
    assert requeued.json()["last_error"] is None

    jobs = client.get("/api/v1/scan-jobs?limit=100", headers=tenant_headers)
    matching = [
        item
        for item in jobs.json()["items"]
        if item["deduplication_key"] == original["deduplication_key"]
    ]
    assert [item["id"] for item in matching] == [original["id"]]
    policies = client.get("/api/v1/masking-policies", headers=tenant_headers).json()["items"]
    requeued_policy = next(item for item in policies if item["id"] == policy["id"])
    assert requeued_policy["parameters"]["workflow_status"] == "approved"
    assert requeued_policy["parameters"]["copy_status"] == "queued"
    review = client.get(
        f"/api/v1/assessments/{setup['assessment_id']}/review", headers=tenant_headers
    )
    assert review.json()["assessment"]["status"] == "review_required"
    assert review.json()["assessment"]["score"] is None


def test_concurrent_sqlite_masking_copy_requests_share_one_deterministic_job(
    client, tenant_headers
):
    setup = setup_local_masking_review(client, tenant_headers)
    policy = setup["policy"]

    def queue(index: int):
        return client.post(
            f"/api/v1/masking-policies/{policy['id']}/copy-runs",
            headers=mutation_headers(tenant_headers, f"masking-concurrent-queue-{index:02d}"),
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(queue, (1, 2)))

    assert sorted(response.status_code for response in responses) == [200, 201]
    assert len({response.json()["id"] for response in responses}) == 1
    jobs = client.get("/api/v1/scan-jobs?limit=100", headers=tenant_headers).json()["items"]
    key = (
        f"masking-copy:{policy['id']}:"
        f"{policy['parameters']['target_database']}"
    )
    matching = [job for job in jobs if job["deduplication_key"] == key]
    assert len(matching) == 1


def test_mysql_access_job_upserts_collector_account_review(client, tenant_headers):
    asset_payload = {
        **ASSET_PAYLOAD,
        "external_id": "local-mysql-insurance",
        "name": "insurance_sample",
        "platform": "mysql",
        "version": "8.4",
        "edition": None,
        "environment": "development",
    }
    asset = create_asset(
        client,
        tenant_headers,
        key="mysql-access-asset-01",
        payload=asset_payload,
    ).json()
    connector = client.post(
        "/api/v1/connectors",
        headers=mutation_headers(as_admin(tenant_headers), "mysql-access-connector-01"),
        json={
            "asset_id": asset["id"],
            "name": "local-mysql-insurance-sample",
            "platform": "mysql",
            "endpoint_ref": "dns://mysql.local:3306/insurance_sample",
            "secret_ref": "vault://local/database/mysql-insurance-sample#read-only",
            "collector_id": "local-mysql-test-collector",
            "capabilities": ["read_only_metadata"],
        },
    ).json()
    collector_headers = {
        "X-Tenant-ID": tenant_headers["X-Tenant-ID"],
        "X-Subject": "local-mysql-test-collector",
        "X-Roles": "collector",
    }
    heartbeat = client.post(
        "/api/v1/collectors/heartbeat",
        headers=mutation_headers(collector_headers, "mysql-access-heartbeat-01"),
        json={
            "collector_id": "local-mysql-test-collector",
            "version": "0.1.0",
            "capabilities": ["access_review"],
        },
    )
    assert heartbeat.status_code == 200, heartbeat.text

    sequence = 0

    def complete_access_job(grants, *, context=None):
        nonlocal sequence
        sequence += 1
        created = client.post(
            "/api/v1/scan-jobs",
            headers=mutation_headers(tenant_headers, f"mysql-access-job-{sequence:02}"),
            json={
                "connector_id": connector["id"],
                "job_type": "access_review",
                "deduplication_key": f"mysql-access-review-{sequence:02}",
                "payload": {
                    "probe_ids": [
                        "mysql.account_context",
                        "mysql.account_privileges",
                    ],
                    "metadata": {
                        "mode": "collector_account_only",
                        "reads_row_values": False,
                    },
                },
                "max_attempts": 1,
            },
        )
        assert created.status_code == 201, created.text
        lease = client.post(
            "/api/v1/scan-jobs/lease",
            headers=mutation_headers(collector_headers, f"mysql-access-lease-{sequence:02}"),
            json={
                "collector_id": "local-mysql-test-collector",
                "supported_job_types": ["access_review"],
            },
        )
        assert lease.status_code == 200, lease.text
        context_rows = context or [
            {"account": "assurance_hub_ro@localhost", "active_role": "NONE"}
        ]
        probe_results = [
            {
                "probe_id": "mysql.account_context",
                "outcome": "collected",
                "duration_ms": 2,
                "row_count": len(context_rows),
                "evidence_sha256": evidence_digest(context_rows),
                "observations": context_rows,
            }
        ]
        if grants is None:
            probe_results.append(
                {
                    "probe_id": "mysql.account_privileges",
                    "outcome": "error",
                    "duration_ms": 2,
                }
            )
        else:
            probe_results.append(
                {
                    "probe_id": "mysql.account_privileges",
                    "outcome": "collected",
                    "duration_ms": 2,
                    "row_count": len(grants),
                    "evidence_sha256": evidence_digest(grants),
                    "observations": grants,
                }
            )
        completed = client.post(
            f"/api/v1/scan-jobs/{lease.json()['id']}/complete",
            headers=mutation_headers(
                collector_headers,
                f"mysql-access-complete-{sequence:02}",
            ),
            json={
                "collector_id": "local-mysql-test-collector",
                "lease_token": lease.json()["lease_token"],
                "success": True,
                "result": {"probe_results": probe_results},
            },
        )
        assert completed.status_code == 200, completed.text

    readonly_grants = [
        {
            "account": "assurance_hub_ro@localhost",
            "privilege_type": "SELECT",
            "is_grantable": "NO",
        },
        {
            "account": "assurance_hub_ro@localhost",
            "privilege_type": "SHOW VIEW",
            "is_grantable": "NO",
        },
    ]
    complete_access_job(readonly_grants)
    reviews = client.get("/api/v1/access-reviews", headers=tenant_headers).json()["items"]
    assert len(reviews) == 1
    assert reviews[0]["status"] == "approved"
    assert reviews[0]["scope"]["risk"] == "low"
    assert reviews[0]["scope"]["access"] == "SELECT, SHOW VIEW"
    assert reviews[0]["scope"]["scan_scope"] == "collector_account_only"

    excessive_grants = [
        *readonly_grants,
        {
            "account": "assurance_hub_ro@localhost",
            "privilege_type": "UPDATE",
            "is_grantable": "YES",
        },
    ]
    complete_access_job(excessive_grants)
    reviews = client.get("/api/v1/access-reviews", headers=tenant_headers).json()["items"]
    assert len(reviews) == 1
    assert reviews[0]["status"] == "remediation_required"
    assert reviews[0]["scope"]["risk"] == "critical"

    complete_access_job(None)
    reviews = client.get("/api/v1/access-reviews", headers=tenant_headers).json()["items"]
    assert len(reviews) == 1
    assert reviews[0]["status"] == "in_review"
    assert reviews[0]["scope"]["risk"] == "medium"

    other_tenant = {**tenant_headers, "X-Tenant-ID": "tenant-beta"}
    isolated = client.get("/api/v1/access-reviews", headers=other_tenant)
    assert isolated.status_code == 200
    assert isolated.json()["items"] == []


def test_evidence_has_a_server_derived_envelope_digest(client, tenant_headers):
    asset = create_asset(client, tenant_headers).json()
    assessment = client.post(
        "/api/v1/assessments",
        headers=mutation_headers(tenant_headers, "assessment-evidence-01"),
        json={
            "asset_id": asset["id"],
            "control_pack": "enterprise-baseline",
            "control_pack_version": "1.0.0",
        },
    ).json()
    evidence = client.post(
        "/api/v1/evidence",
        headers=mutation_headers(tenant_headers, "evidence-create-01"),
        json={
            "assessment_id": assessment["id"],
            "control_id": "ORACLE-TDE-001",
            "evidence_type": "configuration",
            "sha256": "A" * 64,
            "collected_at": datetime.now(UTC).isoformat(),
            "collector_version": "0.1.0",
            "attributes": {"source": "allowlisted_probe"},
        },
    )
    assert evidence.status_code == 201, evidence.text
    assert evidence.json()["sha256"] == "a" * 64
    assert len(evidence.json()["attributes"]["server_envelope_sha256"]) == 64


def test_evidence_filters_are_validated_tenant_scoped_and_paginated(client, tenant_headers):
    asset = create_asset(client, tenant_headers).json()

    assessments = []
    for sequence in range(2):
        response = client.post(
            "/api/v1/assessments",
            headers=mutation_headers(tenant_headers, f"evidence-filter-assessment-{sequence}"),
            json={
                "asset_id": asset["id"],
                "control_pack": "enterprise-baseline",
                "control_pack_version": f"1.0.{sequence}",
            },
        )
        assert response.status_code == 201, response.text
        assessments.append(response.json())

    evidence_specs = [
        (assessments[0]["id"], "mysql.data-protection.schema-inventory"),
        (assessments[0]["id"], "mysql.data-protection.schema-inventory"),
        (assessments[0]["id"], "mysql.encryption.transport-security-metadata"),
        (assessments[1]["id"], "mysql.data-protection.schema-inventory"),
    ]
    evidence_ids = []
    for sequence, (assessment_id, control_id) in enumerate(evidence_specs):
        response = client.post(
            "/api/v1/evidence",
            headers=mutation_headers(tenant_headers, f"evidence-filter-create-{sequence}"),
            json={
                "assessment_id": assessment_id,
                "control_id": control_id,
                "evidence_type": "configuration",
                "sha256": f"{sequence + 1:064x}",
                "collected_at": datetime.now(UTC).isoformat(),
                "collector_version": "0.1.0",
                "attributes": {"source": "filter_test"},
            },
        )
        assert response.status_code == 201, response.text
        evidence_ids.append(response.json()["id"])

    by_assessment = client.get(
        "/api/v1/evidence",
        headers=tenant_headers,
        params={"assessment_id": assessments[0]["id"]},
    )
    assert by_assessment.status_code == 200
    assert {item["id"] for item in by_assessment.json()["items"]} == set(evidence_ids[:3])

    by_control = client.get(
        "/api/v1/evidence",
        headers=tenant_headers,
        params={"control_id": "mysql.data-protection.schema-inventory"},
    )
    assert by_control.status_code == 200
    assert {item["id"] for item in by_control.json()["items"]} == {
        evidence_ids[0],
        evidence_ids[1],
        evidence_ids[3],
    }

    combined_params = {
        "assessment_id": assessments[0]["id"],
        "control_id": "mysql.data-protection.schema-inventory",
        "limit": 1,
    }
    first_page = client.get("/api/v1/evidence", headers=tenant_headers, params=combined_params)
    assert first_page.status_code == 200
    assert len(first_page.json()["items"]) == 1
    assert first_page.json()["next_cursor"] is not None

    second_page = client.get(
        "/api/v1/evidence",
        headers=tenant_headers,
        params={**combined_params, "cursor": first_page.json()["next_cursor"]},
    )
    assert second_page.status_code == 200
    assert len(second_page.json()["items"]) == 1
    assert second_page.json()["next_cursor"] is None
    assert {
        first_page.json()["items"][0]["id"],
        second_page.json()["items"][0]["id"],
    } == {evidence_ids[0], evidence_ids[1]}

    other_tenant = {**tenant_headers, "X-Tenant-ID": "tenant-beta"}
    isolated = client.get("/api/v1/evidence", headers=other_tenant, params=combined_params)
    assert isolated.status_code == 200
    assert isolated.json()["items"] == []

    invalid_assessment = client.get(
        "/api/v1/evidence",
        headers=tenant_headers,
        params={"assessment_id": "not-an-assessment-id"},
    )
    assert invalid_assessment.status_code == 422
    assert invalid_assessment.json()["error"]["code"] == "validation_failed"

    invalid_control = client.get(
        "/api/v1/evidence",
        headers=tenant_headers,
        params={"control_id": " invalid control "},
    )
    assert invalid_control.status_code == 422
    assert invalid_control.json()["error"]["code"] == "validation_failed"


def test_pagination_limits_are_validated(client, tenant_headers):
    response = client.get("/api/v1/assets?limit=201", headers=tenant_headers)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_failed"
