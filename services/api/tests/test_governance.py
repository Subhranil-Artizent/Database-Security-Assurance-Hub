from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest
from conftest import mutation_headers

from assurance_hub.governance import evaluate_analyst_review_control
from assurance_hub.models import ControlResultOutcome

ASSET_PAYLOAD = {
    "external_id": "governance-oracle-001",
    "name": "Governed Oracle",
    "platform": "oracle",
    "version": "23ai",
    "environment": "test",
    "owner": "Database Engineering",
    "criticality": "high",
    "tags": {"domain": "finance"},
}


def evidence_digest(observations):
    canonical = json.dumps(
        observations, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def admin_headers() -> dict[str, str]:
    return {
        "X-Tenant-ID": "tenant-alpha",
        "X-Subject": "admin@example.com",
        "X-Roles": "admin",
    }


def pack_payload() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "pack_id": "aegisdb.database-security.oracle",
        "version": "1.0.0",
        "platform": "oracle",
        "title": "Oracle database security baseline",
        "description": (
            "Immutable metadata-only Oracle evidence collection requiring analyst review."
        ),
        "status": "active",
        "released_at": datetime.now(UTC).isoformat(),
        "immutable": True,
        "controls": [
            {
                "control_id": "oracle.encryption.tablespace-metadata",
                "domain": "encryption",
                "title": "Review tablespace encryption metadata",
                "objective": (
                    "Collect declared tablespace encryption metadata for authorized review."
                ),
                "severity": "high",
                "environments": ["production", "test"],
                "version_scope": "customer_validated",
                "applicability_notes": "Validate the exact Oracle edition and release.",
                "assessment_mode": "automated_evidence",
                "probe_ids": ["oracle.tablespace_encryption"],
                "decision_mode": "analyst_review_required",
                "manual_evidence_requirements": [],
                "allowed_fields": ["tablespace_name", "encrypted"],
                "limitations": [
                    "Metadata collection does not prove key custody or recovery readiness."
                ],
                "remediation_guidance": (
                    "Review approved exclusions and key management before making any change."
                ),
            }
        ],
    }


def multi_probe_pack_payload() -> dict[str, object]:
    payload = pack_payload()
    controls = list(payload["controls"])
    controls.append(
        {
            "control_id": "oracle.data-protection.unified-auditing-metadata",
            "domain": "data_protection",
            "title": "Review unified auditing metadata",
            "objective": "Collect unified auditing configuration metadata for authorized review.",
            "severity": "medium",
            "environments": ["production", "test"],
            "version_scope": "customer_validated",
            "applicability_notes": "Validate the exact Oracle edition and release.",
            "assessment_mode": "automated_evidence",
            "probe_ids": ["oracle.unified_auditing"],
            "decision_mode": "analyst_review_required",
            "manual_evidence_requirements": [],
            "allowed_fields": ["parameter", "value"],
            "limitations": [
                "Configuration metadata does not prove that every required event is retained."
            ],
            "remediation_guidance": (
                "Grant only the approved metadata privilege and review the audit policy scope."
            ),
        }
    )
    payload["controls"] = controls
    return payload


def four_control_pack_payload() -> dict[str, object]:
    payload = multi_probe_pack_payload()
    controls = list(payload["controls"])
    controls.extend(
        [
            {
                "control_id": "oracle.access-security.collector-account-context",
                "domain": "access_security",
                "title": "Review collector account context",
                "objective": "Collect authenticated account metadata for authorized review.",
                "severity": "high",
                "environments": ["production", "test"],
                "version_scope": "customer_validated",
                "applicability_notes": "Validate the exact Oracle account and deployment.",
                "assessment_mode": "automated_evidence",
                "probe_ids": ["oracle.account_posture"],
                "decision_mode": "analyst_review_required",
                "manual_evidence_requirements": [],
                "allowed_fields": [
                    "username",
                    "account_status",
                    "authentication_type",
                    "profile",
                ],
                "limitations": [
                    "Account metadata does not prove how every privilege is exercised."
                ],
                "remediation_guidance": (
                    "Restrict the collector identity to approved metadata reads."
                ),
            },
            {
                "control_id": "oracle.data-masking.governance-evidence",
                "domain": "data_masking",
                "title": "Review masking governance evidence",
                "objective": "Require approved masking execution and validation evidence.",
                "severity": "high",
                "environments": ["test"],
                "version_scope": "customer_validated",
                "applicability_notes": "This test environment requires reviewed masking evidence.",
                "assessment_mode": "manual_evidence",
                "probe_ids": [],
                "decision_mode": "analyst_review_required",
                "manual_evidence_requirements": [
                    "Approved execution record and privacy validation evidence"
                ],
                "allowed_fields": [],
                "limitations": [
                    "The assurance collector never executes a masking transformation."
                ],
                "remediation_guidance": (
                    "Run an approved masking copy and attach validation evidence."
                ),
            },
        ]
    )
    payload["controls"] = controls
    return payload


def create_asset_connector_pack(client, tenant_headers, *, pack=None):
    asset = client.post(
        "/api/v1/assets",
        headers=mutation_headers(tenant_headers, "governance-create-asset-01"),
        json=ASSET_PAYLOAD,
    ).json()
    connector = client.post(
        "/api/v1/connectors",
        headers=mutation_headers(admin_headers(), "governance-create-connector-01"),
        json={
            "asset_id": asset["id"],
            "name": "governed-oracle",
            "platform": "oracle",
            "endpoint_ref": "dns://governed-oracle.internal:1521/finance",
            "secret_ref": "vault://database/governed-oracle#readonly",
            "collector_id": "collector-east-1",
            "capabilities": ["control_assessment"],
        },
    ).json()
    pack_response = client.post(
        "/api/v1/control-pack-versions",
        headers=mutation_headers(admin_headers(), "publish-control-pack-0001"),
        json=pack or pack_payload(),
    )
    assert pack_response.status_code == 201, pack_response.text
    return asset, connector, pack_response.json()


def start_run(
    client,
    tenant_headers,
    asset,
    connector,
    pack,
    key="assessment-run-0001",
    max_attempts=5,
):
    return client.post(
        "/api/v1/assessment-runs",
        headers=mutation_headers(tenant_headers, key),
        json={
            "asset_id": asset["id"],
            "connector_id": connector["id"],
            "control_pack_version_id": pack["id"],
            "run_key": key,
            "max_attempts": max_attempts,
        },
    )


def complete_run(client, *, probe_results, key_prefix: str):
    collector_headers = {
        "X-Tenant-ID": "tenant-alpha",
        "X-Subject": "collector-east-1",
        "X-Roles": "collector",
    }
    heartbeat = client.post(
        "/api/v1/collectors/heartbeat",
        headers=mutation_headers(collector_headers, f"{key_prefix}-heartbeat"),
        json={
            "collector_id": "collector-east-1",
            "version": "0.1.0",
            "capabilities": ["control_assessment"],
        },
    )
    assert heartbeat.status_code == 200, heartbeat.text
    lease = client.post(
        "/api/v1/scan-jobs/lease",
        headers=mutation_headers(collector_headers, f"{key_prefix}-lease"),
        json={
            "collector_id": "collector-east-1",
            "supported_job_types": ["control_assessment"],
        },
    )
    assert lease.status_code == 200, lease.text
    completed = client.post(
        f"/api/v1/scan-jobs/{lease.json()['id']}/complete",
        headers=mutation_headers(collector_headers, f"{key_prefix}-complete"),
        json={
            "collector_id": "collector-east-1",
            "lease_token": lease.json()["lease_token"],
            "success": True,
            "result": {"probe_results": probe_results},
        },
    )
    assert completed.status_code == 200, completed.text
    return completed.json()


def collected_probe(probe_id: str, observations: list[dict[str, object]]) -> dict[str, object]:
    return {
        "probe_id": probe_id,
        "outcome": "collected",
        "duration_ms": 10,
        "row_count": len(observations),
        "evidence_sha256": evidence_digest(observations),
        "observations": observations,
    }


def test_analyst_review_finalizes_four_controls_and_creates_one_finding(
    client, tenant_headers
):
    asset, connector, pack = create_asset_connector_pack(
        client,
        tenant_headers,
        pack=four_control_pack_payload(),
    )
    run = start_run(
        client,
        tenant_headers,
        asset,
        connector,
        pack,
        key="four-control-assessment-run-01",
    )
    assert run.status_code == 201, run.text
    assessment_id = run.json()["assessment"]["id"]
    complete_run(
        client,
        key_prefix="four-control",
        probe_results=[
            collected_probe(
                "oracle.account_posture",
                [
                    {
                        "username": "ASSURANCE_RO",
                        "account_status": "OPEN",
                        "authentication_type": "PASSWORD",
                        "profile": "READ_ONLY",
                    }
                ],
            ),
            collected_probe(
                "oracle.tablespace_encryption",
                [{"tablespace_name": "USERS", "encrypted": "YES"}],
            ),
            collected_probe(
                "oracle.unified_auditing",
                [{"parameter": "Unified Auditing", "value": "TRUE"}],
            ),
        ],
    )

    review = client.get(
        f"/api/v1/assessments/{assessment_id}/review", headers=tenant_headers
    )
    assert review.status_code == 200, review.text
    assert review.json()["assessment"]["status"] == "review_required"
    assert review.json()["total_controls"] == 4
    assert review.json()["decided_count"] == 0
    assert review.json()["ready_to_finalize"] is False

    duplicate = start_run(
        client,
        tenant_headers,
        asset,
        connector,
        pack,
        key="four-control-assessment-run-02",
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["details"]["assessment_id"] == assessment_id

    premature = client.post(
        f"/api/v1/assessments/{assessment_id}/finalize",
        headers=mutation_headers(tenant_headers, "four-control-finalize-premature"),
        json={"confirmation": "finalize"},
    )
    assert premature.status_code == 409
    assert premature.json()["error"]["code"] == "assessment_not_ready"

    controls = review.json()["controls"]
    manual = next(
        item
        for item in controls
        if item["definition"]["assessment_mode"] == "manual_evidence"
    )
    manual_pass = client.put(
        (
            f"/api/v1/assessments/{assessment_id}/control-decisions/"
            f"{manual['definition']['id']}"
        ),
        headers=mutation_headers(tenant_headers, "four-control-manual-pass-rejected"),
        json={
            "outcome": "passed",
            "rationale": "No execution evidence is linked, so this must be rejected.",
        },
    )
    assert manual_pass.status_code == 422
    assert manual_pass.json()["error"]["code"] == "manual_evidence_required"

    for index, control in enumerate(controls, start=1):
        outcome = (
            "failed"
            if control["definition"]["assessment_mode"] == "manual_evidence"
            else "passed"
        )
        decision = client.put(
            (
                f"/api/v1/assessments/{assessment_id}/control-decisions/"
                f"{control['definition']['id']}"
            ),
            headers=mutation_headers(tenant_headers, f"four-control-decision-{index}"),
            json={
                "outcome": outcome,
                "rationale": (
                    "Collected metadata matches the approved local review criteria."
                    if outcome == "passed"
                    else "Masking execution and validation evidence has not been linked yet."
                ),
            },
        )
        assert decision.status_code == 200, decision.text

    ready = client.get(
        f"/api/v1/assessments/{assessment_id}/review", headers=tenant_headers
    ).json()
    assert ready["decided_count"] == 4
    assert ready["ready_to_finalize"] is True

    finalized = client.post(
        f"/api/v1/assessments/{assessment_id}/finalize",
        headers=mutation_headers(tenant_headers, "four-control-finalize-01"),
        json={"confirmation": "finalize"},
    )
    assert finalized.status_code == 200, finalized.text
    finalized_review = finalized.json()
    assert finalized_review["assessment"]["status"] == "completed"
    assert finalized_review["assessment"]["score"] == 75
    assert finalized_review["assessment"]["summary"]["score_formula"] == (
        "3 passed / 4 applicable controls"
    )

    findings = client.get("/api/v1/findings", headers=tenant_headers).json()["items"]
    assert len(findings) == 1
    assert findings[0]["control_id"] == manual["definition"]["control_id"]
    assert findings[0]["status"] == "open"
    assert findings[0]["risk_context"]["generated_by"] == "assessment_review"

    replay = client.post(
        f"/api/v1/assessments/{assessment_id}/finalize",
        headers=mutation_headers(tenant_headers, "four-control-finalize-02"),
        json={"confirmation": "finalize"},
    )
    assert replay.status_code == 200, replay.text
    assert replay.json()["assessment"]["score"] == 75
    assert len(client.get("/api/v1/findings", headers=tenant_headers).json()["items"]) == 1

    locked = client.put(
        (
            f"/api/v1/assessments/{assessment_id}/control-decisions/"
            f"{controls[0]['definition']['id']}"
        ),
        headers=mutation_headers(tenant_headers, "four-control-locked-decision"),
        json={
            "outcome": "failed",
            "rationale": "A finalized decision must not be changed after completion.",
        },
    )
    assert locked.status_code == 409

    other_tenant = {
        "X-Tenant-ID": "tenant-beta",
        "X-Subject": "other-analyst@example.com",
        "X-Roles": "security_analyst",
    }
    hidden = client.get(
        f"/api/v1/assessments/{assessment_id}/review", headers=other_tenant
    )
    assert hidden.status_code == 404


def test_immutable_pack_atomic_run_and_review_required_evaluation(client, tenant_headers):
    asset, connector, pack = create_asset_connector_pack(client, tenant_headers)
    assert pack["immutable"] is True
    assert len(pack["content_sha256"]) == 64
    assert len(pack["controls"][0]["definition_sha256"]) == 64

    run = start_run(client, tenant_headers, asset, connector, pack)
    assert run.status_code == 201, run.text
    run_data = run.json()
    assert run_data["assessment"]["id"] == run_data["job"]["assessment_id"]
    assert run_data["job"]["payload"]["probe_ids"] == ["oracle.tablespace_encryption"]

    replay = start_run(client, tenant_headers, asset, connector, pack)
    assert replay.status_code == 201
    assert replay.headers["Idempotent-Replayed"] == "true"
    assert replay.json()["assessment"]["id"] == run_data["assessment"]["id"]
    assert client.get("/api/v1/assessments", headers=tenant_headers).json()["items"] == [
        run_data["assessment"]
    ]
    assert client.get("/api/v1/scan-jobs", headers=tenant_headers).json()["items"] == [
        run_data["job"]
    ]

    alternate_connector = client.post(
        "/api/v1/connectors",
        headers=mutation_headers(admin_headers(), "governance-alt-connector-01"),
        json={
            "asset_id": asset["id"],
            "name": "governed-oracle-alternate",
            "platform": "oracle",
            "endpoint_ref": "dns://governed-oracle-alt.internal:1521/finance",
            "secret_ref": "vault://database/governed-oracle-alternate#readonly",
            "collector_id": "collector-east-2",
        },
    ).json()
    mismatched_run = client.post(
        "/api/v1/assessment-runs",
        headers=mutation_headers(tenant_headers, "assessment-run-mismatch-request-01"),
        json={
            "asset_id": asset["id"],
            "connector_id": alternate_connector["id"],
            "control_pack_version_id": pack["id"],
            "run_key": "assessment-run-0001",
        },
    )
    assert mismatched_run.status_code == 409
    assert mismatched_run.json()["error"]["code"] == "conflict"
    assert len(client.get("/api/v1/assessments", headers=tenant_headers).json()["items"]) == 1
    assert len(client.get("/api/v1/scan-jobs", headers=tenant_headers).json()["items"]) == 1

    definition = pack["controls"][0]
    missing_source = client.post(
        "/api/v1/control-results/evaluate",
        headers=mutation_headers(tenant_headers, "evaluate-without-source-job-01"),
        json={
            "assessment_id": run_data["assessment"]["id"],
            "control_definition_id": definition["id"],
        },
    )
    assert missing_source.status_code == 422
    assert missing_source.json()["error"]["code"] == "source_job_required"

    collector_headers = {
        "X-Tenant-ID": "tenant-alpha",
        "X-Subject": "collector-east-1",
        "X-Roles": "collector",
    }
    heartbeat = client.post(
        "/api/v1/collectors/heartbeat",
        headers=mutation_headers(collector_headers, "governance-heartbeat-job-01"),
        json={
            "collector_id": "collector-east-1",
            "version": "0.1.0",
            "capabilities": ["control_assessment"],
        },
    )
    assert heartbeat.status_code == 200
    lease = client.post(
        "/api/v1/scan-jobs/lease",
        headers=mutation_headers(collector_headers, "governance-lease-job-01"),
        json={
            "collector_id": "collector-east-1",
            "supported_job_types": ["control_assessment"],
        },
    )
    assert lease.status_code == 200, lease.text
    completed = client.post(
        f"/api/v1/scan-jobs/{lease.json()['id']}/complete",
        headers=mutation_headers(collector_headers, "governance-complete-job-01"),
        json={
            "collector_id": "collector-east-1",
            "lease_token": lease.json()["lease_token"],
            "success": True,
            "result": {
                "probe_results": [
                    {
                        "probe_id": "oracle.tablespace_encryption",
                        "outcome": "collected",
                        "duration_ms": 20,
                        "row_count": 1,
                        "evidence_sha256": evidence_digest(
                            [{"tablespace_name": "USERS", "encrypted": "YES"}]
                        ),
                        "observations": [{"tablespace_name": "USERS", "encrypted": "YES"}],
                    }
                ]
            },
        },
    )
    assert completed.status_code == 200, completed.text

    evaluation_payload = {
        "assessment_id": run_data["assessment"]["id"],
        "control_definition_id": definition["id"],
        "source_job_id": completed.json()["id"],
    }
    evaluated = client.post(
        "/api/v1/control-results/evaluate",
        headers=mutation_headers(tenant_headers, "evaluate-control-result-01"),
        json=evaluation_payload,
    )
    assert evaluated.status_code == 201, evaluated.text
    assert evaluated.json()["outcome"] == "review_required"
    assert evaluated.json()["outcome"] != "passed"

    forged_result = client.post(
        "/api/v1/control-results/evaluate",
        headers=mutation_headers(tenant_headers, "evaluate-forged-observation-01"),
        json={
            **evaluation_payload,
            "probe_results": [
                {
                    "probe_id": "oracle.tablespace_encryption",
                    "outcome": "collected",
                    "duration_ms": 20,
                    "row_count": 1,
                    "evidence_sha256": evidence_digest([{"unapproved_value": "never accept"}]),
                    "observations": [{"unapproved_value": "never accept"}],
                }
            ],
        },
    )
    assert forged_result.status_code == 422
    assert forged_result.json()["error"]["code"] == "source_job_result_mismatch"


def test_multi_probe_completion_orchestrates_exact_control_subsets_once(client, tenant_headers):
    asset, connector, pack = create_asset_connector_pack(
        client,
        tenant_headers,
        pack=multi_probe_pack_payload(),
    )
    run = start_run(
        client,
        tenant_headers,
        asset,
        connector,
        pack,
        key="multi-probe-assessment-run-01",
    ).json()
    collector_headers = {
        "X-Tenant-ID": "tenant-alpha",
        "X-Subject": "collector-east-1",
        "X-Roles": "collector",
    }
    heartbeat = client.post(
        "/api/v1/collectors/heartbeat",
        headers=mutation_headers(collector_headers, "multi-probe-heartbeat-01"),
        json={
            "collector_id": "collector-east-1",
            "version": "0.1.0",
            "capabilities": ["control_assessment"],
        },
    )
    assert heartbeat.status_code == 200, heartbeat.text
    lease = client.post(
        "/api/v1/scan-jobs/lease",
        headers=mutation_headers(collector_headers, "multi-probe-lease-01"),
        json={
            "collector_id": "collector-east-1",
            "supported_job_types": ["control_assessment"],
        },
    )
    assert lease.status_code == 200, lease.text
    assert lease.json()["payload"]["probe_ids"] == [
        "oracle.tablespace_encryption",
        "oracle.unified_auditing",
    ]
    completion_payload = {
        "collector_id": "collector-east-1",
        "lease_token": lease.json()["lease_token"],
        "success": True,
        "result": {
            "probe_results": [
                {
                    "probe_id": "oracle.tablespace_encryption",
                    "outcome": "collected",
                    "duration_ms": 20,
                    "row_count": 1,
                    "evidence_sha256": evidence_digest(
                        [{"tablespace_name": "USERS", "encrypted": "YES"}]
                    ),
                    "observations": [{"tablespace_name": "USERS", "encrypted": "YES"}],
                },
                {
                    "probe_id": "oracle.unified_auditing",
                    "outcome": "insufficient_privilege",
                    "duration_ms": 8,
                    "row_count": 0,
                    "message": "Approved metadata privilege is unavailable.",
                    "observations": [],
                },
            ]
        },
    }
    completion_headers = mutation_headers(collector_headers, "multi-probe-complete-01")
    completed = client.post(
        f"/api/v1/scan-jobs/{lease.json()['id']}/complete",
        headers=completion_headers,
        json=completion_payload,
    )
    assert completed.status_code == 200, completed.text

    replay = client.post(
        f"/api/v1/scan-jobs/{lease.json()['id']}/complete",
        headers=completion_headers,
        json=completion_payload,
    )
    assert replay.status_code == 200
    assert replay.headers["Idempotent-Replayed"] == "true"
    duplicate = client.post(
        f"/api/v1/scan-jobs/{lease.json()['id']}/complete",
        headers=mutation_headers(collector_headers, "multi-probe-complete-02"),
        json=completion_payload,
    )
    assert duplicate.status_code == 409

    results = client.get("/api/v1/control-results", headers=tenant_headers).json()["items"]
    assert len(results) == 2
    by_control = {result["control_id"]: result for result in results}
    assert by_control["oracle.encryption.tablespace-metadata"]["outcome"] == "review_required"
    assert by_control["oracle.encryption.tablespace-metadata"]["probe_outcomes"] == ["collected"]
    assert by_control["oracle.encryption.tablespace-metadata"]["evidence_count"] == 1
    assert (
        by_control["oracle.data-protection.unified-auditing-metadata"]["outcome"]
        == "insufficient_privilege"
    )
    assert by_control["oracle.data-protection.unified-auditing-metadata"]["probe_outcomes"] == [
        "insufficient_privilege"
    ]
    findings = client.get("/api/v1/findings", headers=tenant_headers).json()["items"]
    assert len(findings) == 1
    assert findings[0]["control_id"] == "oracle.data-protection.unified-auditing-metadata"
    evidence = client.get("/api/v1/evidence", headers=tenant_headers).json()["items"]
    assert len(evidence) == 1
    assert evidence[0]["control_id"] == "oracle.encryption.tablespace-metadata"
    assert (
        evidence[0]["sha256"] == completion_payload["result"]["probe_results"][0]["evidence_sha256"]
    )
    assert evidence[0]["attributes"] == {
        "source_job_id": completed.json()["id"],
        "probe_id": "oracle.tablespace_encryption",
        "row_count": 1,
        "outcome": "collected",
    }
    assert "observations" not in evidence[0]["attributes"]

    assessment = next(
        item
        for item in client.get("/api/v1/assessments", headers=tenant_headers).json()["items"]
        if item["id"] == run["assessment"]["id"]
    )
    assert assessment["status"] == "failed"
    assert assessment["score"] is None
    assert assessment["summary"]["control_results"] == 2
    assert assessment["summary"]["collection_coverage"] == 50
    assert assessment["summary"]["evidence"] == 1
    assert assessment["summary"]["score_basis"] == "human_control_decision_required"

    encryption_definition = next(
        item
        for item in pack["controls"]
        if item["control_id"] == "oracle.encryption.tablespace-metadata"
    )
    evaluated = client.post(
        "/api/v1/control-results/evaluate",
        headers=mutation_headers(tenant_headers, "evaluate-multi-probe-subset-01"),
        json={
            "assessment_id": run["assessment"]["id"],
            "control_definition_id": encryption_definition["id"],
            "source_job_id": completed.json()["id"],
        },
    )
    assert evaluated.status_code == 201, evaluated.text
    assert evaluated.json()["id"] == by_control["oracle.encryption.tablespace-metadata"]["id"]
    assert len(client.get("/api/v1/control-results", headers=tenant_headers).json()["items"]) == 2


def test_exhausted_collector_failure_atomically_fails_assessment(client, tenant_headers):
    asset, connector, pack = create_asset_connector_pack(client, tenant_headers)
    run = start_run(
        client,
        tenant_headers,
        asset,
        connector,
        pack,
        key="terminal-failure-assessment-run-01",
        max_attempts=1,
    ).json()
    collector_headers = {
        "X-Tenant-ID": "tenant-alpha",
        "X-Subject": "collector-east-1",
        "X-Roles": "collector",
    }
    assert (
        client.post(
            "/api/v1/collectors/heartbeat",
            headers=mutation_headers(collector_headers, "terminal-failure-heartbeat-01"),
            json={
                "collector_id": "collector-east-1",
                "version": "0.1.0",
                "capabilities": ["control_assessment"],
            },
        ).status_code
        == 200
    )
    lease = client.post(
        "/api/v1/scan-jobs/lease",
        headers=mutation_headers(collector_headers, "terminal-failure-lease-01"),
        json={
            "collector_id": "collector-east-1",
            "supported_job_types": ["control_assessment"],
        },
    ).json()
    failure_payload = {
        "collector_id": "collector-east-1",
        "lease_token": lease["lease_token"],
        "success": False,
        "result": {"probe_results": []},
        "error": "source credential could not be resolved",
    }
    failure_headers = mutation_headers(collector_headers, "terminal-failure-complete-01")
    failed = client.post(
        f"/api/v1/scan-jobs/{lease['id']}/complete",
        headers=failure_headers,
        json=failure_payload,
    )
    assert failed.status_code == 200, failed.text
    assert failed.json()["status"] == "failed"
    replay = client.post(
        f"/api/v1/scan-jobs/{lease['id']}/complete",
        headers=failure_headers,
        json=failure_payload,
    )
    assert replay.status_code == 200
    assert replay.headers["Idempotent-Replayed"] == "true"

    assessment = next(
        item
        for item in client.get("/api/v1/assessments", headers=tenant_headers).json()["items"]
        if item["id"] == run["assessment"]["id"]
    )
    assert assessment["status"] == "failed"
    assert assessment["score"] is None
    assert assessment["completed_at"] is not None
    assert assessment["summary"]["collection_status"] == "failed"
    assert assessment["summary"]["score_basis"] == ("no_assurance_score_when_collection_fails")
    assert client.get("/api/v1/control-results", headers=tenant_headers).json()["items"] == []


@pytest.mark.parametrize(
    ("source_outcome", "expected"),
    [
        ("collected", ControlResultOutcome.REVIEW_REQUIRED),
        ("review_required", ControlResultOutcome.REVIEW_REQUIRED),
        ("passed", ControlResultOutcome.REVIEW_REQUIRED),
        ("failed", ControlResultOutcome.REVIEW_REQUIRED),
        ("error", ControlResultOutcome.COLLECTION_ERROR),
        ("unsupported", ControlResultOutcome.UNSUPPORTED),
        ("insufficient_privilege", ControlResultOutcome.INSUFFICIENT_PRIVILEGE),
    ],
)
def test_analyst_review_evaluator_never_infers_pass(source_outcome, expected):
    decision = evaluate_analyst_review_control(
        assessment_mode="automated_evidence",
        probe_outcomes=[source_outcome],
        evidence_count=0,
    )
    assert decision.outcome == expected
    assert decision.outcome != ControlResultOutcome.PASSED


def test_exception_separation_delivery_fencing_and_inbox_deduplication(client, tenant_headers):
    asset, connector, pack = create_asset_connector_pack(client, tenant_headers)
    run = start_run(
        client,
        tenant_headers,
        asset,
        connector,
        pack,
        key="exception-assessment-run-01",
    ).json()
    finding = client.post(
        "/api/v1/findings",
        headers=mutation_headers(tenant_headers, "create-exception-finding-01"),
        json={
            "assessment_id": run["assessment"]["id"],
            "asset_id": asset["id"],
            "control_id": pack["controls"][0]["control_id"],
            "fingerprint": "exception-fingerprint-01",
            "domain": "encryption",
            "title": "Encryption metadata requires review",
            "description": "Review collected metadata against the approved exception scope.",
            "severity": "high",
            "remediation": "Validate policy scope before changing database configuration.",
        },
    ).json()

    for disposition in ("risk_accepted", "false_positive"):
        rejected_disposition = client.patch(
            f"/api/v1/findings/{finding['id']}",
            headers=mutation_headers(
                tenant_headers,
                f"reject-generic-{disposition.replace('_', '-')}-01",
            ),
            json={
                "status": disposition,
                "reason": "A terminal risk disposition requires a governed workflow.",
            },
        )
        assert rejected_disposition.status_code == 422
        assert rejected_disposition.json()["error"]["code"] == "validation_failed"

    in_progress = client.patch(
        f"/api/v1/findings/{finding['id']}",
        headers=mutation_headers(tenant_headers, "start-finding-remediation-01"),
        json={
            "status": "in_progress",
            "owner": "Database Engineering",
            "reason": "Database Engineering started the approved remediation plan.",
        },
    )
    assert in_progress.status_code == 200, in_progress.text
    assert in_progress.json()["status"] == "in_progress"

    requested = client.post(
        f"/api/v1/findings/{finding['id']}/exceptions",
        headers=mutation_headers(tenant_headers, "request-finding-exception-01"),
        json={
            "request_key": "finding-exception-request-01",
            "justification": "A documented migration window requires temporary risk acceptance.",
            "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
        },
    )
    assert requested.status_code == 201, requested.text

    requester_as_approver = {
        **tenant_headers,
        "X-Roles": "security_analyst,exception_approver",
    }
    self_approval = client.post(
        f"/api/v1/finding-exceptions/{requested.json()['id']}/decision",
        headers=mutation_headers(requester_as_approver, "self-approve-exception-01"),
        json={
            "decision": "approve",
            "reason": "The requester must never be able to approve this request.",
        },
    )
    assert self_approval.status_code == 403
    assert self_approval.json()["error"]["code"] == "separation_of_duties_violation"

    approver = {
        "X-Tenant-ID": "tenant-alpha",
        "X-Subject": "risk-approver@example.com",
        "X-Roles": "exception_approver",
    }
    approved = client.post(
        f"/api/v1/finding-exceptions/{requested.json()['id']}/decision",
        headers=mutation_headers(approver, "approve-finding-exception-01"),
        json={
            "decision": "approve",
            "reason": "Risk owner approval is recorded for the bounded migration period.",
        },
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"
    assert (
        client.get("/api/v1/findings", headers=tenant_headers).json()["items"][0]["status"]
        == "risk_accepted"
    )

    bypass_revoke = client.patch(
        f"/api/v1/findings/{finding['id']}",
        headers=mutation_headers(tenant_headers, "bypass-approved-exception-01"),
        json={
            "status": "resolved",
            "reason": "A generic workflow update must not bypass exception revocation.",
        },
    )
    assert bypass_revoke.status_code == 409
    assert bypass_revoke.json()["error"]["code"] == "conflict"

    revoked = client.post(
        f"/api/v1/finding-exceptions/{requested.json()['id']}/revoke",
        headers=mutation_headers(approver, "revoke-finding-exception-01"),
        json={"reason": "The migration window ended and normal control handling resumes."},
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"
    assert (
        client.get("/api/v1/findings", headers=tenant_headers).json()["items"][0]["status"]
        == "open"
    )

    resolved = client.patch(
        f"/api/v1/findings/{finding['id']}",
        headers=mutation_headers(tenant_headers, "resolve-after-exception-revoke-01"),
        json={
            "status": "resolved",
            "reason": "The exception is revoked and remediation is independently verified.",
        },
    )
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["status"] == "resolved"

    worker = {
        "X-Tenant-ID": "tenant-alpha",
        "X-Subject": "integration-worker-1",
        "X-Roles": "integration_worker",
    }
    leased = client.post(
        "/api/v1/integrations/outbox/lease",
        headers=mutation_headers(worker, "lease-governance-outbox-01"),
        json={"worker_id": "integration-worker-1", "destinations": ["grc"]},
    )
    assert leased.status_code == 200, leased.text
    stale = client.post(
        f"/api/v1/integrations/outbox/{leased.json()['id']}/complete",
        headers=mutation_headers(worker, "complete-outbox-stale-01"),
        json={
            "worker_id": "integration-worker-1",
            "lease_token": "00000000-0000-4000-8000-000000000000",
            "success": True,
        },
    )
    assert stale.status_code == 409
    delivered = client.post(
        f"/api/v1/integrations/outbox/{leased.json()['id']}/complete",
        headers=mutation_headers(worker, "complete-outbox-valid-01"),
        json={
            "worker_id": "integration-worker-1",
            "lease_token": leased.json()["lease_token"],
            "success": True,
            "external_reference": "grc-event-0001",
        },
    )
    assert delivered.status_code == 200
    assert delivered.json()["status"] == "delivered"

    inbox_payload = {
        "worker_id": "integration-worker-1",
        "source": "grc",
        "message_id": "grc-message-0001",
        "event_type": "exception.acknowledged",
        "payload": {"status": "acknowledged"},
    }
    accepted = client.post(
        "/api/v1/integrations/inbox",
        headers=mutation_headers(worker, "accept-inbox-message-01"),
        json=inbox_payload,
    )
    assert accepted.status_code == 201, accepted.text
    duplicate = client.post(
        "/api/v1/integrations/inbox",
        headers=mutation_headers(worker, "accept-inbox-message-02"),
        json=inbox_payload,
    )
    assert duplicate.status_code == 201
    assert duplicate.json()["id"] == accepted.json()["id"]
    mismatch = client.post(
        "/api/v1/integrations/inbox",
        headers=mutation_headers(worker, "accept-inbox-message-03"),
        json={**inbox_payload, "payload": {"status": "changed"}},
    )
    assert mismatch.status_code == 409
