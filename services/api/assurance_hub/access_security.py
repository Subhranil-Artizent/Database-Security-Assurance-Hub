from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import (
    AccessReview,
    Connector,
    DatabasePlatform,
    ReviewStatus,
    ScanJob,
    WorkStatus,
)
from .schemas import JobResult

REVIEW_NAME = "Local MySQL collector account verification"
EXPECTED_PRIVILEGES = {"SELECT", "SHOW VIEW"}


async def reconcile_mysql_access_review(
    session: AsyncSession,
    *,
    job: ScanJob,
    job_result: JobResult,
    now: datetime,
) -> None:
    """Upsert the local collector-account review from bounded metadata evidence."""
    if job.job_type != "access_review" or job.status == WorkStatus.PENDING:
        return
    connector = await session.scalar(
        select(Connector).where(
            Connector.id == job.connector_id,
            Connector.tenant_id == job.tenant_id,
        )
    )
    if connector is None or connector.platform != DatabasePlatform.MYSQL:
        return

    results = {result.probe_id: result for result in job_result.probe_results}
    context = results.get("mysql.account_context")
    grants = results.get("mysql.account_privileges")
    context_rows = context.observations if context and context.outcome == "collected" else []
    grant_rows = grants.observations if grants and grants.outcome == "collected" else []

    account = "Collector account not reported"
    active_role = "Not reported"
    privileges: set[str] = set()
    grantable = False
    evidence_complete = len(context_rows) == 1 and bool(grant_rows)
    if context_rows:
        account = str(context_rows[0].get("account", account))
        active_role = str(context_rows[0].get("active_role", active_role))
    grant_accounts = {str(row.get("account", "")) for row in grant_rows}
    for row in grant_rows:
        privilege = str(row.get("privilege_type", "")).upper()
        if privilege:
            privileges.add(privilege)
        grantable = grantable or str(row.get("is_grantable", "")).upper() == "YES"
    evidence_complete = (
        evidence_complete
        and grant_accounts == {account}
        and active_role.upper() in {"NONE", "NULL"}
    )

    excessive = bool(privileges - EXPECTED_PRIVILEGES) or grantable
    verified = evidence_complete and privileges == EXPECTED_PRIVILEGES and not excessive
    if verified:
        status = ReviewStatus.APPROVED
        risk = "low"
        recommendation = "No action required; retain SELECT and SHOW VIEW only."
        evaluation = "verified_read_only"
    elif excessive:
        status = ReviewStatus.REMEDIATION_REQUIRED
        risk = "critical"
        recommendation = "Remove write, administrative, or grantable privileges immediately."
        evaluation = "excessive_privilege"
    else:
        status = ReviewStatus.IN_REVIEW
        risk = "medium"
        recommendation = (
            "Verification is incomplete; review the collector evidence before approval."
        )
        evaluation = "verification_incomplete"

    review = await session.scalar(
        select(AccessReview).where(
            AccessReview.tenant_id == job.tenant_id,
            AccessReview.asset_id == connector.asset_id,
            AccessReview.name == REVIEW_NAME,
        )
    )
    if review is None:
        review = AccessReview(
            tenant_id=job.tenant_id,
            asset_id=connector.asset_id,
            name=REVIEW_NAME,
            reviewer="Local Database Owner",
            due_at=now + timedelta(days=30),
        )
        session.add(review)
    review.scope = {
        "principal": account,
        "principal_type": "service_account",
        "access": ", ".join(sorted(privileges)) if privileges else "Not verified",
        "risk": risk,
        "checked_at": now.astimezone(UTC).isoformat(),
        "active_role": active_role,
        "recommendation": recommendation,
        "scan_scope": "collector_account_only",
    }
    review.status = status
    review.decision_summary = {
        "evaluation": evaluation,
        "reason": recommendation,
    }
    review.due_at = now + timedelta(days=365 if verified else 30)
