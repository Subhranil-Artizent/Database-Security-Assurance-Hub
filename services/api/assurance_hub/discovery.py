from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

Classification = Literal["restricted", "confidential", "internal"]

_RESTRICTED = (
    "aadhaar",
    "pan_attached",
    "national_id",
    "passport",
    "tax_identifier",
    "client_full_name",
    "account_number",
    "card_number",
    "cvv",
    "iban",
)
_CONFIDENTIAL = (
    "payee",
    "service_provider",
    "garage_name",
    "hospital_name",
    "court_name",
    "agent_name",
    "policy_id",
    "policy_trans",
    "claim_id",
    "claimid",
    "case_id",
    "caseid",
    "paid_amount",
    "paidamount",
    "premium",
    "commission",
    "expenses",
    "gross_estimate",
    "service_tax",
    "insured",
    "employee",
    "lives",
)
_INTERNAL = (
    "payment_mode",
    "settlement_mode",
    "survey_type",
    "city",
    "state",
    "loss_date",
    "paid_date",
    "close_date",
    "issued_date",
)


@dataclass(frozen=True, slots=True)
class DiscoveredColumn:
    id: str
    asset_id: str
    asset_name: str
    platform: Literal["mysql"]
    schema: str
    table: str
    column: str
    classification: Classification
    data_type: str
    confidence: int
    protection: Literal["unknown"]
    created_at: datetime


def normalized_identifier(value: str) -> str:
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return re.sub(r"[^a-z0-9]+", "_", separated.lower()).strip("_")


def classify_column(column_name: str) -> tuple[Classification, int] | None:
    name = normalized_identifier(column_name)
    if any(marker in name for marker in _RESTRICTED):
        return "restricted", 98
    if any(marker in name for marker in _CONFIDENTIAL):
        return "confidential", 92
    if any(marker in name for marker in _INTERNAL):
        return "internal", 84
    return None


def discovered_column(
    *,
    asset_id: str,
    asset_name: str,
    schema: str,
    table: str,
    column: str,
    data_type: str,
    collected_at: datetime,
) -> DiscoveredColumn | None:
    classified = classify_column(column)
    if classified is None:
        return None
    classification, confidence = classified
    identifier = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"aegisdb://assets/{asset_id}/columns/{schema}/{table}/{column}",
    )
    return DiscoveredColumn(
        id=str(identifier),
        asset_id=asset_id,
        asset_name=asset_name,
        platform="mysql",
        schema=schema,
        table=table,
        column=column,
        classification=classification,
        data_type=data_type,
        confidence=confidence,
        protection="unknown",
        created_at=collected_at,
    )
