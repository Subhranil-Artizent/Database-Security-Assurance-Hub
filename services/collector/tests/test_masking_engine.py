from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal

import pytest

from assurance_collector.masking_engine import (
    ROW_CAP,
    SOURCE_DATABASE,
    TARGET_DATABASE,
    TARGET_DATABASE_PREFIX,
    ColumnSpec,
    DatabaseSnapshot,
    MaskingBoundaryError,
    TableSnapshot,
    mask_snapshot,
    snapshot_hmac,
    staging_database_for_target,
    validate_local_boundary,
)

MASTER_KEY = bytes(range(32))


def insurance_snapshot() -> DatabaseSnapshot:
    return DatabaseSnapshot(
        database=SOURCE_DATABASE,
        tables=(
            TableSnapshot(
                name="customers",
                columns=(
                    ColumnSpec(
                        "customer_id",
                        "INT",
                        nullable=False,
                        sensitive=True,
                        relation_group="customer_id",
                    ),
                    ColumnSpec("full_name", "VARCHAR(40)", sensitive=True, max_length=40),
                    ColumnSpec("email", "VARCHAR(80)", sensitive=True, max_length=80),
                    ColumnSpec("active", "BOOLEAN", nullable=False),
                ),
                primary_key=("customer_id",),
                rows=(
                    (101, "Alice Roy", "alice@example.test", True),
                    (202, "Bob Sen", "bob@example.test", False),
                ),
            ),
            TableSnapshot(
                name="claims",
                columns=(
                    ColumnSpec("claim_id", "BIGINT", nullable=False),
                    ColumnSpec(
                        "customer_id",
                        "INT",
                        nullable=False,
                        sensitive=True,
                        relation_group="customer_id",
                    ),
                    ColumnSpec(
                        "paid_amount",
                        "DECIMAL(12,2)",
                        sensitive=True,
                        precision=12,
                        scale=2,
                    ),
                    ColumnSpec("loss_date", "DATE", sensitive=True),
                    ColumnSpec("document", "VARBINARY(32)", sensitive=True, max_length=32),
                ),
                primary_key=("claim_id",),
                rows=(
                    (1, 101, Decimal("1250.50"), date(2025, 1, 5), b"claim-one"),
                    (2, 202, Decimal("980.00"), date(2025, 2, 6), b"claim-two"),
                ),
            ),
        ),
    )


def test_masking_is_deterministic_type_safe_and_preserves_relationships() -> None:
    source = insurance_snapshot()
    first = mask_snapshot(source, MASTER_KEY)
    second = mask_snapshot(source, MASTER_KEY)

    assert first == second
    assert first.target.database == TARGET_DATABASE
    assert first.tables_copied == 2
    assert first.rows_copied == 4
    assert first.columns_masked == 7
    assert first.values_masked == 14

    customers, claims = first.target.tables
    customer_rows = customers.rows
    claim_rows = claims.rows
    assert customer_rows[0][0] == claim_rows[0][1]
    assert customer_rows[1][0] == claim_rows[1][1]
    assert customer_rows[0][0] != 101
    assert customer_rows[0][1] != "Alice Roy"
    assert len(str(customer_rows[0][1])) == len("Alice Roy")
    assert len(str(customer_rows[0][2])) == len("alice@example.test")
    assert customer_rows[0][3] is True
    assert isinstance(claim_rows[0][2], Decimal)
    assert isinstance(claim_rows[0][3], date)
    assert isinstance(claim_rows[0][4], bytes)
    assert len(claim_rows[0][4]) == len(b"claim-one")
    assert source == insurance_snapshot(), "the pure engine must not mutate its source"


def test_snapshot_hmac_is_order_independent_but_detects_changes() -> None:
    source = insurance_snapshot()
    reordered = DatabaseSnapshot(
        database=source.database,
        tables=tuple(
            TableSnapshot(
                name=table.name,
                columns=table.columns,
                rows=tuple(reversed(table.rows)),
                primary_key=table.primary_key,
                foreign_keys=table.foreign_keys,
            )
            for table in source.tables
        ),
    )
    changed_customers = source.tables[0]
    changed = DatabaseSnapshot(
        database=source.database,
        tables=(
            TableSnapshot(
                name=changed_customers.name,
                columns=changed_customers.columns,
                rows=((101, "Changed Name", "alice@example.test", True),)
                + changed_customers.rows[1:],
                primary_key=changed_customers.primary_key,
            ),
            source.tables[1],
        ),
    )
    key = b"e" * 32
    assert snapshot_hmac(source, key) == snapshot_hmac(reordered, key)
    assert snapshot_hmac(source, key) != snapshot_hmac(changed, key)


@pytest.mark.parametrize("host", ["db.example", "192.0.2.1", "::1", "127.0.0.2"])
def test_boundary_rejects_every_nonliteral_loopback_host(host: str) -> None:
    with pytest.raises(MaskingBoundaryError, match="literal loopback"):
        validate_local_boundary(host, SOURCE_DATABASE, TARGET_DATABASE)


def test_boundary_rejects_same_or_unapproved_databases() -> None:
    with pytest.raises(MaskingBoundaryError, match="fixed source"):
        validate_local_boundary("127.0.0.1", "another_database", TARGET_DATABASE)
    with pytest.raises(MaskingBoundaryError, match="derived target"):
        validate_local_boundary("127.0.0.1", SOURCE_DATABASE, SOURCE_DATABASE)
    with pytest.raises(MaskingBoundaryError, match="derived target"):
        validate_local_boundary("127.0.0.1", SOURCE_DATABASE, "insurance_sample_copy")


def test_each_workflow_can_use_its_own_server_derived_target() -> None:
    target_database = f"{TARGET_DATABASE_PREFIX}0123456789ab"

    validate_local_boundary("127.0.0.1", SOURCE_DATABASE, target_database)
    transformation = mask_snapshot(
        insurance_snapshot(), MASTER_KEY, target_database=target_database
    )

    assert transformation.target.database == target_database
    assert staging_database_for_target(target_database) == "aegisdb_mask_stage_0123456789ab"


def test_row_cap_generated_columns_and_unsupported_types_fail_closed() -> None:
    too_many = DatabaseSnapshot(
        database=SOURCE_DATABASE,
        tables=(
            TableSnapshot(
                name="claims",
                columns=(ColumnSpec("claim_id", "INT"),),
                rows=tuple((index,) for index in range(ROW_CAP + 1)),
            ),
        ),
    )
    with pytest.raises(MaskingBoundaryError, match="row cap"):
        mask_snapshot(too_many, MASTER_KEY)

    generated = DatabaseSnapshot(
        database=SOURCE_DATABASE,
        tables=(
            TableSnapshot(
                name="claims",
                columns=(ColumnSpec("derived", "VARCHAR(10)", generated=True),),
                rows=(("value",),),
            ),
        ),
    )
    with pytest.raises(MaskingBoundaryError, match="generated"):
        mask_snapshot(generated, MASTER_KEY)

    unsupported = DatabaseSnapshot(
        database=SOURCE_DATABASE,
        tables=(
            TableSnapshot(
                name="claims",
                columns=(ColumnSpec("location", "GEOMETRY", sensitive=True),),
                rows=((b"point",),),
            ),
        ),
    )
    with pytest.raises(MaskingBoundaryError, match="unsupported"):
        mask_snapshot(unsupported, MASTER_KEY)


def test_incompatible_relationship_types_and_exhausted_domains_fail_closed() -> None:
    incompatible = DatabaseSnapshot(
        database=SOURCE_DATABASE,
        tables=(
            TableSnapshot(
                name="parents",
                columns=(ColumnSpec("id", "INT", sensitive=True, relation_group="link"),),
                rows=((1,),),
            ),
            TableSnapshot(
                name="children",
                columns=(
                    ColumnSpec("parent_id", "VARCHAR(10)", sensitive=True, relation_group="link"),
                ),
                rows=(("1",),),
            ),
        ),
    )
    with pytest.raises(MaskingBoundaryError, match="incompatible"):
        mask_snapshot(incompatible, MASTER_KEY)

    exhausted_boolean = DatabaseSnapshot(
        database=SOURCE_DATABASE,
        tables=(
            TableSnapshot(
                name="flags",
                columns=(ColumnSpec("flag", "BOOLEAN", sensitive=True),),
                rows=((True,), (False,)),
            ),
        ),
    )
    with pytest.raises(MaskingBoundaryError, match="collision-free"):
        mask_snapshot(exhausted_boolean, MASTER_KEY)


def test_dense_numeric_strings_use_the_full_reviewed_string_domain() -> None:
    source = DatabaseSnapshot(
        database=SOURCE_DATABASE,
        tables=(
            TableSnapshot(
                name="policies",
                columns=(
                    ColumnSpec(
                        "premium",
                        "VARCHAR(50)",
                        sensitive=True,
                        max_length=50,
                    ),
                ),
                rows=tuple((str(index),) for index in range(31)),
            ),
        ),
    )

    masked_rows = mask_snapshot(source, MASTER_KEY).target.tables[0].rows

    assert len({row[0] for row in masked_rows}) == len(source.tables[0].rows)
    assert all(
        isinstance(masked[0], str)
        and len(masked[0]) == len(original[0])
        and masked[0] != original[0]
        for original, masked in zip(source.tables[0].rows, masked_rows, strict=True)
    )


def test_timestamp_masking_stays_inside_the_supported_database_range() -> None:
    source = DatabaseSnapshot(
        database=SOURCE_DATABASE,
        tables=(
            TableSnapshot(
                name="events",
                columns=(ColumnSpec("occurred_at", "TIMESTAMP", sensitive=True),),
                rows=((datetime(2038, 1, 18, 12, 0),),),
            ),
        ),
    )
    masked = mask_snapshot(source, MASTER_KEY).target.tables[0].rows[0][0]
    assert isinstance(masked, datetime)
    assert datetime(1970, 1, 1) <= masked <= datetime(2038, 1, 19, 3, 14, 7)
