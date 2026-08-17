from __future__ import annotations

import json
from dataclasses import replace

import pytest

from assurance_collector.local_masker import execute_local_masking_copy
from assurance_collector.masking_engine import (
    ROW_CAP,
    SOURCE_DATABASE,
    STAGING_DATABASE,
    TARGET_DATABASE,
    ColumnSpec,
    DatabaseSnapshot,
    MaskingBoundaryError,
    TableSnapshot,
    mask_snapshot,
)

MASTER_KEY = b"m" * 32
RAW_NAME = "Sensitive Person"


def source_snapshot(name: str = RAW_NAME) -> DatabaseSnapshot:
    return DatabaseSnapshot(
        database=SOURCE_DATABASE,
        tables=(
            TableSnapshot(
                name="policy_holders",
                columns=(
                    ColumnSpec("holder_id", "INT", nullable=False),
                    ColumnSpec(
                        "client_full_name", "VARCHAR(80)", sensitive=True, max_length=80
                    ),
                ),
                primary_key=("holder_id",),
                rows=((1, name),),
            ),
        ),
    )


class FakeSource:
    def __init__(self, snapshots: list[DatabaseSnapshot], *, read_only: bool = True) -> None:
        self.snapshots = snapshots
        self.read_only = read_only
        self.reads = 0

    def verify_read_only(self, database: str) -> bool:
        assert database == SOURCE_DATABASE
        return self.read_only

    def read_snapshot(self, database: str, row_cap: int) -> DatabaseSnapshot:
        assert database == SOURCE_DATABASE
        assert row_cap == ROW_CAP
        selected = self.snapshots[min(self.reads, len(self.snapshots) - 1)]
        self.reads += 1
        return selected


class FakeTarget:
    def __init__(
        self,
        *,
        target_only: bool = True,
        empty: bool = True,
        foreign_keys_valid: bool = True,
        tamper: bool = False,
        existing_final: DatabaseSnapshot | None = None,
    ) -> None:
        self.target_only = target_only
        self.empty = empty
        self.fk_valid = foreign_keys_valid
        self.tamper = tamper
        self.existing_final = existing_final
        self.staged: DatabaseSnapshot | None = None
        self.published: DatabaseSnapshot | None = None
        self.committed = False
        self.rolled_back = False

    def verify_target_only(
        self, source_database: str, target_database: str, staging_database: str
    ) -> bool:
        assert source_database == SOURCE_DATABASE
        assert target_database == TARGET_DATABASE
        assert staging_database == STAGING_DATABASE
        return self.target_only

    def read_existing_final(
        self, expected: DatabaseSnapshot, row_cap: int
    ) -> DatabaseSnapshot | None:
        assert expected.database == TARGET_DATABASE
        assert row_cap == ROW_CAP
        if self.existing_final is not None:
            return self.existing_final
        if not self.empty:
            raise MaskingBoundaryError("no overwrite was attempted")
        return None

    def stage(self, snapshot: DatabaseSnapshot) -> None:
        assert snapshot.database == TARGET_DATABASE
        self.staged = snapshot

    def read_staged_snapshot(self, database: str, row_cap: int) -> DatabaseSnapshot:
        assert database == STAGING_DATABASE
        assert row_cap == ROW_CAP
        assert self.staged is not None
        observed = replace(self.staged, database=STAGING_DATABASE)
        if not self.tamper:
            return observed
        table = observed.tables[0]
        return replace(
            observed,
            tables=(replace(table, rows=((1, "tampered"),)),),
        )

    def foreign_keys_valid(self, database: str) -> bool:
        assert database in {STAGING_DATABASE, TARGET_DATABASE}
        return self.fk_valid

    def publish(self) -> None:
        assert self.staged is not None
        self.published = self.staged

    def read_final_snapshot(self, row_cap: int) -> DatabaseSnapshot:
        assert row_cap == ROW_CAP
        assert self.published is not None
        return self.published

    def finish(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True


def execute(source: FakeSource, target: FakeTarget):
    return execute_local_masking_copy(
        host="127.0.0.1",
        port=3306,
        source_database=SOURCE_DATABASE,
        target_database=TARGET_DATABASE,
        master_key=MASTER_KEY,
        source=source,
        target=target,
    )


def test_copy_verifies_source_and_returns_aggregate_only_evidence() -> None:
    original = source_snapshot()
    source = FakeSource([original, original])
    target = FakeTarget()

    result = execute(source, target)

    assert source.reads == 3
    assert target.committed is True
    assert target.rolled_back is False
    assert target.staged is not None
    assert target.staged.tables[0].rows[0][1] != RAW_NAME
    assert original.tables[0].rows[0][1] == RAW_NAME
    assert result.source_digest_match is True
    assert result.target_counts_match is True
    assert result.foreign_keys_valid is True
    assert result.raw_values_exported is False
    assert result.rows_copied == 1
    assert len(result.manifest_sha256) == 64
    encoded = json.dumps(result.as_summary(), sort_keys=True)
    assert RAW_NAME not in encoded
    assert "password" not in encoded.lower()


def test_source_change_rolls_back_and_never_reports_success() -> None:
    source = FakeSource([source_snapshot(), source_snapshot("Changed During Copy")])
    target = FakeTarget()

    with pytest.raises(MaskingBoundaryError, match="source changed"):
        execute(source, target)

    assert target.committed is False
    assert target.rolled_back is True


def test_source_change_after_publish_creates_no_success_evidence() -> None:
    original = source_snapshot()
    changed = source_snapshot("Changed After Publish")
    source = FakeSource([original, original, changed])
    target = FakeTarget()

    with pytest.raises(MaskingBoundaryError, match="source changed"):
        execute(source, target)

    assert target.published is not None
    assert target.committed is False
    assert target.rolled_back is True


@pytest.mark.parametrize(
    ("source", "target", "message"),
    [
        (FakeSource([source_snapshot()], read_only=False), FakeTarget(), "strictly read-only"),
        (FakeSource([source_snapshot()]), FakeTarget(target_only=False), "restricted"),
        (FakeSource([source_snapshot()]), FakeTarget(empty=False), "no overwrite"),
    ],
)
def test_credential_and_no_overwrite_boundaries_fail_before_staging(
    source: FakeSource, target: FakeTarget, message: str
) -> None:
    with pytest.raises(MaskingBoundaryError, match=message):
        execute(source, target)
    assert target.staged is None
    assert target.committed is False


def test_target_tamper_or_foreign_key_failure_rolls_back() -> None:
    original = source_snapshot()
    for target in (FakeTarget(tamper=True), FakeTarget(foreign_keys_valid=False)):
        with pytest.raises(MaskingBoundaryError):
            execute(FakeSource([original, original]), target)
        assert target.committed is False
        assert target.rolled_back is True


def test_exact_existing_final_replays_without_any_write() -> None:
    original = source_snapshot()
    expected = mask_snapshot(original, MASTER_KEY).target
    target = FakeTarget(existing_final=expected)

    result = execute(FakeSource([original, original]), target)

    assert result.target_counts_match is True
    assert target.staged is None
    assert target.published is None
    assert target.committed is False
    assert target.rolled_back is False


def test_mismatched_existing_final_fails_closed_without_any_write() -> None:
    original = source_snapshot()
    expected = mask_snapshot(original, MASTER_KEY).target
    table = expected.tables[0]
    mismatched = replace(expected, tables=(replace(table, rows=((1, "wrong"),)),))
    target = FakeTarget(existing_final=mismatched)

    with pytest.raises(MaskingBoundaryError, match="deterministic copy"):
        execute(FakeSource([original]), target)

    assert target.staged is None
    assert target.published is None


def test_invalid_port_and_short_key_fail_closed() -> None:
    with pytest.raises(MaskingBoundaryError, match="port"):
        execute_local_masking_copy(
            host="127.0.0.1",
            port=0,
            source_database=SOURCE_DATABASE,
            target_database=TARGET_DATABASE,
            master_key=MASTER_KEY,
            source=FakeSource([source_snapshot()]),
            target=FakeTarget(),
        )
    with pytest.raises(MaskingBoundaryError, match="256-bit"):
        execute_local_masking_copy(
            host="127.0.0.1",
            port=3306,
            source_database=SOURCE_DATABASE,
            target_database=TARGET_DATABASE,
            master_key=b"short",
            source=FakeSource([source_snapshot()]),
            target=FakeTarget(),
        )
