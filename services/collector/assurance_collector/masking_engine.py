from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, replace
from datetime import date, datetime, time, timedelta
from decimal import Decimal

SOURCE_DATABASE = "insurance_sample"
TARGET_DATABASE = "insurance_sample_masked"
STAGING_DATABASE = "insurance_sample_masked_staging"
TARGET_DATABASE_PREFIX = "insurance_sample_masked_"
STAGING_DATABASE_PREFIX = "aegisdb_mask_stage_"
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1"})
ROW_CAP = 500
MASKING_ALGORITHM = "hmac-sha256-local-v1"

type MaskValue = None | bool | int | float | Decimal | str | bytes | date | datetime | time

_IDENTIFIER = re.compile(r"^[A-Za-z0-9_]{1,64}$")
_WORKFLOW_SUFFIX = re.compile(r"^[a-f0-9]{12}$")
_INTEGER_RANGES: dict[str, tuple[int, int]] = {
    "tinyint": (-128, 127),
    "smallint": (-32768, 32767),
    "mediumint": (-8388608, 8388607),
    "int": (-2147483648, 2147483647),
    "integer": (-2147483648, 2147483647),
    "bigint": (-9223372036854775808, 9223372036854775807),
    "year": (1901, 2155),
}
_STRING_TYPES = {"char", "varchar", "tinytext", "text", "mediumtext", "longtext"}
_BINARY_TYPES = {"binary", "varbinary", "tinyblob", "blob", "mediumblob", "longblob"}
_DECIMAL_TYPES = {"decimal", "numeric"}
_FLOAT_TYPES = {"float", "double", "real"}
_DATE_TYPES = {"date", "datetime", "timestamp"}


class MaskingBoundaryError(RuntimeError):
    """A local masking operation crossed or could not prove a safety boundary."""


@dataclass(frozen=True, slots=True)
class ColumnSpec:
    name: str
    mysql_type: str
    nullable: bool = True
    sensitive: bool = False
    max_length: int | None = None
    precision: int | None = None
    scale: int | None = None
    unsigned: bool = False
    relation_group: str | None = None
    generated: bool = False


@dataclass(frozen=True, slots=True)
class ForeignKeySpec:
    child_columns: tuple[str, ...]
    parent_table: str
    parent_columns: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TableSnapshot:
    name: str
    columns: tuple[ColumnSpec, ...]
    rows: tuple[tuple[MaskValue, ...], ...]
    primary_key: tuple[str, ...] = ()
    foreign_keys: tuple[ForeignKeySpec, ...] = ()
    table_kind: str = "BASE TABLE"
    create_statement: str | None = None


@dataclass(frozen=True, slots=True)
class DatabaseSnapshot:
    database: str
    tables: tuple[TableSnapshot, ...]


@dataclass(frozen=True, slots=True)
class MaskingTransformation:
    target: DatabaseSnapshot
    tables_copied: int
    rows_copied: int
    columns_masked: int
    values_masked: int


def validate_local_boundary(host: str, source_database: str, target_database: str) -> None:
    if host not in LOOPBACK_HOSTS:
        raise MaskingBoundaryError("local masking accepts only a literal loopback host")
    if source_database != SOURCE_DATABASE:
        raise MaskingBoundaryError("local masking accepts only its fixed source database")
    if not is_approved_target_database(target_database):
        raise MaskingBoundaryError("local masking accepts only a server-derived target database")
    if source_database.casefold() == target_database.casefold():
        raise MaskingBoundaryError("source and target databases must be distinct")


def is_approved_target_database(database: str) -> bool:
    """Accept the legacy target or a server-derived per-workflow target."""
    if database == TARGET_DATABASE:
        return True
    if not database.startswith(TARGET_DATABASE_PREFIX):
        return False
    return _WORKFLOW_SUFFIX.fullmatch(database[len(TARGET_DATABASE_PREFIX) :]) is not None


def staging_database_for_target(target_database: str) -> str:
    if target_database == TARGET_DATABASE:
        return STAGING_DATABASE
    if not is_approved_target_database(target_database):
        raise MaskingBoundaryError("masking target database is outside the approved boundary")
    suffix = target_database[len(TARGET_DATABASE_PREFIX) :]
    return f"{STAGING_DATABASE_PREFIX}{suffix}"


def is_approved_staging_database(database: str) -> bool:
    if database == STAGING_DATABASE:
        return True
    if not database.startswith(STAGING_DATABASE_PREFIX):
        return False
    return _WORKFLOW_SUFFIX.fullmatch(database[len(STAGING_DATABASE_PREFIX) :]) is not None


def validate_snapshot(snapshot: DatabaseSnapshot, *, expected_database: str) -> None:
    if snapshot.database != expected_database:
        raise MaskingBoundaryError("database snapshot does not match the approved boundary")
    table_names: set[str] = set()
    for table in snapshot.tables:
        _validate_identifier(table.name, "table")
        if table.name in table_names:
            raise MaskingBoundaryError("database snapshot contains a duplicate table")
        table_names.add(table.name)
        if table.table_kind != "BASE TABLE":
            raise MaskingBoundaryError("local masking copies base tables only")
        if len(table.rows) > ROW_CAP:
            raise MaskingBoundaryError(f"table {table.name} exceeds the {ROW_CAP}-row cap")
        column_names: set[str] = set()
        for column in table.columns:
            _validate_identifier(column.name, "column")
            if column.name in column_names:
                raise MaskingBoundaryError(f"table {table.name} contains a duplicate column")
            column_names.add(column.name)
            if column.generated:
                raise MaskingBoundaryError("generated columns require a separately reviewed copier")
            _validate_column_contract(column)
        for name in table.primary_key:
            if name not in column_names:
                raise MaskingBoundaryError("primary key references an unknown column")
        for foreign_key in table.foreign_keys:
            _validate_identifier(foreign_key.parent_table, "parent table")
            if not foreign_key.child_columns or len(foreign_key.child_columns) != len(
                foreign_key.parent_columns
            ):
                raise MaskingBoundaryError("foreign key shape is invalid")
            if any(name not in column_names for name in foreign_key.child_columns):
                raise MaskingBoundaryError("foreign key references an unknown child column")
        for row in table.rows:
            if len(row) != len(table.columns):
                raise MaskingBoundaryError(f"table {table.name} returned a malformed row")
            for value, column in zip(row, table.columns, strict=True):
                if value is None and not column.nullable:
                    raise MaskingBoundaryError("a non-nullable source column returned null")
                if value is not None and not isinstance(
                    value, (bool, int, float, Decimal, str, bytes, date, datetime, time)
                ):
                    raise MaskingBoundaryError("source returned an unsupported value type")
    columns_by_table = {
        table.name: {column.name for column in table.columns} for table in snapshot.tables
    }
    for table in snapshot.tables:
        for foreign_key in table.foreign_keys:
            if foreign_key.parent_table not in table_names:
                raise MaskingBoundaryError("foreign key references a table outside the snapshot")
            if any(
                name not in columns_by_table[foreign_key.parent_table]
                for name in foreign_key.parent_columns
            ):
                raise MaskingBoundaryError("foreign key references an unknown parent column")


def derive_key(master_key: bytes, purpose: bytes) -> bytes:
    if len(master_key) != 32:
        raise MaskingBoundaryError("local masking requires a 256-bit key")
    if not purpose or len(purpose) > 64:
        raise MaskingBoundaryError("masking key purpose is invalid")
    return hmac.new(master_key, b"aegisdb-local-masker/" + purpose, hashlib.sha256).digest()


def snapshot_hmac(snapshot: DatabaseSnapshot, key: bytes) -> str:
    validate_snapshot(snapshot, expected_database=snapshot.database)
    if len(key) < 32:
        raise MaskingBoundaryError("snapshot evidence requires at least 256 bits of key material")
    digest = hmac.new(key, digestmod=hashlib.sha256)
    digest.update(_framed(snapshot.database.encode("utf-8")))
    for table in sorted(snapshot.tables, key=lambda item: item.name):
        digest.update(_framed(table.name.encode("utf-8")))
        digest.update(_framed(table.table_kind.encode("ascii")))
        digest.update(_framed((table.create_statement or "").encode("utf-8")))
        digest.update(_framed("|".join(table.primary_key).encode("utf-8")))
        for foreign_key in sorted(
            table.foreign_keys,
            key=lambda item: (item.parent_table, item.child_columns, item.parent_columns),
        ):
            contract = (
                f"{'|'.join(foreign_key.child_columns)}>{foreign_key.parent_table}:"
                f"{'|'.join(foreign_key.parent_columns)}"
            ).encode()
            digest.update(_framed(contract))
        for column in table.columns:
            contract = (
                f"{column.name}|{column.mysql_type}|{int(column.nullable)}|"
                f"{column.max_length}|{column.precision}|{column.scale}|{int(column.unsigned)}"
            ).encode()
            digest.update(_framed(contract))
        canonical_rows = sorted(_canonical_row(row) for row in table.rows)
        for row in canonical_rows:
            digest.update(_framed(row))
    return digest.hexdigest()


def mask_snapshot(
    snapshot: DatabaseSnapshot,
    master_key: bytes,
    *,
    target_database: str = TARGET_DATABASE,
) -> MaskingTransformation:
    validate_snapshot(snapshot, expected_database=SOURCE_DATABASE)
    if not is_approved_target_database(target_database):
        raise MaskingBoundaryError("masking target database is outside the approved boundary")
    masking_key = derive_key(master_key, b"values")
    mappings = _build_mappings(snapshot, masking_key)
    masked_tables: list[TableSnapshot] = []
    values_masked = 0
    sensitive_columns = 0
    for table in snapshot.tables:
        sensitive_columns += sum(1 for column in table.columns if column.sensitive)
        masked_rows: list[tuple[MaskValue, ...]] = []
        for row in table.rows:
            masked_row: list[MaskValue] = []
            for value, column in zip(row, table.columns, strict=True):
                if not column.sensitive or value is None or value in {"", b""}:
                    masked_row.append(value)
                    continue
                namespace = _mapping_namespace(table.name, column)
                masked = mappings[(namespace, _canonical_value(value))]
                if _canonical_value(masked) == _canonical_value(value):
                    raise MaskingBoundaryError("a selected nonempty value was not changed")
                masked_row.append(masked)
                values_masked += 1
            masked_rows.append(tuple(masked_row))
        masked_tables.append(replace(table, rows=tuple(masked_rows)))
    return MaskingTransformation(
        target=DatabaseSnapshot(database=target_database, tables=tuple(masked_tables)),
        tables_copied=len(masked_tables),
        rows_copied=sum(len(table.rows) for table in masked_tables),
        columns_masked=sensitive_columns,
        values_masked=values_masked,
    )


def _build_mappings(snapshot: DatabaseSnapshot, key: bytes) -> dict[tuple[str, bytes], MaskValue]:
    grouped: dict[str, list[tuple[ColumnSpec, MaskValue]]] = {}
    for table in snapshot.tables:
        for column_index, column in enumerate(table.columns):
            if not column.sensitive:
                continue
            namespace = _mapping_namespace(table.name, column)
            for row in table.rows:
                value = row[column_index]
                if value is not None and value not in {"", b""}:
                    grouped.setdefault(namespace, []).append((column, value))

    mappings: dict[tuple[str, bytes], MaskValue] = {}
    for namespace, entries in grouped.items():
        columns = [column for column, _value in entries]
        representative = _compatible_column(columns)
        originals = {_canonical_value(value): value for _column, value in entries}
        forbidden = set(originals)
        used: set[bytes] = set()
        for original_key in sorted(originals):
            original = originals[original_key]
            for counter in range(4096):
                candidate = _candidate_value(
                    original,
                    representative,
                    key,
                    namespace,
                    counter,
                )
                candidate_key = _canonical_value(candidate)
                if candidate_key not in forbidden and candidate_key not in used:
                    mappings[(namespace, original_key)] = candidate
                    used.add(candidate_key)
                    break
            else:
                raise MaskingBoundaryError("a collision-free deterministic mapping was unavailable")
    return mappings


def _candidate_value(
    value: MaskValue,
    column: ColumnSpec,
    key: bytes,
    namespace: str,
    counter: int,
) -> MaskValue:
    material = (
        namespace.encode("utf-8")
        + b"\0"
        + _canonical_value(value)
        + b"\0"
        + str(counter).encode("ascii")
    )
    digest = hmac.new(key, material, hashlib.sha256).digest()
    base_type = _base_type(column.mysql_type)
    if isinstance(value, str) and base_type in _STRING_TYPES:
        return _mask_string(value, digest)
    if isinstance(value, bytes) and base_type in _BINARY_TYPES:
        return _mask_bytes(value, digest)
    if isinstance(value, bool) and base_type in {"bit", "bool", "boolean", "tinyint"}:
        return not value
    if isinstance(value, int) and not isinstance(value, bool) and base_type in _INTEGER_RANGES:
        low, high = _INTEGER_RANGES[base_type]
        if column.unsigned and base_type != "year":
            low, high = 0, (high * 2) + 1
        return low + (int.from_bytes(digest[:8], "big") % (high - low + 1))
    if isinstance(value, Decimal) and base_type in _DECIMAL_TYPES:
        precision = column.precision
        scale = column.scale or 0
        if precision is None or precision < 1 or scale < 0 or scale > precision:
            raise MaskingBoundaryError("decimal masking requires valid precision and scale")
        unscaled = int.from_bytes(digest, "big") % (10**precision)
        if not column.unsigned and digest[0] & 1:
            unscaled = -unscaled
        return Decimal(unscaled).scaleb(-scale)
    if isinstance(value, float) and base_type in _FLOAT_TYPES:
        magnitude = (int.from_bytes(digest[:8], "big") % 10_000_000_000) / 1_000_000
        return magnitude if column.unsigned or not (digest[0] & 1) else -magnitude
    if isinstance(value, datetime) and base_type in _DATE_TYPES:
        return _shift_datetime(value, digest, base_type)
    if isinstance(value, date) and not isinstance(value, datetime) and base_type == "date":
        return _shift_date(value, digest)
    if isinstance(value, time) and base_type == "time":
        seconds = (value.hour * 3600) + (value.minute * 60) + value.second
        shifted = (seconds + 1 + (int.from_bytes(digest[:2], "big") % 86_399)) % 86_400
        return time(shifted // 3600, (shifted % 3600) // 60, shifted % 60, value.microsecond)
    raise MaskingBoundaryError(
        f"column {column.name} has no reviewed masking rule for {column.mysql_type}"
    )


def _mask_string(value: str, digest: bytes) -> str:
    # Use one case-normalized alphabet for every character. Preserving a source
    # value's digit-only shape can exhaust tiny domains (for example 31 distinct
    # one-character values), while lowercase ASCII remains safe for common
    # case-insensitive MySQL collations and still preserves the exact length.
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(
        alphabet[digest[index % len(digest)] % len(alphabet)]
        for index in range(len(value))
    )


def _mask_bytes(value: bytes, digest: bytes) -> bytes:
    repeated = (digest * ((len(value) // len(digest)) + 1))[: len(value)]
    if repeated == value and repeated:
        repeated = bytes([repeated[0] ^ 1]) + repeated[1:]
    return repeated


def _shift_date(value: date, digest: bytes) -> date:
    shift = 1 + (int.from_bytes(digest[:2], "big") % 365)
    minimum = date(1000, 1, 1)
    maximum = date(9999, 12, 31)
    try:
        candidate = value + timedelta(days=shift)
    except OverflowError:
        candidate = value - timedelta(days=shift)
    if candidate > maximum:
        candidate = value - timedelta(days=shift)
    if candidate < minimum or candidate > maximum:
        raise MaskingBoundaryError("date masking cannot remain inside the MySQL type range")
    return candidate


def _shift_datetime(value: datetime, digest: bytes, base_type: str) -> datetime:
    shift = 1 + (int.from_bytes(digest[:2], "big") % 365)
    minimum = datetime(1000, 1, 1, tzinfo=value.tzinfo)
    maximum = datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=value.tzinfo)
    if base_type == "timestamp":
        minimum = datetime(1970, 1, 1, tzinfo=value.tzinfo)
        maximum = datetime(2038, 1, 19, 3, 14, 7, tzinfo=value.tzinfo)
    try:
        candidate = value + timedelta(days=shift)
    except OverflowError:
        candidate = value - timedelta(days=shift)
    if candidate > maximum:
        candidate = value - timedelta(days=shift)
    if candidate < minimum or candidate > maximum:
        raise MaskingBoundaryError("date masking cannot remain inside the MySQL type range")
    return candidate


def _compatible_column(columns: list[ColumnSpec]) -> ColumnSpec:
    if not columns:
        raise MaskingBoundaryError("masking mapping group is empty")
    families = {_type_family(column.mysql_type) for column in columns}
    if len(families) != 1:
        raise MaskingBoundaryError("related sensitive columns use incompatible data types")
    signatures = {
        (
            _base_type(column.mysql_type),
            column.max_length,
            column.precision,
            column.scale,
            column.unsigned,
        )
        for column in columns
    }
    if len(signatures) != 1:
        raise MaskingBoundaryError("related sensitive columns use incompatible data types")
    return columns[0]


def _validate_column_contract(column: ColumnSpec) -> None:
    base_type = _base_type(column.mysql_type)
    if base_type not in (
        _STRING_TYPES
        | _BINARY_TYPES
        | _DECIMAL_TYPES
        | _FLOAT_TYPES
        | _DATE_TYPES
        | set(_INTEGER_RANGES)
        | {"bit", "bool", "boolean", "time"}
    ):
        raise MaskingBoundaryError(f"column {column.name} uses an unsupported MySQL type")
    if column.max_length is not None and column.max_length < 1:
        raise MaskingBoundaryError("column maximum length must be positive")
    if column.relation_group is not None:
        _validate_identifier(column.relation_group, "relationship group")


def _mapping_namespace(table_name: str, column: ColumnSpec) -> str:
    return column.relation_group or f"{table_name}_{column.name}"


def _type_family(mysql_type: str) -> str:
    base_type = _base_type(mysql_type)
    if base_type in _STRING_TYPES:
        return "string"
    if base_type in _BINARY_TYPES:
        return "binary"
    if base_type in _INTEGER_RANGES or base_type in {"bit", "bool", "boolean"}:
        return "integer"
    if base_type in _DECIMAL_TYPES:
        return "decimal"
    if base_type in _FLOAT_TYPES:
        return "float"
    if base_type in _DATE_TYPES:
        return "date"
    if base_type == "time":
        return "time"
    raise MaskingBoundaryError("column uses an unsupported MySQL type")


def _base_type(mysql_type: str) -> str:
    return mysql_type.strip().lower().split("(", 1)[0].split()[0]


def _canonical_row(row: tuple[MaskValue, ...]) -> bytes:
    return b"".join(_framed(_canonical_value(value)) for value in row)


def _canonical_value(value: MaskValue) -> bytes:
    if value is None:
        return b"n"
    if isinstance(value, bool):
        return b"b1" if value else b"b0"
    if isinstance(value, int):
        return b"i" + str(value).encode("ascii")
    if isinstance(value, float):
        return b"f" + value.hex().encode("ascii")
    if isinstance(value, Decimal):
        return b"d" + format(value, "f").encode("ascii")
    if isinstance(value, str):
        return b"s" + value.encode("utf-8")
    if isinstance(value, bytes):
        return b"x" + value
    if isinstance(value, datetime):
        return b"z" + value.isoformat(timespec="microseconds").encode("ascii")
    if isinstance(value, date):
        return b"a" + value.isoformat().encode("ascii")
    if isinstance(value, time):
        return b"t" + value.isoformat(timespec="microseconds").encode("ascii")
    raise MaskingBoundaryError("source returned an unsupported value type")


def _framed(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def _validate_identifier(value: str, label: str) -> None:
    if not _IDENTIFIER.fullmatch(value):
        raise MaskingBoundaryError(f"{label} is outside the approved identifier subset")
