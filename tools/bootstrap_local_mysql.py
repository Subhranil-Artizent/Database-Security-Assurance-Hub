"""Provision and verify the Hub's local, least-privilege MySQL source account."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import sys
import time
from io import StringIO
from pathlib import Path

import mysql.connector
from dotenv import dotenv_values

SOURCE_DATABASE = "insurance_sample"
TARGET_DATABASE = "insurance_sample_masked"
STAGING_DATABASE = "insurance_sample_masked_staging"
TARGET_DATABASE_PREFIX = "insurance_sample_masked_"
STAGING_DATABASE_PREFIX = "aegisdb_mask_stage_"
FINAL_GRANT_DATABASE_PATTERN = r"insurance\_sample\_masked%"
STAGING_GRANT_DATABASE_PATTERN = r"aegisdb\_mask\_stage\_%"
SECRET_REF = "vault://local/database/mysql-insurance-sample#read-only"
TARGET_WRITER_SECRET_REF = "vault://local/database/mysql-insurance-sample-masked#writer"
TARGET_READER_SECRET_REF = (
    "vault://local/database/mysql-insurance-sample-masked#read-only-test"
)
MASKING_KEY_REF = "vault://local/database/mysql-insurance-sample-masked#masking-key"
READ_ONLY_USERNAME = "assurance_hub_ro"
TARGET_WRITER_USERNAME = "assurance_hub_mask_writer"
TARGET_READER_USERNAME = "insurance_masked_test_ro"
LOOPBACK_HOSTS = {"localhost", "127.0.0.1"}
TARGET_READER_PRIVILEGES = {
    "SELECT",
    "SHOW VIEW",
}
TARGET_WRITER_PRIVILEGES = {
    "CREATE",
    "INSERT",
    "SELECT",
}
STAGING_WRITER_PRIVILEGES = {
    "ALTER",
    "CREATE",
    "DROP",
    "INSERT",
    "REFERENCES",
    "SELECT",
}
LOCAL_MYSQL_ENV_KEYS = frozenset(
    {
        "MYSQL_TARGET_HOST",
        "MYSQL_TARGET_PORT",
        "MYSQL_TARGET_DATABASE",
        "MYSQL_TARGET_USERNAME",
        "MYSQL_TARGET_PASSWORD",
        "MYSQL_TARGET_CHARSET",
    }
)


class BootstrapError(RuntimeError):
    def __init__(self, stage: str, cause: Exception) -> None:
        super().__init__(stage)
        self.stage = stage
        self.errno = getattr(cause, "errno", None)


def required(values: dict[str, str | None], name: str) -> str:
    value = values.get(name)
    if not value:
        raise ValueError(f"{name} is missing from the MySQL environment file")
    return value


def load_local_mysql_values(env_file: Path) -> dict[str, str | None]:
    """Parse only the six approved local keys and discard every unrelated line."""
    values: dict[str, str | None] = {}
    with env_file.open(encoding="utf-8") as handle:
        for line in handle:
            if len(line) > 4096:
                raise ValueError(
                    "the local MySQL environment file contains an oversized line"
                )
            candidate = line.lstrip()
            if candidate.startswith("export "):
                candidate = candidate[7:].lstrip()
            key = candidate.partition("=")[0].strip()
            if key not in LOCAL_MYSQL_ENV_KEYS:
                continue
            if key in values:
                raise ValueError(
                    f"{key} appears more than once in the MySQL environment file"
                )
            parsed = dotenv_values(stream=StringIO(line), interpolate=False)
            values[key] = parsed.get(key)
    return values


def quote_identifier(value: str) -> str:
    if not value or len(value) > 64 or any(char in value for char in "\0\r\n"):
        raise ValueError("MYSQL_TARGET_DATABASE is not a valid MySQL identifier")
    return "`" + value.replace("`", "``") + "`"


def account(host: str, username: str = READ_ONLY_USERNAME) -> str:
    if host not in LOOPBACK_HOSTS:
        raise ValueError("local bootstrap accepts only localhost or 127.0.0.1")
    if username not in {
        READ_ONLY_USERNAME,
        TARGET_READER_USERNAME,
        TARGET_WRITER_USERNAME,
    }:
        raise ValueError("local bootstrap accepts only its three fixed MySQL accounts")
    return f"'{username}'@'{host}'"


def require_supported_mysql_version(version: str) -> None:
    if "mariadb" in version.casefold():
        raise ValueError("local masking requires Oracle MySQL, not MariaDB")
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", version)
    if match is None or tuple(int(part) for part in match.groups()) < (8, 0, 13):
        raise ValueError("local masking requires MySQL 8.0.13 or newer")


def grants_match_scopes(
    rows: list[tuple[object, ...]], expected: dict[str, set[str]]
) -> bool:
    saw_usage = False
    remaining = {database: frozenset(privileges) for database, privileges in expected.items()}
    for row in rows:
        if len(row) != 1:
            return False
        statement = str(row[0]).strip()
        match = re.fullmatch(
            r"GRANT\s+(.+?)\s+ON\s+(.+?)\s+TO\s+.+", statement, re.IGNORECASE
        )
        if match is None or "WITH GRANT OPTION" in statement.upper():
            return False
        privileges = frozenset(item.strip().upper() for item in match.group(1).split(","))
        scope = match.group(2).strip()
        if scope == "*.*" and privileges == {"USAGE"} and not saw_usage:
            saw_usage = True
            continue
        selected = next(
            (
                database
                for database in remaining
                if scope == f"{quote_identifier(database)}.*"
            ),
            None,
        )
        if selected is None or privileges != remaining[selected]:
            return False
        del remaining[selected]
    return saw_usage and not remaining


def schema_object_counts(cursor: object, database: str) -> dict[str, int]:
    queries = {
        "base_tables": (
            "SELECT COUNT(*) FROM information_schema.tables "
            "WHERE table_schema = %s AND table_type = 'BASE TABLE'"
        ),
        "views": (
            "SELECT COUNT(*) FROM information_schema.tables "
            "WHERE table_schema = %s AND table_type = 'VIEW'"
        ),
        "triggers": (
            "SELECT COUNT(*) FROM information_schema.triggers WHERE trigger_schema = %s"
        ),
        "routines": (
            "SELECT COUNT(*) FROM information_schema.routines WHERE routine_schema = %s"
        ),
        "events": (
            "SELECT COUNT(*) FROM information_schema.events WHERE event_schema = %s"
        ),
    }
    counts: dict[str, int] = {}
    for name, query in queries.items():
        cursor.execute(query, (database,))
        counts[name] = int(cursor.fetchone()[0])
    return counts


def projected_path(root: Path, secret_ref: str) -> Path:
    return root / f"{hashlib.sha256(secret_ref.encode('utf-8')).hexdigest()}.json"


def write_projected_secret(
    root: Path,
    password: str,
    *,
    secret_ref: str = SECRET_REF,
    username: str = READ_ONLY_USERNAME,
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = projected_path(root, secret_ref)
    temporary = root / f".{path.name}.{secrets.token_hex(8)}.tmp"
    try:
        temporary.write_text(
            json.dumps(
                {"username": username, "password": password, "ca_file": None},
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        if os.name != "nt":
            temporary.chmod(0o600)
        for attempt in range(5):
            try:
                temporary.replace(path)
                break
            except PermissionError:
                if attempt == 4:
                    raise
                time.sleep(0.02 * (attempt + 1))
    finally:
        temporary.unlink(missing_ok=True)
    return path


def write_persistent_masking_key(root: Path) -> tuple[Path, str]:
    """Create a stable local key without ever returning or printing its value."""
    root.mkdir(parents=True, exist_ok=True)
    path = projected_path(root, MASKING_KEY_REF)
    if not path.exists():
        payload = json.dumps(
            {
                "version": 1,
                "key_b64": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(
                    "ascii"
                ),
            },
            separators=(",", ":"),
        ).encode("utf-8")
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
        encoded = stored["key_b64"]
        key = base64.urlsafe_b64decode(encoded.encode("ascii"))
    except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError) as exc:
        raise ValueError("the local masking key projection is invalid") from exc
    if stored.get("version") != 1 or len(key) != 32:
        raise ValueError("the local masking key projection is invalid")
    fingerprint = hashlib.sha256(key).hexdigest()[:16]
    return path, fingerprint


def bootstrap(env_file: Path, credential_root: Path) -> dict[str, object]:
    values = load_local_mysql_values(env_file)
    host = required(values, "MYSQL_TARGET_HOST").lower()
    if host not in LOOPBACK_HOSTS:
        raise ValueError("this command is restricted to a loopback MySQL server")
    port = int(values.get("MYSQL_TARGET_PORT") or "3306")
    if port < 1 or port > 65535:
        raise ValueError("MYSQL_TARGET_PORT must be between 1 and 65535")
    database = required(values, "MYSQL_TARGET_DATABASE")
    if database != SOURCE_DATABASE:
        raise ValueError(
            f"local masking accepts only the {SOURCE_DATABASE} source database"
        )
    target_database = f"{database}_masked"
    if (
        target_database != TARGET_DATABASE
        or target_database.casefold() == database.casefold()
    ):
        raise ValueError(
            "the local masking target must be the fixed, distinct masked copy"
        )
    username = required(values, "MYSQL_TARGET_USERNAME")
    password = required(values, "MYSQL_TARGET_PASSWORD")
    charset = values.get("MYSQL_TARGET_CHARSET") or "utf8mb4"
    if charset != "utf8mb4":
        raise ValueError(
            "the Hub local connector requires MYSQL_TARGET_CHARSET=utf8mb4"
        )

    generated_password = secrets.token_urlsafe(36)
    target_writer_password = secrets.token_urlsafe(36)
    target_reader_password = secrets.token_urlsafe(36)
    try:
        admin = mysql.connector.connect(
            host=host,
            port=port,
            database=database,
            user=username,
            password=password,
            charset=charset,
            connection_timeout=10,
            autocommit=True,
        )
    except (BootstrapError, ValueError, OSError, mysql.connector.Error) as exc:
        raise BootstrapError("existing local MySQL login", exc) from exc
    try:
        try:
            cursor = admin.cursor()
            try:
                cursor.execute("SELECT VERSION()")
                admin_version = str(cursor.fetchone()[0])
                require_supported_mysql_version(admin_version)
                for source_host in sorted(LOOPBACK_HOSTS):
                    source_account = account(source_host)
                    cursor.execute(
                        f"CREATE USER IF NOT EXISTS {source_account} IDENTIFIED BY %s",
                        (generated_password,),
                    )
                    cursor.execute(
                        f"ALTER USER {source_account} IDENTIFIED BY %s",
                        (generated_password,),
                    )
                    cursor.execute(
                        f"REVOKE ALL PRIVILEGES, GRANT OPTION FROM {source_account}"
                    )
                    cursor.execute(
                        f"GRANT SELECT, SHOW VIEW ON {quote_identifier(database)}.* TO {source_account}"
                    )
                    target_account = account(source_host, TARGET_WRITER_USERNAME)
                    cursor.execute(
                        f"CREATE USER IF NOT EXISTS {target_account} IDENTIFIED BY %s",
                        (target_writer_password,),
                    )
                    cursor.execute(
                        f"ALTER USER {target_account} IDENTIFIED BY %s",
                        (target_writer_password,),
                    )
                    cursor.execute(
                        f"REVOKE ALL PRIVILEGES, GRANT OPTION FROM {target_account}"
                    )
                    target_reader_account = account(
                        source_host, TARGET_READER_USERNAME
                    )
                    cursor.execute(
                        f"CREATE USER IF NOT EXISTS {target_reader_account} IDENTIFIED BY %s",
                        (target_reader_password,),
                    )
                    cursor.execute(
                        f"ALTER USER {target_reader_account} IDENTIFIED BY %s",
                        (target_reader_password,),
                    )
                    cursor.execute(
                        "REVOKE ALL PRIVILEGES, GRANT OPTION FROM "
                        f"{target_reader_account}"
                    )
                cursor.execute(
                    f"CREATE DATABASE IF NOT EXISTS {quote_identifier(target_database)} "
                    f"CHARACTER SET {charset}"
                )
                cursor.execute(
                    f"CREATE DATABASE IF NOT EXISTS {quote_identifier(STAGING_DATABASE)} "
                    f"CHARACTER SET {charset}"
                )
                final_privileges = ", ".join(sorted(TARGET_WRITER_PRIVILEGES))
                staging_privileges = ", ".join(sorted(STAGING_WRITER_PRIVILEGES))
                target_reader_privileges_sql = ", ".join(
                    sorted(TARGET_READER_PRIVILEGES)
                )
                for source_host in sorted(LOOPBACK_HOSTS):
                    target_account = account(source_host, TARGET_WRITER_USERNAME)
                    cursor.execute(
                        f"GRANT {final_privileges} ON "
                        f"{quote_identifier(FINAL_GRANT_DATABASE_PATTERN)}.* "
                        f"TO {target_account}"
                    )
                    cursor.execute(
                        f"GRANT {staging_privileges} ON "
                        f"{quote_identifier(STAGING_GRANT_DATABASE_PATTERN)}.* "
                        f"TO {target_account}"
                    )
                    target_reader_account = account(
                        source_host, TARGET_READER_USERNAME
                    )
                    cursor.execute(
                        f"GRANT {target_reader_privileges_sql} ON "
                        f"{quote_identifier(FINAL_GRANT_DATABASE_PATTERN)}.* "
                        f"TO {target_reader_account}"
                    )
                target_object_counts = schema_object_counts(cursor, target_database)
                staging_object_counts = schema_object_counts(cursor, STAGING_DATABASE)
                for label, counts in (
                    ("masked target", target_object_counts),
                    ("masking staging", staging_object_counts),
                ):
                    if any(counts[name] for name in ("views", "triggers", "routines", "events")):
                        raise ValueError(f"the {label} contains an unsupported object")
            finally:
                cursor.close()
        except mysql.connector.Error as exc:
            raise BootstrapError("read-only account provisioning", exc) from exc
    finally:
        admin.close()

    try:
        reader = mysql.connector.connect(
            host=host,
            port=port,
            database=database,
            user=READ_ONLY_USERNAME,
            password=generated_password,
            charset=charset,
            connection_timeout=10,
            autocommit=False,
        )
    except mysql.connector.Error as exc:
        raise BootstrapError("read-only account verification", exc) from exc
    try:
        reader.start_transaction(readonly=True)
        cursor = reader.cursor()
        try:
            cursor.execute("SELECT VERSION()")
            version = str(cursor.fetchone()[0])
            require_supported_mysql_version(version)
            cursor.execute(
                "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE()"
            )
            table_count = int(cursor.fetchone()[0])
            cursor.execute(
                "SELECT privilege_type FROM information_schema.schema_privileges "
                "WHERE table_schema = DATABASE()"
            )
            privileges = {str(row[0]).upper() for row in cursor.fetchall()}
            if privileges != {"SELECT", "SHOW VIEW"}:
                raise ValueError(
                    "the projected MySQL account is not strictly read-only"
                )
        finally:
            cursor.close()
        reader.rollback()
    finally:
        reader.close()

    try:
        writer = mysql.connector.connect(
            host=host,
            port=port,
            database=target_database,
            user=TARGET_WRITER_USERNAME,
            password=target_writer_password,
            charset=charset,
            connection_timeout=10,
            autocommit=False,
        )
    except mysql.connector.Error as exc:
        raise BootstrapError("target-only account verification", exc) from exc
    try:
        cursor = writer.cursor()
        try:
            cursor.execute("SELECT DATABASE()")
            selected_database = str(cursor.fetchone()[0])
            if selected_database != target_database:
                raise ValueError(
                    "the target writer did not select the fixed masked database"
                )
            cursor.execute("SHOW GRANTS FOR CURRENT_USER()")
            grant_rows = [tuple(row) for row in cursor.fetchall()]
            if not grants_match_scopes(
                grant_rows,
                {
                    FINAL_GRANT_DATABASE_PATTERN: TARGET_WRITER_PRIVILEGES,
                    STAGING_GRANT_DATABASE_PATTERN: STAGING_WRITER_PRIVILEGES,
                },
            ):
                raise ValueError("the projected target writer grants are not exact")
            writer_privileges = set(TARGET_WRITER_PRIVILEGES)
            staging_writer_privileges = set(STAGING_WRITER_PRIVILEGES)
            cursor.execute(
                "SELECT privilege_type FROM information_schema.schema_privileges "
                "WHERE table_schema = %s",
                (database,),
            )
            if cursor.fetchall():
                raise ValueError(
                    "the target writer has privileges on the source database"
                )
            target_table_count = target_object_counts["base_tables"]
            staging_table_count = staging_object_counts["base_tables"]
        finally:
            cursor.close()
        writer.rollback()
    finally:
        writer.close()

    try:
        target_reader = mysql.connector.connect(
            host=host,
            port=port,
            database=target_database,
            user=TARGET_READER_USERNAME,
            password=target_reader_password,
            charset=charset,
            connection_timeout=10,
            autocommit=False,
        )
    except mysql.connector.Error as exc:
        raise BootstrapError("masked test reader verification", exc) from exc
    try:
        target_reader.start_transaction(readonly=True)
        cursor = target_reader.cursor()
        try:
            cursor.execute("SELECT DATABASE()")
            if str(cursor.fetchone()[0]) != target_database:
                raise ValueError(
                    "the masked test reader did not select the fixed target database"
                )
            cursor.execute("SHOW GRANTS FOR CURRENT_USER()")
            target_reader_grant_rows = [tuple(row) for row in cursor.fetchall()]
            if not grants_match_scopes(
                target_reader_grant_rows,
                {FINAL_GRANT_DATABASE_PATTERN: TARGET_READER_PRIVILEGES},
            ):
                raise ValueError("the masked test reader grants are not exact")
            target_reader_privileges = set(TARGET_READER_PRIVILEGES)
            for forbidden_database in (database, STAGING_DATABASE):
                cursor.execute(
                    "SELECT privilege_type FROM information_schema.schema_privileges "
                    "WHERE table_schema = %s",
                    (forbidden_database,),
                )
                if cursor.fetchall():
                    raise ValueError(
                        "the masked test reader escaped the final target database"
                    )
        finally:
            cursor.close()
        target_reader.rollback()
    finally:
        target_reader.close()

    credential_root = credential_root.resolve()
    secret_path = write_projected_secret(credential_root, generated_password)
    target_secret_path = write_projected_secret(
        credential_root,
        target_writer_password,
        secret_ref=TARGET_WRITER_SECRET_REF,
        username=TARGET_WRITER_USERNAME,
    )
    target_reader_secret_path = write_projected_secret(
        credential_root,
        target_reader_password,
        secret_ref=TARGET_READER_SECRET_REF,
        username=TARGET_READER_USERNAME,
    )
    masking_key_path, masking_key_fingerprint = write_persistent_masking_key(
        credential_root
    )
    return {
        "host": host,
        "port": port,
        "database": database,
        "version": version,
        "table_count": table_count,
        "reader_account": READ_ONLY_USERNAME,
        "privileges": sorted(privileges),
        "secret_ref": SECRET_REF,
        "target_database": target_database,
        "staging_database": STAGING_DATABASE,
        "target_database_prefix": TARGET_DATABASE_PREFIX,
        "staging_database_prefix": STAGING_DATABASE_PREFIX,
        "target_writer_account": TARGET_WRITER_USERNAME,
        "target_writer_privileges": sorted(writer_privileges),
        "staging_writer_privileges": sorted(staging_writer_privileges),
        "target_writer_secret_ref": TARGET_WRITER_SECRET_REF,
        "target_reader_account": TARGET_READER_USERNAME,
        "target_reader_privileges": sorted(target_reader_privileges),
        "target_reader_secret_ref": TARGET_READER_SECRET_REF,
        "target_table_count": target_table_count,
        "staging_table_count": staging_table_count,
        "target_object_counts": target_object_counts,
        "staging_object_counts": staging_object_counts,
        "masking_key_ref": MASKING_KEY_REF,
        "masking_key_fingerprint": masking_key_fingerprint,
        "credential_root": str(credential_root),
        "secret_file": str(secret_path),
        "target_secret_file": str(target_secret_path),
        "target_reader_secret_file": str(target_reader_secret_path),
        "masking_key_file": str(masking_key_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--credential-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = bootstrap(args.env_file.resolve(), args.credential_root)
    except (BootstrapError, ValueError, OSError, mysql.connector.Error) as exc:
        error_code = getattr(exc, "errno", None)
        suffix = f" (MySQL error {error_code})" if isinstance(error_code, int) else ""
        stage = getattr(exc, "stage", "bootstrap")
        print(
            f"Local MySQL {stage} failed: {type(exc).__name__}{suffix}", file=sys.stderr
        )
        return 1
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
