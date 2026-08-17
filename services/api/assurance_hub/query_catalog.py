from __future__ import annotations

from dataclasses import dataclass

from .models import DatabasePlatform


@dataclass(frozen=True, slots=True)
class Probe:
    id: str
    domain: str
    sql: str
    timeout_seconds: int = 15


# This immutable catalog is the only source of SQL available to collectors. Probe
# changes require code review and a versioned collector release; API payloads never
# accept SQL text.
PROBES: dict[DatabasePlatform, dict[str, Probe]] = {
    DatabasePlatform.ORACLE: {
        "oracle.version": Probe("oracle.version", "inventory", "SELECT banner FROM v$version"),
        "oracle.tablespace_encryption": Probe(
            "oracle.tablespace_encryption",
            "encryption",
            "SELECT tablespace_name, encrypted FROM dba_tablespaces",
        ),
        "oracle.account_posture": Probe(
            "oracle.account_posture",
            "access_security",
            "SELECT username, account_status, authentication_type, profile FROM dba_users",
        ),
        "oracle.unified_auditing": Probe(
            "oracle.unified_auditing",
            "data_protection",
            "SELECT parameter, value FROM v$option WHERE parameter = 'Unified Auditing'",
        ),
    },
    DatabasePlatform.POSTGRESQL: {
        "postgresql.version": Probe(
            "postgresql.version", "inventory", "SELECT current_setting('server_version') AS version"
        ),
        "postgresql.tls_sessions": Probe(
            "postgresql.tls_sessions",
            "encryption",
            "SELECT ssl, version, cipher, bits FROM pg_stat_ssl",
        ),
        "postgresql.role_posture": Probe(
            "postgresql.role_posture",
            "access_security",
            "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin FROM pg_roles",
        ),
        "postgresql.row_security": Probe(
            "postgresql.row_security",
            "data_protection",
            "SELECT n.nspname, c.relname, c.relrowsecurity, c.relforcerowsecurity "
            "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE c.relkind = 'r'",
        ),
    },
    DatabasePlatform.SYBASE: {
        "sybase.version": Probe("sybase.version", "inventory", "SELECT @@version AS version"),
        "sybase.login_posture": Probe(
            "sybase.login_posture",
            "access_security",
            "SELECT name, suid, status, fullname FROM master..syslogins",
        ),
        "sybase.audit_configuration": Probe(
            "sybase.audit_configuration",
            "data_protection",
            "SELECT name, value FROM master..sysconfigures WHERE name LIKE '%audit%'",
        ),
    },
    DatabasePlatform.MYSQL: {
        "mysql.version": Probe(
            "mysql.version", "inventory", "SELECT VERSION() AS version"
        ),
        "mysql.transport_security": Probe(
            "mysql.transport_security",
            "encryption",
            "SELECT @@require_secure_transport AS require_secure_transport, "
            "COALESCE(MAX(variable_value), 'unavailable') AS session_cipher "
            "FROM performance_schema.session_status WHERE variable_name = 'Ssl_cipher'",
        ),
        "mysql.schema_inventory": Probe(
            "mysql.schema_inventory",
            "data_protection",
            "SELECT table_schema, table_name, table_type FROM information_schema.tables "
            "WHERE table_schema = DATABASE() ORDER BY table_name",
        ),
        "mysql.account_context": Probe(
            "mysql.account_context",
            "access_security",
            "SELECT CURRENT_USER() AS account, CURRENT_ROLE() AS active_role",
        ),
        "mysql.account_privileges": Probe(
            "mysql.account_privileges",
            "access_security",
            "SELECT CURRENT_USER() AS account, privilege_type, is_grantable "
            "FROM information_schema.schema_privileges WHERE table_schema = DATABASE() "
            "AND grantee = CONCAT(CHAR(39), SUBSTRING_INDEX(CURRENT_USER(), '@', 1), "
            "CHAR(39), '@', CHAR(39), SUBSTRING_INDEX(CURRENT_USER(), '@', -1), CHAR(39)) "
            "ORDER BY privilege_type",
        ),
        "mysql.column_inventory": Probe(
            "mysql.column_inventory",
            "data_protection",
            "SELECT table_schema, table_name, column_name, data_type, column_type "
            "FROM information_schema.columns WHERE table_schema = DATABASE() "
            "ORDER BY CASE WHEN LOWER(column_name) REGEXP "
            "'aadhaar|pan|client|name|payee|hospital|garage|court|policy|claim|agent|amount|"
            "premium|tax|employee|lives|insured|commission|expense|date|mode|city|state' "
            "THEN 0 ELSE 1 END, table_name, ordinal_position LIMIT 100",
        ),
    },
}


def get_probe(platform: DatabasePlatform, probe_id: str) -> Probe:
    try:
        return PROBES[platform][probe_id]
    except KeyError as exc:
        raise ValueError(f"probe '{probe_id}' is not approved for {platform.value}") from exc


def validate_probe_ids(platform: DatabasePlatform, probe_ids: object) -> None:
    if probe_ids is None:
        return
    if not isinstance(probe_ids, list) or len(probe_ids) > 100:
        raise ValueError("probe_ids must be a list with at most 100 items")
    for probe_id in probe_ids:
        if not isinstance(probe_id, str):
            raise ValueError("probe IDs must be strings")
        get_probe(platform, probe_id)
