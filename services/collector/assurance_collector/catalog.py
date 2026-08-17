from __future__ import annotations

from types import MappingProxyType
from typing import Literal

from .models import Platform, ProbeSpec


def _probe(
    probe_id: str,
    platform: Platform,
    domain: Literal["inventory", "encryption", "data_protection", "access_security"],
    sql: str,
    *allowed_fields: str,
) -> ProbeSpec:
    return ProbeSpec(
        probe_id=probe_id,
        platform=platform,
        domain=domain,
        sql=sql,
        allowed_fields=frozenset(allowed_fields),
    )


_PROBES = {
    "oracle.version": _probe(
        "oracle.version", Platform.ORACLE, "inventory", "SELECT banner FROM v$version", "banner"
    ),
    "oracle.tablespace_encryption": _probe(
        "oracle.tablespace_encryption",
        Platform.ORACLE,
        "encryption",
        "SELECT tablespace_name, encrypted FROM dba_tablespaces",
        "tablespace_name",
        "encrypted",
    ),
    "oracle.account_posture": _probe(
        "oracle.account_posture",
        Platform.ORACLE,
        "access_security",
        "SELECT username, account_status, authentication_type, profile FROM dba_users",
        "username",
        "account_status",
        "authentication_type",
        "profile",
    ),
    "oracle.unified_auditing": _probe(
        "oracle.unified_auditing",
        Platform.ORACLE,
        "data_protection",
        "SELECT parameter, value FROM v$option WHERE parameter = 'Unified Auditing'",
        "parameter",
        "value",
    ),
    "postgresql.version": _probe(
        "postgresql.version",
        Platform.POSTGRESQL,
        "inventory",
        "SELECT current_setting('server_version') AS version",
        "version",
    ),
    "postgresql.tls_sessions": _probe(
        "postgresql.tls_sessions",
        Platform.POSTGRESQL,
        "encryption",
        "SELECT ssl, version, cipher, bits FROM pg_stat_ssl",
        "ssl",
        "version",
        "cipher",
        "bits",
    ),
    "postgresql.role_posture": _probe(
        "postgresql.role_posture",
        Platform.POSTGRESQL,
        "access_security",
        "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin FROM pg_roles",
        "rolname",
        "rolsuper",
        "rolcreaterole",
        "rolcreatedb",
        "rolcanlogin",
    ),
    "postgresql.row_security": _probe(
        "postgresql.row_security",
        Platform.POSTGRESQL,
        "data_protection",
        "SELECT n.nspname, c.relname, c.relrowsecurity, c.relforcerowsecurity "
        "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE c.relkind = 'r'",
        "nspname",
        "relname",
        "relrowsecurity",
        "relforcerowsecurity",
    ),
    "sybase.version": _probe(
        "sybase.version", Platform.SYBASE, "inventory", "SELECT @@version AS version", "version"
    ),
    "sybase.login_posture": _probe(
        "sybase.login_posture",
        Platform.SYBASE,
        "access_security",
        "SELECT name, suid, status, fullname FROM master..syslogins",
        "name",
        "suid",
        "status",
        "fullname",
    ),
    "sybase.audit_configuration": _probe(
        "sybase.audit_configuration",
        Platform.SYBASE,
        "data_protection",
        "SELECT name, value FROM master..sysconfigures WHERE name LIKE '%audit%'",
        "name",
        "value",
    ),
    "mysql.version": _probe(
        "mysql.version", Platform.MYSQL, "inventory", "SELECT VERSION() AS version", "version"
    ),
    "mysql.transport_security": _probe(
        "mysql.transport_security",
        Platform.MYSQL,
        "encryption",
        "SELECT @@require_secure_transport AS require_secure_transport, "
        "COALESCE(MAX(variable_value), 'unavailable') AS session_cipher "
        "FROM performance_schema.session_status WHERE variable_name = 'Ssl_cipher'",
        "require_secure_transport",
        "session_cipher",
    ),
    "mysql.schema_inventory": _probe(
        "mysql.schema_inventory",
        Platform.MYSQL,
        "data_protection",
        "SELECT table_schema, table_name, table_type FROM information_schema.tables "
        "WHERE table_schema = DATABASE() ORDER BY table_name",
        "table_schema",
        "table_name",
        "table_type",
    ),
    "mysql.account_context": _probe(
        "mysql.account_context",
        Platform.MYSQL,
        "access_security",
        "SELECT CURRENT_USER() AS account, CURRENT_ROLE() AS active_role",
        "account",
        "active_role",
    ),
    "mysql.account_privileges": _probe(
        "mysql.account_privileges",
        Platform.MYSQL,
        "access_security",
        "SELECT CURRENT_USER() AS account, privilege_type, is_grantable "
        "FROM information_schema.schema_privileges WHERE table_schema = DATABASE() "
        "AND grantee = CONCAT(CHAR(39), SUBSTRING_INDEX(CURRENT_USER(), '@', 1), "
        "CHAR(39), '@', CHAR(39), SUBSTRING_INDEX(CURRENT_USER(), '@', -1), CHAR(39)) "
        "ORDER BY privilege_type",
        "account",
        "privilege_type",
        "is_grantable",
    ),
    "mysql.column_inventory": _probe(
        "mysql.column_inventory",
        Platform.MYSQL,
        "data_protection",
        "SELECT table_schema, table_name, column_name, data_type, column_type "
        "FROM information_schema.columns WHERE table_schema = DATABASE() "
        "ORDER BY CASE WHEN LOWER(column_name) REGEXP "
        "'aadhaar|pan|client|name|payee|hospital|garage|court|policy|claim|agent|amount|"
        "premium|tax|employee|lives|insured|commission|expense|date|mode|city|state' "
        "THEN 0 ELSE 1 END, table_name, ordinal_position LIMIT 100",
        "table_schema",
        "table_name",
        "column_name",
        "data_type",
        "column_type",
    ),
}

PROBES = MappingProxyType(_PROBES)


def get_probe(platform: Platform, probe_id: str) -> ProbeSpec:
    try:
        probe = PROBES[probe_id]
    except KeyError as exc:
        raise ValueError(f"probe '{probe_id}' is not in the signed collector catalogue") from exc
    if probe.platform != platform:
        raise ValueError(f"probe '{probe_id}' is not valid for {platform.value}")
    return probe
