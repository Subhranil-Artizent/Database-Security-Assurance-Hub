from __future__ import annotations

import asyncio
import importlib
from collections.abc import Mapping, Sequence
from types import ModuleType
from typing import Any, Protocol

from .models import DatabaseEndpoint, ExecutionLimits, Platform, ProbeSpec, SourceCredential

Row = Mapping[str, object]


class DriverUnavailableError(RuntimeError):
    pass


class QueryBoundaryError(RuntimeError):
    pass


class TransientSourceError(RuntimeError):
    """A deliberately classified source failure that is safe to retry."""


class InsufficientPrivilegeError(RuntimeError):
    """The projected database identity lacks an approved metadata read grant."""


class UnsupportedSourceError(RuntimeError):
    """The approved probe is unavailable on this database version or edition."""


def _transient_postgresql(error: Exception) -> bool:
    sqlstate = str(getattr(error, "sqlstate", ""))
    return sqlstate.startswith("08") or sqlstate in {"57P01", "57P02", "57P03"}


def _transient_oracle(error: Exception) -> bool:
    detail = error.args[0] if error.args else None
    code = getattr(detail, "code", None)
    return code in {
        12514,
        12516,
        12520,
        12537,
        12541,
        12543,
        12545,
        12560,
        12571,
        3135,
    }


def _transient_odbc(error: Exception) -> bool:
    state = str(error.args[0]) if error.args else ""
    return state.startswith("08")


def _mysql_boundary_error(error: Exception) -> Exception | None:
    errno = getattr(error, "errno", None)
    if errno in {1044, 1045, 1142}:
        return InsufficientPrivilegeError("MySQL metadata privilege is insufficient")
    if errno in {1054, 1193}:
        return UnsupportedSourceError("MySQL probe is unsupported")
    if errno in {2002, 2003, 2006, 2013, 2055}:
        return TransientSourceError("MySQL is temporarily unavailable")
    return None


def _postgresql_boundary_error(error: Exception) -> Exception | None:
    sqlstate = str(getattr(error, "sqlstate", ""))
    if sqlstate == "42501":
        return InsufficientPrivilegeError("PostgreSQL metadata privilege is insufficient")
    if sqlstate == "0A000":
        return UnsupportedSourceError("PostgreSQL probe is unsupported")
    if _transient_postgresql(error):
        return TransientSourceError("PostgreSQL is temporarily unavailable")
    return None


def _oracle_boundary_error(error: Exception) -> Exception | None:
    detail = error.args[0] if error.args else None
    code = getattr(detail, "code", None)
    if code == 1031:
        return InsufficientPrivilegeError("Oracle metadata privilege is insufficient")
    if code in {904, 942}:
        return UnsupportedSourceError("Oracle probe is unsupported")
    if _transient_oracle(error):
        return TransientSourceError("Oracle is temporarily unavailable")
    return None


def _odbc_boundary_error(error: Exception) -> Exception | None:
    state = str(error.args[0]) if error.args else ""
    if state == "42501":
        return InsufficientPrivilegeError("Sybase metadata privilege is insufficient")
    if state in {"HYC00", "IM001"}:
        return UnsupportedSourceError("Sybase probe is unsupported")
    if _transient_odbc(error):
        return TransientSourceError("Sybase is temporarily unavailable")
    return None


class DatabaseAdapter(Protocol):
    platform: Platform

    async def execute(
        self,
        endpoint: DatabaseEndpoint,
        credential: SourceCredential,
        probe: ProbeSpec,
        limits: ExecutionLimits,
    ) -> Sequence[Row]: ...

    async def verify_read_only(
        self,
        endpoint: DatabaseEndpoint,
        credential: SourceCredential,
        limits: ExecutionLimits,
    ) -> bool: ...


def _load_driver(name: str, extra: str) -> ModuleType:
    try:
        return importlib.import_module(name)
    except ImportError as exc:
        raise DriverUnavailableError(
            f"approved {name} driver is not installed; install the '{extra}' collector extra"
        ) from exc


def _mapped_rows(cursor: Any, max_rows: int) -> list[Row]:
    description = cursor.description or []
    columns = [str(column[0]).lower() for column in description]
    rows = cursor.fetchmany(max_rows + 1)
    if len(rows) > max_rows:
        raise QueryBoundaryError(f"probe exceeded the {max_rows}-row safety limit")
    return [dict(zip(columns, row, strict=True)) for row in rows]


class PostgreSQLAdapter:
    platform = Platform.POSTGRESQL

    async def execute(
        self,
        endpoint: DatabaseEndpoint,
        credential: SourceCredential,
        probe: ProbeSpec,
        limits: ExecutionLimits,
    ) -> Sequence[Row]:
        return await asyncio.to_thread(self._execute, endpoint, credential, probe, limits)

    async def verify_read_only(
        self,
        endpoint: DatabaseEndpoint,
        credential: SourceCredential,
        limits: ExecutionLimits,
    ) -> bool:
        # A BEGIN READ ONLY check proves only the transaction mode selected by
        # this process, not the login's least privilege. Promotion requires a
        # separately approved negative-write test against a disposable canary.
        _ = (endpoint, credential, limits)
        return False

    def _execute(
        self,
        endpoint: DatabaseEndpoint,
        credential: SourceCredential,
        probe: ProbeSpec,
        limits: ExecutionLimits,
    ) -> Sequence[Row]:
        psycopg = _load_driver("psycopg", "postgresql")
        if credential.ca_file is None:
            raise DriverUnavailableError("PostgreSQL TLS requires a projected ca_file")
        try:
            connection = psycopg.connect(
                host=endpoint.host,
                port=endpoint.port,
                dbname=endpoint.database,
                user=credential.username,
                password=credential.password.get_secret_value(),
                connect_timeout=limits.connect_timeout_seconds,
                sslmode="verify-full",
                sslrootcert=str(credential.ca_file),
            )
            try:
                with connection.cursor() as cursor:
                    cursor.execute("BEGIN READ ONLY")
                    cursor.execute(
                        "SELECT set_config('statement_timeout', %s, true)",
                        (str(limits.statement_timeout_seconds * 1000),),
                    )
                    cursor.execute(probe.sql)
                    return _mapped_rows(cursor, limits.max_rows)
            finally:
                connection.rollback()
                connection.close()
        except Exception as exc:
            mapped = _postgresql_boundary_error(exc)
            if mapped is not None:
                raise mapped from exc
            raise


class OracleAdapter:
    platform = Platform.ORACLE

    async def execute(
        self,
        endpoint: DatabaseEndpoint,
        credential: SourceCredential,
        probe: ProbeSpec,
        limits: ExecutionLimits,
    ) -> Sequence[Row]:
        return await asyncio.to_thread(self._execute, endpoint, credential, probe, limits)

    async def verify_read_only(
        self,
        endpoint: DatabaseEndpoint,
        credential: SourceCredential,
        limits: ExecutionLimits,
    ) -> bool:
        # Oracle does not expose a universal login-level read-only flag. The
        # customer promotion gate must prove the projected identity has only
        # approved catalog SELECT grants through database audit evidence.
        _ = (endpoint, credential, limits)
        return False

    def _execute(
        self,
        endpoint: DatabaseEndpoint,
        credential: SourceCredential,
        probe: ProbeSpec,
        limits: ExecutionLimits,
    ) -> Sequence[Row]:
        oracledb = _load_driver("oracledb", "oracle")
        if credential.wallet_directory is None:
            raise DriverUnavailableError("Oracle TCPS requires a projected wallet_directory")
        try:
            connection = oracledb.connect(
                user=credential.username,
                password=credential.password.get_secret_value(),
                host=endpoint.host,
                port=endpoint.port,
                service_name=endpoint.database,
                protocol="tcps",
                wallet_location=str(credential.wallet_directory),
                ssl_server_dn_match=True,
                tcp_connect_timeout=limits.connect_timeout_seconds,
            )
            try:
                connection.call_timeout = limits.statement_timeout_seconds * 1000
                with connection.cursor() as cursor:
                    cursor.execute(probe.sql)
                    return _mapped_rows(cursor, limits.max_rows)
            finally:
                connection.rollback()
                connection.close()
        except Exception as exc:
            mapped = _oracle_boundary_error(exc)
            if mapped is not None:
                raise mapped from exc
            raise


class SybaseAdapter:
    platform = Platform.SYBASE

    def __init__(self, driver_name: str) -> None:
        if any(character in driver_name for character in "{};\0\r\n"):
            raise ValueError("Sybase driver name contains forbidden characters")
        self._driver_name = driver_name

    async def execute(
        self,
        endpoint: DatabaseEndpoint,
        credential: SourceCredential,
        probe: ProbeSpec,
        limits: ExecutionLimits,
    ) -> Sequence[Row]:
        return await asyncio.to_thread(self._execute, endpoint, credential, probe, limits)

    async def verify_read_only(
        self,
        endpoint: DatabaseEndpoint,
        credential: SourceCredential,
        limits: ExecutionLimits,
    ) -> bool:
        # SAP ASE read-only enforcement is privilege-matrix specific and must
        # be demonstrated with negative DML/DDL tests before enabling leasing.
        _ = (endpoint, credential, limits)
        return False

    def _execute(
        self,
        endpoint: DatabaseEndpoint,
        credential: SourceCredential,
        probe: ProbeSpec,
        limits: ExecutionLimits,
    ) -> Sequence[Row]:
        pyodbc = _load_driver("pyodbc", "sybase")
        if credential.ca_file is None:
            raise DriverUnavailableError("Sybase TLS requires a projected ca_file")
        connection_string = (
            f"DRIVER={odbc_value(self._driver_name)};"
            f"SERVER={odbc_value(endpoint.host)};PORT={endpoint.port};"
            f"DATABASE={odbc_value(endpoint.database)};"
            f"UID={odbc_value(credential.username)};"
            f"PWD={odbc_value(credential.password.get_secret_value())};"
            f"Encryption=ssl;TrustedFile={odbc_value(str(credential.ca_file))};"
        )
        try:
            connection = pyodbc.connect(
                connection_string,
                timeout=limits.connect_timeout_seconds,
                autocommit=False,
            )
            try:
                with connection.cursor() as cursor:
                    cursor.timeout = limits.statement_timeout_seconds
                    cursor.execute("set transaction isolation level 1")
                    cursor.execute(probe.sql)
                    return _mapped_rows(cursor, limits.max_rows)
            finally:
                connection.rollback()
                connection.close()
        except Exception as exc:
            mapped = _odbc_boundary_error(exc)
            if mapped is not None:
                raise mapped from exc
            raise


class MySQLAdapter:
    platform = Platform.MYSQL

    def __init__(self, *, allow_insecure_loopback: bool = False) -> None:
        self._allow_insecure_loopback = allow_insecure_loopback

    async def execute(
        self,
        endpoint: DatabaseEndpoint,
        credential: SourceCredential,
        probe: ProbeSpec,
        limits: ExecutionLimits,
    ) -> Sequence[Row]:
        return await asyncio.to_thread(self._execute, endpoint, credential, probe, limits)

    async def verify_read_only(
        self,
        endpoint: DatabaseEndpoint,
        credential: SourceCredential,
        limits: ExecutionLimits,
    ) -> bool:
        # Transaction mode is defense in depth. The dedicated source account's
        # SELECT/SHOW VIEW grants are the actual read-only enforcement boundary.
        _ = (endpoint, credential, limits)
        return False

    def _execute(
        self,
        endpoint: DatabaseEndpoint,
        credential: SourceCredential,
        probe: ProbeSpec,
        limits: ExecutionLimits,
    ) -> Sequence[Row]:
        mysql_connector = _load_driver("mysql.connector", "mysql")
        loopback = endpoint.host in {"localhost", "127.0.0.1"}
        if credential.ca_file is None and not (self._allow_insecure_loopback and loopback):
            raise DriverUnavailableError(
                "MySQL TLS requires ca_file except for an explicitly enabled development loopback"
            )
        tls: dict[str, object]
        if credential.ca_file is None:
            # Connector/Python negotiates TLS when the local server offers it.
            # Certificate verification is waived only for development loopback.
            tls = {"ssl_disabled": False}
        else:
            tls = {
                "ssl_ca": str(credential.ca_file),
                "ssl_verify_cert": True,
                "ssl_verify_identity": True,
            }
        try:
            connection = mysql_connector.connect(
                host=endpoint.host,
                port=endpoint.port,
                database=endpoint.database,
                user=credential.username,
                password=credential.password.get_secret_value(),
                connection_timeout=limits.connect_timeout_seconds,
                autocommit=False,
                **tls,
            )
            try:
                connection.start_transaction(readonly=True)
                cursor = connection.cursor()
                try:
                    cursor.execute(probe.sql)
                    return _mapped_rows(cursor, limits.max_rows)
                finally:
                    cursor.close()
            finally:
                connection.rollback()
                connection.close()
        except Exception as exc:
            mapped = _mysql_boundary_error(exc)
            if mapped is not None:
                raise mapped from exc
            raise


def default_adapters(
    sybase_driver: str, *, allow_insecure_loopback: bool = False
) -> dict[Platform, DatabaseAdapter]:
    return {
        Platform.POSTGRESQL: PostgreSQLAdapter(),
        Platform.ORACLE: OracleAdapter(),
        Platform.SYBASE: SybaseAdapter(sybase_driver),
        Platform.MYSQL: MySQLAdapter(allow_insecure_loopback=allow_insecure_loopback),
    }


def odbc_value(value: str) -> str:
    """Encode an ODBC connection-string value without permitting attributes."""
    if "\0" in value or "\r" in value or "\n" in value:
        raise ValueError("ODBC connection value contains a forbidden character")
    return "{" + value.replace("}", "}}") + "}"
