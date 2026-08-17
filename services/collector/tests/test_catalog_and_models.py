from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from assurance_collector.adapters import odbc_value
from assurance_collector.catalog import PROBES, get_probe
from assurance_collector.models import (
    CollectorSettings,
    DatabaseEndpoint,
    Platform,
    ProbeSpec,
    RuntimeConnector,
)


def test_catalog_is_read_only_and_platform_scoped() -> None:
    assert len(PROBES) == 17
    assert get_probe(Platform.MYSQL, "mysql.schema_inventory").platform == Platform.MYSQL
    privileges = get_probe(Platform.MYSQL, "mysql.account_privileges")
    assert privileges.allowed_fields == frozenset({"account", "privilege_type", "is_grantable"})
    assert privileges.sql.lstrip().upper().startswith("SELECT ")
    assert get_probe(Platform.POSTGRESQL, "postgresql.role_posture").platform == Platform.POSTGRESQL
    with pytest.raises(ValueError, match="not valid"):
        get_probe(Platform.ORACLE, "postgresql.role_posture")
    with pytest.raises(ValidationError, match="read-only"):
        ProbeSpec(
            probe_id="postgresql.bad",
            platform=Platform.POSTGRESQL,
            domain="inventory",
            sql="DELETE FROM users",
            allowed_fields=frozenset(),
        )


def test_runtime_endpoint_rejects_credentials_and_non_dns_aliases() -> None:
    endpoint = DatabaseEndpoint.from_reference("dns://db.internal:5432/assurance")
    assert endpoint.host == "db.internal"
    assert endpoint.database == "assurance"
    with pytest.raises(ValueError, match="dns"):
        DatabaseEndpoint.from_reference("dns://user:password@db.internal:5432/assurance")
    with pytest.raises(ValueError, match="dns"):
        DatabaseEndpoint.from_reference("asset://database-one")
    with pytest.raises(ValueError, match="forbidden"):
        DatabaseEndpoint.from_reference("dns://db.internal:5432/app%3BUID%3Dattacker")


def test_production_configuration_fails_closed() -> None:
    with pytest.raises(ValidationError, match="HTTPS"):
        CollectorSettings(
            collector_id="collector-one",
            tenant_id="tenant-one",
            environment="production",
            api_url="http://api.internal",
            token_file=Path("token"),
            enable_leasing=True,
        )
    with pytest.raises(ValidationError, match="token_file"):
        CollectorSettings(
            collector_id="collector-one",
            tenant_id="tenant-one",
            environment="production",
            api_url="https://api.internal",
            enable_leasing=True,
        )


def test_connector_rejects_unapproved_secret_provider() -> None:
    with pytest.raises(ValidationError, match="approved"):
        RuntimeConnector(
            connector_id="00000000-0000-4000-8000-000000000001",
            platform="postgresql",
            endpoint_ref="dns://db.internal:5432/app",
            secret_ref="file:///tmp/not-a-credential",  # noqa: S106 - negative validation fixture
        )


def test_odbc_values_are_attribute_safe() -> None:
    assert odbc_value("password;UID=attacker}") == "{password;UID=attacker}}}"
    with pytest.raises(ValueError, match="forbidden"):
        odbc_value("password\nSERVER=attacker")
