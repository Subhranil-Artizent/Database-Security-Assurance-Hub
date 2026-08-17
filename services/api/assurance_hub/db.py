from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from sqlalchemy import MetaData, event, text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session

from .config import Settings

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def enable_sqlite_foreign_keys(dbapi_connection: Any, _connection_record: object) -> None:
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()


@event.listens_for(Session, "after_begin")
def establish_tenant_context(
    session: Session, _transaction: object, connection: Connection
) -> None:
    """Apply transaction-local PostgreSQL RLS context on every transaction.

    A refresh after commit opens a new transaction, so setting the value only once
    when the request session is created is insufficient. Session metadata survives
    transaction boundaries without leaking into a pooled database connection.
    """
    if connection.dialect.name != "postgresql":
        return
    tenant_id = session.info.get("tenant_id")
    if tenant_id:
        connection.execute(
            text("SELECT set_config('app.tenant_id', :tenant_id, true)"),
            {"tenant_id": tenant_id},
        )


class Database:
    def __init__(self, settings: Settings) -> None:
        engine_kwargs: dict[str, object] = {"pool_pre_ping": True}
        if not settings.database_url.startswith("sqlite"):
            engine_kwargs.update(
                pool_size=settings.database_pool_size,
                max_overflow=settings.database_max_overflow,
                pool_recycle=1800,
            )
        self.engine: AsyncEngine = create_async_engine(settings.database_url, **engine_kwargs)
        if self.engine.dialect.name == "sqlite":
            event.listen(self.engine.sync_engine, "connect", enable_sqlite_foreign_keys)
        self.session_factory = async_sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
        )
        maintenance_url = settings.database_maintenance_url
        self.maintenance_engine: AsyncEngine | None = None
        self.maintenance_session_factory = self.session_factory
        if maintenance_url and maintenance_url != settings.database_url:
            self.maintenance_engine = create_async_engine(maintenance_url, **engine_kwargs)
            self.maintenance_session_factory = async_sessionmaker(
                self.maintenance_engine,
                class_=AsyncSession,
                expire_on_commit=False,
                autoflush=False,
            )

    async def session(self) -> AsyncIterator[AsyncSession]:
        async with self.session_factory() as session:
            yield session

    async def create_all_for_test_or_dev(self) -> None:
        async with self.engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

    async def dispose(self) -> None:
        if self.maintenance_engine is not None:
            await self.maintenance_engine.dispose()
        await self.engine.dispose()
