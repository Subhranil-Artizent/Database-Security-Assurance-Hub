from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from .auth import resolve_identity


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    async with request.app.state.database.session_factory() as session:
        identity = await resolve_identity(request)
        session.info["tenant_id"] = identity.tenant_id
        yield session


SessionDep = Annotated[AsyncSession, Depends(get_session)]


class Pagination(BaseModel):
    cursor: str | None = None
    limit: int = Field(default=50, ge=1, le=200)


def pagination(
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> Pagination:
    return Pagination(cursor=cursor, limit=limit)


PaginationDep = Annotated[Pagination, Depends(pagination)]
