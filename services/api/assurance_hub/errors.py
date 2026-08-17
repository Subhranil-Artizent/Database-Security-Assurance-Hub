from __future__ import annotations

from typing import Any


class DomainError(Exception):
    def __init__(
        self, code: str, message: str, status_code: int = 400, details: Any = None
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details


class NotFoundError(DomainError):
    def __init__(self, resource: str, resource_id: str) -> None:
        super().__init__(
            "resource_not_found", f"{resource} was not found", 404, {"id": resource_id}
        )


class ConflictError(DomainError):
    def __init__(self, message: str, details: Any = None) -> None:
        super().__init__("conflict", message, 409, details)


class LeaseConflictError(DomainError):
    def __init__(self, message: str) -> None:
        super().__init__("job_lease_conflict", message, 409)
