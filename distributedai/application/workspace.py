# SPDX-License-Identifier: AGPL-3.0-only
"""Application entry point; adapters receive this interface, never a SQL engine.

Repositories implement whole transactional commands. Invariant checks that must be atomic
with a write (tenant ownership, quotas, version and lease fencing) stay in that command.
Splitting those into independent remote reads/writes would introduce TOCTOU races.
"""
from typing import Any, Protocol
from ..domain import Principal, ServiceError


class WorkspaceRepository(Protocol):
    def authenticate(self, token: str) -> Principal | None: ...
    def resolve_principal(self, principal_id: str) -> Principal | None: ...
    def authenticate_connection(self, credential: str) -> Any: ...
    def resolve_connection(self, connection_id: str) -> Any: ...
    def dispatch(self, principal: Principal, operation: str, arguments: dict) -> dict: ...
    def health(self) -> bool: ...


class WorkspaceApplication:
    """Transport-neutral use-case boundary, injectable with any conforming repository."""
    def __init__(self, repository: WorkspaceRepository, *, metered=False,
                 keys=None, billing_application=None, platform=None, sessions=None, support=None):
        self.__repository = repository
        self.metered = metered
        self.keys = keys
        self.billing_application = billing_application
        self.platform = platform
        self.sessions = sessions
        self.support = support

    def authenticate(self, token: str) -> Principal | None:
        return self.__repository.authenticate(token)

    def resolve_principal(self, principal_id: str) -> Principal | None:
        return self.__repository.resolve_principal(principal_id)

    def authenticate_connection(self, credential: str):
        return self.__repository.authenticate_connection(credential)

    def resolve_connection(self, connection_id: str):
        return self.__repository.resolve_connection(connection_id)

    def dispatch(self, principal: Principal, operation: str, arguments: dict) -> dict:
        if not isinstance(principal, Principal):
            raise ServiceError("denied", "a Principal is required")
        if not isinstance(arguments, dict):
            raise ServiceError("invalid_argument", "arguments must be a dict")
        # Early rejection is useful for non-SQL backends; the transactional repository
        # must also revalidate, since revocation may race this read.
        actual = self.__repository.resolve_principal(principal.id)
        if actual is None or actual.org_id != principal.org_id or actual.name != principal.name:
            raise ServiceError("denied", "Account or identity unavailable")
        if operation.startswith("support_"):
            if self.support is None:
                raise ServiceError("invalid_state", "Support is not configured")
            return self.support.dispatch(actual, operation, arguments)
        return self.__repository.dispatch(actual, operation, arguments)

    def health(self) -> bool:
        return self.__repository.health()
