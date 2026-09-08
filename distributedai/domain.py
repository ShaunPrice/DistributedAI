# SPDX-License-Identifier: AGPL-3.0-only
"""Transport- and database-independent identity and error contracts."""
from dataclasses import dataclass

class ServiceError(Exception):
    """Raised by the service on invalid or denied input. ``code`` is a stable machine label."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Principal:
    """Authenticated caller identity. Advisory once issued — dispatch re-checks the database."""

    id: str
    org_id: str
    name: str
    is_org_admin: bool = False



class EncryptionError(Exception):
    """An encryption failure; messages deliberately contain no key or content."""


