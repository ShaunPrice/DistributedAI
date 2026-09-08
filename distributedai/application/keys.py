# SPDX-License-Identifier: AGPL-3.0-only
"""Organisation key use cases, independent of HTTP and key persistence."""
import base64
from typing import Protocol
from ..domain import Principal, ServiceError


class KeyRepository(Protocol):
    def provision(self, org_id: str): ...
    def status(self, org_id: str) -> dict: ...
    def rotate(self, org_id: str, provider: str, key: bytes | None) -> dict: ...


class KeyApplication:
    def __init__(self, identities, repository: KeyRepository, allowed_providers: dict):
        self.identities, self.repository = identities, repository
        self.allowed_providers = allowed_providers

    def _actor(self, actor):
        actual = self.identities.resolve_principal(actor.id) if isinstance(actor, Principal) else None
        if not actual or not actual.is_org_admin:
            raise ServiceError("denied", "Organisation administrator access required")
        return actual

    def _allowed(self, org_id):
        aliases = self.allowed_providers.get(org_id, [])
        if not isinstance(aliases, list) or any(not isinstance(v, str) for v in aliases):
            aliases = []
        return {"local", *aliases}

    def status(self, actor):
        actor = self._actor(actor)
        self.repository.provision(actor.org_id)
        return {**self.repository.status(actor.org_id), "providers": sorted(self._allowed(actor.org_id))}

    def rotate(self, actor, data):
        actor = self._actor(actor)
        if not isinstance(data, dict) or set(data) - {"provider", "manual_key"}:
            raise ValueError("Invalid key configuration")
        provider = data.get("provider")
        if not isinstance(provider, str) or provider not in self._allowed(actor.org_id):
            raise ValueError("Invalid key provider")
        key = None
        if "manual_key" in data:
            encoded = data["manual_key"]
            if not isinstance(encoded, str) or len(encoded) != 44:
                raise ValueError("Invalid key")
            key = base64.b64decode(encoded, validate=True)
            if len(key) != 32:
                raise ValueError("Invalid key")
        self.repository.provision(actor.org_id)
        return self.repository.rotate(actor.org_id, provider, key)
