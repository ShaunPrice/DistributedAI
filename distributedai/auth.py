# SPDX-License-Identifier: AGPL-3.0-only
"""Authenticate at the transport; authorization remains in the store on every operation."""
import asyncio
import logging

import jwt
from mcp.server.auth.provider import AccessToken

from .config import Settings

log = logging.getLogger(__name__)


class Verifier:
    def __init__(self, store, settings: Settings, *, purpose="mcp"):
        self.store, self.settings, self.purpose = store, settings, purpose
        self.metered = bool(getattr(getattr(store, "billing", None), "enabled", False))
        self.jwks = jwt.PyJWKClient(settings.jwks_url, timeout=5, lifespan=300) if settings.issuer else None

    async def verify_token(self, token: str) -> AccessToken | None:
        if not token or len(token) > 8192:
            return None
        # JWT-looking values are never retried as opaque credentials when OAuth is configured.
        if self.jwks and token.count(".") == 2:
            try:
                key = await asyncio.to_thread(self.jwks.get_signing_key_from_jwt, token)
                claims = jwt.decode(
                    token, key.key, algorithms=["RS256", "ES256"],
                    audience=self.settings.public_url, issuer=self.settings.issuer,
                    options={"require": ["exp", "iat", "sub", "iss", "aud"]},
                )
                subject = claims["sub"]
                principal_id = self.settings.subjects.get(subject)
                if not principal_id:
                    return None
                principal = await asyncio.to_thread(self.store.resolve_principal, principal_id)
                if not principal:
                    return None
                scopes = ["mcp"]
                if self.purpose == "mcp" and self.metered:
                    connection_id = self.settings.oidc_connections.get(subject)
                    connection = await asyncio.to_thread(self.store.resolve_connection, connection_id) if connection_id else None
                    if connection is None or connection.principal.id != principal.id:
                        return None
                    scopes.append("connection")
                return AccessToken(
                    token=token, client_id=principal.id, subject=subject,
                    scopes=scopes, expires_at=int(claims["exp"]),
                    resource=self.settings.public_url,
                )
            except (jwt.PyJWTError, ValueError, TypeError, KeyError):
                return None
        if self.purpose == "mcp":
            connection = await asyncio.to_thread(self.store.authenticate_connection, token) if hasattr(self.store, "authenticate_connection") else None
            if connection is not None:
                principal = await asyncio.to_thread(self.store.resolve_principal, connection.principal.id)
                if principal is None:
                    return None
                return AccessToken(token=token, client_id=principal.id, scopes=["mcp", "connection"],
                                   resource=self.settings.public_url)
            if self.metered:
                return None  # Principal browser tokens cannot bypass metered client slots.
        principal = await asyncio.to_thread(self.store.authenticate, token)
        if principal is None:
            return None
        return AccessToken(token=token, client_id=principal.id, scopes=["mcp"],
                           resource=self.settings.public_url)
