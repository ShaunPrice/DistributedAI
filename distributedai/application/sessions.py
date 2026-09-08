# SPDX-License-Identifier: AGPL-3.0-only
"""Browser logout replay protection; persistence receives only opaque cookie hashes."""
import hashlib
import time
from typing import Protocol

MAX_COOKIE_LENGTH = 131072
MAX_TTL = 86400


class RevocationRepository(Protocol):
    def is_revoked(self, digest: str, now: float) -> bool: ...
    def revoke(self, digest: str, expires: float, now: float) -> None: ...


class BrowserSessions:
    def __init__(self, repository: RevocationRepository, *, purpose="management", clock=time.time):
        if not isinstance(purpose, str) or not purpose or len(purpose) > 128:
            raise ValueError("Invalid session purpose")
        self._repository, self._purpose, self._clock = repository, purpose, clock

    def _digest(self, cookie):
        return hashlib.sha256(b"distributedai-session-revocation-v1\0" +
            self._purpose.encode() + b"\0" + cookie.encode()).hexdigest()

    def is_revoked(self, cookie: str) -> bool:
        # Malformed credentials must not become an alternative authentication path.
        if not isinstance(cookie, str) or not cookie or len(cookie) > MAX_COOKIE_LENGTH:
            return True
        return self._repository.is_revoked(self._digest(cookie), self._clock())

    def revoke(self, cookie: str, ttl: int) -> None:
        if type(ttl) is not int or not 1 <= ttl <= MAX_TTL:
            raise ValueError("Invalid session revocation lifetime")
        if cookie == "":
            return
        if not isinstance(cookie, str) or len(cookie) > MAX_COOKIE_LENGTH:
            raise ValueError("Invalid session cookie")
        now = self._clock()
        self._repository.revoke(self._digest(cookie), now + ttl, now)
