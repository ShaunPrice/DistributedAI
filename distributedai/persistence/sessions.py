# SPDX-License-Identifier: AGPL-3.0-only
"""Shared SQL revocation registry. No cookie, access token or user content is stored."""
from datetime import datetime, timezone
import re

from sqlalchemy import Column, DateTime, MetaData, String, Table, case, delete, select

metadata = MetaData()
revocations = Table("browser_session_revocations", metadata,
    Column("digest", String(64), primary_key=True),
    Column("expires_at", DateTime, nullable=False, index=True))
CLEANUP_BATCH = 100


def _timestamp(value):
    return datetime.fromtimestamp(value, timezone.utc).replace(tzinfo=None)


def _validate_digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise ValueError("Invalid revocation identifier")


class SQLBrowserSessions:
    def __init__(self, engine):
        if engine.dialect.name not in {"sqlite", "postgresql"}:
            raise ValueError("Unsupported revocation database")
        self._engine = engine

    def is_revoked(self, digest: str, now: float) -> bool:
        _validate_digest(digest)
        with self._engine.connect() as conn:
            return conn.execute(select(revocations.c.digest).where(
                revocations.c.digest == digest,
                revocations.c.expires_at > _timestamp(now))).first() is not None

    def revoke(self, digest: str, expires: float, now: float) -> None:
        _validate_digest(digest)
        if expires <= now:
            raise ValueError("Revocation must expire in the future")
        if self._engine.dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import insert
        else:
            from sqlalchemy.dialects.sqlite import insert
        until = _timestamp(expires)
        statement = insert(revocations).values(digest=digest, expires_at=until)
        statement = statement.on_conflict_do_update(index_elements=[revocations.c.digest], set_={
            "expires_at": case((revocations.c.expires_at < until, until),
                               else_=revocations.c.expires_at)})
        with self._engine.begin() as conn:
            conn.execute(statement)
            # Bounded indexed cleanup in the same transaction. Concurrent deleters are safe.
            expired = select(revocations.c.digest).where(
                revocations.c.expires_at <= _timestamp(now)).order_by(
                    revocations.c.expires_at, revocations.c.digest).limit(CLEANUP_BATCH)
            conn.execute(delete(revocations).where(revocations.c.digest.in_(expired),
                revocations.c.expires_at <= _timestamp(now)))
