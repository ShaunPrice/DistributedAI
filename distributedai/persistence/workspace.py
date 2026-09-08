# SPDX-License-Identifier: AGPL-3.0-only
"""DistributedAI shared memory and coordination store.

Multi-tenant PostgreSQL-backed persistence core (SQLite permitted for unit tests). All service
traffic enters through ``Store.dispatch``: every call re-authenticates the acting principal
against the database, strictly validates arguments, enforces organisation ownership on every
object lookup, and returns JSON-safe values. Identity and scope NEVER come from model
assertions — a forged ``Principal`` dataclass is neutralised because dispatch re-derives the
effective identity (including org-admin status) from the database row.

Concurrency: memory review serialises on the canonical row (SELECT ... FOR UPDATE on
PostgreSQL), job claims use a conditional UPDATE fenced by the attempt counter, and schema
bootstrap takes a PostgreSQL advisory lock so replicas can initialise concurrently.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    event,
    or_,
    select,
    text,
    update,
)
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from .. import security

# ---------------------------------------------------------------------------
# Public error / principal types
# ---------------------------------------------------------------------------


from ..domain import Principal, ServiceError

# ---------------------------------------------------------------------------
# Limits and enumerations
# ---------------------------------------------------------------------------

MIN_TOKEN_LEN = 32
MAX_NAME = 200
MAX_KEY = 200
MAX_CONTENT = 20_000
MAX_BODY = 20_000
MAX_OBJECTIVE = 4_000
MAX_QUERY = 500
MAX_SOURCE = 500
MAX_RESULT_JSON = 20_000
MAX_IDEMPOTENCY = 200
MAX_HISTORY = 50

SCOPE_KINDS = ("organisation", "department", "project")
CREATABLE_SCOPE_KINDS = ("department", "project")
ROLES = ("reader", "writer", "reviewer", "admin")
_ROLE_RANK = {"reader": 1, "writer": 2, "reviewer": 3, "admin": 4}
EPISTEMIC_KINDS = (
    "observation", "fact", "belief", "hypothesis", "assumption", "inference", "decision",
)

JOB_MIN_LEASE = 30
JOB_MAX_LEASE = 1800
JOB_DEFAULT_LEASE = 300
JOB_MAX_ATTEMPTS = 5

_BOOTSTRAP_LOCK_KEY = 0x_D157A1  # advisory-lock key for serialised schema bootstrap

_REQUIRED = object()


def _now() -> datetime:
    """Naive UTC timestamp (consistent storage/comparison semantics on SQLite and PostgreSQL)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _new_id() -> str:
    return uuid.uuid4().hex


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() + "Z" if dt is not None else None


# ---------------------------------------------------------------------------
# ORM models
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    pass


class Org(Base):
    __tablename__ = "orgs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(MAX_NAME), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class Scope(Base):
    __tablename__ = "scopes"
    __table_args__ = (UniqueConstraint("org_id", "parent_id", "name"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(32), ForeignKey("orgs.id"), index=True)
    parent_id: Mapped[str | None] = mapped_column(String(32), ForeignKey("scopes.id"),
                                                  nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(MAX_NAME))
    kind: Mapped[str] = mapped_column(String(20))
    # Non-secret shareable locator for project scopes (never a permission), globally unique.
    project_code: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class MemoryLock(Base):
    """Per (scope, key) mutex row so memory review can serialise even before the first
    canonical version exists (there is no canonical row to SELECT ... FOR UPDATE yet)."""

    __tablename__ = "memory_locks"
    scope_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    key: Mapped[str] = mapped_column(String(MAX_KEY), primary_key=True)


class PrincipalRow(Base):
    __tablename__ = "principals"
    __table_args__ = (UniqueConstraint("org_id", "name"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(32), ForeignKey("orgs.id"), index=True)
    name: Mapped[str] = mapped_column(String(MAX_NAME))
    token_digest: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    is_org_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Grant(Base):
    __tablename__ = "grants"
    __table_args__ = (UniqueConstraint("principal_id", "scope_id"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(32), ForeignKey("orgs.id"), index=True)
    principal_id: Mapped[str] = mapped_column(String(32), ForeignKey("principals.id"), index=True)
    scope_id: Mapped[str] = mapped_column(String(32), ForeignKey("scopes.id"), index=True)
    role: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class MemoryRecord(Base):
    """Canonical (current) value per (scope, key)."""

    __tablename__ = "memory_records"
    __table_args__ = (UniqueConstraint("scope_id", "key"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(32), ForeignKey("orgs.id"), index=True)
    scope_id: Mapped[str] = mapped_column(String(32), ForeignKey("scopes.id"), index=True)
    key: Mapped[str] = mapped_column(String(MAX_KEY))
    content: Mapped[str] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer, default=0)
    epistemic_kind: Mapped[str] = mapped_column(String(20))
    source: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(32))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class MemoryVersion(Base):
    """Immutable append-only version history."""

    __tablename__ = "memory_versions"
    __table_args__ = (UniqueConstraint("scope_id", "key", "version"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(32), ForeignKey("orgs.id"), index=True)
    scope_id: Mapped[str] = mapped_column(String(32), ForeignKey("scopes.id"), index=True)
    key: Mapped[str] = mapped_column(String(MAX_KEY))
    version: Mapped[int] = mapped_column(Integer)
    content: Mapped[str] = mapped_column(Text)
    epistemic_kind: Mapped[str] = mapped_column(String(20))
    source: Mapped[str] = mapped_column(Text, default="")
    proposal_id: Mapped[str] = mapped_column(String(32))
    created_by: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class MemoryProposal(Base):
    __tablename__ = "memory_proposals"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(32), ForeignKey("orgs.id"), index=True)
    scope_id: Mapped[str] = mapped_column(String(32), ForeignKey("scopes.id"), index=True)
    key: Mapped[str] = mapped_column(String(MAX_KEY))
    content: Mapped[str] = mapped_column(Text)
    expected_version: Mapped[int] = mapped_column(Integer, default=0)
    epistemic_kind: Mapped[str] = mapped_column(String(20))
    source: Mapped[str] = mapped_column(Text, default="")
    proposer_id: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    quarantined: Mapped[bool] = mapped_column(Boolean, default=False)
    findings: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    reviewed_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Message(Base):
    __tablename__ = "messages"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(32), ForeignKey("orgs.id"), index=True)
    scope_id: Mapped[str] = mapped_column(String(32), ForeignKey("scopes.id"), index=True)
    sender_id: Mapped[str] = mapped_column(String(32))
    recipient_id: Mapped[str] = mapped_column(String(32), index=True)
    body: Mapped[str] = mapped_column(Text)
    quarantined: Mapped[bool] = mapped_column(Boolean, default=False)
    findings: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class Job(Base):
    __tablename__ = "jobs"
    __table_args__ = (UniqueConstraint("creator_id", "scope_id", "idempotency_key"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(32), ForeignKey("orgs.id"), index=True)
    scope_id: Mapped[str] = mapped_column(String(32), ForeignKey("scopes.id"), index=True)
    creator_id: Mapped[str] = mapped_column(String(32))
    assignee_id: Mapped[str] = mapped_column(String(32), index=True)
    objective: Mapped[str] = mapped_column(Text)
    idempotency_key: Mapped[str] = mapped_column(String(MAX_IDEMPOTENCY))
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    quarantined: Mapped[bool] = mapped_column(Boolean, default=False)
    findings: Mapped[str] = mapped_column(Text, default="[]")
    claim_token_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(32), ForeignKey("orgs.id"), index=True)
    scope_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    actor_id: Mapped[str] = mapped_column(String(32))
    action: Mapped[str] = mapped_column(String(50))
    record_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    at: Mapped[datetime] = mapped_column(DateTime, default=_now)


# ---------------------------------------------------------------------------
# Argument validation helpers
# ---------------------------------------------------------------------------


def _check_keys(args: dict, allowed: set[str]) -> None:
    extra = set(args) - allowed
    if extra:
        raise ServiceError("invalid_argument", f"unexpected arguments: {sorted(extra)}")


def _str_arg(args: dict, name: str, *, default: Any = _REQUIRED, max_len: int = MAX_NAME,
             allow_empty: bool = False) -> str:
    value = args.get(name, default)
    if value is _REQUIRED:
        raise ServiceError("invalid_argument", f"'{name}' is required")
    if not isinstance(value, str):
        raise ServiceError("invalid_argument", f"'{name}' must be a string")
    if not allow_empty and not value.strip():
        raise ServiceError("invalid_argument", f"'{name}' must not be empty")
    if len(value) > max_len:
        raise ServiceError("invalid_argument", f"'{name}' exceeds {max_len} characters")
    return value


def _int_arg(args: dict, name: str, *, default: Any = _REQUIRED, lo: int, hi: int) -> int:
    value = args.get(name, default)
    if value is _REQUIRED:
        raise ServiceError("invalid_argument", f"'{name}' is required")
    if isinstance(value, bool) or not isinstance(value, int):
        raise ServiceError("invalid_argument", f"'{name}' must be an integer")
    if not lo <= value <= hi:
        raise ServiceError("invalid_argument", f"'{name}' must be between {lo} and {hi}")
    return value


def _bool_arg(args: dict, name: str) -> bool:
    value = args.get(name, _REQUIRED)
    if value is _REQUIRED:
        raise ServiceError("invalid_argument", f"'{name}' is required")
    if not isinstance(value, bool):
        raise ServiceError("invalid_argument", f"'{name}' must be a boolean")
    return value


def _enum_arg(args: dict, name: str, choices: tuple[str, ...],
              *, default: Any = _REQUIRED) -> str:
    value = _str_arg(args, name, default=default, max_len=50)
    if value not in choices:
        raise ServiceError("invalid_argument", f"'{name}' must be one of {list(choices)}")
    return value


def _validate_token(token: Any) -> str:
    if not isinstance(token, str):
        raise ServiceError("invalid_argument", "token must be a string")
    if len(token) < MIN_TOKEN_LEN:
        raise ServiceError("weak_token", f"token must be at least {MIN_TOKEN_LEN} characters")
    if len(token) > 512:
        raise ServiceError("invalid_argument", "token exceeds 512 characters")
    return token


def _escape_like(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


_OPERATIONS = {
    "scope_create", "scope_list", "principal_create", "principal_revoke", "principal_list",
    "grant", "grant_list", "grant_revoke", "project_resolve",
    "memory_propose", "memory_review", "memory_search", "memory_history", "proposal_list",
    "message_send", "message_inbox",
    "job_create", "job_list", "job_claim", "job_renew", "job_submit", "job_review",
    "job_cancel", "audit_list",
    "instance_create", "instance_list", "connection_issue", "connection_revoke",
    "connection_list", "billing_status",
}


class Store:
    """Synchronous persistence and authorisation core. One instance per process is fine;
    every dispatch uses its own session/transaction."""

    def __init__(self, database_url: str, *, billing_enabled: bool = False,
                 plan_limits: dict | None = None) -> None:
        if not isinstance(database_url, str) or not database_url:
            raise ValueError("database_url must be a non-empty string")
        kwargs: dict[str, Any] = {}
        if database_url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
        self._engine = create_engine(database_url, hide_parameters=True, pool_pre_ping=True, **kwargs)
        if database_url.startswith("sqlite"):
            @event.listens_for(self._engine, "connect")
            def sqlite_foreign_keys(connection, record):
                connection.execute("PRAGMA foreign_keys=ON")
        # Deferred import: billing's registry tables extend this module's Base. Billing is
        # per-instance state (no mutable globals); disabled means fully unmetered.
        from . import billing as billing_module
        self.billing = billing_module.BillingEngine(enabled=billing_enabled,
                                                    plan_limits=plan_limits)

    # -- lifecycle ----------------------------------------------------------

    def initialize(self) -> None:
        """Create the schema idempotently. PostgreSQL bootstrap is serialised with an
        advisory lock so concurrent replicas cannot race CREATE TABLE."""
        with self._engine.begin() as conn:
            if conn.dialect.name == "postgresql":
                conn.execute(text("SELECT pg_advisory_xact_lock(:key)"),
                             {"key": _BOOTSTRAP_LOCK_KEY})
            Base.metadata.create_all(conn)

    def health(self) -> bool:
        try:
            with self._engine.connect() as conn:
                conn.execute(select(1))
            return True
        except SQLAlchemyError:
            return False

    # -- bootstrap / authentication ----------------------------------------

    @staticmethod
    def _validate_org_args(org: str, principal: str, token: str) -> None:
        if not isinstance(org, str) or not org.strip() or len(org) > MAX_NAME:
            raise ServiceError("invalid_argument", "org must be a non-empty bounded string")
        if not isinstance(principal, str) or not principal.strip() or len(principal) > MAX_NAME:
            raise ServiceError("invalid_argument", "principal must be a non-empty bounded string")
        _validate_token(token)

    def _create_org(self, sess: Session, org: str, principal: str, token: str) -> dict:
        org_row = Org(id=_new_id(), name=org)
        sess.add(org_row)
        # No ORM relationships are configured, so explicitly persist parent rows first.
        sess.flush([org_row])
        root = Scope(id=_new_id(), org_id=org_row.id, parent_id=None,
                     name=org, kind="organisation")
        sess.add(root)
        sess.flush([root])
        admin = PrincipalRow(id=_new_id(), org_id=org_row.id, name=principal,
                             token_digest=_digest(token), is_org_admin=True)
        sess.add(admin)
        sess.flush([admin])
        self._audit(sess, org_row.id, admin.id, "bootstrap",
                    record_id=admin.id, scope_id=root.id)
        return {"org_id": org_row.id, "principal_id": admin.id, "root_scope_id": root.id}

    def bootstrap(self, org: str, principal: str, token: str) -> dict:
        """Idempotent installer entry point. On a fresh database (no principals anywhere) it
        creates the initial organisation and org admin, storing only the SHA-256 token digest.
        On an initialised database it NEVER creates or grants anything: it returns the
        existing initial org only when the supplied token authenticates an active org admin
        of that organisation, and denies otherwise. Additional tenants come from the offline
        operator method ``create_organisation``."""
        self._validate_org_args(org, principal, token)
        with Session(self._engine) as sess, sess.begin():
            if self._engine.dialect.name == "postgresql":
                sess.execute(text("SELECT pg_advisory_xact_lock(:key)"),
                             {"key": _BOOTSTRAP_LOCK_KEY})
            org_row = sess.execute(select(Org).where(Org.name == org)).scalar_one_or_none()
            if org_row is not None:
                admin = sess.execute(
                    select(PrincipalRow).where(PrincipalRow.org_id == org_row.id,
                                               PrincipalRow.token_digest == _digest(token),
                                               PrincipalRow.active.is_(True),
                                               PrincipalRow.is_org_admin.is_(True))
                ).scalar_one_or_none()
                if admin is None:
                    raise ServiceError("denied",
                                       "organisation is already initialised and the token "
                                       "does not authenticate its org admin")
                root = sess.execute(
                    select(Scope).where(Scope.org_id == org_row.id,
                                        Scope.kind == "organisation")
                ).scalar_one()
                return {"org_id": org_row.id, "principal_id": admin.id,
                        "root_scope_id": root.id, "existing": True}
            any_principal = sess.execute(
                select(PrincipalRow.id).limit(1)
            ).scalar_one_or_none()
            if any_principal is not None:
                raise ServiceError("denied",
                                   "database is already initialised; use create_organisation "
                                   "(offline operator authority) for additional tenants")
            created = self._create_org(sess, org, principal, token)
            return {**created, "existing": False}

    def create_organisation(self, name: str, principal_name: str, token: str) -> dict:
        """OFFLINE operator authority (CLI provisioning, not reachable through dispatch):
        create an additional tenant organisation with its own org admin. There is no global
        MCP superadmin — dispatch principals can never call this."""
        self._validate_org_args(name, principal_name, token)
        with Session(self._engine) as sess, sess.begin():
            exists = sess.execute(select(Org.id).where(Org.name == name)).scalar_one_or_none()
            if exists is not None:
                raise ServiceError("conflict", "organisation name already exists")
            return self._create_org(sess, name, principal_name, token)

    def resolve_principal(self, principal_id: str) -> Principal | None:
        """Resolve a database principal id to its ACTIVE identity, for transports that verify
        identity externally (e.g. OAuth) and map issuer/subject to a principal id via trusted
        admin configuration. Returns None for unknown, revoked, or malformed ids — identity is
        only ever the database's, never an id asserted by a token or model."""
        if not isinstance(principal_id, str) or not principal_id or len(principal_id) > 64:
            return None
        with Session(self._engine) as sess:
            row = sess.execute(
                select(PrincipalRow).where(PrincipalRow.id == principal_id,
                                           PrincipalRow.active.is_(True))
            ).scalar_one_or_none()
            if row is None:
                return None
            return Principal(id=row.id, org_id=row.org_id, name=row.name,
                             is_org_admin=row.is_org_admin)

    def authenticate(self, token: str) -> Principal | None:
        """Look up an active principal by token digest. Returns None on any failure —
        revocation takes effect immediately because inactive rows never match."""
        if not isinstance(token, str) or not token:
            return None
        with Session(self._engine) as sess:
            row = sess.execute(
                select(PrincipalRow).where(PrincipalRow.token_digest == _digest(token),
                                           PrincipalRow.active.is_(True))
            ).scalar_one_or_none()
            if row is None:
                return None
            return Principal(id=row.id, org_id=row.org_id, name=row.name,
                             is_org_admin=row.is_org_admin)

    # -- dispatch -----------------------------------------------------------

    def dispatch(self, principal: Principal, operation: str, arguments: dict) -> dict:
        """Sole service entry point. Re-checks the caller's identity against the database on
        every call, so revocation and forged Principal objects are caught here."""
        if not isinstance(principal, Principal):
            raise ServiceError("denied", "a Principal is required")
        if not isinstance(operation, str) or operation not in _OPERATIONS:
            raise ServiceError("unknown_operation", "unsupported operation")
        if not isinstance(arguments, dict):
            raise ServiceError("invalid_argument", "arguments must be a dict")
        handler = getattr(self, f"_op_{operation}")
        try:
            with Session(self._engine) as sess, sess.begin():
                dbp = sess.get(PrincipalRow, principal.id)
                if (dbp is None or not dbp.active or dbp.org_id != principal.org_id
                        or dbp.name != principal.name):
                    raise ServiceError("denied", "principal is unknown, revoked, or mismatched")
                # dbp (database truth) is authoritative from here on; the caller-supplied
                # is_org_admin flag is deliberately ignored.
                return handler(sess, dbp, arguments)
        except IntegrityError as exc:
            raise ServiceError("conflict", "concurrent write conflict") from exc

    # -- authorisation helpers ---------------------------------------------

    def _audit(self, sess: Session, org_id: str, actor_id: str, action: str,
               record_id: str | None = None, scope_id: str | None = None) -> None:
        sess.add(AuditLog(id=_new_id(), org_id=org_id, scope_id=scope_id,
                          actor_id=actor_id, action=action, record_id=record_id))

    def _get_scope(self, sess: Session, org_id: str, scope_id: str) -> Scope:
        if not isinstance(scope_id, str) or not scope_id or len(scope_id) > 64:
            raise ServiceError("invalid_argument", "'scope_id' must be a bounded string")
        scope = sess.execute(
            select(Scope).where(Scope.id == scope_id, Scope.org_id == org_id)
        ).scalar_one_or_none()
        if scope is None:
            raise ServiceError("not_found", "scope not found in this organisation")
        return scope

    def _scope_chain(self, sess: Session, scope: Scope) -> list[Scope]:
        """The scope followed by its ancestors up to the org root (bounded walk)."""
        chain = [scope]
        current = scope
        for _ in range(100):
            if current.parent_id is None:
                break
            parent = sess.execute(
                select(Scope).where(Scope.id == current.parent_id,
                                    Scope.org_id == scope.org_id)
            ).scalar_one_or_none()
            if parent is None:
                break
            chain.append(parent)
            current = parent
        else:
            raise ServiceError("invalid_state", "scope hierarchy too deep or cyclic")
        return chain

    def _role_for(self, sess: Session, principal_row: PrincipalRow, scope: Scope) -> str | None:
        """Effective role of a principal on a scope: org admins are admin everywhere in their
        org; otherwise the highest-ranked grant on the scope or any ancestor (grants apply to
        the granted scope and its descendants, never across organisations)."""
        if scope.org_id != principal_row.org_id:
            return None
        if principal_row.is_org_admin:
            return "admin"
        chain_ids = [s.id for s in self._scope_chain(sess, scope)]
        rows = sess.execute(
            select(Grant.role).where(Grant.principal_id == principal_row.id,
                                     Grant.org_id == principal_row.org_id,
                                     Grant.scope_id.in_(chain_ids))
        ).scalars().all()
        if not rows:
            return None
        return max(rows, key=lambda r: _ROLE_RANK[r])

    def _require_role(self, sess: Session, dbp: PrincipalRow, scope: Scope,
                      minimum: str) -> str:
        role = self._role_for(sess, dbp, scope)
        if role is None or _ROLE_RANK[role] < _ROLE_RANK[minimum]:
            raise ServiceError("denied", f"requires '{minimum}' access on this scope")
        return role

    def _require_org_admin(self, dbp: PrincipalRow) -> None:
        if not dbp.is_org_admin:
            raise ServiceError("denied", "org admin only")

    # -- scope / principal / grant operations -------------------------------

    def _new_project_code(self, sess: Session) -> str:
        """Generate a globally unique, non-secret project locator (>=12 URL-safe chars)."""
        for _ in range(8):
            code = secrets.token_urlsafe(12)  # 16 URL-safe characters
            taken = sess.execute(
                select(Scope.id).where(Scope.project_code == code)
            ).scalar_one_or_none()
            if taken is None:
                return code
        raise ServiceError("internal", "could not generate a unique project code")

    def _op_scope_create(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, {"name", "kind", "parent_id"})
        self._require_org_admin(dbp)
        name = _str_arg(args, "name")
        kind = _enum_arg(args, "kind", CREATABLE_SCOPE_KINDS)
        parent = self._get_scope(sess, dbp.org_id, args.get("parent_id"))
        if parent.kind == "project":
            raise ServiceError("invalid_argument", "a project cannot contain child scopes")
        if kind == "department" and parent.kind not in ("organisation", "department"):
            raise ServiceError("invalid_argument",
                               "departments must sit under the organisation or a department")
        code = self._new_project_code(sess) if kind == "project" else None
        scope = Scope(id=_new_id(), org_id=dbp.org_id, parent_id=parent.id,
                      name=name, kind=kind, project_code=code)
        sess.add(scope)
        self._audit(sess, dbp.org_id, dbp.id, "scope_create",
                    record_id=scope.id, scope_id=scope.id)
        return {"scope_id": scope.id, "name": name, "kind": kind, "parent_id": parent.id,
                "project_code": code}

    def _op_scope_list(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, set())
        scopes = sess.execute(
            select(Scope).where(Scope.org_id == dbp.org_id).order_by(Scope.created_at)
        ).scalars().all()
        visible = [s for s in scopes if self._role_for(sess, dbp, s) is not None]
        return {"scopes": [
            {"scope_id": s.id, "name": s.name, "kind": s.kind, "parent_id": s.parent_id,
             "project_code": s.project_code}
            for s in visible
        ]}

    def _op_project_resolve(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, {"project_code"})
        code = _str_arg(args, "project_code", max_len=64)
        scope = sess.execute(
            select(Scope).where(Scope.project_code == code, Scope.org_id == dbp.org_id)
        ).scalar_one_or_none()
        # One generic answer for unknown code / other tenant / no read grant: the project
        # code is a locator, never a permission, and must not act as an existence oracle.
        if scope is None or self._role_for(sess, dbp, scope) is None:
            raise ServiceError("not_found", "project code unavailable")
        return {"scope_id": scope.id, "name": scope.name, "kind": scope.kind,
                "parent_id": scope.parent_id, "project_code": scope.project_code}

    def _op_principal_create(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, {"name", "token"})
        self._require_org_admin(dbp)
        name = _str_arg(args, "name")
        token = _validate_token(args.get("token"))
        self.billing.check_user_quota(sess, dbp.org_id)  # no-op when billing is disabled
        row = PrincipalRow(id=_new_id(), org_id=dbp.org_id, name=name,
                           token_digest=_digest(token), is_org_admin=False)
        sess.add(row)
        self._audit(sess, dbp.org_id, dbp.id, "principal_create", record_id=row.id)
        return {"principal_id": row.id, "name": name}

    def _op_principal_revoke(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, {"principal_id"})
        self._require_org_admin(dbp)
        pid = _str_arg(args, "principal_id", max_len=64)
        target = sess.execute(
            select(PrincipalRow).where(PrincipalRow.id == pid,
                                       PrincipalRow.org_id == dbp.org_id)
        ).scalar_one_or_none()
        if target is None:
            raise ServiceError("not_found", "principal not found in this organisation")
        if not target.active:
            raise ServiceError("invalid_state", "principal is already revoked")
        if target.is_org_admin:
            admins = sess.execute(
                select(PrincipalRow.id).where(PrincipalRow.org_id == dbp.org_id,
                                              PrincipalRow.is_org_admin.is_(True),
                                              PrincipalRow.active.is_(True))
            ).scalars().all()
            if len(admins) <= 1:
                raise ServiceError("denied", "cannot revoke the final active org admin")
        target.active = False
        target.revoked_at = _now()
        self._audit(sess, dbp.org_id, dbp.id, "principal_revoke", record_id=target.id)
        return {"principal_id": target.id, "revoked": True}

    def _op_grant(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, {"principal_id", "scope_id", "role"})
        self._require_org_admin(dbp)
        role = _enum_arg(args, "role", ROLES)
        pid = _str_arg(args, "principal_id", max_len=64)
        target = sess.execute(
            select(PrincipalRow).where(PrincipalRow.id == pid,
                                       PrincipalRow.org_id == dbp.org_id,
                                       PrincipalRow.active.is_(True))
        ).scalar_one_or_none()
        if target is None:
            raise ServiceError("not_found", "active principal not found in this organisation")
        scope = self._get_scope(sess, dbp.org_id, args.get("scope_id"))
        existing = sess.execute(
            select(Grant).where(Grant.principal_id == target.id, Grant.scope_id == scope.id)
        ).scalar_one_or_none()
        if existing is not None:
            existing.role = role
            grant_id = existing.id
        else:
            grant = Grant(id=_new_id(), org_id=dbp.org_id, principal_id=target.id,
                          scope_id=scope.id, role=role)
            sess.add(grant)
            grant_id = grant.id
        self._audit(sess, dbp.org_id, dbp.id, "grant", record_id=grant_id, scope_id=scope.id)
        return {"grant_id": grant_id, "principal_id": target.id,
                "scope_id": scope.id, "role": role}

    def _op_principal_list(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, set())
        self._require_org_admin(dbp)
        rows = sess.execute(
            select(PrincipalRow).where(PrincipalRow.org_id == dbp.org_id)
            .order_by(PrincipalRow.created_at)
        ).scalars().all()
        # Token digests are deliberately excluded from every read surface.
        return {"principals": [
            {"principal_id": p.id, "name": p.name, "active": p.active,
             "is_org_admin": p.is_org_admin}
            for p in rows
        ]}

    def _op_grant_list(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, set())
        self._require_org_admin(dbp)
        rows = sess.execute(
            select(Grant).where(Grant.org_id == dbp.org_id).order_by(Grant.created_at)
        ).scalars().all()
        return {"grants": [
            {"grant_id": g.id, "principal_id": g.principal_id,
             "scope_id": g.scope_id, "role": g.role}
            for g in rows
        ]}

    def _op_grant_revoke(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, {"principal_id", "scope_id"})
        self._require_org_admin(dbp)
        pid = _str_arg(args, "principal_id", max_len=64)
        scope = self._get_scope(sess, dbp.org_id, args.get("scope_id"))
        grant = sess.execute(
            select(Grant).where(Grant.principal_id == pid, Grant.scope_id == scope.id,
                                Grant.org_id == dbp.org_id)
        ).scalar_one_or_none()
        if grant is None:
            raise ServiceError("not_found", "no such grant in this organisation")
        target = sess.get(PrincipalRow, grant.principal_id)
        if (grant.role == "admin" and target is not None and target.is_org_admin
                and target.active):
            admins = sess.execute(
                select(PrincipalRow.id).where(PrincipalRow.org_id == dbp.org_id,
                                              PrincipalRow.is_org_admin.is_(True),
                                              PrincipalRow.active.is_(True))
            ).scalars().all()
            if len(admins) <= 1:
                raise ServiceError("denied",
                                   "cannot strip the admin grant of the final org admin")
        sess.delete(grant)
        self._audit(sess, dbp.org_id, dbp.id, "grant_revoke",
                    record_id=grant.id, scope_id=scope.id)
        return {"principal_id": grant.principal_id, "scope_id": scope.id, "revoked": True}

    # -- memory operations ---------------------------------------------------

    def _op_memory_propose(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, {"scope_id", "key", "content", "expected_version",
                           "epistemic_kind", "source"})
        scope = self._get_scope(sess, dbp.org_id, args.get("scope_id"))
        self._require_role(sess, dbp, scope, "writer")
        key = _str_arg(args, "key", max_len=MAX_KEY)
        content = _str_arg(args, "content", max_len=MAX_CONTENT)
        expected = _int_arg(args, "expected_version", default=0, lo=0, hi=1_000_000_000)
        kind = _enum_arg(args, "epistemic_kind", EPISTEMIC_KINDS, default="observation")
        source = _str_arg(args, "source", default="", max_len=MAX_SOURCE, allow_empty=True)
        findings = security.scan_payload({"key": key, "content": content, "source": source})
        self.billing.charge_storage(sess, dbp.org_id, sum(len(v.encode("utf-8")) for v in (content, source, json.dumps(findings))))
        proposal = MemoryProposal(
            id=_new_id(), org_id=dbp.org_id, scope_id=scope.id, key=key, content=content,
            expected_version=expected, epistemic_kind=kind, source=source,
            proposer_id=dbp.id, quarantined=bool(findings), findings=json.dumps(findings),
        )
        sess.add(proposal)
        self._audit(sess, dbp.org_id, dbp.id, "memory_propose",
                    record_id=proposal.id, scope_id=scope.id)
        return {"proposal_id": proposal.id, "status": "pending",
                "quarantined": proposal.quarantined, "findings": findings}

    def _acquire_memory_mutex(self, sess: Session, scope_id: str, key: str) -> None:
        """Take (creating on first use) the per (scope, key) mutex row under FOR UPDATE.
        This serialises reviews even when no canonical row exists yet, so two first-version
        accepts cannot both pass the expected_version check. On SQLite the insert itself is
        the serialisation point (single writer); on PostgreSQL the row lock is."""
        locked = sess.execute(
            select(MemoryLock).where(MemoryLock.scope_id == scope_id, MemoryLock.key == key)
            .with_for_update()
        ).scalar_one_or_none()
        if locked is None:
            try:
                with sess.begin_nested():
                    sess.add(MemoryLock(scope_id=scope_id, key=key))
                    sess.flush()
            except IntegrityError:
                pass  # a concurrent reviewer created it; fall through and lock it
            sess.execute(
                select(MemoryLock).where(MemoryLock.scope_id == scope_id,
                                         MemoryLock.key == key)
                .with_for_update()
            ).scalar_one()

    def _transition_proposal(self, sess: Session, proposal: MemoryProposal,
                             new_status: str, reviewer_id: str) -> None:
        """Move a proposal out of 'pending' with a conditional UPDATE. Exactly one reviewer
        can win this transition on any database — a concurrent accept/reject/conflict loses
        with rowcount 0 and the whole losing transaction rolls back."""
        result = sess.execute(
            update(MemoryProposal)
            .where(MemoryProposal.id == proposal.id, MemoryProposal.status == "pending")
            .values(status=new_status, reviewed_by=reviewer_id, reviewed_at=_now())
        )
        if result.rowcount != 1:
            raise ServiceError("conflict", "proposal was reviewed concurrently")

    def _op_memory_review(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, {"proposal_id", "accept"})
        pid = _str_arg(args, "proposal_id", max_len=64)
        accept = _bool_arg(args, "accept")
        # Lock the proposal row first (row lock on PostgreSQL) so concurrent reviews of the
        # same proposal serialise here; the fenced status transition below is the authority.
        proposal = sess.execute(
            select(MemoryProposal).where(MemoryProposal.id == pid,
                                         MemoryProposal.org_id == dbp.org_id)
            .with_for_update()
        ).scalar_one_or_none()
        if proposal is None:
            raise ServiceError("not_found", "proposal not found in this organisation")
        # Permission is checked on the proposal's ACTUAL scope, never a caller-supplied one.
        scope = self._get_scope(sess, dbp.org_id, proposal.scope_id)
        self._require_role(sess, dbp, scope, "reviewer")
        if proposal.proposer_id == dbp.id:
            raise ServiceError("self_review", "a proposer cannot review their own proposal")
        if proposal.status != "pending":
            raise ServiceError("invalid_state", f"proposal is already '{proposal.status}'")
        if not accept:
            self._transition_proposal(sess, proposal, "rejected", dbp.id)
            self._audit(sess, dbp.org_id, dbp.id, "memory_review_reject",
                        record_id=proposal.id, scope_id=scope.id)
            return {"proposal_id": proposal.id, "status": "rejected"}
        if proposal.quarantined:
            raise ServiceError("quarantined", "quarantined proposals cannot be promoted")
        # Take the (scope, key) mutex BEFORE reading the canonical row: first-version races
        # (no canonical row to lock yet) serialise on the mutex, later versions additionally
        # on the canonical row lock.
        self._acquire_memory_mutex(sess, proposal.scope_id, proposal.key)
        canonical = sess.execute(
            select(MemoryRecord)
            .where(MemoryRecord.scope_id == proposal.scope_id,
                   MemoryRecord.key == proposal.key)
            .with_for_update()
        ).scalar_one_or_none()
        current_version = canonical.version if canonical is not None else 0
        if proposal.expected_version != current_version:
            self._transition_proposal(sess, proposal, "conflict", dbp.id)
            self._audit(sess, dbp.org_id, dbp.id, "memory_review_conflict",
                        record_id=proposal.id, scope_id=scope.id)
            return {"proposal_id": proposal.id, "status": "conflict",
                    "current_version": current_version,
                    "expected_version": proposal.expected_version}
        # Charge the immutable version copy; on quota_exceeded the whole transaction rolls
        # back, so the proposal stays pending and can be re-reviewed after an upgrade.
        self.billing.charge_storage(sess, dbp.org_id,
                                    len(proposal.content.encode("utf-8")) + len(proposal.source.encode("utf-8")))
        self._transition_proposal(sess, proposal, "accepted", dbp.id)
        new_version = current_version + 1
        if canonical is None:
            canonical = MemoryRecord(id=_new_id(), org_id=dbp.org_id,
                                     scope_id=proposal.scope_id, key=proposal.key,
                                     content=proposal.content, version=new_version,
                                     epistemic_kind=proposal.epistemic_kind,
                                     source=proposal.source, created_by=proposal.proposer_id,
                                     updated_at=_now())
            sess.add(canonical)
        else:
            canonical.content = proposal.content
            canonical.version = new_version
            canonical.epistemic_kind = proposal.epistemic_kind
            canonical.source = proposal.source
            canonical.created_by = proposal.proposer_id
            canonical.updated_at = _now()
        sess.add(MemoryVersion(id=_new_id(), org_id=dbp.org_id, scope_id=proposal.scope_id,
                               key=proposal.key, version=new_version,
                               content=proposal.content,
                               epistemic_kind=proposal.epistemic_kind,
                               source=proposal.source, proposal_id=proposal.id,
                               created_by=proposal.proposer_id))
        self._audit(sess, dbp.org_id, dbp.id, "memory_review_accept",
                    record_id=proposal.id, scope_id=scope.id)
        return {"proposal_id": proposal.id, "status": "accepted", "version": new_version}

    def _op_memory_search(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, {"scope_id", "query", "limit"})
        scope = self._get_scope(sess, dbp.org_id, args.get("scope_id"))
        self._require_role(sess, dbp, scope, "reader")
        query = _str_arg(args, "query", default="", max_len=MAX_QUERY, allow_empty=True)
        limit = _int_arg(args, "limit", default=20, lo=1, hi=100)
        # Requested scope plus only those ancestors the principal can read — never siblings
        # or descendants implicitly.
        readable = [s.id for s in self._scope_chain(sess, scope)
                    if self._role_for(sess, dbp, s) is not None]
        stmt = select(MemoryRecord).where(MemoryRecord.org_id == dbp.org_id,
                                          MemoryRecord.scope_id.in_(readable),
                                          MemoryRecord.active.is_(True))
        # Encrypted content cannot be searched with a plaintext SQL index. Bound the
        # authorised candidate scan and report truncation; never build a plaintext index.
        candidates = sess.execute(
            stmt.order_by(MemoryRecord.updated_at.desc(), MemoryRecord.id).limit(1001)
        ).scalars().all()
        rows = [row for row in candidates[:1000] if query.casefold() in row.content.casefold()][:limit]
        return {"search_truncated": len(candidates) > 1000, "records": [
            {"scope_id": r.scope_id, "key": r.key, "content": r.content,
             "version": r.version, "epistemic_kind": r.epistemic_kind, "source": r.source,
             "created_by": r.created_by, "updated_at": _iso(r.updated_at),
             "trust": "untrusted_data"}
            for r in rows
        ]}

    def _op_memory_history(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, {"scope_id", "key"})
        scope = self._get_scope(sess, dbp.org_id, args.get("scope_id"))
        self._require_role(sess, dbp, scope, "reader")
        key = _str_arg(args, "key", max_len=MAX_KEY)
        rows = sess.execute(
            select(MemoryVersion)
            .where(MemoryVersion.org_id == dbp.org_id,
                   MemoryVersion.scope_id == scope.id, MemoryVersion.key == key)
            .order_by(MemoryVersion.version.desc()).limit(MAX_HISTORY)
        ).scalars().all()
        return {"versions": [
            {"version": v.version, "content": v.content, "epistemic_kind": v.epistemic_kind,
             "source": v.source, "proposal_id": v.proposal_id, "created_by": v.created_by,
             "created_at": _iso(v.created_at), "trust": "untrusted_data"}
            for v in rows
        ]}

    def _op_proposal_list(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, {"scope_id", "limit"})
        scope = self._get_scope(sess, dbp.org_id, args.get("scope_id"))
        self._require_role(sess, dbp, scope, "reviewer")
        limit = _int_arg(args, "limit", default=20, lo=1, hi=100)
        rows = sess.execute(
            select(MemoryProposal)
            .where(MemoryProposal.org_id == dbp.org_id, MemoryProposal.scope_id == scope.id)
            .order_by(MemoryProposal.created_at.desc()).limit(limit)
        ).scalars().all()
        return {"proposals": [
            {"proposal_id": p.id, "key": p.key, "content": p.content, "source": p.source,
             "status": p.status, "quarantined": p.quarantined,
             "findings": json.loads(p.findings), "epistemic_kind": p.epistemic_kind,
             "proposer_id": p.proposer_id}
            for p in rows
        ]}

    # -- messaging -----------------------------------------------------------

    def _op_message_send(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, {"scope_id", "recipient_id", "body"})
        scope = self._get_scope(sess, dbp.org_id, args.get("scope_id"))
        self._require_role(sess, dbp, scope, "writer")
        body = _str_arg(args, "body", max_len=MAX_BODY)
        rid = _str_arg(args, "recipient_id", max_len=64)
        recipient = sess.execute(
            select(PrincipalRow).where(PrincipalRow.id == rid,
                                       PrincipalRow.org_id == dbp.org_id,
                                       PrincipalRow.active.is_(True))
        ).scalar_one_or_none()
        if recipient is None:
            raise ServiceError("not_found", "recipient not found in this organisation")
        if self._role_for(sess, recipient, scope) is None:
            raise ServiceError("denied", "recipient has no read access to this scope")
        findings = security.scan_text(body)
        self.billing.charge_storage(sess, dbp.org_id, len(body.encode("utf-8")) + len(json.dumps(findings).encode("utf-8")))
        message = Message(id=_new_id(), org_id=dbp.org_id, scope_id=scope.id,
                          sender_id=dbp.id, recipient_id=recipient.id, body=body,
                          quarantined=bool(findings), findings=json.dumps(findings))
        sess.add(message)
        self._audit(sess, dbp.org_id, dbp.id, "message_send",
                    record_id=message.id, scope_id=scope.id)
        return {"message_id": message.id, "quarantined": message.quarantined}

    def _op_message_inbox(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, {"limit"})
        limit = _int_arg(args, "limit", default=20, lo=1, hi=100)
        rows = sess.execute(
            select(Message)
            .where(Message.recipient_id == dbp.id, Message.org_id == dbp.org_id,
                   Message.quarantined.is_(False))
            .order_by(Message.created_at.desc()).limit(limit * 4)
        ).scalars().all()
        out = []
        for m in rows:
            scope = sess.get(Scope, m.scope_id)
            # Re-check CURRENT grants at read time; access revoked since delivery hides mail.
            if scope is None or self._role_for(sess, dbp, scope) is None:
                continue
            out.append({"message_id": m.id, "scope_id": m.scope_id, "sender_id": m.sender_id,
                        "body": m.body, "created_at": _iso(m.created_at),
                        "trust": "untrusted_data"})
            if len(out) >= limit:
                break
        return {"messages": out}

    # -- jobs ---------------------------------------------------------------

    def _get_job(self, sess: Session, org_id: str, job_id: Any, *,
                 for_update: bool = False) -> Job:
        if not isinstance(job_id, str) or not job_id or len(job_id) > 64:
            raise ServiceError("invalid_argument", "'job_id' must be a bounded string")
        stmt = select(Job).where(Job.id == job_id, Job.org_id == org_id)
        if for_update:
            stmt = stmt.with_for_update()
        job = sess.execute(stmt).scalar_one_or_none()
        if job is None:
            raise ServiceError("not_found", "job not found in this organisation")
        return job

    @staticmethod
    def _job_public(job: Job) -> dict:
        """Public job view — the claim token digest is never exposed anywhere."""
        return {"job_id": job.id, "scope_id": job.scope_id, "creator_id": job.creator_id,
                "assignee_id": job.assignee_id, "objective": job.objective,
                "status": job.status, "quarantined": job.quarantined,
                "attempts": job.attempts, "lease_expires_at": _iso(job.lease_expires_at),
                "created_at": _iso(job.created_at), "updated_at": _iso(job.updated_at)}

    def _op_job_create(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, {"scope_id", "assignee_id", "objective", "idempotency_key"})
        scope = self._get_scope(sess, dbp.org_id, args.get("scope_id"))
        self._require_role(sess, dbp, scope, "writer")
        objective = _str_arg(args, "objective", max_len=MAX_OBJECTIVE)
        idem = _str_arg(args, "idempotency_key", max_len=MAX_IDEMPOTENCY)
        aid = _str_arg(args, "assignee_id", max_len=64)
        assignee = sess.execute(
            select(PrincipalRow).where(PrincipalRow.id == aid,
                                       PrincipalRow.org_id == dbp.org_id,
                                       PrincipalRow.active.is_(True))
        ).scalar_one_or_none()
        if assignee is None:
            raise ServiceError("not_found", "assignee not found in this organisation")
        role = self._role_for(sess, assignee, scope)
        if role is None or _ROLE_RANK[role] < _ROLE_RANK["writer"]:
            raise ServiceError("denied", "assignee lacks writer access to this scope")
        existing = sess.execute(
            select(Job).where(Job.creator_id == dbp.id, Job.scope_id == scope.id,
                              Job.idempotency_key == idem)
        ).scalar_one_or_none()
        if existing is not None:
            if existing.objective == objective and existing.assignee_id == aid:
                return {"job_id": existing.id, "status": existing.status,
                        "quarantined": existing.quarantined, "idempotent_replay": True}
            raise ServiceError("idempotency_conflict",
                               "idempotency key reused with a different payload")
        findings = security.scan_payload({"objective": objective, "idempotency_key": idem})
        self.billing.charge_storage(sess, dbp.org_id, len(objective.encode("utf-8")) + len(json.dumps(findings).encode("utf-8")))
        job = Job(id=_new_id(), org_id=dbp.org_id, scope_id=scope.id, creator_id=dbp.id,
                  assignee_id=assignee.id, objective=objective, idempotency_key=idem,
                  status="quarantined" if findings else "queued",
                  quarantined=bool(findings), findings=json.dumps(findings))
        sess.add(job)
        self._audit(sess, dbp.org_id, dbp.id, "job_create",
                    record_id=job.id, scope_id=scope.id)
        return {"job_id": job.id, "status": job.status, "quarantined": job.quarantined,
                "idempotent_replay": False}

    def _op_job_list(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, {"scope_id", "limit"})
        scope = self._get_scope(sess, dbp.org_id, args.get("scope_id"))
        self._require_role(sess, dbp, scope, "reader")
        limit = _int_arg(args, "limit", default=20, lo=1, hi=100)
        rows = sess.execute(
            select(Job).where(Job.org_id == dbp.org_id, Job.scope_id == scope.id)
            .order_by(Job.created_at.desc()).limit(limit)
        ).scalars().all()
        return {"jobs": [self._job_public(j) for j in rows]}

    def _op_job_claim(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, {"job_id", "lease_seconds"})
        lease = _int_arg(args, "lease_seconds", default=JOB_DEFAULT_LEASE,
                         lo=JOB_MIN_LEASE, hi=JOB_MAX_LEASE)
        job = self._get_job(sess, dbp.org_id, args.get("job_id"), for_update=True)
        if job.assignee_id != dbp.id:
            raise ServiceError("denied", "only the assignee may claim this job")
        # The assignee's writer grant must still be current at claim time.
        self._require_role(sess, dbp, self._get_scope(sess, dbp.org_id, job.scope_id),
                           "writer")
        now = _now()
        expired_claim = job.status == "claimed" and (job.lease_expires_at is None
                                                    or job.lease_expires_at < now)
        if not (job.status == "queued" or expired_claim):
            raise ServiceError("invalid_state", f"job is not claimable (status '{job.status}')")
        if job.attempts >= JOB_MAX_ATTEMPTS:
            raise ServiceError("attempts_exhausted",
                               f"job already claimed {JOB_MAX_ATTEMPTS} times")
        claim_token = secrets.token_urlsafe(32)
        # Conditional update fenced on the attempt counter: under concurrency exactly one
        # claimer advances attempts, the loser's rowcount is 0. Reclaiming an expired lease
        # rotates the token, invalidating the previous holder.
        fence = job.attempts
        result = sess.execute(
            update(Job)
            .where(Job.id == job.id, Job.org_id == dbp.org_id, Job.attempts == fence,
                   or_(Job.status == "queued",
                       (Job.status == "claimed") & (Job.lease_expires_at < now)))
            .values(status="claimed", claim_token_digest=_digest(claim_token),
                    lease_expires_at=now + timedelta(seconds=lease),
                    attempts=fence + 1, updated_at=now)
        )
        if result.rowcount != 1:
            raise ServiceError("conflict", "job was claimed concurrently")
        self._audit(sess, dbp.org_id, dbp.id, "job_claim",
                    record_id=job.id, scope_id=job.scope_id)
        return {"job_id": job.id, "claim_token": claim_token, "attempts": fence + 1,
                "lease_expires_at": _iso(now + timedelta(seconds=lease))}

    def _job_fenced(self, sess: Session, dbp: PrincipalRow, args: dict) -> Job:
        """Shared lease fencing for renew/submit: assignee identity, CURRENT writer grant,
        claimed status, live lease, token match."""
        claim_token = _str_arg(args, "claim_token", max_len=512)
        job = self._get_job(sess, dbp.org_id, args.get("job_id"), for_update=True)
        if job.assignee_id != dbp.id:
            raise ServiceError("denied", "only the assignee may act on this claim")
        self._require_role(sess, dbp, self._get_scope(sess, dbp.org_id, job.scope_id),
                           "writer")
        if job.status != "claimed":
            raise ServiceError("invalid_state", f"job is not claimed (status '{job.status}')")
        if job.lease_expires_at is None or job.lease_expires_at < _now():
            raise ServiceError("lease_expired", "the claim lease has expired")
        if (job.claim_token_digest is None
                or not hmac.compare_digest(job.claim_token_digest, _digest(claim_token))):
            raise ServiceError("denied", "claim token does not match the current claim")
        return job

    def _op_job_renew(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, {"job_id", "claim_token", "lease_seconds"})
        lease = _int_arg(args, "lease_seconds", default=JOB_DEFAULT_LEASE,
                         lo=JOB_MIN_LEASE, hi=JOB_MAX_LEASE)
        job = self._job_fenced(sess, dbp, args)  # includes the current writer-grant check
        now = _now()
        job.lease_expires_at = now + timedelta(seconds=lease)
        job.updated_at = now
        return {"job_id": job.id, "lease_expires_at": _iso(job.lease_expires_at)}

    def _op_job_submit(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, {"job_id", "claim_token", "result"})
        if "result" not in args:
            raise ServiceError("invalid_argument", "'result' is required")
        try:
            result_json = json.dumps(args["result"])
        except (TypeError, ValueError) as exc:
            raise ServiceError("invalid_argument", "'result' must be JSON-serialisable") from exc
        if len(result_json) > MAX_RESULT_JSON:
            raise ServiceError("invalid_argument",
                               f"'result' exceeds {MAX_RESULT_JSON} JSON characters")
        job = self._job_fenced(sess, dbp, args)
        findings = security.scan_payload(args["result"])
        self.billing.charge_storage(sess, dbp.org_id, len(result_json.encode("utf-8")) + max(0, len(json.dumps(findings).encode("utf-8")) - len(job.findings.encode("utf-8"))))
        job.result = result_json
        job.findings = json.dumps(findings)
        job.quarantined = bool(findings)
        job.status = "quarantined" if findings else "awaiting_review"
        job.updated_at = _now()
        self._audit(sess, dbp.org_id, dbp.id, "job_submit",
                    record_id=job.id, scope_id=job.scope_id)
        return {"job_id": job.id, "status": job.status, "quarantined": job.quarantined}

    def _op_job_review(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, {"job_id", "accept"})
        accept = _bool_arg(args, "accept")
        job = self._get_job(sess, dbp.org_id, args.get("job_id"), for_update=True)
        if job.assignee_id == dbp.id:
            raise ServiceError("denied", "the assignee can never review its own job")
        scope = self._get_scope(sess, dbp.org_id, job.scope_id)
        role = self._role_for(sess, dbp, scope)
        creator_ok = (job.creator_id == dbp.id and role is not None
                      and _ROLE_RANK[role] >= _ROLE_RANK["writer"])
        reviewer_ok = role is not None and _ROLE_RANK[role] >= _ROLE_RANK["reviewer"]
        if not (creator_ok or reviewer_ok):
            raise ServiceError("denied", "requires the creator (writer) or a scope reviewer")
        if job.status not in ("awaiting_review", "quarantined"):
            raise ServiceError("invalid_state", f"job is not reviewable (status '{job.status}')")
        if accept and job.quarantined:
            raise ServiceError("quarantined", "quarantined results cannot be accepted")
        job.status = "completed" if accept else "failed"
        job.claim_token_digest = None
        job.lease_expires_at = None
        job.updated_at = _now()
        self._audit(sess, dbp.org_id, dbp.id,
                    "job_review_accept" if accept else "job_review_reject",
                    record_id=job.id, scope_id=job.scope_id)
        return {"job_id": job.id, "status": job.status}

    def _op_job_cancel(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, {"job_id"})
        job = self._get_job(sess, dbp.org_id, args.get("job_id"), for_update=True)
        scope = self._get_scope(sess, dbp.org_id, job.scope_id)
        role = self._role_for(sess, dbp, scope)
        reviewer_ok = role is not None and _ROLE_RANK[role] >= _ROLE_RANK["reviewer"]
        if not (job.creator_id == dbp.id or reviewer_ok):
            raise ServiceError("denied", "only the creator or a scope reviewer may cancel")
        if job.status in ("completed", "failed", "cancelled"):
            raise ServiceError("invalid_state",
                               f"cannot cancel a terminal job (status '{job.status}')")
        job.status = "cancelled"
        job.claim_token_digest = None  # invalidates the outstanding lease
        job.lease_expires_at = None
        job.updated_at = _now()
        self._audit(sess, dbp.org_id, dbp.id, "job_cancel",
                    record_id=job.id, scope_id=job.scope_id)
        return {"job_id": job.id, "status": "cancelled",
                "note": "cancellation is cooperative; remote execution is not forcibly stopped"}

    # -- audit ---------------------------------------------------------------

    def _op_audit_list(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        _check_keys(args, {"scope_id", "limit"})
        scope = self._get_scope(sess, dbp.org_id, args.get("scope_id"))
        self._require_role(sess, dbp, scope, "admin")
        limit = _int_arg(args, "limit", default=20, lo=1, hi=100)
        rows = sess.execute(
            select(AuditLog).where(AuditLog.org_id == dbp.org_id,
                                   AuditLog.scope_id == scope.id)
            .order_by(AuditLog.at.desc()).limit(limit)
        ).scalars().all()
        return {"entries": [
            {"actor_id": e.actor_id, "action": e.action, "record_id": e.record_id,
             "scope_id": e.scope_id, "at": _iso(e.at)}
            for e in rows
        ]}

    # -- billing / connections (logic lives in distributedai.billing) --------

    def _op_instance_create(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        return self.billing.op_instance_create(sess, dbp, args)

    def _op_instance_list(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        return self.billing.op_instance_list(sess, dbp, args)

    def _op_connection_issue(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        return self.billing.op_connection_issue(sess, dbp, args)

    def _op_connection_revoke(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        return self.billing.op_connection_revoke(sess, dbp, args)

    def _op_connection_list(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        return self.billing.op_connection_list(sess, dbp, args)

    def _op_billing_status(self, sess: Session, dbp: PrincipalRow, args: dict) -> dict:
        return self.billing.op_billing_status(sess, dbp, args)

    def authenticate_connection(self, credential: str):
        """Authenticate an individually issued connection credential (the MCP/HTTP transport
        hook for AI-client traffic). Returns a billing.ConnectionAuth or None."""
        with Session(self._engine) as sess:
            return self.billing.authenticate_connection(sess, credential)

    def resolve_connection(self, connection_id: str):
        with Session(self._engine) as sess:
            return self.billing.resolve_connection(sess, connection_id)

    def billing_webhook(self, provider_name: str, headers: dict, body: bytes) -> dict:
        """Verify and apply one payment-provider webhook (root wires the HTTP route).
        Provider verification (which may call the provider's trusted API) happens before
        the database transaction opens."""
        provider = self.billing.provider(provider_name)
        event_data = provider.verify_and_parse(headers, body)
        with Session(self._engine) as sess, sess.begin():
            return self.billing.process_event(sess, event_data)

    def assign_plan(self, org_id: str, plan: str) -> dict:
        """OFFLINE trusted billing authority only (operator CLI / platform billing service);
        never reachable through dispatch or any tenant surface."""
        with Session(self._engine) as sess, sess.begin():
            return self.billing.assign_plan(sess, org_id, plan)

    def register_billing_subscription(self, org_id: str, provider: str, customer_id: str,
                                      subscription_id: str, plan: str | None = None) -> dict:
        """OFFLINE/server-side binding of a provider subscription to an organisation."""
        with Session(self._engine) as sess, sess.begin():
            return self.billing.register_subscription(sess, org_id, provider,
                                                      customer_id, subscription_id, plan)

    def recalculate_storage(self, org_id: str) -> dict:
        """Rebuild the org's storage counter from stored rows (offline reconciliation)."""
        with Session(self._engine) as sess, sess.begin():
            return self.billing.recompute_usage(sess, org_id)
