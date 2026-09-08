# SPDX-License-Identifier: AGPL-3.0-only
"""Encrypted support-ticket SQL adapter. Stored credentials and memories are never queried."""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import uuid

from sqlalchemy import Column, DateTime, Integer, MetaData, String, Table, Text, UniqueConstraint, func, select, update

from ..domain import ServiceError
from .workspace import Org, PrincipalRow

metadata = MetaData()
configuration = Table("support_configuration", metadata,
    Column("scope_id", String(64), primary_key=True),
    Column("external_url", Text, nullable=False),
    Column("principal_ids", Text, nullable=False),
    Column("version", Integer, nullable=False, default=1))
tickets = Table("support_tickets", metadata,
    Column("id", String(32), primary_key=True),
    Column("org_id", String(32), nullable=False, index=True),
    Column("reporter_id", String(32), nullable=False, index=True),
    Column("queue", String(20), nullable=False, index=True),
    Column("subject", Text, nullable=False), Column("body", Text, nullable=False),
    Column("page", Text, nullable=False),
    Column("idempotency_digest", String(64), nullable=False),
    Column("request_digest", Text, nullable=False),
    Column("status", String(20), nullable=False),
    Column("assigned_to", String(32), nullable=True),
    Column("payload_bytes", Integer, nullable=False),
    Column("created_at", DateTime, nullable=False),
    UniqueConstraint("org_id", "reporter_id", "idempotency_digest"))
replies = Table("support_replies", metadata,
    Column("id", String(32), primary_key=True),
    Column("ticket_id", String(32), nullable=False, index=True),
    Column("org_id", String(32), nullable=False, index=True),
    Column("author_id", String(32), nullable=False),
    Column("body", Text, nullable=False),
    Column("payload_bytes", Integer, nullable=False),
    Column("created_at", DateTime, nullable=False))
audit = Table("support_audit", metadata,
    Column("id", String(32), primary_key=True), Column("org_id", String(64), nullable=False),
    Column("actor_id", String(64), nullable=False), Column("ticket_id", String(32)),
    Column("action", String(40), nullable=False), Column("created_at", DateTime, nullable=False))
GLOBAL_SCOPE = "solution-support"
MAX_OPEN = 100
MAX_TICKETS = 1000
MAX_REPLIES = 100
MAX_BYTES = 10 * 1024 * 1024
META_FIELDS = (tickets.c.id, tickets.c.org_id, tickets.c.reporter_id, tickets.c.queue,
               tickets.c.status, tickets.c.assigned_to, tickets.c.created_at)


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _json_row(row):
    return {key: value.isoformat() + "Z" if isinstance(value, datetime) else value for key, value in dict(row).items()}


class SQLSupportRepository:
    def __init__(self, engine, crypto):
        if engine.dialect.name not in {"sqlite", "postgresql"}:
            raise ValueError("Unsupported support database")
        self._engine, self._crypto = engine, crypto

    @contextmanager
    def _transaction(self, org_id=None):
        with self._engine.connect() as conn:
            try:
                if self._engine.dialect.name == "sqlite":
                    conn.exec_driver_sql("BEGIN IMMEDIATE")
                else:
                    conn.begin()
                if org_id:
                    found = conn.execute(select(Org.id).where(Org.id == org_id).with_for_update()).first()
                    if found is None:
                        raise ServiceError("not_found", "Organisation unavailable")
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    @staticmethod
    def _actor(conn, actor_id):
        row = conn.execute(select(PrincipalRow.id, PrincipalRow.org_id, PrincipalRow.active,
            PrincipalRow.is_org_admin).where(PrincipalRow.id == actor_id).with_for_update()).mappings().first()
        if not row or not row["active"]:
            raise ServiceError("denied", "Ticket unavailable")
        return row

    @staticmethod
    def _audit(conn, org_id, actor_id, action, ticket_id=None):
        conn.execute(audit.insert().values(id=uuid.uuid4().hex, org_id=org_id,
            actor_id=actor_id, action=action, ticket_id=ticket_id, created_at=_now()))

    def _handler(self, conn, actor, ticket, defaults):
        scope = GLOBAL_SCOPE if ticket["queue"] == "solution" else ticket["org_id"]
        cfg = conn.execute(select(configuration.c.principal_ids).where(
            configuration.c.scope_id == scope).with_for_update()).scalar_one_or_none()
        ids = json.loads(cfg) if cfg is not None else list(defaults) if scope == GLOBAL_SCOPE else []
        if scope == GLOBAL_SCOPE:
            return actor["id"] in ids
        return actor["org_id"] == ticket["org_id"] and (actor["is_org_admin"] or actor["id"] in ids)

    def _authorized(self, conn, ticket_id, actor_id, defaults, handler=False):
        actor = self._actor(conn, actor_id)
        ticket = conn.execute(select(tickets).where(tickets.c.id == ticket_id).with_for_update()).mappings().first()
        if not ticket or not ((not handler and ticket["reporter_id"] == actor_id) or
                              self._handler(conn, actor, ticket, defaults)):
            raise ServiceError("denied", "Ticket unavailable")
        return ticket

    def configuration(self, org_id):
        with self._engine.connect() as conn:
            row = conn.execute(select(configuration).where(configuration.c.scope_id == org_id)).mappings().first()
        return {"external_url": row["external_url"] if row else "",
                "support_principal_ids": json.loads(row["principal_ids"]) if row else [],
                "version": row["version"] if row else 0, "configured": row is not None}

    def configure(self, org_id, external_url, principal_ids, *, actor_id=None):
        if self._engine.dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import insert
        else:
            from sqlalchemy.dialects.sqlite import insert
        values = {"external_url": external_url, "principal_ids": json.dumps(principal_ids)}
        query = insert(configuration).values(scope_id=org_id, version=1, **values)
        with self._transaction(None if org_id == GLOBAL_SCOPE else org_id) as conn:
            if org_id != GLOBAL_SCOPE:
                actor = self._actor(conn, actor_id)
                if actor["org_id"] != org_id or not actor["is_org_admin"]:
                    raise ServiceError("denied", "Organisation administrator required")
            for pid in sorted(principal_ids):
                candidate = self._actor(conn, pid)
                if org_id != GLOBAL_SCOPE and candidate["org_id"] != org_id:
                    raise ServiceError("denied", "Invalid support identity")
            self._audit(conn, org_id, actor_id or "platform", "configure")
            conn.execute(query.on_conflict_do_update(index_elements=[configuration.c.scope_id],
                set_={**values, "version": configuration.c.version + 1}))

    def solution_configuration(self):
        return self.configuration(GLOBAL_SCOPE)

    def configure_solution(self, external_url, principal_ids):
        self.configure(GLOBAL_SCOPE, external_url, principal_ids)

    def candidates(self, org_id, principal_ids=None, admins_only=False):
        query = select(PrincipalRow.id).where(PrincipalRow.org_id == org_id, PrincipalRow.active.is_(True))
        if principal_ids is not None:
            query = query.where(PrincipalRow.id.in_(principal_ids))
        if admins_only:
            query = query.where(PrincipalRow.is_org_admin.is_(True))
        with self._engine.connect() as conn:
            return list(conn.execute(query.limit(100)).scalars())

    def list_metadata(self, org_id=None, reporter_id=None, queue=None):
        query = select(*META_FIELDS)
        if org_id is not None:
            query = query.where(tickets.c.org_id == org_id)
        if reporter_id is not None:
            query = query.where(tickets.c.reporter_id == reporter_id)
        if queue is not None:
            query = query.where(tickets.c.queue == queue)
        with self._engine.connect() as conn:
            return [_json_row(row) for row in conn.execute(query.order_by(tickets.c.created_at.desc(), tickets.c.id.desc()).limit(101)).mappings()]

    def ticket_metadata(self, ticket_id):
        with self._engine.connect() as conn:
            row = conn.execute(select(*META_FIELDS).where(tickets.c.id == ticket_id)).mappings().first()
        return _json_row(row) if row else None

    @staticmethod
    def _quota(conn, org_id, added):
        total = sum(conn.scalar(select(func.coalesce(func.sum(table.c.payload_bytes), 0)).where(table.c.org_id == org_id))
                    for table in (tickets, replies))
        if total + added > MAX_BYTES:
            raise ServiceError("quota_exceeded", "Support storage limit reached")

    def create(self, org_id, reporter_id, queue, subject, body, page, idempotency_key):
        self._crypto.provision(org_id)
        idem = hashlib.sha256(idempotency_key.encode()).hexdigest()
        request_digest = hashlib.sha256(json.dumps([queue, subject, body, page], separators=(",", ":")).encode()).hexdigest()
        amount = sum(len(value.encode()) for value in (subject, body, page))
        with self._transaction(org_id) as conn:
            actor = self._actor(conn, reporter_id)
            if actor["org_id"] != org_id or queue != ("solution" if actor["is_org_admin"] else "organisation"):
                raise ServiceError("denied", "Ticket unavailable")
            prior = conn.execute(select(tickets.c.id, tickets.c.queue, tickets.c.request_digest).where(
                tickets.c.org_id == org_id, tickets.c.reporter_id == reporter_id,
                tickets.c.idempotency_digest == idem)).mappings().first()
            if prior:
                if self._crypto.decrypt(org_id, prior["id"], "support_tickets.request_digest", prior["request_digest"]) != request_digest:
                    raise ServiceError("conflict", "Idempotency key already used for different content")
                return {"ticket_id": prior["id"], "created": False, "duplicate": True, "queue": prior["queue"]}
            count = conn.scalar(select(func.count()).select_from(tickets).where(tickets.c.org_id == org_id))
            opened = conn.scalar(select(func.count()).select_from(tickets).where(tickets.c.org_id == org_id, tickets.c.status == "open"))
            if count >= MAX_TICKETS or opened >= MAX_OPEN:
                raise ServiceError("quota_exceeded", "Support ticket limit reached")
            self._quota(conn, org_id, amount)
            tid = uuid.uuid4().hex
            encrypted = {name: self._crypto.encrypt(org_id, tid, "support_tickets." + name, value)
                         for name, value in {"subject": subject, "body": body, "page": page}.items()}
            conn.execute(tickets.insert().values(id=tid, org_id=org_id, reporter_id=reporter_id, queue=queue,
                **encrypted, idempotency_digest=idem, request_digest=self._crypto.encrypt(org_id, tid, "support_tickets.request_digest", request_digest), status="open",
                payload_bytes=amount, created_at=_now()))
            self._audit(conn, org_id, reporter_id, "create", tid)
        return {"ticket_id": tid, "created": True, "queue": queue, "assigned_to": None}

    def subject(self, ticket_id, *, actor_id, solution_principals=()):
        with self._transaction() as conn:
            row = self._authorized(conn, ticket_id, actor_id, solution_principals)
        return self._crypto.decrypt(row["org_id"], ticket_id, "support_tickets.subject", row["subject"])

    def get(self, ticket_id, *, actor_id, solution_principals=()):
        with self._transaction() as conn:
            row = self._authorized(conn, ticket_id, actor_id, solution_principals)
            messages = conn.execute(select(replies).where(replies.c.ticket_id == ticket_id).order_by(replies.c.created_at, replies.c.id)).mappings().all()
        result = {**{key: value for key, value in _json_row(row).items()
                     if key not in {"idempotency_digest", "request_digest", "payload_bytes"}}}
        for field in ("subject", "body", "page"):
            result[field] = self._crypto.decrypt(row["org_id"], ticket_id, "support_tickets." + field, row[field])
        result["replies"] = [{"id": reply["id"], "author_id": reply["author_id"],
            "body": self._crypto.decrypt(row["org_id"], reply["id"], "support_replies.body", reply["body"]),
            "created_at": reply["created_at"].isoformat() + "Z"} for reply in messages]
        return result

    def reply(self, ticket_id, actor_id, body, status=None, *, solution_principals=()):
        ticket = self.ticket_metadata(ticket_id)
        if not ticket:
            raise ServiceError("denied", "Ticket unavailable")
        org_id = ticket["org_id"]
        amount = len(body.encode())
        with self._transaction(org_id) as conn:
            row = self._authorized(conn, ticket_id, actor_id, solution_principals)
            if conn.scalar(select(func.count()).select_from(replies).where(replies.c.ticket_id == ticket_id)) >= MAX_REPLIES:
                raise ServiceError("quota_exceeded", "Ticket reply limit reached")
            if status == "open" and row["status"] == "closed":
                if conn.scalar(select(func.count()).select_from(tickets).where(tickets.c.org_id == org_id, tickets.c.status == "open")) >= MAX_OPEN:
                    raise ServiceError("quota_exceeded", "Open ticket limit reached")
            self._quota(conn, org_id, amount)
            rid = uuid.uuid4().hex
            conn.execute(replies.insert().values(id=rid, org_id=org_id, ticket_id=ticket_id,
                author_id=actor_id, body=self._crypto.encrypt(org_id, rid, "support_replies.body", body),
                payload_bytes=amount, created_at=_now()))
            if status is not None:
                conn.execute(update(tickets).where(tickets.c.id == ticket_id).values(status=status))
            self._audit(conn, org_id, actor_id, "reply", ticket_id)
        return {"ticket_id": ticket_id, "reply_id": rid, "status": status or row["status"]}

    def assign(self, ticket_id, principal_id, *, actor_id, solution_principals=()):
        ticket = self.ticket_metadata(ticket_id)
        if not ticket:
            raise ServiceError("denied", "Ticket unavailable")
        with self._transaction(ticket["org_id"]) as conn:
            for pid in sorted({actor_id, principal_id}):
                self._actor(conn, pid)
            row = self._authorized(conn, ticket_id, actor_id, solution_principals, handler=True)
            if not self._handler(conn, self._actor(conn, principal_id), row, solution_principals):
                raise ServiceError("denied", "Invalid support assignee")
            self._audit(conn, ticket["org_id"], actor_id, "assign", ticket_id)
            conn.execute(update(tickets).where(tickets.c.id == ticket_id).values(assigned_to=principal_id))
        return {"ticket_id": ticket_id, "assigned_to": principal_id}
