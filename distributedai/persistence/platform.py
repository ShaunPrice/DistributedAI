# SPDX-License-Identifier: AGPL-3.0-only
"""SQL platform repository: metadata-only queries and transactional operational audit."""
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Integer, MetaData, String, Table, func, select
from sqlalchemy.orm import Session

from ..store import Org, PrincipalRow, Scope

metadata = MetaData()
accounts = Table("platform_accounts", metadata,
                 Column("org_id", String(32), primary_key=True),
                 Column("suspended", Boolean, nullable=False),
                 Column("updated_at", DateTime, nullable=False))
audit = Table("platform_audit", metadata,
              Column("id", Integer, primary_key=True, autoincrement=True),
              Column("org_id", String(32), nullable=False),
              Column("suspended", Boolean, nullable=False),
              Column("created_at", DateTime, nullable=False))
plan_audit = Table("platform_plan_audit", metadata,
                  Column("id", Integer, primary_key=True, autoincrement=True),
                  Column("org_id", String(32), nullable=False),
                  Column("plan", String(50), nullable=False),
                  Column("created_at", DateTime, nullable=False))


class SQLPlatformRepository:
    def __init__(self, engine):
        self.engine = engine

    def initialize(self):
        metadata.create_all(self.engine)
        from .sessions import metadata as session_metadata
        session_metadata.create_all(self.engine)

    def is_active(self, org_id):
        with self.engine.connect() as conn:
            return not bool(conn.scalar(select(accounts.c.suspended).where(accounts.c.org_id == org_id)))

    def account_rows(self, include_billing):
        people = select(func.count()).where(PrincipalRow.org_id == Org.id).correlate(Org).scalar_subquery()
        scopes = select(func.count()).where(Scope.org_id == Org.id).correlate(Org).scalar_subquery()
        statement = select(Org.id, Org.created_at, people.label("principal_count"), scopes.label("scope_count"),
                           accounts.c.suspended).outerjoin(accounts, accounts.c.org_id == Org.id)
        if include_billing:
            from ..billing import BillingAccount
            table = BillingAccount.__table__
            statement = statement.add_columns(table.c.plan, table.c.status, table.c.needs_reconciliation).outerjoin(
                table, table.c.org_id == Org.id)
        with self.engine.connect() as conn:
            return [dict(row) for row in conn.execute(statement.order_by(Org.id).limit(1001)).mappings()]

    def assign_plan(self, org_id, plan, billing):
        with Session(self.engine) as sess, sess.begin():
            if sess.execute(select(Org.id).where(Org.id == org_id).with_for_update()).scalar_one_or_none() is None:
                raise LookupError("Account not found")
            billing.assign_plan(sess, org_id, plan)
            sess.execute(plan_audit.insert().values(org_id=org_id, plan=plan,
                         created_at=datetime.now(timezone.utc).replace(tzinfo=None)))

    def set_suspended(self, org_id, suspended):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        with self.engine.begin() as conn:
            if conn.scalar(select(Org.id).where(Org.id == org_id)) is None:
                raise LookupError("Account not found")
            if self.engine.dialect.name == "postgresql":
                from sqlalchemy.dialects.postgresql import insert
            elif self.engine.dialect.name == "sqlite":
                from sqlalchemy.dialects.sqlite import insert
            else:
                raise RuntimeError("Unsupported database")
            statement = insert(accounts).values(org_id=org_id, suspended=suspended, updated_at=now)
            conn.execute(statement.on_conflict_do_update(index_elements=[accounts.c.org_id],
                                                        set_={"suspended": suspended, "updated_at": now}))
            conn.execute(audit.insert().values(org_id=org_id, suspended=suspended, created_at=now))


def build_platform_service(engine):
    """Legacy construction helper; new composition roots should inject the repository."""
    from ..application.platform import PlatformService
    from ..application.sessions import BrowserSessions
    from .sessions import SQLBrowserSessions
    service = PlatformService(SQLPlatformRepository(engine))
    service.sessions = BrowserSessions(SQLBrowserSessions(engine), purpose="platform")
    return service
