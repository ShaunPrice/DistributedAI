# SPDX-License-Identifier: AGPL-3.0-only
"""Content-blind platform operations; deliberately separate from tenant authorisation."""
import asyncio
import base64
import copy
from dataclasses import asdict
import hashlib
import hmac
import json
import time
from types import SimpleNamespace
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import Boolean, Column, DateTime, Integer, MetaData, String, Table, func, select
from sqlalchemy.orm import Session
from starlette.applications import Starlette
from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Route

from .management import BrowserHeaders
from .oidc import CloudLogin
from .session_crypto import SessionCipher
from .store import Org, PrincipalRow, Scope, ServiceError

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
COOKIE = "da_platform"
TTL = 900
STATIC = Path(__file__).parent / "static"


class PlatformService:
    """Use this service's is_active check in every tenant authentication/dispatch path.

    No names, content, project codes, credentials, key material or tenant audit entries
    are selected. This is an application-role boundary, not host administrator isolation.
    """

    def __init__(self, engine):
        self.engine = engine
        self.billing = None

    def initialize(self):
        metadata.create_all(self.engine)

    def is_active(self, org_id):
        with self.engine.connect() as conn:
            return not bool(conn.scalar(select(accounts.c.suspended).where(accounts.c.org_id == org_id)))

    def list_accounts(self):
        people = select(func.count()).where(PrincipalRow.org_id == Org.id).correlate(Org).scalar_subquery()
        scopes = select(func.count()).where(Scope.org_id == Org.id).correlate(Org).scalar_subquery()
        statement = select(Org.id, Org.created_at, people.label("principal_count"), scopes.label("scope_count"),
                           accounts.c.suspended).outerjoin(accounts, accounts.c.org_id == Org.id)
        enabled = bool(self.billing and self.billing.enabled)
        if enabled:
            from .billing import BillingAccount
            table = BillingAccount.__table__
            statement = statement.add_columns(table.c.plan, table.c.status, table.c.needs_reconciliation).outerjoin(
                table, table.c.org_id == Org.id)
        with self.engine.connect() as conn:
            rows = conn.execute(statement.order_by(Org.id).limit(1001)).mappings().all()
        result = []
        for row in rows[:1000]:
            account = {"account_id": row["id"], "created_at": row["created_at"].isoformat() + "Z",
                       "principal_count": row["principal_count"], "scope_count": row["scope_count"],
                       "suspended": bool(row["suspended"])}
            if enabled:
                active = row["status"] == "active" and not row["needs_reconciliation"]
                account.update(plan=row["plan"] if active and row["plan"] in self.billing.plans else self.billing.default_plan,
                               billing_status=row["status"] or "unregistered",
                               needs_reconciliation=bool(row["needs_reconciliation"]))
            result.append(account)
        return {"accounts": result, "truncated": len(rows) > 1000, "billing_enabled": enabled,
                "plans": {name: asdict(limits) for name, limits in self.billing.plans.items()} if enabled else {}}

    def set_plan(self, org_id, plan):
        if not self.billing or not self.billing.enabled:
            raise ValueError("Billing is disabled")
        if not isinstance(org_id, str) or len(org_id) != 32 or not isinstance(plan, str) or plan not in self.billing.plans:
            raise ValueError("Invalid account plan")
        with Session(self.engine) as sess, sess.begin():
            if sess.execute(select(Org.id).where(Org.id == org_id).with_for_update()).scalar_one_or_none() is None:
                raise LookupError("Account not found")
            self.billing.assign_plan(sess, org_id, plan)
            sess.execute(plan_audit.insert().values(org_id=org_id, plan=plan,
                         created_at=datetime.now(timezone.utc).replace(tzinfo=None)))
        return {"account_id": org_id, "plan": plan}

    def set_suspended(self, org_id, suspended):
        if not isinstance(org_id, str) or len(org_id) != 32 or type(suspended) is not bool:
            raise ValueError("Invalid account operation")
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
        return {"account_id": org_id, "suspended": suspended}


def platform_app(service, settings):
    token = getattr(settings, "platform_admin_token", "")
    mode = getattr(settings, "login_mode", "token")
    subjects = getattr(settings, "platform_subjects", [])
    if not isinstance(token, str) or (mode != "oidc" and len(token) < 48) or not settings.management_key:
        raise ValueError("Platform console requires a separate credential of at least 48 characters and MANAGEMENT_KEY")
    # Domain separation prevents even a valid management cookie from being used here.
    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                   info=b"distributedai/platform-session/v1").derive(base64.urlsafe_b64decode(settings.management_key))
    cipher = SessionCipher(base64.urlsafe_b64encode(derived), purpose=b"distributedai/platform-session/v1")
    credential_digest = hashlib.sha256(token.encode()).hexdigest()
    cloud_settings = copy.copy(settings)
    cloud_settings.login_mode = mode
    cloud_settings.login_subjects = {subject: "platform-administrator" for subject in subjects}
    class PlatformIdentity:
        def resolve_principal(self, principal_id):
            return SimpleNamespace(id="platform-administrator") if principal_id == "platform-administrator" else None
    cloud = CloudLogin(cloud_settings, cipher, PlatformIdentity(), base_path="/platform", session_cookie=COOKIE)
    url = urlparse(settings.public_url)
    origin = f"{url.scheme}://{url.netloc}"

    def csrf(request):
        return request.headers.get("origin") == origin and request.headers.get("content-type", "").split(";")[0] == "application/json"

    def identity(request):
        try:
            cookie = request.cookies.get(COOKIE, "")
            if len(cookie) > 4096:
                return False
            session = json.loads(cipher.decrypt(cookie.encode(), ttl=TTL))
            if session.get("kind") == "oidc":
                return (mode != "token" and session.get("sub") in getattr(settings, "platform_subjects", [])
                        and session.get("issuer") == settings.login_issuer
                        and session.get("principal_id") == "platform-administrator"
                        and session.get("expires", 0) > time.time())
            return mode != "oidc" and session == {"purpose": "platform", "credential": credential_digest}
        except (InvalidToken, ValueError, UnicodeError, TypeError):
            return False

    async def page(request):
        return FileResponse(STATIC / "platform.html")

    async def asset(request):
        name = request.path_params["name"]
        if name not in {"platform.js", "style.css"}:
            return JSONResponse({"error": "Not found"}, 404)
        return FileResponse(STATIC / name)

    async def login_options(request):
        return JSONResponse({"token": mode in {"token", "both"}, "oidc": mode in {"oidc", "both"},
                             "provider": getattr(settings, "login_provider", "Organisation")})

    async def login(request):
        if mode == "oidc":
            return JSONResponse({"error": "Use platform identity sign-in"}, 403)
        if not csrf(request):
            return JSONResponse({"error": "Request origin rejected"}, 403)
        try:
            data = await request.json()
            supplied = data.get("token", "")
            valid = isinstance(supplied, str) and len(supplied) <= 2048 and hmac.compare_digest(
                hashlib.sha256(supplied.encode()).hexdigest(), credential_digest)
        except (ValueError, TypeError, AttributeError):
            valid = False
        if not valid:
            return JSONResponse({"error": "Invalid platform credential"}, 401)
        response = JSONResponse({"authenticated": True})
        response.set_cookie(COOKIE, cipher.encrypt(json.dumps({"purpose": "platform", "credential": credential_digest}).encode()).decode(),
                            max_age=TTL, httponly=True, secure=url.scheme == "https", samesite="strict", path="/platform")
        return response

    async def logout(request):
        if not csrf(request):
            return JSONResponse({"error": "Request origin rejected"}, 403)
        response = JSONResponse({"authenticated": False})
        response.delete_cookie(COOKIE, path="/platform", secure=url.scheme == "https", httponly=True, samesite="strict")
        return response

    async def state(request):
        if not identity(request):
            return JSONResponse({"error": "Platform sign-in required"}, 401)
        result = await asyncio.to_thread(service.list_accounts)
        return JSONResponse({"status": "available", **result})

    async def update(request):
        if not csrf(request):
            return JSONResponse({"error": "Request origin rejected"}, 403)
        if not identity(request):
            return JSONResponse({"error": "Platform sign-in required"}, 401)
        try:
            data = await request.json()
            if not isinstance(data, dict) or set(data) != {"account_id", "suspended"}:
                raise ValueError("Only account_id and suspended are accepted")
            return JSONResponse(await asyncio.to_thread(service.set_suspended, data["account_id"], data["suspended"]))
        except (ValueError, TypeError):
            return JSONResponse({"error": "Invalid account operation"}, 400)
        except LookupError:
            return JSONResponse({"error": "Account not found"}, 404)

    async def assign_plan(request):
        if not csrf(request):
            return JSONResponse({"error": "Request origin rejected"}, 403)
        if not identity(request):
            return JSONResponse({"error": "Platform sign-in required"}, 401)
        try:
            body = await request.body()
            if len(body) > 4096:
                raise ValueError()
            data = json.loads(body)
            if not isinstance(data, dict) or set(data) != {"account_id", "plan"}:
                raise ValueError()
            return JSONResponse(await asyncio.to_thread(service.set_plan, data["account_id"], data["plan"]))
        except (ValueError, TypeError, ServiceError):
            return JSONResponse({"error": "Invalid account plan"}, 400)
        except LookupError:
            return JSONResponse({"error": "Account not found"}, 404)

    return BrowserHeaders(Starlette(routes=[Route("/", page), Route("/assets/{name}", asset),
        Route("/login", login, methods=["POST"]), Route("/logout", logout, methods=["POST"]),
        Route("/login-options", login_options), Route("/oidc/start", cloud.start), Route("/oidc/callback", cloud.finish),
        Route("/state", state), Route("/accounts", update, methods=["POST"]),
        Route("/accounts/plan", assign_plan, methods=["POST"])]))
