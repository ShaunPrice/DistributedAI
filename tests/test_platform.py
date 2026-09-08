# SPDX-License-Identifier: Apache-2.0
"""The platform role cannot read content or reuse tenant credentials/sessions."""
from types import SimpleNamespace

from cryptography.fernet import Fernet
import httpx
import pytest
from sqlalchemy import select
from starlette.applications import Starlette
from starlette.routing import Mount

from distributedai.platform import PlatformService, audit, platform_app
from distributedai.store import Store

TOKEN = "platform-secret-fixture-" * 4
TENANT = "tenant-secret-fixture-" * 4
ORIGIN = "https://memory.example"


@pytest.fixture
def platform(tmp_path):
    store = Store(f"sqlite:///{tmp_path / 'platform.db'}")
    store.initialize()
    boot = store.bootstrap("PRIVATE-ORG-NAME", "PRIVATE-USER-NAME", TENANT)
    service = PlatformService(store._engine)
    service.initialize()
    settings = SimpleNamespace(platform_admin_token=TOKEN, management_key=Fernet.generate_key().decode(),
                               public_url=ORIGIN + "/mcp")
    app = Starlette(routes=[Mount("/platform", app=platform_app(service, settings))])
    return store, boot, service, settings, app


async def test_platform_auth_is_separate_and_no_content_routes(platform):
    store, _, _, settings, app = platform
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as client:
        assert (await client.get("/platform/state")).status_code == 401
        assert (await client.post("/platform/login", json={"token": TOKEN})).status_code == 403
        client.headers["Origin"] = ORIGIN
        assert (await client.post("/platform/login", json={"token": TENANT})).status_code == 401
        client.cookies.set("da_platform", Fernet(settings.management_key.encode()).encrypt(b'{}').decode(), path="/platform")
        assert (await client.get("/platform/state")).status_code == 401
        login = await client.post("/platform/login", json={"token": TOKEN})
        assert login.status_code == 200
        for flag in ["HttpOnly", "Secure", "SameSite=strict", "Path=/platform", "Max-Age=900"]:
            assert flag in login.headers["set-cookie"]
        assert TOKEN not in login.headers["set-cookie"]
        # Any accidental dispatch delegation must fail this test.
        store.dispatch = lambda *_: pytest.fail("Platform must never dispatch tenant operations")
        response = await client.get("/platform/state")
        assert response.status_code == 200
        for forbidden in ["PRIVATE-ORG-NAME", "PRIVATE-USER-NAME", TENANT, TOKEN, "project_code", "content"]:
            assert forbidden not in response.text
        assert set(response.json()["accounts"][0]) == {"account_id", "created_at", "principal_count", "scope_count", "suspended"}
        for route in ["memory_search", "principal_create", "grant", "impersonate", "keys"]:
            assert (await client.post(f"/platform/api/{route}", json={})).status_code == 404
        assert (await client.post("/platform/logout", json={})).status_code == 200
        assert (await client.get("/platform/state")).status_code == 401


async def test_suspension_metadata_csrf_and_audit(platform):
    store, boot, service, _, app = platform
    account = boot["org_id"]
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN,
                                 headers={"Origin": ORIGIN}) as client:
        await client.post("/platform/login", json={"token": TOKEN})
        body = {"account_id": account, "suspended": True}
        assert (await client.post("/platform/accounts", json=body, headers={"Origin": "https://evil.example"})).status_code == 403
        assert service.is_active(account)
        assert (await client.post("/platform/accounts", json={**body, "key": "secret"})).status_code == 400
        assert (await client.post("/platform/accounts", json={**body, "suspended": "true"})).status_code == 400
        assert (await client.post("/platform/accounts", json=body)).status_code == 200
        assert not service.is_active(account)
        assert not PlatformService(store._engine).is_active(account)
        body["suspended"] = False
        assert (await client.post("/platform/accounts", json=body)).status_code == 200
        assert service.is_active(account)
        body["account_id"] = "0" * 32
        assert (await client.post("/platform/accounts", json=body)).status_code == 404
    with store._engine.connect() as conn:
        rows = conn.execute(select(audit.c.suspended)).scalars().all()
    assert rows == [True, False]


def test_platform_requires_strong_independent_secret(platform):
    _, _, service, settings, _ = platform
    settings.platform_admin_token = "weak"
    with pytest.raises(ValueError):
        platform_app(service, settings)


@pytest.mark.parametrize("subject,expected", [("central-admin", 303), ("tenant-admin", 401)])
async def test_platform_cloud_identity_is_not_tenant_identity(platform, monkeypatch, subject, expected):
    import time
    from urllib.parse import parse_qs, urlparse
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    _, _, service, settings, _ = platform
    settings.login_mode = "oidc"
    settings.platform_admin_token = ""
    settings.platform_subjects = ["central-admin"]
    settings.login_subjects = {"tenant-admin": "a-tenant-principal"}
    settings.login_issuer = "https://identity.example"
    settings.login_client_id = "browser-client"
    settings.login_client_secret = ""
    settings.login_provider = "Cloud"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    runtime = {}
    def provider(request):
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json={"issuer": settings.login_issuer,
                "authorization_endpoint": settings.login_issuer + "/authorize",
                "token_endpoint": settings.login_issuer + "/token", "jwks_uri": settings.login_issuer + "/keys"})
        data = parse_qs(request.content.decode())
        assert data["redirect_uri"] == [ORIGIN + "/platform/oidc/callback"]
        assert data["code_verifier"]
        claims = {"iss": settings.login_issuer, "aud": settings.login_client_id,
                  "sub": subject, "nonce": runtime["nonce"], "iat": int(time.time()), "exp": int(time.time()) + 600}
        return httpx.Response(200, json={"id_token": jwt.encode(claims, key, algorithm="RS256")})
    original = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: original(transport=httpx.MockTransport(provider), **kw))
    monkeypatch.setattr(jwt, "PyJWKClient", lambda *a, **kw: SimpleNamespace(get_signing_key_from_jwt=lambda token: SimpleNamespace(key=key.public_key())))
    app = Starlette(routes=[Mount("/platform", app=platform_app(service, settings))])
    async with original(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as client:
        assert (await client.get("/platform/login-options")).json()["token"] is False
        assert (await client.post("/platform/login", json={"token": TOKEN}, headers={"Origin": ORIGIN})).status_code == 403
        begin = await client.get("/platform/oidc/start")
        assert "Path=/platform/oidc" in begin.headers["set-cookie"]
        query = parse_qs(urlparse(begin.headers["location"]).query)
        runtime["nonce"] = query["nonce"][0]
        result = await client.get("/platform/oidc/callback", params={"state": query["state"][0], "code": "code"})
        assert result.status_code == expected
        if expected == 303:
            assert result.headers["location"] == "/platform/"
            assert "da_platform=" in result.headers["set-cookie"]
            assert (await client.get("/platform/state")).status_code == 200
            settings.platform_subjects.clear()
            assert (await client.get("/platform/state")).status_code == 401
        else:
            assert (await client.get("/platform/state")).status_code == 401


async def test_central_plan_assignment_is_metadata_only_and_never_grants_access(platform):
    from sqlalchemy import func
    from distributedai.platform import plan_audit
    from distributedai.store import Grant, PrincipalRow
    store, boot, service, _, app = platform
    service.billing = store.billing
    service.billing.enabled = True
    with store._engine.connect() as conn:
        before_grants = conn.scalar(select(func.count()).select_from(Grant))
        before_users = conn.scalar(select(func.count()).select_from(PrincipalRow))
    original_dispatch = store.dispatch
    store.dispatch = lambda *_: pytest.fail("Central plan changes cannot dispatch tenant operations")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN,
                                 headers={"Origin": ORIGIN}) as client:
        payload = {"account_id": boot["org_id"], "plan": "org_business"}
        assert (await client.post("/platform/accounts/plan", json=payload)).status_code == 401
        assert (await client.post("/platform/login", json={"token": TENANT})).status_code == 401
        await client.post("/platform/login", json={"token": TOKEN})
        assert (await client.post("/platform/accounts/plan", json=payload, headers={"Origin": "https://evil.example"})).status_code == 403
        assert (await client.post("/platform/accounts/plan", json={**payload, "grant": "admin"})).status_code == 400
        assert (await client.post("/platform/accounts/plan", json={**payload, "plan": "invented"})).status_code == 400
        assert (await client.post("/platform/accounts/plan", json=payload)).status_code == 200
        state = (await client.get("/platform/state")).json()
        assert state["billing_enabled"] and "org_business" in state["plans"]
        account = state["accounts"][0]
        assert account["plan"] == "org_business" and account["billing_status"] == "active"
        assert set(account) == {"account_id", "created_at", "principal_count", "scope_count", "suspended",
                                "plan", "billing_status", "needs_reconciliation"}
        assert "PRIVATE-ORG-NAME" not in str(state) and "PRIVATE-USER-NAME" not in str(state)
        service.billing.enabled = False
        assert (await client.post("/platform/accounts/plan", json=payload)).status_code == 400
        assert (await client.get("/platform/state")).json()["plans"] == {}
    with store._engine.connect() as conn:
        assert conn.scalar(select(func.count()).select_from(Grant)) == before_grants
        assert conn.scalar(select(func.count()).select_from(PrincipalRow)) == before_users
        assert conn.execute(select(plan_audit.c.org_id, plan_audit.c.plan)).all() == [(boot["org_id"], "org_business")]
    store.dispatch = original_dispatch
