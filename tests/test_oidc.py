# SPDX-License-Identifier: Apache-2.0
"""Browser OIDC security tests using signed tokens and a simulated identity provider."""
import json
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
import httpx
import jwt
import pytest
from starlette.applications import Starlette
from starlette.routing import Mount

from distributedai.config import Settings
from distributedai.management import management_app
from distributedai.oidc import FLOW_COOKIE
from distributedai.store import Store


@pytest.fixture
def cloud(tmp_path, monkeypatch):
    store = Store(f"sqlite:///{tmp_path / 'oidc.db'}")
    store.initialize()
    boot = store.bootstrap("Example", "Owner", "oidc-admin-token-" * 4)
    settings = Settings(database_url="sqlite://", public_url="https://memory.example/mcp",
                        management_key=Fernet.generate_key().decode(), login_mode="oidc",
                        login_issuer="https://identity.example", login_client_id="browser-client",
                        login_subjects={"subject-1": boot["principal_id"]})
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    runtime = {"nonce": "", "claims": {}, "requests": [], "used": set()}
    def provider(request):
        runtime["requests"].append(request)
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json={"issuer": settings.login_issuer,
                "authorization_endpoint": settings.login_issuer + "/authorize",
                "token_endpoint": settings.login_issuer + "/token",
                "jwks_uri": settings.login_issuer + "/keys"})
        data = parse_qs(request.content.decode())
        assert data["code_verifier"] and data["redirect_uri"] == ["https://memory.example/manage/oidc/callback"]
        assert data["client_id"] == ["browser-client"]
        if data["code"][0] in runtime["used"]:
            return httpx.Response(400, json={"error": "invalid_grant"})
        runtime["used"].add(data["code"][0])
        claims = {"iss": settings.login_issuer, "aud": settings.login_client_id,
                  "sub": "subject-1", "nonce": runtime["nonce"], "iat": int(time.time()),
                  "exp": int(time.time()) + 600, **runtime["claims"]}
        return httpx.Response(200, json={"id_token": jwt.encode(claims, key, algorithm="RS256")})
    original = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: original(transport=httpx.MockTransport(provider), **kw))
    monkeypatch.setattr(jwt, "PyJWKClient", lambda *a, **kw: SimpleNamespace(get_signing_key_from_jwt=lambda token: SimpleNamespace(key=key.public_key())))
    app = Starlette(routes=[Mount("/manage", app=management_app(store, settings))])
    return original(transport=httpx.ASGITransport(app=app), base_url="https://memory.example"), runtime, settings, store, boot


async def begin(client, runtime):
    response = await client.get("/manage/oidc/start")
    assert response.status_code == 302
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["code_challenge_method"] == ["S256"]
    assert len(query["code_challenge"][0]) == 43
    runtime["nonce"] = query["nonce"][0]
    assert "SameSite=lax" in response.headers["set-cookie"]
    return query["state"][0]


@pytest.mark.parametrize("issuer", ["https://cognito-idp.ap-southeast-2.amazonaws.com/pool",
                                   "https://login.microsoftonline.com/tenant-id/v2.0",
                                   "https://accounts.google.com"])
async def test_provider_login_explicit_assignment_and_revocation(cloud, issuer):
    client, runtime, settings, store, boot = cloud
    settings.login_issuer = issuer
    async with client:
        state = await begin(client, runtime)
        result = await client.get("/manage/oidc/callback", params={"state": state, "code": "auth-code"})
        assert result.status_code == 303
        assert "HttpOnly" in result.headers["set-cookie"] and "Secure" in result.headers["set-cookie"]
        assert (await client.get("/manage/state")).status_code == 200
        # Mapping removal takes effect without waiting for session expiry.
        settings.login_subjects.clear()
        assert (await client.get("/manage/state")).status_code == 401
        settings.login_subjects["subject-1"] = boot["principal_id"]
        settings.login_mode = "token"
        assert (await client.get("/manage/state")).status_code == 401


@pytest.mark.parametrize("claims", [
    {"nonce": "wrong"}, {"aud": "mcp-resource"}, {"iss": "https://evil.example"},
    {"exp": 1}, {"iat": 9999999999}, {"sub": "unknown"}, {"azp": "other"},
    {"aud": ["browser-client", "other"]}, {"token_use": "access"},
])
async def test_invalid_claims_never_create_session(cloud, claims):
    client, runtime, _, _, _ = cloud
    runtime["claims"] = claims
    async with client:
        state = await begin(client, runtime)
        result = await client.get("/manage/oidc/callback", params={"state": state, "code": "code"})
        assert result.status_code == 401
        assert (await client.get("/manage/state")).status_code == 401


async def test_state_tamper_missing_duplicate_and_replay(cloud):
    client, runtime, _, _, _ = cloud
    async with client:
        state = await begin(client, runtime)
        result = await client.get("/manage/oidc/callback", params={"state": "wrong", "code": "code"})
        assert result.status_code == 401
        assert len(runtime["requests"]) == 1  # no token exchange for wrong state
        state = await begin(client, runtime)
        cookie = client.cookies.get(FLOW_COOKIE)
        result = await client.get("/manage/oidc/callback", params={"state": state, "code": "code"})
        assert result.status_code == 303
        client.cookies.clear()
        # Even a replay of the original encrypted flow cannot redeem the same provider code twice.
        result = await client.get("/manage/oidc/callback", params={"state": state, "code": "code"}, headers={"Cookie": f"{FLOW_COOKIE}={cookie}"})
        assert result.status_code == 401
        result = await client.get("/manage/oidc/callback?state=x&state=y&code=z")
        assert result.status_code == 401


async def test_cloud_only_blocks_local_credential(cloud):
    client, _, _, _, _ = cloud
    async with client:
        options = (await client.get("/manage/login-options")).json()
        assert options["oidc"] and not options["token"]
        result = await client.post("/manage/login", json={"token": "oidc-admin-token-" * 4}, headers={"Origin": "https://memory.example"})
        assert result.status_code == 403


def test_configuration_rejects_insecure_or_incomplete_cloud_login():
    for values in [{"login_mode": "invalid"}, {"login_mode": "oidc"},
                   {"login_mode": "oidc", "login_issuer": "http://identity.example", "login_client_id": "x"}]:
        with pytest.raises(ValueError):
            Settings(database_url="sqlite://", **values)


async def test_forged_session_fails(cloud):
    client, _, _, _, _ = cloud
    async with client:
        response = await client.get("/manage/state", headers={"Cookie": "da_management=" + Fernet(Fernet.generate_key()).encrypt(json.dumps({"kind":"oidc"}).encode()).decode()})
        assert response.status_code == 401
