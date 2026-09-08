# SPDX-License-Identifier: Apache-2.0
"""Protocol perimeter tests, independent of the persistence implementation."""
import time
from types import SimpleNamespace

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from distributedai.auth import Verifier
from distributedai.config import Settings
from distributedai.server import Limits, create_server


class FakeStore:
    def __init__(self):
        self.active = True
        self.calls = []

    def authenticate(self, token):
        return self.resolve_principal("client") if token == "test-token-" * 5 else None

    def resolve_principal(self, identifier):
        if self.active and identifier == "client":
            return SimpleNamespace(id="client", org_id="org", name="example")

    def dispatch(self, principal, op, arguments):
        self.calls.append((principal.id, op, arguments))
        return {"scopes": []}

    def health(self):
        return True


@pytest.fixture
def settings():
    return Settings(database_url="sqlite://", public_url="http://localhost:8090/mcp")


async def test_bearer_auth_and_revocation(settings):
    store = FakeStore()
    verifier = Verifier(store, settings)
    assert await verifier.verify_token("bad") is None
    assert (await verifier.verify_token("test-token-" * 5)).client_id == "client"
    store.active = False
    assert await verifier.verify_token("test-token-" * 5) is None


@pytest.mark.parametrize("claim,value", [("aud", "https://attacker.example/mcp"),
                                         ("iss", "https://attacker.example"),
                                         ("exp", 1), ("sub", "unmapped")])
async def test_oauth_rejects_wrong_claims(claim, value):
    settings = Settings(database_url="sqlite://", public_url="https://memory.example/mcp",
                        issuer="https://identity.example", jwks_url="https://identity.example/keys",
                        subjects={"subject": "client"})
    verifier = Verifier(FakeStore(), settings)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier.jwks = SimpleNamespace(get_signing_key_from_jwt=lambda token: SimpleNamespace(key=key.public_key()))
    claims = {"iss": settings.issuer, "aud": settings.public_url, "sub": "subject",
              "exp": int(time.time()) + 60, "iat": int(time.time())}
    good = jwt.encode(claims, key, algorithm="RS256")
    assert await verifier.verify_token(good) is not None
    claims[claim] = value
    assert await verifier.verify_token(jwt.encode(claims, key, algorithm="RS256")) is None
    verifier.store.active = False
    assert await verifier.verify_token(good) is None


async def test_oauth_rejects_unsigned_and_wrong_key(settings):
    settings.issuer, settings.jwks_url = "https://identity.example", "https://identity.example/keys"
    settings.subjects = {"subject": "client"}
    verifier = Verifier(FakeStore(), settings)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier.jwks = SimpleNamespace(get_signing_key_from_jwt=lambda token: SimpleNamespace(key=key.public_key()))
    claims = {"iss": settings.issuer, "aud": settings.public_url, "sub": "subject",
              "exp": int(time.time()) + 60, "iat": int(time.time())}
    assert await verifier.verify_token(jwt.encode(claims, "", algorithm="none")) is None
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert await verifier.verify_token(jwt.encode(claims, other, algorithm="RS256")) is None


async def test_http_auth_discovery_and_tool_binding(settings):
    store = FakeStore()
    server = create_server(store, settings)
    app = Limits(server.streamable_http_app())
    headers = {"Accept": "application/json, text/event-stream"}
    async with server.session_manager.run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost:8090") as client:
            denied = await client.post("/mcp", json={}, headers=headers)
            assert denied.status_code == 401
            assert "resource_metadata=" in denied.headers["www-authenticate"]
            meta = await client.get("/.well-known/oauth-protected-resource/mcp")
            assert meta.status_code == 200
            assert meta.json()["resource"] == settings.public_url
            headers["Authorization"] = "Bearer " + "test-token-" * 5
            init = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                    "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                                               "clientInfo": {"name": "test", "version": "1"}}}, headers=headers)
            assert init.status_code == 200
            headers["MCP-Protocol-Version"] = init.json()["result"]["protocolVersion"]
            result = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                      "params": {"name": "scope_list", "arguments": {}}}, headers=headers)
            assert result.status_code == 200
            assert not result.json()["result"].get("isError")
            assert result.json()["result"]["structuredContent"] == {"scopes": []}
            assert store.calls[-1] == ("client", "scope_list", {"include_personal": True})
            result = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                      "params": {"name": "memory_search", "arguments": {"scope_id": "scope"}}}, headers=headers)
            assert not result.json()["result"].get("isError")
            assert store.calls[-1][2] == {"scope_id": "scope", "query": "", "limit": 20}
            bad_origin = await client.post("/mcp", json={}, headers={**headers, "Origin": "https://evil.example"})
            assert bad_origin.status_code == 403
            bad_host = await client.post("/mcp", json={}, headers={**headers, "Host": "evil.example"})
            assert bad_host.status_code == 421
            store.active = False
            assert (await client.post("/mcp", json={}, headers=headers)).status_code == 401


async def test_size_and_rate_bounds(settings):
    server = create_server(FakeStore(), settings)
    app = Limits(server.streamable_http_app(), rpm=2)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost:8090") as client:
        assert (await client.post("/mcp", content=b"x" * 131073)).status_code == 413
        assert (await client.get("/healthz")).status_code == 200
        assert (await client.get("/healthz")).status_code == 429


def test_configuration_rejects_remote_cleartext():
    with pytest.raises(ValueError, match="HTTPS"):
        Settings(database_url="sqlite://", public_url="http://memory.example/mcp")
    with pytest.raises(ValueError, match="together"):
        Settings(database_url="sqlite://", issuer="https://identity.example")
