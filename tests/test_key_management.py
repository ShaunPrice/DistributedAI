# SPDX-License-Identifier: Apache-2.0
import base64
from types import SimpleNamespace

from starlette.applications import Starlette
from starlette.testclient import TestClient

from distributedai.encryption import CryptoBox, LocalWrapper
from distributedai.key_management import key_routes
from distributedai.storage_encryption import enable_encryption
from test_store import env as env


def client(e, actor):
    async def identity(request):
        return actor
    def csrf(request):
        return request.headers.get("origin") == "https://example.test" and request.headers.get("content-type") == "application/json"
    settings = SimpleNamespace(tenant_key_providers={e.admin.org_id: ["own-cloud"]})
    return TestClient(Starlette(routes=key_routes(e.store, settings, identity, csrf)))


def setup(e):
    box = CryptoBox(e.store._engine, {name: LocalWrapper(b"k" * 32)
        for name in ["local", "own-cloud", "other-tenant"]})
    box.initialize()
    enable_encryption(e.store, box)
    box.provision(e.admin.org_id)
    return box


def test_manual_rotation_does_not_export_key_and_preserves_history(env):
    box = setup(env)
    old = box.encrypt(env.admin.org_id, "row", "content", "tenant secret")
    key = base64.b64encode(b"x" * 32).decode()
    with client(env, env.admin) as c:
        response = c.post("/keys/rotate", json={"provider": "own-cloud", "manual_key": key},
                          headers={"origin": "https://example.test"})
        assert response.status_code == 200
        assert response.json()["version"] == 2
        status = c.get("/keys")
        assert "other-tenant" not in status.text
        assert key not in status.text + response.text
        assert "wrapped_key" not in status.text
    assert box.decrypt(env.admin.org_id, "row", "content", old) == "tenant secret"


def test_access_csrf_and_provider_boundaries(env):
    setup(env)
    for actor in [env.alice, None, SimpleNamespace(id=env.admin.id, is_org_admin=True)]:
        with client(env, actor) as c:
            assert c.get("/keys").status_code == 403
            assert c.post("/keys/rotate", json={"provider": "local"},
                headers={"origin": "https://example.test"}).status_code == 403
    with client(env, env.admin) as c:
        assert c.post("/keys/rotate", json={"provider": "local"}).status_code == 403
        for data in [{"provider": "other-tenant"}, {"provider": "https://attacker"},
                     {"provider": "local", "org_id": "other"},
                     {"provider": "local", "manual_key": "invalid-secret"}, []]:
            r = c.post("/keys/rotate", json=data, headers={"origin": "https://example.test"})
            assert r.status_code == 400
            assert "invalid-secret" not in r.text
    assert env.store.crypto.status(env.admin.org_id)["active_version"] == 1


def test_revoked_org_administrator_is_denied(env):
    from sqlalchemy import update
    from distributedai.store import PrincipalRow
    setup(env)
    with env.store._engine.begin() as conn:
        conn.execute(update(PrincipalRow.__table__).where(PrincipalRow.id == env.admin.id).values(active=False))
    with client(env, env.admin) as c:
        assert c.get("/keys").status_code == 403
        assert c.post("/keys/rotate", json={"provider": "local"},
            headers={"origin": "https://example.test"}).status_code == 403
