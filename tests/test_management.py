# SPDX-License-Identifier: Apache-2.0
"""Browser security and organisation/project access integration."""
from cryptography.fernet import Fernet
import httpx
import pytest

from distributedai.config import Settings
from distributedai.management import management_app
from distributedai.server import Limits
from distributedai.store import Store


@pytest.fixture
def management(tmp_path):
    store = Store(f"sqlite:///{tmp_path / 'management.db'}")
    store.initialize()
    bootstrap = store.bootstrap("Test organisation", "admin", "ui-test-admin-token-" * 3)
    settings = Settings(database_url="sqlite://", public_url="https://memory.example/mcp",
                        management_key=Fernet.generate_key().decode())
    return store, bootstrap, Limits(management_app(store, settings)), settings


async def test_secure_login_csrf_and_cookie(management):
    _, _, app, _ = management
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://memory.example") as client:
        assert (await client.get("/state")).status_code == 401
        assert (await client.post("/login", json={"token": "ui-test-admin-token-" * 3})).status_code == 403
        assert (await client.post("/login", json={"token": "ui-test-admin-token-" * 3}, headers={"Origin":"https://evil.example"})).status_code == 403
        login = await client.post("/login", json={"token": "ui-test-admin-token-" * 3}, headers={"Origin":"https://memory.example"})
        assert login.status_code == 200
        cookie = login.headers["set-cookie"]
        for flag in ["HttpOnly", "Secure", "SameSite=strict", "Max-Age=1800"]:
            assert flag in cookie
        assert "ui-test-admin-token" not in cookie
        assert "frame-ancestors 'none'" in login.headers["content-security-policy"]


async def test_project_assignment_and_code_do_not_grant_access(management):
    store, boot, app, _ = management
    # Mount the subapp so cookie path matches its deployed route.
    from starlette.applications import Starlette
    from starlette.routing import Mount
    mounted = Starlette(routes=[Mount("/manage", app=app)])
    headers = {"Origin":"https://memory.example"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=mounted), base_url="https://memory.example", headers=headers) as admin:
        assert (await admin.post("/manage/login", json={"token": "ui-test-admin-token-" * 3})).status_code == 200
        project = (await admin.post("/manage/api/scope_create", json={"name":"Shared project", "kind":"project", "parent_id":boot["root_scope_id"]})).json()
        created = (await admin.post("/manage/api/principal_create", json={"name":"Colleague"})).json()
        assert len(created["issued_token"]) >= 32
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=mounted), base_url="https://memory.example", headers=headers) as member:
            await member.post("/manage/login", json={"token":created["issued_token"]})
            denied = await member.post("/manage/api/project_resolve", json={"project_code":project["project_code"]})
            assert denied.status_code == 403
            assert (await member.post("/manage/api/principal_list", json={})).status_code == 403
            assert (await admin.post("/manage/api/grant", json={"principal_id":created["principal_id"],"scope_id":project["scope_id"],"role":"writer"})).status_code == 200
            resolved = await member.post("/manage/api/project_resolve", json={"project_code":project["project_code"]})
            assert resolved.status_code == 200
            assert project["scope_id"] in resolved.text
            await admin.post("/manage/api/grant_revoke", json={"principal_id":created["principal_id"],"scope_id":project["scope_id"]})
            assert (await member.post("/manage/api/project_resolve", json={"project_code":project["project_code"]})).status_code == 403
            await admin.post("/manage/api/principal_revoke", json={"principal_id":created["principal_id"]})
            assert (await member.get("/manage/state")).status_code == 401
        assert (await admin.post("/manage/api/principal_create",json={"name":"bad","token":"short"})).status_code == 400
        assert (await admin.post("/manage/api/grant",json={},headers={"Origin":"https://evil.example"})).status_code == 403
