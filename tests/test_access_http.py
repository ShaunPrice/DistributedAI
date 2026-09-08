# SPDX-License-Identifier: Apache-2.0
"""Access lifecycle through the encrypted runtime and browser API boundary."""
import base64
import secrets

import httpx
import pytest
from starlette.applications import Starlette
from starlette.routing import Mount

from distributedai.config import Settings
from distributedai.management import management_app
from distributedai.runtime import configured_store

ORIGIN = "https://memory.example"
ADMIN = "admin-access-lifecycle-fixture-" * 3
USER = "user-access-lifecycle-fixture-" * 3


@pytest.fixture
def access_app(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'access.db'}", public_url=ORIGIN + "/mcp",
        management_key=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
        content_master_key=base64.b64encode(secrets.token_bytes(32)).decode())
    store = configured_store(settings)
    store.initialize()
    store.bootstrap("Organisation", "Admin", ADMIN)
    admin = store.authenticate(ADMIN)
    user = store.dispatch(admin, "principal_create", {"name": "User", "token": USER})
    app = Starlette(routes=[Mount("/manage", management_app(store, settings))])
    return store, admin, user["principal_id"], app


async def test_personal_memory_export_delete_are_independent_and_private(access_app):
    store, admin, user_id, app = access_app
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN,
                                headers={"Origin": ORIGIN}) as client:
        assert (await client.post("/manage/login", json={"token": USER})).status_code == 200
        state = (await client.get("/manage/state")).json()
        personal = next(s for s in state["scopes"] if s["kind"] == "personal")
        proposal = await client.post("/manage/api/memory_propose", json={
            "scope_id": personal["scope_id"], "key": "preference", "content": "Private writing preference"})
        assert proposal.status_code == 200
        assert (await client.post("/manage/api/memory_review", json={
            "proposal_id": proposal.json()["proposal_id"], "accept": True})).status_code == 200
        store.dispatch(admin, "scope_policy_set", {"scope_id": personal["scope_id"], "principal_id": user_id,
                                                 "can_export": True, "can_delete": False})
        exported = await client.post("/manage/api/memory_export", json={"scope_id": personal["scope_id"]})
        assert exported.status_code == 200 and "Private writing preference" in exported.text
        assert (await client.post("/manage/api/memory_delete", json={
            "scope_id": personal["scope_id"], "key": "preference"})).status_code == 403
        store.dispatch(admin, "scope_policy_set", {"scope_id": personal["scope_id"], "principal_id": user_id,
                                                 "can_export": False, "can_delete": True})
        assert (await client.post("/manage/api/memory_export", json={"scope_id": personal["scope_id"]})).status_code == 403
        assert (await client.post("/manage/api/scope_policy_get", json={"scope_id": personal["scope_id"], "principal_id": user_id})).status_code == 403
        assert (await client.post("/manage/api/memory_delete", json={
            "scope_id": personal["scope_id"], "key": "preference"})).status_code == 200
        assert (await client.post("/manage/login", json={"token": ADMIN})).status_code == 200
        policy = await client.post("/manage/api/scope_policy_get", json={"scope_id": personal["scope_id"], "principal_id": user_id})
        assert policy.status_code == 200 and not policy.json()["can_export"] and policy.json()["can_delete"]
        assert (await client.post("/manage/api/memory_search", json={
            "scope_id": personal["scope_id"], "query": ""})).status_code == 403


async def test_organisation_backup_contains_ciphertext_not_personal_content(access_app):
    store, admin, user_id, app = access_app
    user = store.resolve_principal(user_id)
    personal = store.dispatch(user, "personal_scope", {})
    proposal = store.dispatch(user, "memory_propose", {"scope_id": personal["scope_id"],
        "key": "private", "content": "PERSONAL-SECRET-CONTENT"})
    store.dispatch(user, "memory_review", {"proposal_id": proposal["proposal_id"], "accept": True})
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN,
                                headers={"Origin": ORIGIN}) as client:
        await client.post("/manage/login", json={"token": ADMIN})
        response = await client.post("/manage/api/organisation_backup", json={})
        assert response.status_code == 200
        assert "PERSONAL-SECRET-CONTENT" not in response.text
        assert ADMIN not in response.text and USER not in response.text
        assert personal["scope_id"] in response.text
