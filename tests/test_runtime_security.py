# SPDX-License-Identifier: Apache-2.0
"""Integrated encrypted runtime boundaries, separate from plaintext Store unit tests."""
import base64
import secrets
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select
from starlette.applications import Starlette
from starlette.routing import Mount

from distributedai.config import Settings
from distributedai.management import management_app
from distributedai.platform import platform_app
from distributedai.runtime import configured_store
from distributedai.server import create_app
from distributedai.store import MemoryProposal, MemoryRecord, MemoryVersion, ServiceError

ORIGIN = "https://memory.example"
OWNER = "runtime-owner-fixture-" * 4
OTHER = "runtime-other-fixture-" * 4
WORKER = "runtime-worker-fixture-" * 4
CENTRAL = "runtime-central-fixture-" * 4


@pytest.fixture
def runtime(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'runtime.db'}", public_url=ORIGIN + "/mcp",
                        management_key=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
                        content_master_key=base64.b64encode(secrets.token_bytes(32)).decode(),
                        platform_admin_token=CENTRAL)
    store = configured_store(settings)
    store.initialize()
    first = store.bootstrap("Private first tenant", "Owner", OWNER)
    second = store.create_organisation("Private second tenant", "Owner", OTHER)
    owner, other = store.authenticate(OWNER), store.authenticate(OTHER)
    worker_id = store.dispatch(owner, "principal_create", {"name": "Reviewer", "token": WORKER})["principal_id"]
    store.dispatch(owner, "grant", {"principal_id": worker_id, "scope_id": first["root_scope_id"], "role": "reviewer"})
    worker = store.authenticate(WORKER)
    def publish(scope, key, content):
        proposal = store.dispatch(owner, "memory_propose", {"scope_id": scope, "key": key, "content": content,
                                                           "source": "private-source-marker"})
        store.dispatch(worker, "memory_review", {"proposal_id": proposal["proposal_id"], "accept": True})
    app = Starlette(routes=[Mount("/manage", app=management_app(store, settings)),
                           Mount("/platform", app=platform_app(store.platform, settings))])
    return SimpleNamespace(settings=settings, store=store, first=first, second=second,
                           owner=owner, other=other, worker=worker, publish=publish, app=app)


def test_encrypted_search_tenant_scope_and_database(runtime):
    env = runtime
    root = env.first["root_scope_id"]
    project = env.store.dispatch(env.owner, "scope_create", {"name": "Project", "kind": "project", "parent_id": root})["scope_id"]
    sibling = env.store.dispatch(env.owner, "scope_create", {"name": "Sibling", "kind": "project", "parent_id": root})["scope_id"]
    env.publish(root, "root", "Bluebird scope ancestor")
    env.publish(project, "project", "Bluebird project confidential marker")
    env.publish(sibling, "sibling", "Bluebird hidden sibling")
    result = env.store.dispatch(env.owner, "memory_search", {"scope_id": project, "query": "BLUEBIRD"})
    assert {row["key"] for row in result["records"]} == {"root", "project"}
    assert not result["search_truncated"]
    assert env.store.dispatch(env.owner, "memory_search", {"scope_id": project, "query": "nomatch"})["records"] == []
    with pytest.raises(ServiceError):
        env.store.dispatch(env.other, "memory_search", {"scope_id": project, "query": "Bluebird"})
    assert env.store.dispatch(env.other, "memory_search", {"scope_id": env.second["root_scope_id"], "query": "Bluebird"})["records"] == []
    # Core selects bypass ORM decryption, proving what the database actually stores.
    with env.store._engine.connect() as conn:
        for model in (MemoryRecord, MemoryVersion, MemoryProposal):
            rows = conn.execute(select(model.__table__.c.content, model.__table__.c.source)).all()
            assert len(rows) == 3
            for content, source in rows:
                assert content.startswith("enc:v1:") and source.startswith("enc:v1:")
                assert "Bluebird" not in content and "private-source-marker" not in source
    # History and ordinary reads still transparently decrypt authorised records.
    history = env.store.dispatch(env.owner, "memory_history", {"scope_id": project, "key": "project"})
    assert history["versions"][0]["content"] == "Bluebird project confidential marker"


async def test_suspension_terminates_auth_dispatch_browser_and_keys(runtime):
    env = runtime
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=env.app), base_url=ORIGIN,
                                 headers={"Origin": ORIGIN}) as client:
        assert (await client.post("/manage/login", json={"token": OWNER})).status_code == 200
        assert (await client.get("/manage/state")).status_code == 200
        assert (await client.get("/manage/keys")).status_code == 200
        env.store.platform.set_suspended(env.first["org_id"], True)
        assert env.store.authenticate(OWNER) is None
        assert env.store.resolve_principal(env.owner.id) is None
        with pytest.raises(ServiceError):
            env.store.dispatch(env.owner, "scope_list", {})
        assert (await client.get("/manage/state")).status_code == 401
        assert (await client.get("/manage/keys")).status_code == 403
        assert (await client.post("/manage/keys/rotate", json={"provider": "local"})).status_code == 403
        assert env.store.authenticate(OTHER) is not None
        env.store.platform.set_suspended(env.first["org_id"], False)
        assert (await client.get("/manage/state")).status_code == 200


async def test_platform_never_gains_tenant_or_key_access(runtime):
    env = runtime
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=env.app), base_url=ORIGIN,
                                 headers={"Origin": ORIGIN}) as client:
        assert (await client.post("/platform/login", json={"token": CENTRAL})).status_code == 200
        assert (await client.get("/platform/state")).status_code == 200
        assert (await client.get("/manage/keys")).status_code == 403
        assert (await client.post("/manage/keys/rotate", json={"provider": "local"})).status_code == 403
        assert (await client.post("/manage/login", json={"token": CENTRAL})).status_code == 401
        assert (await client.post("/manage/api/memory_search", json={"scope_id": env.first["root_scope_id"]})).status_code == 401
        assert (await client.get("/platform/keys")).status_code == 404
        assert (await client.post("/platform/accounts", json={"account_id": env.first["org_id"], "suspended": False,
                                                            "manual_key": "forbidden"})).status_code == 400
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=env.app), base_url=ORIGIN,
                                 headers={"Origin": ORIGIN}) as client:
        await client.post("/manage/login", json={"token": WORKER})
        assert (await client.get("/manage/keys")).status_code == 403
        assert (await client.post("/platform/login", json={"token": OWNER})).status_code == 401


def test_serve_fails_closed_without_content_key(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'no-key.db'}")
    with pytest.raises(ValueError, match="CONTENT_MASTER_KEY"):
        configured_store(settings)
    with pytest.raises(ValueError, match="CONTENT_MASTER_KEY"):
        create_app(settings)


async def test_tenant_key_rotation_is_scoped_and_preserves_history(runtime):
    env = runtime
    root = env.first["root_scope_id"]
    env.publish(root, "retained", "Confidential historical value")
    env.store.dispatch(env.other, "scope_list", {})  # provision the independent second keyring
    other_before = env.store.crypto.status(env.second["org_id"])
    manual = base64.b64encode(secrets.token_bytes(32)).decode()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=env.app), base_url=ORIGIN,
                                 headers={"Origin": ORIGIN}) as client:
        await client.post("/manage/login", json={"token": OWNER})
        # Caller-supplied tenant IDs and unassigned provider aliases are never accepted.
        assert (await client.post("/manage/keys/rotate", json={"provider": "local", "org_id": env.second["org_id"]})).status_code == 400
        assert (await client.post("/manage/keys/rotate", json={"provider": "unassigned"})).status_code == 400
        response = await client.post("/manage/keys/rotate", json={"provider": "local", "manual_key": manual})
        assert response.status_code == 200
        assert response.json()["algorithm"] == "AES-256-GCM"
        assert manual not in response.text
        status = await client.get("/manage/keys")
        assert manual not in status.text and "wrapped_key" not in status.text
    assert env.store.crypto.status(env.second["org_id"]) == other_before
    assert env.store.dispatch(env.owner, "memory_search", {"scope_id": root, "query": "historical"})["records"][0]["content"] == "Confidential historical value"
