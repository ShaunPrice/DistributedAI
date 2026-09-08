# SPDX-License-Identifier: Apache-2.0
import base64
import secrets

import httpx
import pytest
from starlette.applications import Starlette
from starlette.routing import Mount

from distributedai.config import Settings
from distributedai.composition import as_application
from distributedai.runtime import configured_store
from distributedai.presentation.management import management_app
from distributedai.presentation.platform import platform_app

ORIGIN = "https://memory.example"
ADMIN, USER, PLATFORM = ("support-admin-" * 5, "support-user-" * 5, "support-platform-" * 5)


@pytest.fixture
def support_http(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'support.db'}", public_url=ORIGIN + "/mcp",
        management_key=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
        content_master_key=base64.b64encode(secrets.token_bytes(32)).decode(), platform_admin_token=PLATFORM)
    store = configured_store(settings)
    store.initialize()
    store.bootstrap("Support test", "Admin", ADMIN)
    admin = store.authenticate(ADMIN)
    user = store.dispatch(admin, "principal_create", {"name": "User", "token": USER})
    application = as_application(store, settings)
    app = Starlette(routes=[Mount("/manage", management_app(application, settings)),
                           Mount("/platform", platform_app(application.platform, settings))])
    return store, user["principal_id"], app


async def test_help_is_public_but_ticket_and_configuration_are_protected(support_http):
    _, user_id, app = support_http
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN,
                                headers={"Origin": ORIGIN}) as client:
        for prefix in ["manage", "platform"]:
            help_result = await client.get(f"/{prefix}/help?page=signin")
            assert help_result.status_code == 200
            assert "bootstrap_token" in help_result.text
            assert (await client.get(f"/{prefix}/assets/help.js")).status_code == 200
        assert (await client.post("/manage/api/support_list", json={})).status_code == 401
        assert (await client.get("/platform/support-settings")).status_code == 401
        await client.post("/manage/login", json={"token": USER})
        assert (await client.post("/manage/api/support_configure", json={
            "external_url": "https://help.example", "support_principal_ids": []})).status_code == 403
        assert (await client.post("/platform/support-settings", json={
            "external_url": "https://help.example", "support_principal_ids": []})).status_code == 401
        created = await client.post("/manage/api/support_create", json={"subject": "Connection issue",
            "body": "The expected project is not listed.", "page": "projects", "idempotency_key": "http-ticket-1"})
        assert created.status_code == 200
        ticket_id = created.json()["ticket_id"]
        assert (await client.post("/manage/api/support_get", json={"ticket_id": ticket_id})).status_code == 200
        await client.post("/manage/logout", json={})
        await client.post("/manage/login", json={"token": ADMIN})
        tickets = await client.post("/manage/api/support_list", json={})
        assert ticket_id in tickets.text  # Default administrator fallback.
        assert (await client.post("/manage/api/support_reply", json={
            "ticket_id": ticket_id, "body": "Check your project assignment.", "status": "closed"})).status_code == 200
        await client.post("/platform/login", json={"token": PLATFORM})
        result = await client.post("/platform/support-settings", json={
            "external_url": "https://solution.example/support", "support_principal_ids": [user_id]})
        assert result.status_code == 200
        public = await client.get("/manage/support-entry")
        assert public.json()["route"]["url"] == "https://solution.example/support"
        assert user_id not in public.text
        options = await client.post("/manage/api/support_options", json={})
        assert options.json()["route"]["url"] == "https://solution.example/support"
        assert (await client.post("/platform/support-settings", json={
            "external_url": "javascript:alert(1)", "support_principal_ids": []})).status_code == 400
        assert (await client.post("/platform/support-settings", json={
            "external_url": "", "support_principal_ids": []}, headers={"Origin": "https://evil.example"})).status_code == 403
