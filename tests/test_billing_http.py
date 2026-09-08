# SPDX-License-Identifier: Apache-2.0
"""Billing HTTP security using signed fixtures and mocked provider APIs, never charges."""
import hmac
import json
import time
from types import SimpleNamespace
from urllib.parse import parse_qs

import httpx
import pytest
from sqlalchemy import select
from starlette.applications import Starlette
from starlette.routing import Mount

from distributedai.billing import StripeProvider, PaymentProvider
from distributedai.billing_http import billing_routes, webhook_routes, metadata, pending
from distributedai.store import Store

OWNER = "billing-http-owner-fixture-" * 3
OTHER = "billing-http-other-fixture-" * 3
SECRET = "synthetic-webhook-secret"
ORIGIN = "https://memory.example"


@pytest.fixture
def billing(tmp_path):
    store = Store(f"sqlite:///{tmp_path / 'billing-http.db'}", billing_enabled=True)
    store.initialize()
    metadata.create_all(store._engine)
    first = store.bootstrap("First", "Owner", OWNER)
    second = store.create_organisation("Second", "Owner", OTHER)
    runtime = {"requests": [], "reference": None, "status": "active", "customer": "cus_customer", "price": "price_personal"}
    def provider(request):
        runtime["requests"].append(request)
        assert request.url.host == "api.stripe.com"
        if request.url.path == "/v1/checkout/sessions":
            data = parse_qs(request.content.decode())
            assert data["line_items[0][price]"] == ["price_personal"]
            assert data["success_url"] == [ORIGIN + "/manage/"]
            assert "customer" not in data
            runtime["reference"] = data["client_reference_id"][0]
            return httpx.Response(200, json={"id": "cs_test_pending", "url": "https://checkout.stripe.com/c/pay/test"})
        if request.url.path == "/v1/subscriptions/sub_subscription":
            return httpx.Response(200, json={"id": "sub_subscription", "customer": runtime["customer"],
                "status": runtime["status"], "items": {"data": [{"price": {"id": runtime["price"]}}]}})
        if request.url.path == "/v1/billing_portal/sessions":
            data = parse_qs(request.content.decode())
            assert data["customer"] == ["cus_customer"]
            return httpx.Response(200, json={"url": "https://billing.stripe.com/p/session/test"})
        pytest.fail("Unexpected provider endpoint")
    adapter = StripeProvider(SECRET, api_key="synthetic-api-key", transport=httpx.MockTransport(provider))
    store.billing.register_provider(adapter)
    paypal = PaymentProvider()
    paypal.name = "paypal"
    store.billing.register_provider(paypal)
    store.billing.price_map = {"price_personal": "personal_paid", "stripe:price_personal": "personal_paid"}
    settings = SimpleNamespace(public_url=ORIGIN + "/mcp", billing_prices={"stripe:price_personal": "personal_paid"})
    async def identity(request):
        return store.authenticate(request.headers.get("x-test-credential", ""))
    def csrf(request):
        return request.headers.get("origin") == ORIGIN and request.headers.get("content-type", "").split(";")[0] == "application/json"
    app = Starlette(routes=[Mount("/manage", app=Starlette(routes=billing_routes(store, settings, identity, csrf))), *webhook_routes(store)])
    return SimpleNamespace(store=store, first=first, second=second, runtime=runtime, app=app)


def signed(event):
    body = json.dumps(event).encode()
    timestamp = str(int(time.time()))
    signature = hmac.new(SECRET.encode(), timestamp.encode() + b"." + body, "sha256").hexdigest()
    return body, {"Stripe-Signature": f"t={timestamp},v1={signature}", "Content-Type": "application/json"}


def completion(env, **extra):
    return {"id": "evt_checkout", "created": int(time.time()), "type": "checkout.session.completed",
            "data": {"object": {"id": "cs_test_pending", "mode": "subscription", "status": "complete",
                "subscription": "sub_subscription", "customer": "cus_customer",
                "client_reference_id": env.runtime["reference"], **extra}}}


async def test_checkout_verified_completion_replay_portal_and_no_redirect_grant(billing):
    env = billing
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=env.app), base_url=ORIGIN,
                                 headers={"Origin": ORIGIN, "x-test-credential": OWNER}) as client:
        result = await client.post("/manage/billing/checkout", json={"provider": "stripe", "plan": "personal_paid"})
        assert result.status_code == 200
        assert env.store.dispatch(env.store.authenticate(OWNER), "billing_status", {})["plan"] == "free_personal"
        assert (await client.post("/manage/billing/checkout", json={"provider": "stripe", "plan": "personal_paid"})).status_code == 409
        body, headers = signed(completion(env))
        assert (await client.post("/billing/webhooks/stripe", content=body, headers=headers)).status_code == 200
        assert env.store.dispatch(env.store.authenticate(OWNER), "billing_status", {})["plan"] == "personal_paid"
        count = len(env.runtime["requests"])
        assert (await client.post("/billing/webhooks/stripe", content=body, headers=headers)).status_code == 200
        assert len(env.runtime["requests"]) == count  # completed replay never re-fetches/grants
        assert (await client.post("/manage/billing/portal", json={"provider": "stripe"})).status_code == 200
        assert env.store.dispatch(env.store.authenticate(OTHER), "billing_status", {})["plan"] == "free_personal"
        with env.store._engine.connect() as conn:
            assert conn.scalar(select(pending.c.completed)) is True


async def test_auth_csrf_fixed_configuration_and_unsupported_provider(billing):
    env = billing
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=env.app), base_url=ORIGIN) as client:
        assert (await client.get("/manage/billing/options")).status_code == 403
        client.headers["x-test-credential"] = OWNER
        options = (await client.get("/manage/billing/options")).json()
        assert options["providers"]["stripe"]["checkout"]
        assert not options["providers"]["paypal"]["checkout"]
        body = {"provider": "stripe", "plan": "personal_paid"}
        assert (await client.post("/manage/billing/checkout", json=body)).status_code == 403
        client.headers["Origin"] = ORIGIN
        for extra in [{"org_id": env.second["org_id"]}, {"success_url": "https://evil.example"}, {"price_id": "price_free"}]:
            assert (await client.post("/manage/billing/checkout", json={**body, **extra})).status_code == 400
        assert (await client.post("/manage/billing/checkout", json={**body, "plan": "org_enterprise"})).status_code == 400
        assert (await client.post("/manage/billing/checkout", json={**body, "provider": "paypal"})).status_code == 501
        assert (await client.post("/manage/billing/portal", json={"provider": "stripe", "customer_id": "cus_other"})).status_code == 400
        assert (await client.post("/manage/billing/portal", json={"provider": "stripe"})).status_code == 400
        assert not env.runtime["requests"]


@pytest.mark.parametrize("attack", ["signature", "reference", "session", "customer", "price"])
async def test_webhook_binding_signature_and_current_provider_state(billing, attack):
    env = billing
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=env.app), base_url=ORIGIN,
                                 headers={"Origin": ORIGIN, "x-test-credential": OWNER}) as client:
        await client.post("/manage/billing/checkout", json={"provider": "stripe", "plan": "personal_paid"})
        event = completion(env)
        if attack == "reference":
            event["data"]["object"]["client_reference_id"] = env.second["org_id"]
        if attack == "session":
            event["data"]["object"]["id"] = "cs_unknown"
        if attack in {"customer", "price"}:
            env.runtime[attack] = "different"
        body, headers = signed(event)
        if attack == "signature":
            headers["Stripe-Signature"] = "t=1,v1=invalid"
        assert (await client.post("/billing/webhooks/stripe", content=body, headers=headers)).status_code == 400
        assert env.store.dispatch(env.store.authenticate(OWNER), "billing_status", {})["plan"] == "free_personal"
        assert (await client.post("/billing/webhooks/unknown", content=body)).status_code == 404
        assert (await client.post("/billing/webhooks/stripe", content=b"x" * 131073)).status_code == 413


async def test_ambiguous_provider_failure_keeps_pending_without_automatic_retry(billing):
    env = billing
    attempts = []
    def timeout(request):
        attempts.append(request)
        raise httpx.ReadTimeout("synthetic provider timeout")
    env.store.billing.provider("stripe")._client = httpx.Client(
        base_url="https://api.stripe.com", transport=httpx.MockTransport(timeout))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=env.app), base_url=ORIGIN,
                                 headers={"Origin": ORIGIN, "x-test-credential": OWNER}) as client:
        request = {"provider": "stripe", "plan": "personal_paid"}
        result = await client.post("/manage/billing/checkout", json=request)
        assert result.status_code == 503
        assert "synthetic provider timeout" not in result.text
        assert (await client.post("/manage/billing/checkout", json=request)).status_code == 409
        assert len(attempts) == 1
        assert env.store.dispatch(env.store.authenticate(OWNER), "billing_status", {})["plan"] == "free_personal"
