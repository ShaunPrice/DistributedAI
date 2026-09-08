# SPDX-License-Identifier: Apache-2.0
"""Unit tests for optional paid accounts (distributedai.billing).

Runs on SQLite for speed (PostgreSQL is the deployment authority; an opt-in cross-replica
race test runs with RUN_POSTGRES_TESTS=1). All tokens/credentials are synthetic fixtures.
No real payment-provider endpoint is ever contacted: Stripe verification is local HMAC and
PayPal's trusted verification API is mocked with an httpx.MockTransport.
"""
from __future__ import annotations

import hmac
import json
import os
import time
import uuid
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from distributedai.billing import (
    BillingAccount,
    PaymentProvider,
    PayPalProvider,
    StripeProvider,
)
from distributedai.store import Grant, ServiceError, Store

ADMIN_TOKEN = "synthetic-admin-token-000000000000"
CAROL_TOKEN = "synthetic-carol-token-000000000000"
ORG2_TOKEN = "synthetic-org2-admin-token-0000000000"

STRIPE_SECRET = "whsec_synthetic_test_secret"
PRICE_MAP = {"stripe:price_personal": "personal_paid", "stripe:price_business": "org_business", "paypal:price_personal": "personal_paid"}


def make_store(tmp_path, name="billing.db", **kwargs):
    store = Store(f"sqlite:///{tmp_path / name}", **kwargs)
    store.initialize()
    return store


def bootstrap(store, org="acme"):
    boot = store.bootstrap(org, "root-admin", ADMIN_TOKEN)
    admin = store.authenticate(ADMIN_TOKEN)
    return SimpleNamespace(store=store, admin=admin, org_id=boot["org_id"],
                           root=boot["root_scope_id"])


@pytest.fixture
def benv(tmp_path):
    """Billing enabled with stock plan defaults; one free_personal org."""
    return bootstrap(make_store(tmp_path, billing_enabled=True))


def make_instance(env, name="laptop"):
    return env.store.dispatch(env.admin, "instance_create", {"name": name})["instance_id"]


def issue(env, instance_id, owner=None):
    args = {"instance_id": instance_id}
    if owner is not None:
        args["owner_principal_id"] = owner
    return env.store.dispatch(env.admin, "connection_issue", args)


# ---------------------------------------------------------------------------
# Disabled billing preserves the unmetered status quo
# ---------------------------------------------------------------------------


def test_disabled_billing_is_unmetered(tmp_path):
    env = bootstrap(make_store(tmp_path, billing_enabled=False))
    instance = make_instance(env)
    for i in range(5):  # far past every free-tier ceiling
        issue(env, instance)
        env.store.dispatch(env.admin, "principal_create",
                           {"name": f"user{i}", "token": f"synthetic-user-{i}-token-{'0' * 20}"})
    assert env.store.dispatch(env.admin, "billing_status", {})["billing_enabled"] is False


# ---------------------------------------------------------------------------
# Connection quotas (free 2 / paid 10), revocation frees a slot
# ---------------------------------------------------------------------------


def test_free_plan_allows_two_connections_third_blocked(benv):
    instance = make_instance(benv)
    issue(benv, instance)
    issue(benv, instance)
    with pytest.raises(ServiceError) as err:
        issue(benv, instance)
    assert err.value.code == "quota_exceeded"


def test_revocation_frees_a_connection_slot(benv):
    instance = make_instance(benv)
    first = issue(benv, instance)
    issue(benv, instance)
    with pytest.raises(ServiceError):
        issue(benv, instance)
    benv.store.dispatch(benv.admin, "connection_revoke",
                        {"connection_id": first["connection_id"]})
    assert issue(benv, instance)["connection_id"]


def test_paid_personal_allows_ten_connections_eleventh_blocked(benv):
    benv.store.assign_plan(benv.org_id, "personal_paid")
    instance = make_instance(benv)
    for _ in range(10):
        issue(benv, instance)
    with pytest.raises(ServiceError) as err:
        issue(benv, instance)
    assert err.value.code == "quota_exceeded"


# ---------------------------------------------------------------------------
# User and instance quotas
# ---------------------------------------------------------------------------


def test_free_plan_allows_one_user_second_blocked(benv):
    with pytest.raises(ServiceError) as err:
        benv.store.dispatch(benv.admin, "principal_create",
                            {"name": "second", "token": CAROL_TOKEN})
    assert err.value.code == "quota_exceeded"


def test_free_plan_allows_one_instance_second_blocked(benv):
    make_instance(benv, "one")
    with pytest.raises(ServiceError) as err:
        make_instance(benv, "two")
    assert err.value.code == "quota_exceeded"


def test_org_tier_user_and_instance_quotas_are_configurable(tmp_path):
    env = bootstrap(make_store(
        tmp_path, billing_enabled=True,
        plan_limits={"org_starter": {"max_users": 3, "max_instances": 2}}))
    env.store.assign_plan(env.org_id, "org_starter")
    for i in range(2):  # admin is user 1; users 2 and 3 fit
        env.store.dispatch(env.admin, "principal_create",
                           {"name": f"member{i}", "token": f"synthetic-member-{i}-{'0' * 20}"})
    with pytest.raises(ServiceError) as err:
        env.store.dispatch(env.admin, "principal_create",
                           {"name": "member-extra", "token": f"synthetic-extra-{'0' * 24}"})
    assert err.value.code == "quota_exceeded"
    make_instance(env, "a")
    make_instance(env, "b")
    with pytest.raises(ServiceError) as err:
        make_instance(env, "c")
    assert err.value.code == "quota_exceeded"


def test_access_controls_preserved_at_paid_tiers(benv):
    """A plan change never grants scope access: paying does not change grants."""
    with Session(benv.store._engine) as sess:
        before = sess.execute(select(Grant)).scalars().all()
    benv.store.assign_plan(benv.org_id, "org_enterprise")
    with Session(benv.store._engine) as sess:
        after = sess.execute(select(Grant)).scalars().all()
    assert len(before) == len(after)


# ---------------------------------------------------------------------------
# Cross-org isolation
# ---------------------------------------------------------------------------


def test_cross_org_denial(benv):
    benv.store.create_organisation("beta", "beta-admin", ORG2_TOKEN)
    beta_admin = benv.store.authenticate(ORG2_TOKEN)
    instance = make_instance(benv)
    connection = issue(benv, instance)
    with pytest.raises(ServiceError) as err:
        benv.store.dispatch(beta_admin, "connection_issue", {"instance_id": instance})
    assert err.value.code == "not_found"
    with pytest.raises(ServiceError) as err:
        benv.store.dispatch(beta_admin, "connection_revoke",
                            {"connection_id": connection["connection_id"]})
    assert err.value.code == "not_found"
    with pytest.raises(ServiceError) as err:
        benv.store.dispatch(beta_admin, "connection_issue",
                            {"instance_id": instance,
                             "owner_principal_id": benv.admin.id})
    assert err.value.code in ("not_found", "denied")


# ---------------------------------------------------------------------------
# Connection credentials: separate from principal tokens, verified server-side
# ---------------------------------------------------------------------------


def test_connection_credential_authenticates_and_revocation_kills_it(benv):
    instance = make_instance(benv)
    issued = issue(benv, instance)
    auth = benv.store.authenticate_connection(issued["credential"])
    assert auth is not None
    assert auth.principal.id == benv.admin.id
    assert auth.instance_id == instance
    assert auth.connection_id == issued["connection_id"]
    # A principal bearer token is NOT a connection credential.
    assert benv.store.authenticate_connection(ADMIN_TOKEN) is None
    assert benv.store.authenticate_connection("bogus") is None
    benv.store.dispatch(benv.admin, "connection_revoke",
                        {"connection_id": issued["connection_id"]})
    assert benv.store.authenticate_connection(issued["credential"]) is None


def test_revoked_owner_principal_invalidates_connection(tmp_path):
    env = bootstrap(make_store(tmp_path, billing_enabled=True,
                               plan_limits={"free_personal": {"max_users": 2}}))
    carol_id = env.store.dispatch(env.admin, "principal_create",
                                  {"name": "carol", "token": CAROL_TOKEN})["principal_id"]
    instance = make_instance(env)
    issued = issue(env, instance, owner=carol_id)
    assert env.store.authenticate_connection(issued["credential"]).principal.id == carol_id
    env.store.dispatch(env.admin, "principal_revoke", {"principal_id": carol_id})
    assert env.store.authenticate_connection(issued["credential"]) is None


def test_non_admin_cannot_issue_for_someone_else(tmp_path):
    env = bootstrap(make_store(tmp_path, billing_enabled=True,
                               plan_limits={"free_personal": {"max_users": 2}}))
    env.store.dispatch(env.admin, "principal_create",
                       {"name": "carol", "token": CAROL_TOKEN})
    carol = env.store.authenticate(CAROL_TOKEN)
    instance = make_instance(env)
    with pytest.raises(ServiceError) as err:
        env.store.dispatch(carol, "connection_issue",
                           {"instance_id": instance, "owner_principal_id": env.admin.id})
    assert err.value.code == "denied"


# ---------------------------------------------------------------------------
# Memory (storage) quota
# ---------------------------------------------------------------------------


def test_memory_quota_blocks_writes_over_the_configured_cap(tmp_path):
    env = bootstrap(make_store(
        tmp_path, billing_enabled=True,
        plan_limits={"free_personal": {"max_storage_bytes": 400, "max_users": 2}}))
    env.store.dispatch(env.admin, "principal_create",
                       {"name": "carol", "token": CAROL_TOKEN})
    carol = env.store.authenticate(CAROL_TOKEN)
    env.store.dispatch(env.admin, "grant", {"principal_id": carol.id,
                                            "scope_id": env.root, "role": "reviewer"})
    content = "x" * 150
    prop = env.store.dispatch(env.admin, "memory_propose",
                              {"scope_id": env.root, "key": "note", "content": content})
    # Accept charges the immutable version copy too: 150 (proposal) + 150 (version) = 300.
    env.store.dispatch(carol, "memory_review",
                       {"proposal_id": prop["proposal_id"], "accept": True})
    usage = env.store.dispatch(env.admin, "billing_status", {})["usage"]
    assert usage["storage_bytes"] == 302
    with pytest.raises(ServiceError) as err:
        env.store.dispatch(env.admin, "memory_propose",
                           {"scope_id": env.root, "key": "note2", "content": content,
                            "expected_version": 0})
    assert err.value.code == "quota_exceeded"


def test_recalculate_storage_rebuilds_counter(tmp_path):
    env = bootstrap(make_store(tmp_path, billing_enabled=True))
    env.store.dispatch(env.admin, "memory_propose",
                       {"scope_id": env.root, "key": "k", "content": "y" * 50})
    result = env.store.recalculate_storage(env.org_id)
    assert result["storage_bytes"] == 52


# ---------------------------------------------------------------------------
# Stripe: signed webhook, tamper, replay, out-of-order, fail-closed downgrade
# ---------------------------------------------------------------------------


def stripe_body(event_id, sub_id, status, price_id, created):
    return json.dumps({
        "id": event_id, "type": "customer.subscription.updated", "created": created,
        "data": {"object": {"id": sub_id, "customer": "cus_1", "status": status,
                            "items": {"data": [{"price": {"id": price_id}}]}}},
    }).encode("utf-8")


def stripe_sign(body, secret=STRIPE_SECRET, t=None):
    t = int(time.time()) if t is None else t
    mac = hmac.new(secret.encode(), f"{t}.".encode() + body, "sha256").hexdigest()
    return {"Stripe-Signature": f"t={t},v1={mac}"}


@pytest.fixture
def stripe_env(benv):
    benv.store.billing.register_provider(StripeProvider(STRIPE_SECRET))
    benv.store.billing.price_map = dict(PRICE_MAP)
    benv.store.register_billing_subscription(benv.org_id, "stripe", "cus_1", "sub_1")
    return benv


def plan_of(env):
    return env.store.dispatch(env.admin, "billing_status", {})["plan"]


def test_stripe_verified_upgrade_applies(stripe_env):
    body = stripe_body("evt_1", "sub_1", "active", "price_personal", 1_000)
    result = stripe_env.store.billing_webhook("stripe", stripe_sign(body), body)
    assert result["applied"] is True
    assert plan_of(stripe_env) == "personal_paid"


def test_stripe_tampered_body_rejected(stripe_env):
    body = stripe_body("evt_1", "sub_1", "active", "price_personal", 1_000)
    headers = stripe_sign(body)
    tampered = body.replace(b"price_personal", b"price_business")
    with pytest.raises(ServiceError) as err:
        stripe_env.store.billing_webhook("stripe", headers, tampered)
    assert err.value.code == "webhook_verification_failed"
    assert plan_of(stripe_env) == "free_personal"


def test_stripe_stale_signature_timestamp_rejected(stripe_env):
    body = stripe_body("evt_1", "sub_1", "active", "price_personal", 1_000)
    with pytest.raises(ServiceError) as err:
        stripe_env.store.billing_webhook("stripe", stripe_sign(body, t=int(time.time()) - 4000),
                                         body)
    assert err.value.code == "webhook_verification_failed"


def test_stripe_replayed_event_id_is_idempotent(stripe_env):
    body = stripe_body("evt_1", "sub_1", "active", "price_personal", 1_000)
    stripe_env.store.billing_webhook("stripe", stripe_sign(body), body)
    replay = stripe_env.store.billing_webhook("stripe", stripe_sign(body), body)
    assert replay == {"applied": False, "reason": "duplicate_event", "event_id": "evt_1"}
    assert plan_of(stripe_env) == "personal_paid"


def test_stripe_out_of_order_event_ignored(stripe_env):
    newer = stripe_body("evt_2", "sub_1", "active", "price_personal", 2_000)
    stripe_env.store.billing_webhook("stripe", stripe_sign(newer), newer)
    older = stripe_body("evt_3", "sub_1", "canceled", "price_personal", 1_000)
    result = stripe_env.store.billing_webhook("stripe", stripe_sign(older), older)
    assert result["reason"] == "out_of_order"
    assert plan_of(stripe_env) == "personal_paid"


def test_stripe_same_second_different_event_fails_closed(stripe_env):
    first = stripe_body("evt_4", "sub_1", "active", "price_personal", 3_000)
    stripe_env.store.billing_webhook("stripe", stripe_sign(first), first)
    second = stripe_body("evt_5", "sub_1", "canceled", "price_personal", 3_000)
    result = stripe_env.store.billing_webhook("stripe", stripe_sign(second), second)
    assert result["reason"] == "same_timestamp_fail_closed"
    status = stripe_env.store.dispatch(stripe_env.admin, "billing_status", {})
    assert status["needs_reconciliation"] is True
    assert status["plan"] == "free_personal"  # paid entitlements disabled until reconciled


def test_stripe_unexpected_status_downgrades_without_deleting_data(stripe_env):
    up = stripe_body("evt_6", "sub_1", "active", "price_personal", 4_000)
    stripe_env.store.billing_webhook("stripe", stripe_sign(up), up)
    stripe_env.store.dispatch(stripe_env.admin, "memory_propose",
                              {"scope_id": stripe_env.root, "key": "keep",
                               "content": "must survive billing changes"})
    weird = stripe_body("evt_7", "sub_1", "some_new_status", "price_personal", 5_000)
    result = stripe_env.store.billing_webhook("stripe", stripe_sign(weird), weird)
    assert result["applied"] is True and result["status"] == "delinquent"
    assert plan_of(stripe_env) == "free_personal"
    proposals = stripe_env.store.dispatch(stripe_env.admin, "proposal_list",
                                          {"scope_id": stripe_env.root})["proposals"]
    assert any(p["key"] == "keep" for p in proposals)  # data preserved


def test_stripe_unknown_price_fails_closed(stripe_env):
    body = stripe_body("evt_8", "sub_1", "active", "price_never_configured", 6_000)
    result = stripe_env.store.billing_webhook("stripe", stripe_sign(body), body)
    assert result["reason"] == "unknown_price"
    assert plan_of(stripe_env) == "free_personal"


def test_webhook_metadata_cannot_select_or_create_a_tenant(stripe_env):
    body = stripe_body("evt_9", "sub_unregistered", "active", "price_business", 7_000)
    result = stripe_env.store.billing_webhook("stripe", stripe_sign(body), body)
    assert result["reason"] == "unregistered_subscription"
    assert plan_of(stripe_env) == "free_personal"
    with Session(stripe_env.store._engine) as sess:
        accounts = sess.execute(select(BillingAccount)).scalars().all()
    assert [a.provider_subscription_id for a in accounts] == ["sub_1"]


def test_subscription_cannot_be_rebound_to_second_org(stripe_env):
    stripe_env.store.create_organisation("beta", "beta-admin", ORG2_TOKEN)
    beta = stripe_env.store.authenticate(ORG2_TOKEN)
    with pytest.raises(ServiceError) as err:
        stripe_env.store.register_billing_subscription(beta.org_id, "stripe",
                                                       "cus_2", "sub_1")
    assert err.value.code == "conflict"


# ---------------------------------------------------------------------------
# PayPal: verification through PayPal's trusted API (mocked transport)
# ---------------------------------------------------------------------------


PAYPAL_HEADERS = {
    "Paypal-Transmission-Id": "t-1", "Paypal-Transmission-Time": "2026-09-08T00:00:00Z",
    "Paypal-Transmission-Sig": "sig", "Paypal-Cert-Url": "https://api.paypal.com/cert",
    "Paypal-Auth-Algo": "SHA256withRSA",
}


def paypal_transport(verified=True, calls=None):
    def handler(request):
        if calls is not None:
            calls.append(request.url.path)
        if request.url.path == "/v1/oauth2/token":
            return httpx.Response(200, json={"access_token": "synthetic"})
        if request.url.path == "/v1/notifications/verify-webhook-signature":
            status = "SUCCESS" if verified else "FAILURE"
            return httpx.Response(200, json={"verification_status": status})
        return httpx.Response(404)
    return httpx.MockTransport(handler)


def paypal_body(event_id="WH-1", status="ACTIVE"):
    return json.dumps({
        "id": event_id, "event_type": "BILLING.SUBSCRIPTION.ACTIVATED",
        "create_time": "2026-09-08T01:02:03Z",
        "resource": {"id": "sub_pp", "status": status, "plan_id": "price_personal"},
    }).encode("utf-8")


def test_paypal_verified_event_applies(benv):
    calls = []
    benv.store.billing.register_provider(
        PayPalProvider("cid", "csecret", "wh-id", transport=paypal_transport(calls=calls)))
    benv.store.billing.price_map = dict(PRICE_MAP)
    benv.store.register_billing_subscription(benv.org_id, "paypal", "payer_1", "sub_pp")
    result = benv.store.billing_webhook("paypal", PAYPAL_HEADERS, paypal_body())
    assert result["applied"] is True
    assert plan_of(benv) == "personal_paid"
    assert "/v1/notifications/verify-webhook-signature" in calls  # trusted API was consulted


def test_paypal_failed_verification_rejected(benv):
    benv.store.billing.register_provider(
        PayPalProvider("cid", "csecret", "wh-id", transport=paypal_transport(verified=False)))
    benv.store.register_billing_subscription(benv.org_id, "paypal", "payer_1", "sub_pp")
    with pytest.raises(ServiceError) as err:
        benv.store.billing_webhook("paypal", PAYPAL_HEADERS, paypal_body())
    assert err.value.code == "webhook_verification_failed"
    assert plan_of(benv) == "free_personal"


def test_paypal_missing_signature_headers_rejected(benv):
    benv.store.billing.register_provider(
        PayPalProvider("cid", "csecret", "wh-id", transport=paypal_transport()))
    with pytest.raises(ServiceError) as err:
        benv.store.billing_webhook("paypal", {}, paypal_body())
    assert err.value.code == "webhook_verification_failed"


# ---------------------------------------------------------------------------
# Checkout adapter interface, status surface, configuration validation
# ---------------------------------------------------------------------------


def test_checkout_adapter_default_is_not_supported():
    with pytest.raises(ServiceError) as err:
        PaymentProvider().create_checkout_session(customer_id=None, price_id="p",
                                                  success_url="https://s", cancel_url="https://c",
                                                  reference="org")
    assert err.value.code == "not_supported"


def test_stripe_checkout_adapter_uses_configured_price(benv):
    seen = {}

    def handler(request):
        seen["path"] = request.url.path
        seen["body"] = request.read().decode()
        return httpx.Response(200, json={"id": "cs_1", "url": "https://checkout.example"})

    provider = StripeProvider(STRIPE_SECRET, api_key="sk_synthetic",
                              transport=httpx.MockTransport(handler))
    result = provider.create_checkout_session(customer_id="cus_1", price_id="price_personal",
                                              success_url="https://ok", cancel_url="https://no",
                                              reference=benv.org_id)
    assert result["url"] == "https://checkout.example"
    assert seen["path"] == "/v1/checkout/sessions"
    assert "price_personal" in seen["body"]


def test_billing_status_is_metadata_only(benv):
    benv.store.dispatch(benv.admin, "memory_propose",
                        {"scope_id": benv.root, "key": "secretish",
                         "content": "TOP-SECRET-CONTENT"})
    status = benv.store.dispatch(benv.admin, "billing_status", {})
    assert "TOP-SECRET-CONTENT" not in json.dumps(status)
    assert status["limits"]["max_connections"] == 2
    assert status["usage"]["users"] == 1


def test_connection_list_never_exposes_credentials(benv):
    instance = make_instance(benv)
    issued = issue(benv, instance)
    listed = benv.store.dispatch(benv.admin, "connection_list", {})
    assert issued["credential"] not in json.dumps(listed)
    assert listed["connections"][0]["connection_id"] == issued["connection_id"]


def test_invalid_plan_configuration_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        make_store(tmp_path, "bad1.db", billing_enabled=True,
                   plan_limits={"free_personal": {"max_widgets": 1}})
    with pytest.raises(ValueError):
        make_store(tmp_path, "bad2.db", billing_enabled=True,
                   plan_limits={"free_personal": {"max_users": -1}})
    with pytest.raises(ValueError):
        make_store(tmp_path, "bad3.db", billing_enabled=True,
                   plan_limits={"brand_new_plan": {"max_users": 1}})  # incomplete new plan


def test_assign_plan_rejects_unknown_plan(benv):
    with pytest.raises(ServiceError) as err:
        benv.store.assign_plan(benv.org_id, "made_up_plan")
    assert err.value.code == "invalid_argument"


# ---------------------------------------------------------------------------
# PostgreSQL cross-replica quota atomicity (opt-in)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(os.getenv("RUN_POSTGRES_TESTS") != "1",
                    reason="PostgreSQL integration opt-in")
def test_connection_quota_race_across_replicas_exactly_one_winner():
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url

    from distributedai.config import Settings

    url = Settings.from_env().database_url
    engine = create_engine(url)
    schema = "test_" + uuid.uuid4().hex
    with engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    scoped = make_url(url).update_query_dict({"options": f"-csearch_path={schema}"})
    scoped_url = scoped.render_as_string(hide_password=False)
    store = Store(scoped_url, billing_enabled=True)
    other = Store(scoped_url, billing_enabled=True)
    try:
        store.initialize()
        env = bootstrap(store)
        instance = make_instance(env)
        issue(env, instance)  # one of two free-tier slots used; ONE slot remains

        barrier = threading.Barrier(2)

        def contend(replica):
            barrier.wait(timeout=10)
            try:
                return replica.dispatch(env.admin, "connection_issue",
                                        {"instance_id": instance})
            except ServiceError as exc:
                return {"error": exc.code}

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(contend, [store, other]))
        assert sum("credential" in o for o in outcomes) == 1
        assert sum(o.get("error") == "quota_exceeded" for o in outcomes) == 1
    finally:
        store._engine.dispose()
        other._engine.dispose()
        with engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        engine.dispose()
