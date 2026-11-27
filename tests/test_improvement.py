# SPDX-License-Identifier: Apache-2.0
"""Improvement memory: problems, attempts, predictions and observed outcomes.

Runs on SQLite; fixtures and tokens are synthetic. Direct database access is used only to
inspect stored ciphertext or to set up bounds that would otherwise need hundreds of calls.
"""
import json

import httpx
import pytest
from sqlalchemy import select

from distributedai.encryption import CryptoBox, LocalWrapper
from distributedai.persistence.workspace import (
    MAX_ATTEMPTS_PER_PROBLEM,
    MAX_PROBLEMS_PER_SCOPE,
    AuditLog,
    ImprovementAttempt,
    ImprovementProblem,
    ServiceError,
    Store,
)
from distributedai.storage_encryption import enable_encryption
from test_access_http import ADMIN, ORIGIN, access_app as access_app
from test_store import ADMIN_TOKEN, INJECTION, ORG2_TOKEN, env as env

PROBLEM = "Agent declares the task complete before running the tests"


def record(e, actor, scope, problem=PROBLEM, change="Add a completion gate", **extra):
    return e.store.dispatch(actor, "improvement_record", {
        "scope_id": scope, "problem": problem, "change": change,
        "rationale": extra.pop("rationale", "Runs ended without a test command"),
        "predicted": extra.pop("predicted", "Fixes tasks 3 and 7; no regressions"), **extra})


def outcome(e, actor, attempt_id, verdict="improved", decision="retain",
            observed="Task 3 fixed, task 7 still fails"):
    return e.store.dispatch(actor, "improvement_outcome", {
        "attempt_id": attempt_id, "observed": observed, "verdict": verdict,
        "decision": decision})


def listing(e, actor, scope, **extra):
    return e.store.dispatch(actor, "improvement_list", {"scope_id": scope, **extra})


def encrypt(e):
    box = CryptoBox(e.store._engine, {"local": LocalWrapper(b"k" * 32)})
    box.initialize()
    enable_encryption(e.store, box)


def test_attempts_group_under_one_problem_and_keep_prediction_then_outcome(env):
    first = record(env, env.alice, env.proj_a, context="model-a / suite-1 / round 2")
    assert first["problem_created"] and first["number"] == 1
    assert first["status"] == "awaiting_outcome"
    # The same problem in different case, spacing and Unicode width joins the same entry.
    second = record(env, env.alice, env.proj_a, change="Require an explicit test command",
                    problem="  AGENT declares the task complete\tbefore running the ｔｅｓｔｓ ")
    assert not second["problem_created"] and second["number"] == 2
    assert second["problem_id"] == first["problem_id"]

    done = outcome(env, env.carol, first["attempt_id"], verdict="regressed", decision="remove",
                   observed="Task 3 fixed but tasks 1 and 9 now time out")
    assert done["independent_outcome"] is True

    problems = listing(env, env.bob, env.proj_a)["problems"]  # a reader can consult history
    assert len(problems) == 1
    entry = problems[0]
    assert entry["problem"] == PROBLEM and entry["trust"] == "untrusted_data"
    assert entry["summary"] == {"attempts": 2, "awaiting_outcome": 1, "improved": 0,
                                "no_change": 0, "regressed": 1, "inconclusive": 0}
    one, two = entry["attempts"]
    assert (one["number"], two["number"]) == (1, 2)
    assert one["predicted"] == "Fixes tasks 3 and 7; no regressions"
    assert one["observed"] == "Task 3 fixed but tasks 1 and 9 now time out"
    assert one["verdict"] == "regressed" and one["decision"] == "remove"
    assert one["recorded_by"] == env.alice.id and one["outcome_by"] == env.carol.id
    assert one["context"] == "model-a / suite-1 / round 2"
    assert one["recorded_at"] <= one["outcome_at"]
    assert two["verdict"] is None and two["observed"] is None and two["outcome_at"] is None
    assert two["independent_outcome"] is False
    json.dumps(problems)


def test_outcome_is_written_once_and_self_report_is_labelled(env):
    attempt = record(env, env.alice, env.proj_a)["attempt_id"]
    assert outcome(env, env.alice, attempt)["independent_outcome"] is False
    with pytest.raises(ServiceError) as err:
        outcome(env, env.carol, attempt, verdict="regressed", decision="remove")
    assert err.value.code == "invalid_state"
    kept = listing(env, env.alice, env.proj_a)["problems"][0]["attempts"][0]
    assert kept["verdict"] == "improved" and kept["outcome_by"] == env.alice.id
    # A correction is a further attempt, never an edit of the earlier record.
    assert record(env, env.alice, env.proj_a, change="Revised gate")["number"] == 2


def test_arguments_are_validated(env):
    attempt = record(env, env.alice, env.proj_a)["attempt_id"]
    bad = [
        ("improvement_record", {"scope_id": env.proj_a, "problem": PROBLEM, "change": "c",
                                "rationale": "r"}),  # a prediction is mandatory
        ("improvement_record", {"scope_id": env.proj_a, "problem": " ", "change": "c",
                                "rationale": "r", "predicted": "p"}),
        ("improvement_record", {"scope_id": env.proj_a, "problem": "x" * 501, "change": "c",
                                "rationale": "r", "predicted": "p"}),
        ("improvement_record", {"scope_id": env.proj_a, "problem": PROBLEM, "change": "c",
                                "rationale": "r", "predicted": "p", "verdict": "improved"}),
        ("improvement_outcome", {"attempt_id": attempt, "observed": "o", "verdict": "great",
                                 "decision": "retain"}),
        ("improvement_outcome", {"attempt_id": attempt, "observed": "o", "verdict": "improved",
                                 "decision": "keep"}),
        ("improvement_outcome", {"attempt_id": attempt, "verdict": "improved",
                                 "decision": "retain"}),
        ("improvement_list", {"scope_id": env.proj_a, "limit": 51}),
    ]
    for operation, arguments in bad:
        with pytest.raises(ServiceError) as err:
            env.store.dispatch(env.alice, operation, arguments)
        assert err.value.code == "invalid_argument", (operation, arguments)
    with pytest.raises(ServiceError) as err:
        outcome(env, env.alice, "0" * 32)
    assert err.value.code == "not_found"


def test_roles_scope_reach_and_tenant_isolation(env):
    dept_attempt = record(env, env.alice, env.dept, problem="Department-wide problem")
    proj_attempt = record(env, env.alice, env.proj_a)
    record(env, env.alice, env.proj_b, problem="Sibling project problem")

    with pytest.raises(ServiceError) as err:  # readers cannot write
        record(env, env.bob, env.proj_a)
    assert err.value.code == "denied"
    with pytest.raises(ServiceError) as err:
        outcome(env, env.bob, proj_attempt["attempt_id"])
    assert err.value.code == "denied"
    with pytest.raises(ServiceError):  # bob has no access to the sibling project
        listing(env, env.bob, env.proj_b)

    # alice reads the project plus the department above it; never the sibling project.
    seen = {p["problem"] for p in listing(env, env.alice, env.proj_a)["problems"]}
    assert seen == {PROBLEM, "Department-wide problem"}
    # bob's grant is on projA only, so the department entry stays hidden from him.
    assert {p["problem"] for p in listing(env, env.bob, env.proj_a)["problems"]} == {PROBLEM}
    # A department listing does not descend into its projects.
    assert {p["problem"] for p in listing(env, env.alice, env.dept)["problems"]} == {
        "Department-wide problem"}
    assert [p["problem"] for p in listing(env, env.alice, env.proj_a, query="DEPARTMENT")[
        "problems"]] == ["Department-wide problem"]

    # The same statement in another scope is a separate entry.
    assert record(env, env.alice, env.proj_b)["problem_created"]

    env.store.create_organisation("other", "other-admin", ORG2_TOKEN)
    outsider = env.store.authenticate(ORG2_TOKEN)
    for operation, arguments in [
        ("improvement_list", {"scope_id": env.proj_a}),
        ("improvement_outcome", {"attempt_id": dept_attempt["attempt_id"], "observed": "o",
                                 "verdict": "improved", "decision": "retain"}),
        ("improvement_delete", {"problem_id": proj_attempt["problem_id"]}),
    ]:
        with pytest.raises(ServiceError) as err:
            env.store.dispatch(outsider, operation, arguments)
        assert err.value.code == "not_found"

    # Access removed after recording: the outcome check uses the attempt's actual scope.
    env.store.dispatch(env.admin, "grant_revoke",
                       {"principal_id": env.alice.id, "scope_id": env.dept})
    with pytest.raises(ServiceError) as err:
        outcome(env, env.alice, proj_attempt["attempt_id"])
    assert err.value.code == "denied"


def test_personal_scope_is_private_to_its_owner(env):
    scope = env.store.dispatch(env.alice, "personal_scope", {})["scope_id"]
    attempt = record(env, env.alice, scope)
    assert outcome(env, env.alice, attempt["attempt_id"])["independent_outcome"] is False
    assert len(listing(env, env.alice, scope)["problems"]) == 1
    for actor in (env.bob, env.admin):
        with pytest.raises(ServiceError):
            listing(env, actor, scope)
        with pytest.raises(ServiceError):
            env.store.dispatch(actor, "improvement_delete",
                               {"problem_id": attempt["problem_id"]})


def test_suspicious_text_is_refused_and_nothing_is_stored(env):
    for field in ("problem", "change", "rationale", "predicted", "context"):
        with pytest.raises(ServiceError) as err:
            record(env, env.alice, env.proj_a, **{field: INJECTION})
        assert err.value.code == "quarantined"
    attempt = record(env, env.alice, env.proj_a)["attempt_id"]
    with pytest.raises(ServiceError) as err:
        outcome(env, env.alice, attempt, observed=INJECTION)
    assert err.value.code == "quarantined"
    entry = listing(env, env.alice, env.proj_a)["problems"][0]
    assert entry["summary"]["attempts"] == 1 and entry["attempts"][0]["verdict"] is None
    assert INJECTION not in json.dumps(entry)


def test_per_scope_and_per_problem_bounds(env):
    first = record(env, env.alice, env.proj_a)
    with env.store._engine.begin() as conn:
        conn.execute(ImprovementAttempt.__table__.insert(), [dict(
            id=f"{n:032x}", org_id=env.alice.org_id, scope_id=env.proj_a,
            problem_id=first["problem_id"], number=n, change="c", rationale="r",
            predicted="p", context="", recorded_by=env.alice.id)
            for n in range(2, MAX_ATTEMPTS_PER_PROBLEM + 1)])
    with pytest.raises(ServiceError) as err:
        record(env, env.alice, env.proj_a)
    assert err.value.code == "limit_exceeded"
    assert listing(env, env.alice, env.proj_a)["problems"][0]["summary"]["attempts"] == 50

    with env.store._engine.begin() as conn:
        conn.execute(ImprovementProblem.__table__.insert(), [dict(
            id=f"{n:032x}", org_id=env.alice.org_id, scope_id=env.proj_a,
            problem=f"filler problem {n}", created_by=env.alice.id)
            for n in range(1000, 1000 + MAX_PROBLEMS_PER_SCOPE - 1)])
    with pytest.raises(ServiceError) as err:
        record(env, env.alice, env.proj_a, problem="one problem too many")
    assert err.value.code == "limit_exceeded"
    full = listing(env, env.alice, env.proj_a, limit=50)
    assert len(full["problems"]) == 50 and full["list_truncated"] is False


def test_text_is_encrypted_at_rest_and_round_trips(env):
    encrypt(env)
    attempt = record(env, env.alice, env.proj_a, context="confidential context")
    outcome(env, env.carol, attempt["attempt_id"], observed="confidential observation")
    with env.store._engine.connect() as conn:
        problem_row = conn.execute(select(ImprovementProblem.__table__)).mappings().one()
        attempt_row = conn.execute(select(ImprovementAttempt.__table__)).mappings().one()
    assert problem_row["problem"].startswith("enc:v1:")
    for field in ("change", "rationale", "predicted", "context", "observed"):
        assert attempt_row[field].startswith("enc:v1:"), field
    assert attempt_row["verdict"] == "improved"  # structural metadata stays readable
    stored = json.dumps([dict(problem_row), dict(attempt_row)], default=str)
    assert "completion gate" not in stored and "confidential" not in stored
    entry = listing(env, env.bob, env.proj_a)["problems"][0]
    assert entry["problem"] == PROBLEM
    assert entry["attempts"][0]["observed"] == "confidential observation"
    assert entry["attempts"][0]["context"] == "confidential context"
    # Grouping still works when stored statements are ciphertext.
    assert not record(env, env.alice, env.proj_a, problem=PROBLEM.upper())["problem_created"]


def test_export_backup_merge_and_scope_deletion_cover_the_ledger(env):
    encrypt(env)
    attempt = record(env, env.alice, env.dept, problem="Department-wide problem")
    outcome(env, env.carol, attempt["attempt_id"], observed="measured improvement")

    exported = env.store.dispatch(env.admin, "memory_export", {"scope_id": env.dept})["data"]
    assert exported["improvement_problems"][0]["problem"] == "Department-wide problem"
    assert exported["improvement_attempts"][0]["observed"] == "measured improvement"

    backup = env.store.dispatch(env.admin, "organisation_backup", {})
    assert backup["data"]["improvement_problems"][0]["problem"].startswith("enc:v1:")
    assert backup["data"]["improvement_attempts"][0]["observed"].startswith("enc:v1:")
    assert "Department-wide problem" not in json.dumps(backup)

    target = env.store.dispatch(env.admin, "scope_create", {
        "parent_id": env.root, "kind": "department", "name": "Target"})["scope_id"]
    env.store.dispatch(env.admin, "scope_merge", {"source_id": env.dept, "target_id": target})
    merged = listing(env, env.admin, target)["problems"]
    assert [p["scope_id"] for p in merged] == [target]
    assert merged[0]["attempts"][0]["observed"] == "measured improvement"

    record(env, env.admin, env.proj_a)
    with pytest.raises(ServiceError, match="improvement records"):
        env.store.dispatch(env.admin, "scope_delete", {"scope_id": env.proj_a})
    removed = env.store.dispatch(env.admin, "scope_delete",
                                 {"scope_id": env.proj_a, "delete_contents": True})
    assert removed["removed_rows"] == 2
    with env.store._engine.connect() as conn:
        assert not conn.execute(select(ImprovementAttempt.id).where(
            ImprovementAttempt.scope_id == env.proj_a)).first()


def test_delete_requires_scope_admin_and_delete_permission(env):
    attempt = record(env, env.alice, env.proj_a)
    for actor in (env.alice, env.carol):  # writer and reviewer are not enough
        with pytest.raises(ServiceError) as err:
            env.store.dispatch(actor, "improvement_delete",
                               {"problem_id": attempt["problem_id"]})
        assert err.value.code == "denied"
    env.store.dispatch(env.admin, "scope_policy_set", {
        "scope_id": env.proj_a, "principal_id": env.admin.id,
        "can_export": True, "can_delete": False})
    with pytest.raises(ServiceError, match="delete permission"):
        env.store.dispatch(env.admin, "improvement_delete",
                           {"problem_id": attempt["problem_id"]})
    env.store.dispatch(env.admin, "scope_policy_set", {
        "scope_id": env.proj_a, "principal_id": env.admin.id,
        "can_export": True, "can_delete": True})
    result = env.store.dispatch(env.admin, "improvement_delete",
                                {"problem_id": attempt["problem_id"]})
    assert result == {"problem_id": attempt["problem_id"], "deleted": True,
                      "removed_attempts": 1}
    assert listing(env, env.alice, env.proj_a)["problems"] == []


def test_audit_holds_metadata_only(env):
    attempt = record(env, env.alice, env.proj_a)
    outcome(env, env.carol, attempt["attempt_id"])
    entries = env.store.dispatch(env.admin, "audit_list", {"scope_id": env.proj_a})["entries"]
    actions = {(e["action"], e["actor_id"], e["record_id"]) for e in entries}
    assert ("improvement_record", env.alice.id, attempt["attempt_id"]) in actions
    assert ("improvement_outcome", env.carol.id, attempt["attempt_id"]) in actions
    with env.store._engine.connect() as conn:
        dumped = json.dumps([dict(r) for r in conn.execute(
            select(AuditLog.__table__)).mappings()], default=str)
    assert "completion gate" not in dumped and PROBLEM not in dumped


def test_storage_quota_is_charged_reconciled_and_enforced(tmp_path):
    store = Store(f"sqlite:///{tmp_path / 'quota.db'}", billing_enabled=True,
                  plan_limits={"free_personal": {"max_storage_bytes": 400}})
    store.initialize()
    root = store.bootstrap("acme", "root-admin", ADMIN_TOKEN)["root_scope_id"]
    admin = store.authenticate(ADMIN_TOKEN)
    args = {"scope_id": root, "problem": "p" * 40, "change": "c" * 50,
            "rationale": "r" * 50, "predicted": "d" * 50, "context": "x" * 10}
    attempt = store.dispatch(admin, "improvement_record", args)
    assert store.recalculate_storage(admin.org_id)["storage_bytes"] == 200
    store.dispatch(admin, "improvement_outcome", {
        "attempt_id": attempt["attempt_id"], "observed": "o" * 30, "verdict": "improved",
        "decision": "retain"})
    assert store.dispatch(admin, "billing_status", {})["usage"]["storage_bytes"] == 230
    assert store.recalculate_storage(admin.org_id)["storage_bytes"] == 230
    # 160 further bytes fit (the problem statement is charged once); the next attempt does not.
    store.dispatch(admin, "improvement_record", args)
    with pytest.raises(ServiceError) as err:
        store.dispatch(admin, "improvement_record", args)
    assert err.value.code == "quota_exceeded"
    assert store.recalculate_storage(admin.org_id)["storage_bytes"] == 390
    store.dispatch(admin, "improvement_delete", {"problem_id": attempt["problem_id"]})
    assert store.dispatch(admin, "billing_status", {})["usage"]["storage_bytes"] == 0


async def test_management_api_exposes_the_ledger(access_app):
    store, admin, user_id, app = access_app
    root = store.dispatch(admin, "scope_list", {})["scopes"][0]["scope_id"]
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN,
                                 headers={"Origin": ORIGIN}) as client:
        assert (await client.post("/manage/login", json={"token": ADMIN})).status_code == 200
        created = await client.post("/manage/api/improvement_record", json={
            "scope_id": root, "problem": PROBLEM, "change": "Add a completion gate",
            "rationale": "Runs ended without a test command", "predicted": "Fixes task 3"})
        assert created.status_code == 200
        refused = await client.post("/manage/api/improvement_outcome", json={
            "attempt_id": created.json()["attempt_id"], "observed": "o",
            "verdict": "unknown", "decision": "retain"})
        assert refused.status_code == 400
        listed = await client.post("/manage/api/improvement_list", json={"scope_id": root})
        assert listed.status_code == 200
        assert listed.json()["problems"][0]["summary"]["awaiting_outcome"] == 1
