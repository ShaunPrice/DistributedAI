"""Real PostgreSQL races and persistence; opt-in, isolated schema per test, no production writes.

Run using the test image on the Compose network with RUN_POSTGRES_TESTS=1.
"""
from concurrent.futures import ThreadPoolExecutor
import os
import threading
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from distributedai.config import Settings
from distributedai.store import Base, Store, ServiceError

pytestmark = pytest.mark.skipif(os.getenv("RUN_POSTGRES_TESTS") != "1", reason="PostgreSQL integration opt-in")


@pytest.fixture
def env():
    url = Settings.from_env().database_url
    assert url.startswith("postgresql"), "PostgreSQL required"
    engine = create_engine(url)
    schema = "test_" + uuid.uuid4().hex
    with engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    scoped = make_url(url).update_query_dict({"options": f"-csearch_path={schema}"})
    store = Store(scoped.render_as_string(hide_password=False))
    store.initialize()
    boot = store.bootstrap("Integration", "owner", "owner-integration-" * 4)
    owner = store.authenticate("owner-integration-" * 4)
    worker_id = store.dispatch(owner, "principal_create", {"name": "worker", "token": "worker-integration-" * 4})["principal_id"]
    root = boot["root_scope_id"]
    store.dispatch(owner, "grant", {"principal_id": worker_id, "scope_id": root, "role": "writer"})
    worker = store.authenticate("worker-integration-" * 4)
    try:
        yield store, owner, worker, root, scoped.render_as_string(hide_password=False)
    finally:
        store._engine.dispose()
        with engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        engine.dispose()


def race(functions):
    barrier = threading.Barrier(len(functions))
    def run(fn):
        barrier.wait(timeout=10)
        try:
            return fn()
        except ServiceError as exc:
            return {"error": exc.code}
    with ThreadPoolExecutor(max_workers=len(functions)) as executor:
        return list(executor.map(run, functions))


def test_claim_across_replicas_exactly_one_winner(env):
    store, owner, worker, root, url = env
    other = Store(url)
    try:
        job = store.dispatch(owner, "job_create", {"scope_id": root, "assignee_id": worker.id,
                            "objective": "Review the architecture evidence", "idempotency_key": "race"})
        outcomes = race([lambda: store.dispatch(worker, "job_claim", {"job_id": job["job_id"]}),
                         lambda: other.dispatch(worker, "job_claim", {"job_id": job["job_id"]})])
        assert sum("claim_token" in result for result in outcomes) == 1
        winner = next(result for result in outcomes if "claim_token" in result)
        result = other.dispatch(worker, "job_submit", {"job_id": job["job_id"],
                                "claim_token": winner["claim_token"], "result": "Evidence reviewed"})
        assert result["status"] == "awaiting_review"
        assert store.dispatch(owner, "job_review", {"job_id": job["job_id"], "accept": True})["status"] == "completed"
    finally:
        other._engine.dispose()


@pytest.mark.parametrize("initial_version", [0, 1])
def test_concurrent_memory_review_no_lost_update(env, initial_version):
    store, owner, worker, root, url = env
    other = Store(url)
    def propose(content, expected):
        return store.dispatch(worker, "memory_propose", {"scope_id": root, "key": "decision",
                              "content": content, "expected_version": expected})["proposal_id"]
    try:
        if initial_version:
            first = propose("Initial version", 0)
            store.dispatch(owner, "memory_review", {"proposal_id": first, "accept": True})
        a, b = propose("Option A", initial_version), propose("Option B", initial_version)
        outcomes = race([lambda: store.dispatch(owner, "memory_review", {"proposal_id": a, "accept": True}),
                         lambda: other.dispatch(owner, "memory_review", {"proposal_id": b, "accept": True})])
        assert sorted(result.get("status", result.get("error")) for result in outcomes) == ["accepted", "conflict"]
        history = store.dispatch(owner, "memory_history", {"scope_id": root, "key": "decision"})
        assert len(history["versions"]) == initial_version + 1
        records = other.dispatch(worker, "memory_search", {"scope_id": root})["records"]
        assert records[0]["version"] == initial_version + 1
    finally:
        other._engine.dispose()


def test_same_proposal_accept_reject_serialises(env):
    store, owner, worker, root, url = env
    other = Store(url)
    try:
        prop = store.dispatch(worker, "memory_propose", {"scope_id": root, "key": "one", "content": "One proposed value"})["proposal_id"]
        outcomes = race([lambda: store.dispatch(owner, "memory_review", {"proposal_id": prop, "accept": True}),
                         lambda: other.dispatch(owner, "memory_review", {"proposal_id": prop, "accept": False})])
        assert sum("error" not in result for result in outcomes) == 1
    finally:
        other._engine.dispose()


def test_first_bootstrap_serialises_across_replicas(env):
    store, _, _, _, url = env
    # This fixture owns a disposable test-only schema. Recreate it empty for bootstrap race.
    Base.metadata.drop_all(store._engine)
    store.initialize()
    other = Store(url)
    try:
        outcomes = race([
            lambda: store.bootstrap("First", "owner", "first-integration-token-" * 3),
            lambda: other.bootstrap("Second", "owner", "second-integration-token-" * 3),
        ])
        assert sum("org_id" in result for result in outcomes) == 1
        assert sum(result.get("error") == "denied" for result in outcomes) == 1
    finally:
        other._engine.dispose()
