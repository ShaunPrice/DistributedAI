# SPDX-License-Identifier: Apache-2.0
import hashlib
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import create_engine, func, select

from distributedai.application.sessions import BrowserSessions
from distributedai.persistence.sessions import SQLBrowserSessions, metadata, revocations


class FakeRepository:
    def __init__(self):
        self.values = {}
    def is_revoked(self, digest, now):
        return self.values.get(digest, 0) > now
    def revoke(self, digest, expires, now):
        self.values[digest] = max(self.values.get(digest, 0), expires)


def test_application_hashes_cookies_and_separates_purposes():
    repo = FakeRepository()
    now = [1000.0]
    management = BrowserSessions(repo, clock=lambda: now[0])
    platform = BrowserSessions(repo, purpose="platform", clock=lambda: now[0])
    cookie = "synthetic-sensitive-cookie"
    assert not management.is_revoked(cookie)
    management.revoke(cookie, 30)
    assert management.is_revoked(cookie)
    assert not platform.is_revoked(cookie)
    assert cookie not in str(repo.values)
    assert all(len(key) == 64 for key in repo.values)
    now[0] = 1030
    assert not management.is_revoked(cookie)
    assert management.is_revoked("")
    management.revoke("", 30)
    with pytest.raises(ValueError):
        management.revoke(cookie, True)


@pytest.fixture
def database(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'sessions.db'}")
    metadata.create_all(engine)
    return engine


def test_logout_replay_persists_across_instances_and_expires(database):
    now = [1000.0]
    first = BrowserSessions(SQLBrowserSessions(database), clock=lambda: now[0])
    second = BrowserSessions(SQLBrowserSessions(database), clock=lambda: now[0])
    cookie = "synthetic-private-browser-cookie"
    assert not second.is_revoked(cookie)
    first.revoke(cookie, 1800)
    assert second.is_revoked(cookie)
    with database.connect() as conn:
        rows = conn.execute(select(revocations)).mappings().all()
    assert cookie not in str(rows)
    assert set(rows[0]) == {"digest", "expires_at"}
    now[0] = 2800
    assert not second.is_revoked(cookie)


def test_concurrent_repeated_logout_cannot_shorten_revocation(database):
    repo = SQLBrowserSessions(database)
    digest = hashlib.sha256(b"synthetic-cookie").hexdigest()
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda ttl: repo.revoke(digest, 1000 + ttl, 1000), [100, 500, 10, 200]))
    assert repo.is_revoked(digest, 1499)
    assert not repo.is_revoked(digest, 1500)
    with database.connect() as conn:
        assert conn.scalar(select(func.count()).select_from(revocations)) == 1


def test_expired_cleanup_is_bounded(database):
    repo = SQLBrowserSessions(database)
    for number in range(105):
        repo.revoke(hashlib.sha256(str(number).encode()).hexdigest(), 1001, 1000)
    digest = hashlib.sha256(b"current").hexdigest()
    repo.revoke(digest, 2000, 1002)
    with database.connect() as conn:
        assert conn.scalar(select(func.count()).select_from(revocations)) == 6
    repo.revoke(digest, 2000, 1002)
    with database.connect() as conn:
        assert conn.scalar(select(func.count()).select_from(revocations)) == 1


def test_database_failure_does_not_report_a_live_session(database):
    sessions = BrowserSessions(SQLBrowserSessions(database))
    metadata.drop_all(database)
    with pytest.raises(Exception):
        sessions.is_revoked("synthetic-cookie")
