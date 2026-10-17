# SPDX-License-Identifier: AGPL-3.0-only
"""Structured evidence provenance and freshness labels; pure functions, no I/O.

Evidence describes where a proposed memory came from. It travels through the normal
proposal/review flow and is encrypted with the proposal. It never makes a record
authoritative, never refreshes a source and never fetches a URL.

Dates the caller does not supply stay unknown. A record's ``updated_at`` is review time,
not retrieval or observation time, and is never substituted for either.
"""
from __future__ import annotations

import hashlib
import re
from datetime import date, datetime, timedelta, timezone
from urllib.parse import parse_qsl, urlsplit, urlunsplit

FORMAT = "distributedai-evidence/v1"
KINDS = ("web", "document", "measurement", "report", "conversation", "other")
DATE_FIELDS = ("published_at", "retrieved_at", "observed_at")
TEXT_LIMITS = {"title": 300, "publisher": 200, "locator": 300}
MAX_URL = 2000
FUTURE_SKEW = timedelta(days=1)
FRESHNESS = ("current", "stale", "unknown")
# Query parameter names that commonly carry bearer material or signatures.
_CREDENTIAL_PARAMS = re.compile(
    r"^(access[_-]?token|id[_-]?token|refresh[_-]?token|token|auth|authorization|api[_-]?key|"
    r"apikey|key|secret|client[_-]?secret|password|passwd|pwd|session|sessionid|sig|signature|"
    r"x-amz-signature|x-amz-credential|x-amz-security-token|x-goog-signature|x-goog-credential|sv|se|sp)$",
    re.IGNORECASE)


class EvidenceError(ValueError):
    """Invalid evidence; the message never echoes the rejected value."""


def content_sha256(content: str) -> str:
    """Server-computed digest; caller-supplied hashes are not accepted."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def normalize_url(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceError("source_url must be a non-empty string")
    if len(value) > MAX_URL:
        raise EvidenceError(f"source_url exceeds {MAX_URL} characters")
    if any(ord(ch) < 33 or ord(ch) == 127 for ch in value.strip()):
        raise EvidenceError("source_url must not contain whitespace or control characters")
    try:
        parts = urlsplit(value.strip())
        port = parts.port
    except ValueError:
        raise EvidenceError("source_url is not a valid URL") from None
    if parts.scheme.lower() not in {"http", "https"}:
        raise EvidenceError("source_url must use http or https")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise EvidenceError("source_url must not contain credentials")
    host = (parts.hostname or "").lower()
    if not host:
        raise EvidenceError("source_url must include a host")
    for name, _ in parse_qsl(parts.query, keep_blank_values=True):
        if _CREDENTIAL_PARAMS.match(name):
            raise EvidenceError("source_url must not contain credential or signature parameters")
    scheme = parts.scheme.lower()
    default = {"http": 80, "https": 443}[scheme]
    netloc = f"[{host}]" if ":" in host else host
    if port is not None and port != default:
        netloc += f":{port}"
    # Fragments are client-side only; dropping them makes duplicate detection stable.
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def parse_when(value: object, field: str, now: datetime, *, allow_future: bool = False) -> str:
    """Accept YYYY-MM-DD or an ISO 8601 datetime WITH a UTC offset; return canonical text."""
    if not isinstance(value, str) or not value or len(value) > 40:
        raise EvidenceError(f"{field} must be an ISO 8601 date or offset datetime")
    try:
        if len(value) == 10:
            day = date.fromisoformat(value)
            moment = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
            canonical = day.isoformat()
        else:
            moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if moment.tzinfo is None:
                raise EvidenceError(f"{field} needs a UTC offset; naive times are ambiguous")
            moment = moment.astimezone(timezone.utc)
            canonical = moment.isoformat().replace("+00:00", "Z")
    except EvidenceError:
        raise
    except ValueError:
        raise EvidenceError(f"{field} must be an ISO 8601 date or offset datetime") from None
    if not allow_future and moment > now + FUTURE_SKEW:
        raise EvidenceError(f"{field} is in the future")
    return canonical


def moment_of(text: str) -> datetime:
    """Parse text produced by ``parse_when``; dates mean midnight UTC."""
    if len(text) == 10:
        day = date.fromisoformat(text)
        return datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def validate(value: object, *, content: str, now: datetime | None = None) -> dict:
    """Return the stored evidence document. Absent fields are stored as explicit nulls."""
    now = now or datetime.now(timezone.utc)
    if not isinstance(value, dict):
        raise EvidenceError("evidence must be an object")
    allowed = {"source_url", "kind", *TEXT_LIMITS, *DATE_FIELDS}
    extra = set(value) - allowed
    if extra:
        raise EvidenceError(f"unexpected evidence fields: {sorted(extra)}")
    doc: dict = {"format": FORMAT}
    doc["source_url"] = normalize_url(value["source_url"]) if value.get("source_url") is not None else None
    kind = value.get("kind", "other")
    if kind not in KINDS:
        raise EvidenceError(f"kind must be one of {list(KINDS)}")
    doc["kind"] = kind
    for name, limit in TEXT_LIMITS.items():
        text = value.get(name)
        if text is not None and (not isinstance(text, str) or len(text) > limit):
            raise EvidenceError(f"{name} must be a string of at most {limit} characters")
        doc[name] = text or None
    for name in DATE_FIELDS:
        doc[name] = parse_when(value[name], name, now) if value.get(name) is not None else None
    if doc["published_at"] and doc["retrieved_at"] and moment_of(doc["retrieved_at"]) < moment_of(doc["published_at"]):
        raise EvidenceError("retrieved_at precedes published_at")
    if doc["source_url"] is None and doc["locator"] is None and doc["title"] is None:
        raise EvidenceError("evidence needs a source_url, locator or title")
    doc["content_sha256"] = content_sha256(content)
    return doc


def freshness(doc: dict | None, *, now: datetime, stale_after_days: int) -> dict:
    """Label a record current/stale/unknown from caller-supplied dates only.

    The content date is ``observed_at`` or else ``published_at``. Retrieval time alone
    cannot show content is new, but an old retrieval does prove the content is at least
    that old, so it can establish staleness and never currency.
    """
    if not doc:
        return {"status": "unknown", "basis": None, "age_days": None,
                "reason": "no structured evidence"}
    threshold = timedelta(days=stale_after_days)
    for basis in ("observed_at", "published_at"):
        if doc.get(basis):
            age = now - moment_of(doc[basis])
            return {"status": "stale" if age > threshold else "current", "basis": basis,
                    "age_days": max(0, age.days)}
    if doc.get("retrieved_at"):
        age = now - moment_of(doc["retrieved_at"])
        if age > threshold:
            return {"status": "stale", "basis": "retrieved_at", "age_days": age.days}
        return {"status": "unknown", "basis": "retrieved_at", "age_days": None,
                "reason": "content date unknown; recent retrieval does not prove currency"}
    return {"status": "unknown", "basis": None, "age_days": None, "reason": "no dates supplied"}


def public(doc: dict | None) -> dict | None:
    """Evidence as returned to readers: always labelled unverified, never authoritative."""
    if not doc:
        return None
    return {**doc, "authority": "unverified", "trust": "untrusted_data"}


def duplicate_key(doc: dict | None) -> tuple[str, str] | None:
    """Conservative duplicate identity: same normalised URL AND same server content hash.

    Different sources with identical text are corroboration, not duplicates, and are kept.
    """
    if not doc or not doc.get("source_url"):
        return None
    return doc["source_url"], doc["content_sha256"]
