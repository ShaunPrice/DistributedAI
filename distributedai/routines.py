# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic routine preflight and capability-change reports; pure functions, no I/O.

Both compare observations the CALLER supplies. Nothing here probes a system, schedules
work, stores state or creates jobs. A suggested idempotency key is only a suggestion:
deduplication is enforced solely by ``job_create`` (creator + scope + key) if the caller
chooses to queue a job. No exactly-once execution is implied.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime

from .evidence import EvidenceError, moment_of, parse_when

OUTCOMES = ("pass", "changed", "fail", "error", "unknown")
LEVELS = ("installed", "configured", "reachable", "functional", "documented")
STATES = ("yes", "no", "unknown")
MAX_ITEMS = 200
MAX_NAME = 200
MAX_FINGERPRINT = 128


def _name(value, field):
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_NAME:
        raise ValueError(f"'{field}' must be a non-empty string of at most {MAX_NAME} characters")
    return value


def _observations(value, field):
    if value is None:
        return {}
    if not isinstance(value, list) or len(value) > MAX_ITEMS:
        raise ValueError(f"'{field}' must be a list of at most {MAX_ITEMS} observations")
    out = {}
    for entry in value:
        if not isinstance(entry, dict) or set(entry) - {"check", "outcome", "fingerprint"}:
            raise ValueError(f"'{field}' entries need only check, outcome and optional fingerprint")
        check = _name(entry.get("check"), "check")
        outcome = entry.get("outcome")
        if outcome not in OUTCOMES:
            raise ValueError(f"outcome must be one of {list(OUTCOMES)}")
        fingerprint = entry.get("fingerprint")
        if fingerprint is not None and (not isinstance(fingerprint, str) or len(fingerprint) > MAX_FINGERPRINT):
            raise ValueError(f"fingerprint must be a string of at most {MAX_FINGERPRINT} characters")
        if check in out:
            raise ValueError("duplicate check name")
        out[check] = {"outcome": outcome, "fingerprint": fingerprint}
    return out


def preflight(scope_id: str, routine: str, run_key: str, current, previous) -> dict:
    """Decide whether a routine result needs attention, without a model in the loop.

    Uncertainty escalates: errors, unknown outcomes, checks without a baseline and checks
    that disappeared all escalate rather than being treated as healthy.
    """
    routine, run_key = _name(routine, "routine"), _name(run_key, "run_key")
    now, before = _observations(current, "observations"), _observations(previous, "previous")
    if not now:
        raise ValueError("'observations' must contain at least one check")
    decisions = []
    for check in sorted(set(now) | set(before)):
        cur, prev = now.get(check), before.get(check)
        if cur is None:
            decision, reason = "escalate", "missing_observation"
        elif cur["outcome"] in {"fail", "error", "unknown"}:
            decision, reason = "escalate", {"fail": "failure", "error": "error", "unknown": "uncertain"}[cur["outcome"]]
        elif prev is None:
            decision, reason = "escalate", "no_baseline"
        elif cur["outcome"] == "changed":
            decision, reason = "escalate", "reported_change"
        elif cur["fingerprint"] != prev["fingerprint"]:
            decision, reason = "escalate", "fingerprint_changed"
        elif prev["outcome"] != "pass":
            decision, reason = "report", "recovered"
        else:
            decision, reason = "skip", "unchanged_pass"
        decisions.append({"check": check, "decision": decision, "reason": reason,
                          "outcome": cur["outcome"] if cur else None})
    overall = ("escalate" if any(d["decision"] == "escalate" for d in decisions)
               else "report" if any(d["decision"] == "report" for d in decisions) else "skip")
    result = {"format": "distributedai-routine-preflight/v1", "scope_id": scope_id,
              "routine": routine, "run_key": run_key, "decision": overall,
              "counts": {name: sum(d["decision"] == name for d in decisions)
                         for name in ("escalate", "report", "skip")},
              "checks": decisions, "side_effects": "none", "trust": "untrusted_data"}
    if overall == "escalate":
        material = json.dumps([scope_id, routine, run_key,
                               [[d["check"], d["reason"], (now.get(d["check"]) or {}).get("fingerprint")]
                                for d in decisions if d["decision"] == "escalate"]],
                              separators=(",", ":"), ensure_ascii=False)
        result["suggested_job"] = {
            "idempotency_key": "routine-" + hashlib.sha256(material.encode()).hexdigest()[:48],
            "note": "Not created. If queued via job_create, its creator+scope+key idempotency is the "
                    "only deduplication; no exactly-once execution is implied."}
    return result


def _capabilities(value, field, now):
    if value is None:
        return {}
    if not isinstance(value, list) or len(value) > MAX_ITEMS:
        raise ValueError(f"'{field}' must be a list of at most {MAX_ITEMS} observations")
    out = {}
    allowed = {"capability", "level", "state", "observed_at", "expires_at"}
    for entry in value:
        if not isinstance(entry, dict) or set(entry) - allowed:
            raise ValueError(f"'{field}' entries allow only {sorted(allowed)}")
        capability = _name(entry.get("capability"), "capability")
        level, state = entry.get("level"), entry.get("state")
        if level not in LEVELS:
            raise ValueError(f"level must be one of {list(LEVELS)}")
        if state not in STATES:
            raise ValueError(f"state must be one of {list(STATES)}")
        try:
            observed = parse_when(entry["observed_at"], "observed_at", now) if entry.get("observed_at") else None
            expires = (parse_when(entry["expires_at"], "expires_at", now, allow_future=True)
                       if entry.get("expires_at") else None)
        except EvidenceError as exc:
            raise ValueError(str(exc)) from None
        if (capability, level) in out:
            raise ValueError("duplicate capability/level observation")
        effective = state
        if expires and moment_of(expires) <= now:
            effective = "expired"
        out[(capability, level)] = {"state": state, "effective": effective,
                                    "observed_at": observed, "expires_at": expires}
    return out


def capability_report(scope_id: str, current, previous, now: datetime,
                      previous_evaluated_at=None) -> dict:
    """Report per-level capability transitions; levels are independent claims.

    ``installed`` never implies ``configured``; ``reachable`` never implies ``functional``;
    ``documented`` says only that documentation claims it. An expired positive
    observation is reported as expired, not as still true.

    Previous observations are evaluated at ``previous_evaluated_at`` (the ``evaluated_at`` of
    the earlier report), not at ``now``: a positive that was valid then and has since expired
    is an actionable loss, and an observation already expired then is unchanged now.
    The baseline is caller-supplied data, not a server-held checkpoint.
    """
    previous_at = None
    if previous:
        if previous_evaluated_at is None:
            raise ValueError("'previous_evaluated_at' is required with previous observations; "
                             "pass the earlier report's evaluated_at")
        try:
            previous_at = moment_of(parse_when(previous_evaluated_at, "previous_evaluated_at", now))
        except EvidenceError as exc:
            raise ValueError(str(exc)) from None
        if previous_at > now:
            raise ValueError("previous_evaluated_at is later than this evaluation")
    elif previous_evaluated_at is not None:
        raise ValueError("'previous_evaluated_at' needs previous observations")
    cur = _capabilities(current, "current", now)
    prev = _capabilities(previous, "previous", previous_at) if previous_at else {}
    changes, unchanged = [], 0
    for key in sorted(set(cur) | set(prev)):
        before = prev[key]["effective"] if key in prev else None
        after = cur[key]["effective"] if key in cur else None
        if after is None:
            change = "not_observed"
        elif before == after:
            unchanged += 1
            continue
        elif after == "expired":
            change = "expired"
        elif after == "yes":
            change = "gained"
        elif after == "no":
            change = "lost" if before == "yes" else "absent"
        else:
            change = "became_unknown" if before == "yes" else "unknown"
        actionable = before == "yes" and change in {"lost", "expired", "became_unknown", "not_observed"}
        changes.append({"capability": key[0], "level": key[1], "change": change,
                        "previous": before, "current": after, "actionable": actionable,
                        **({"observed_at": cur[key]["observed_at"], "expires_at": cur[key]["expires_at"]}
                           if key in cur else {})})
    return {"format": "distributedai-capability-report/v1", "scope_id": scope_id,
            "evaluated_at": now.isoformat().replace("+00:00", "Z"),
            "previous_evaluated_at": previous_at.isoformat().replace("+00:00", "Z") if previous_at else None,
            "baseline": bool(prev), "changes": changes,
            "unchanged": unchanged, "actionable": sum(c["actionable"] for c in changes),
            "levels": list(LEVELS),
            "note": "Levels are independent caller-supplied observations; nothing was probed.",
            "side_effects": "none", "trust": "untrusted_data"}
