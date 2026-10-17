# SPDX-License-Identifier: AGPL-3.0-only
"""Compact/full record views and byte-bounded context packets; pure functions, no I/O.

Two different promises, deliberately kept apart:

* ``view="compact"`` shortens each record to a preview with a drill-down reference. It
  imposes NO total size limit (``bounded: false``).
* ``max_bytes`` makes a hard-bounded packet: the compact UTF-8 JSON encoding of the
  returned object never exceeds the budget. Whole items are kept or omitted, never cut
  mid-item beyond their chosen view. Mandatory items (constraints and conflicts) are
  always included; if they cannot fit, the request fails explicitly.

The bound is JSON bytes of the result object, not model tokens and not the MCP envelope
(which may also carry a text rendering of the same result).
"""
from __future__ import annotations

import json

FORMAT = "distributedai-context/v1"
VIEWS = ("compact", "full")
PREVIEW_CHARS = 280
MIN_BUDGET = 512
MAX_BUDGET = 1_048_576
SIZE_BASIS = "compact UTF-8 JSON of this object; excludes MCP envelope and text rendering"


class BudgetExceeded(ValueError):
    def __init__(self, required: int, budget: int):
        super().__init__(f"mandatory context needs {required} bytes; budget is {budget}")
        self.required, self.budget = required, budget


def encoded_size(value: object) -> int:
    return len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def preview(text: str, chars: int = PREVIEW_CHARS) -> dict:
    """A compact preview never claims to be the whole value."""
    return {"preview": text[:chars], "chars": len(text), "truncated": len(text) > chars}


def ref(scope_id: str, key: str, version: int) -> dict:
    """Stable drill-down reference; resolves through ``memory_get`` under current access."""
    return {"scope_id": scope_id, "key": key, "version": version}


def build_packet(header: dict, mandatory: list[dict], optional: list[dict], *,
                 max_bytes: int | None, limit_omitted: int = 0,
                 omitted_refs: list[dict] | None = None) -> dict:
    """Assemble a packet from pre-rendered items in priority order.

    ``mandatory`` and ``optional`` items are dicts that each contain a ``ref``.
    ``limit_omitted`` counts candidates already cut by the caller's item limit; their refs
    may be supplied in ``omitted_refs`` (listed only while they fit).
    """
    omitted_refs = list(omitted_refs or [])
    packet = {"format": FORMAT, **header, "bounded": max_bytes is not None,
              "max_bytes": max_bytes, "used_bytes": None, "size_basis": SIZE_BASIS,
              "trust": "untrusted_data", "items": list(mandatory),
              "mandatory": {"count": len(mandatory), "complete": True, "content": "full"},
              "omitted": {"total": 0, "by_reason": {"limit": 0, "budget": 0},
                          "refs": [], "refs_unlisted": 0},
              "drill_down": {"tool": "memory_get", "arguments": ["scope_id", "key", "version"]}}

    def finish(budget_omitted: list[dict], listed: int | None = None) -> None:
        refs = [entry["ref"] for entry in budget_omitted] + omitted_refs
        if listed is not None:
            refs = refs[:listed]
        total = len(budget_omitted) + limit_omitted
        packet["omitted"] = {"total": total,
                             "by_reason": {"limit": limit_omitted, "budget": len(budget_omitted)},
                             "refs": refs, "refs_unlisted": total - len(refs)}

    if max_bytes is None:
        packet["items"].extend(optional)
        finish([])
        return packet

    def size() -> int:
        # used_bytes is part of the measured object, so iterate to a fixed point.
        packet["used_bytes"] = 0
        for _ in range(4):
            measured = encoded_size(packet)
            if measured == packet["used_bytes"]:
                break
            packet["used_bytes"] = measured
        return packet["used_bytes"]

    # Worst case first: every optional item omitted and no reference listed.
    finish(list(optional), listed=0)
    used = size()
    if used > max_bytes:
        raise BudgetExceeded(used, max_bytes)
    # Adding an item costs its encoding plus a separator. This running estimate ignores
    # digit changes in the counters (including used_bytes itself), so the exact check
    # below has the final say and backs out optional content until the packet fits.
    kept: list[int] = []
    for position, item in enumerate(optional):
        cost = encoded_size(item) + 1
        if used + cost <= max_bytes:
            kept.append(position)
            used += cost

    def skipped_items() -> list[dict]:
        chosen = set(kept)
        return [item for position, item in enumerate(optional) if position not in chosen]

    listed = 0
    for entry in [item["ref"] for item in skipped_items()] + omitted_refs:
        cost = encoded_size(entry) + 1
        if used + cost > max_bytes:
            break
        used += cost
        listed += 1

    def assemble() -> int:
        packet["items"] = list(mandatory) + [optional[position] for position in kept]
        finish(skipped_items(), listed=listed)
        return size()

    while assemble() > max_bytes:
        if listed:
            listed -= 1
        elif kept:
            kept.pop()
        else:  # identical to the mandatory-only packet measured above
            raise BudgetExceeded(packet["used_bytes"], max_bytes)
    if encoded_size(packet) != packet["used_bytes"]:
        raise RuntimeError("context packet size accounting failed")
    return packet
