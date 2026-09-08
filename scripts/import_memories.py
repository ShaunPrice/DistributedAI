#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Import explicitly exported, reviewed JSONL as proposals. Dry run unless --apply.

Never connects to Cognitive-Memory or reads a database backup automatically.
"""
import argparse
import asyncio
import json
from pathlib import Path

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from distributedai.config import secret
from distributedai.security import scan_payload
from distributedai.config import Settings


def load_records(path):
    if path.stat().st_size > 10_000_000:
        raise ValueError("Import file exceeds 10 MB; split into reviewed batches")
    records = []
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        item = json.loads(line)
        if not isinstance(item, dict) or set(item) - {"key", "content", "source", "epistemic_kind", "expected_version"}:
            raise ValueError(f"Line {number}: unexpected fields")
        for key, bound in [("key", 200), ("content", 20000)]:
            if not isinstance(item.get(key), str) or not 1 <= len(item[key]) <= bound:
                raise ValueError(f"Line {number}: invalid {key}")
        if not isinstance(item.get("source"), str) or not 1 <= len(item["source"]) <= 500:
            raise ValueError(f"Line {number}: provenance source is required, at most 500 characters")
        if item.get("epistemic_kind", "observation") not in {
            "observation", "fact", "belief", "hypothesis", "assumption", "inference", "decision"
        }:
            raise ValueError(f"Line {number}: invalid epistemic_kind")
        version = item.get("expected_version", 0)
        if type(version) is not int or version < 0:
            raise ValueError(f"Line {number}: invalid expected_version")
        records.append(item)
        if len(records) > 1000:
            raise ValueError("Maximum 1000 records per import")
    if len({r["key"] for r in records}) != len(records):
        raise ValueError("Duplicate keys in import batch")
    return records


async def apply(records, url, project_code):
    # Reuse the endpoint validation without requiring a database credential.
    Settings(database_url="unused", public_url=url)
    token = secret("DISTRIBUTEDAI_TOKEN")
    if not token:
        raise ValueError("DISTRIBUTEDAI_TOKEN_FILE is required")
    async with streamablehttp_client(url, headers={"Authorization": "Bearer " + token}) as streams:
        async with ClientSession(streams[0], streams[1]) as client:
            await client.initialize()
            resolved = await client.call_tool("project_resolve", {"project_code": project_code})
            if resolved.isError:
                raise ValueError("Project is not accessible")
            scope = resolved.structuredContent
            scope_id = scope["scope_id"] if "scope_id" in scope else scope["scope"]["scope_id"]
            for index, item in enumerate(records, 1):
                result = await client.call_tool("memory_propose", {"scope_id": scope_id, **item})
                # Receipt contains IDs and status, never source content or credentials.
                print(json.dumps({"line": index, "error": bool(result.isError),
                                  "receipt": result.structuredContent if not result.isError else None}))
                if result.isError:
                    raise RuntimeError("Import stopped; inspect existing proposal receipts before retrying")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=Path)
    parser.add_argument("--url", default="http://127.0.0.1:8090/mcp")
    parser.add_argument("--project-code")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    records = load_records(args.file)
    print(json.dumps({"records": len(records), "flagged": sum(bool(scan_payload(r)) for r in records),
                      "mode": "apply" if args.apply else "dry_run"}))
    if args.apply:
        if not args.project_code:
            parser.error("--project-code required for explicit destination")
        asyncio.run(apply(records, args.url, args.project_code))


if __name__ == "__main__":
    main()
