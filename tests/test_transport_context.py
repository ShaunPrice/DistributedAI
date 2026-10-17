# SPDX-License-Identifier: Apache-2.0
"""MCP contract for compact views, context, evidence, attention and routine tools.

Old clients: argument sets reaching the repository are unchanged unless a new option is
explicitly chosen, and every tool still returns structuredContent with an output schema.
"""
import httpx

from distributedai.config import Settings
from distributedai.server import Limits, create_server
from test_transport import FakeStore

NEW_TOOLS = {"memory_context", "memory_get", "attention_digest", "routine_preflight", "capability_report"}


async def session(client, headers):
    headers["Authorization"] = "Bearer " + "test-token-" * 5
    init = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                   "clientInfo": {"name": "test", "version": "1"}}}, headers=headers)
    headers["MCP-Protocol-Version"] = init.json()["result"]["protocolVersion"]


async def call(client, headers, name, arguments, ident=[100]):
    ident[0] += 1
    response = await client.post("/mcp", json={"jsonrpc": "2.0", "id": ident[0], "method": "tools/call",
                                               "params": {"name": name, "arguments": arguments}}, headers=headers)
    return response.json()["result"]


async def test_tool_contracts_and_old_client_argument_shapes():
    settings = Settings(database_url="sqlite://", public_url="http://localhost:8090/mcp")
    store = FakeStore()
    server = create_server(store, settings)
    app = Limits(server.streamable_http_app())
    headers = {"Accept": "application/json, text/event-stream"}
    async with server.session_manager.run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost:8090") as client:
            await session(client, headers)
            listed = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, headers=headers)
            tools = {tool["name"]: tool for tool in listed.json()["result"]["tools"]}
            assert NEW_TOOLS <= set(tools)
            for name in NEW_TOOLS | {"memory_search", "job_list", "message_inbox", "proposal_list", "memory_propose"}:
                assert tools[name].get("outputSchema"), name
            for name in NEW_TOOLS:
                assert tools[name]["annotations"]["readOnlyHint"] is True
            legacy = [("memory_search", {"scope_id": "s"}, {"scope_id": "s", "query": "", "limit": 20}),
                      ("job_list", {"scope_id": "s"}, {"scope_id": "s", "limit": 20}),
                      ("message_inbox", {}, {"limit": 20}),
                      ("proposal_list", {"scope_id": "s"}, {"scope_id": "s", "limit": 20}),
                      ("memory_propose", {"scope_id": "s", "key": "k", "content": "c"},
                       {"scope_id": "s", "key": "k", "content": "c", "expected_version": 0,
                        "epistemic_kind": "observation", "source": ""})]
            for name, arguments, expected in legacy:
                result = await call(client, headers, name, arguments)
                assert not result.get("isError") and result["structuredContent"] == {"scopes": []}
                assert store.calls[-1] == ("client", name, expected)
            await call(client, headers, "memory_search", {"scope_id": "s", "view": "compact"})
            assert store.calls[-1][2]["view"] == "compact"
            evidence = {"source_url": "https://example.org/", "observed_at": "2026-10-01"}
            await call(client, headers, "memory_propose", {"scope_id": "s", "key": "k", "content": "c",
                                                           "evidence": evidence})
            assert store.calls[-1][2]["evidence"] == evidence
            await call(client, headers, "memory_context", {"scope_id": "s"})
            assert store.calls[-1] == ("client", "memory_context", {"scope_id": "s", "query": "", "view": "compact",
                                                                    "limit": 50, "stale_after_days": 180})
            await call(client, headers, "memory_context", {"scope_id": "s", "max_bytes": 4096})
            assert store.calls[-1][2]["max_bytes"] == 4096
            await call(client, headers, "attention_digest", {})
            assert store.calls[-1] == ("client", "attention_digest", {"limit": 20})
            await call(client, headers, "routine_preflight", {"scope_id": "s", "routine": "r", "run_key": "k",
                                                              "observations": [{"check": "c", "outcome": "pass"}]})
            assert "previous" not in store.calls[-1][2]
            result = await call(client, headers, "capability_report", {"scope_id": "s", "current": []})
            assert result["structuredContent"] == {"scopes": []}
