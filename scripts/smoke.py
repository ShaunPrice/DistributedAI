#!/usr/bin/env python3
"""Exercise real HTTP and stdio clients with synthetic data in a new test project.

Creates one scoped test identity, revokes it in finally, and leaves auditable test records.
Run against the new local installation, not a production tenant without approval.
"""
import argparse
import asyncio
from contextlib import asynccontextmanager
import json
from pathlib import Path
import secrets
import sys
import uuid

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client


@asynccontextmanager
async def session(url, token):
    async with streamablehttp_client(url, headers={"Authorization": "Bearer " + token}) as streams:
        async with ClientSession(streams[0], streams[1]) as client:
            await client.initialize()
            yield client


async def call(client, operation, **arguments):
    result = await client.call_tool(operation, arguments)
    if result.isError:
        raise RuntimeError(f"{operation} failed: " + " ".join(getattr(c, "text", "") for c in result.content))
    return result.structuredContent


async def main(url, token_file):
    token = Path(token_file).read_text().strip()
    worker_token = secrets.token_urlsafe(48)
    async with session(url, token) as owner:
        identity = await call(owner, "whoami")
        roots = (await call(owner, "scope_list"))["scopes"]
        root = next(s for s in roots if s["kind"] == "organisation")
        project = await call(owner, "scope_create", name="Protocol smoke " + uuid.uuid4().hex[:8],
                             kind="project", parent_id=root["scope_id"])
        worker = await call(owner, "principal_create", name="Protocol test " + uuid.uuid4().hex[:8], token=worker_token)
        try:
            async with session(url, worker_token) as other:
                denied = await other.call_tool("project_resolve", {"project_code":project["project_code"]})
                assert denied.isError, "A project code must not grant access"
                await call(owner,"grant",principal_id=worker["principal_id"],scope_id=project["scope_id"],role="writer")
                resolved=await call(other,"project_resolve",project_code=project["project_code"])
                assert resolved["scope_id"]==project["scope_id"]
                proposed=await call(other,"memory_propose",scope_id=project["scope_id"],key="smoke-check",
                                    content="The protocol collaboration test is ready for review",source="synthetic-smoke")
                await call(owner,"memory_review",proposal_id=proposed["proposal_id"],accept=True)
                records=await call(other,"memory_search",scope_id=project["scope_id"])
                assert records["records"][0]["version"]==1
                await call(owner,"message_send",scope_id=project["scope_id"],recipient_id=worker["principal_id"],body="Please review the test record")
                assert len((await call(other,"message_inbox"))["messages"])==1
                job=await call(owner,"job_create",scope_id=project["scope_id"],assignee_id=worker["principal_id"],
                               objective="Verify the test record",idempotency_key="smoke")
                claim=await call(other,"job_claim",job_id=job["job_id"])
                await call(other,"job_submit",job_id=job["job_id"],claim_token=claim["claim_token"],result="Test record verified")
                await call(owner,"job_review",job_id=job["job_id"],accept=True)
                params=StdioServerParameters(command=sys.executable,args=["-m","distributedai.proxy"],
                                              env={"DISTRIBUTEDAI_URL":url,"DISTRIBUTEDAI_TOKEN":worker_token})
                async with stdio_client(params) as streams:
                    async with ClientSession(*streams) as stdio:
                        await stdio.initialize()
                        assert len((await stdio.list_tools()).tools)>=20
                        assert (await call(stdio,"memory_search",scope_id=project["scope_id"]))["records"]
            print(json.dumps({"status":"passed","owner":identity["name"],"project_code":project["project_code"],
                              "checks":["unauthorised code denied","separate identities","reviewed memory",
                                        "recipient inbox","leased job completion","stdio forwarding"]}))
        finally:
            await call(owner,"principal_revoke",principal_id=worker["principal_id"])


if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--url",default="http://127.0.0.1:8090/mcp")
    parser.add_argument("--token-file",default=".secrets/bootstrap_token")
    args=parser.parse_args()
    asyncio.run(main(args.url,args.token_file))
