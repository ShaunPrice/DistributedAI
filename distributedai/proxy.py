"""Stdio-to-HTTP MCP adapter for clients without remote MCP. Never logs credentials."""
import asyncio
import os
from urllib.parse import urlparse

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from .config import secret


async def run_proxy():
    url = os.environ.get("DISTRIBUTEDAI_URL", "http://127.0.0.1:8090/mcp")
    parsed = urlparse(url)
    if parsed.scheme != "https" and not (
        parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    ):
        raise ValueError("Remote MCP requires HTTPS; plain HTTP is only allowed on loopback")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("MCP URL must not contain credentials, query or fragment")
    token = secret("DISTRIBUTEDAI_TOKEN")
    if not token:
        raise ValueError("DISTRIBUTEDAI_TOKEN_FILE or DISTRIBUTEDAI_TOKEN required")
    async with streamablehttp_client(url, headers={"Authorization": f"Bearer {token}"}) as streams:
        async with ClientSession(streams[0], streams[1]) as remote:
            await remote.initialize()
            server = Server("DistributedAI adapter")

            @server.list_tools()
            async def list_tools():
                return (await remote.list_tools()).tools

            @server.call_tool()
            async def call_tool(name, arguments):
                return await remote.call_tool(name, arguments)

            async with stdio_server() as (read, write):
                await server.run(read, write, server.create_initialization_options())


def main():
    asyncio.run(run_proxy())


if __name__ == "__main__":
    main()
