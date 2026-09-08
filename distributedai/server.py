# SPDX-License-Identifier: AGPL-3.0-only
"""Public ASGI entry point and compatibility MCP exports."""
from .presentation.mcp import Limits, create_server  # noqa: F401


def create_app(settings=None):
    from .composition import create_app as build
    return build(settings)
