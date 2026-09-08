# SPDX-License-Identifier: AGPL-3.0-only
"""Compatibility composition wrapper for key HTTP routes."""
def key_routes(store, settings, identity, csrf):
    from .composition import as_application
    from .presentation.keys import key_routes as adapter
    return adapter(as_application(store, settings), settings, identity, csrf)
