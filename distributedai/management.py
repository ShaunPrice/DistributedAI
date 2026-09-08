# SPDX-License-Identifier: AGPL-3.0-only
"""Backward-compatible composition facade for the management HTTP adapter."""
from .presentation.management import BrowserHeaders, COOKIE, TTL, OPERATIONS, STATIC  # noqa: F401


def management_app(store, settings):
    from .composition import as_application
    from .presentation.management import management_app as adapter
    return adapter(as_application(store, settings, initialize_compat=True), settings)
