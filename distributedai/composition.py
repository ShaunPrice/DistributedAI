# SPDX-License-Identifier: AGPL-3.0-only
"""Composition root: the only runtime module that wires all three layers together."""
from .config import Settings
from .presentation.mcp import Limits, create_server
from .application.workspace import WorkspaceApplication
from .application.keys import KeyApplication


def as_application(repository, settings, *, initialize_compat=False):
    if isinstance(repository, WorkspaceApplication):
        return repository
    from .persistence.checkout import compose_billing_application
    from .application.sessions import BrowserSessions
    from .persistence.sessions import SQLBrowserSessions, metadata
    if initialize_compat:
        metadata.create_all(repository._engine)
    sessions = BrowserSessions(SQLBrowserSessions(repository._engine))
    keys = KeyApplication(repository, repository.crypto, settings.tenant_key_providers) if getattr(repository, "crypto", None) else None
    billing = compose_billing_application(repository, settings)
    return WorkspaceApplication(repository, metered=repository.billing.enabled,
        keys=keys, sessions=sessions, billing_application=billing, platform=getattr(repository, "platform", None))


def configured_application(settings):
    from .runtime import configured_store
    return as_application(configured_store(settings), settings)


def create_app(settings=None):
    settings = settings or Settings.from_env()
    store = configured_application(settings)
    app = create_server(store, settings).streamable_http_app()
    from .presentation.billing import webhook_routes
    app.routes.extend(webhook_routes(store))
    if settings.management_key:
        from starlette.routing import Mount
        from .presentation.management import management_app
        app.routes.append(Mount("/manage", app=management_app(store, settings)))
        if settings.platform_admin_token or settings.platform_subjects:
            from .presentation.platform import platform_app
            app.routes.append(Mount("/platform", app=platform_app(store.platform, settings)))
    from urllib.parse import urlparse
    from starlette.middleware.trustedhost import TrustedHostMiddleware
    from .presentation.security import SecurityBoundary
    return SecurityBoundary(Limits(TrustedHostMiddleware(app, allowed_hosts=[urlparse(settings.public_url).hostname,
                                                           "127.0.0.1", "localhost"]),
                  rpm=settings.requests_per_minute), https=settings.public_url.startswith("https://"))
