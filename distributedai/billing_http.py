# SPDX-License-Identifier: AGPL-3.0-only
"""Compatibility composition facade for billing HTTP adapters."""
def webhook_routes(store):
    from .persistence.checkout import compose_billing_application
    from .presentation.billing import webhook_routes as adapter
    if getattr(store, "billing_application", None) is None:
        compose_billing_application(store)
    return adapter(store)


def billing_routes(store, settings, identity, csrf):
    from .composition import as_application
    from .presentation.billing import billing_routes as adapter
    return adapter(as_application(store, settings), settings, identity, csrf)


def __getattr__(name):
    from .persistence import checkout
    return getattr(checkout, name)
