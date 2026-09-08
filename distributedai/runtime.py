# SPDX-License-Identifier: AGPL-3.0-only
"""Build runtime services from deployment secrets; plaintext storage is never a serve option."""
import base64

from .persistence.encryption import CryptoBox, LocalWrapper, AWSKMSWrapper, AzureKeyVaultWrapper, GCPKMSWrapper
from .persistence.workspace import Store


def configured_store(settings, *, encryption=True):
    store = Store(settings.database_url, billing_enabled=settings.billing_enabled,
                  plan_limits=settings.billing_plan_limits)
    store.billing.price_map = dict(settings.billing_prices)
    from .application.payments import StripeProvider, PayPalProvider
    if settings.billing_enabled:
        for name, options in settings.payment_providers.items():
            if name == "stripe":
                provider = StripeProvider(options["signing_secret"], api_key=options.get("api_key", ""))
            elif name == "paypal":
                provider = PayPalProvider(options["client_id"], options["client_secret"], options["webhook_id"],
                    api_base="https://api-m.sandbox.paypal.com" if options.get("sandbox", False) else "https://api-m.paypal.com")
            else:
                raise ValueError("Unsupported payment provider")
            store.billing.register_provider(provider)
    if encryption:
        if not settings.content_master_key:
            raise ValueError("CONTENT_MASTER_KEY_FILE is required; run setup and encrypt-existing before upgrading")
        providers = {"local": LocalWrapper(base64.b64decode(settings.content_master_key, validate=True))}
        factories = {"aws": AWSKMSWrapper, "azure": AzureKeyVaultWrapper, "gcp": GCPKMSWrapper}
        for alias, entry in settings.key_providers.items():
            if alias == "local" or not isinstance(entry, dict) or entry.get("type") not in factories or not isinstance(entry.get("key_id"), str):
                raise ValueError("Invalid configured key provider")
            providers[alias] = factories[entry["type"]](entry["key_id"])
        crypto = CryptoBox(store._engine, providers)
        from .persistence.storage_encryption import enable_encryption
        enable_encryption(store, crypto)
    from .persistence.checkout import metadata as billing_http_metadata
    from .persistence.platform import build_platform_service, metadata as platform_metadata
    from .persistence.encryption import metadata as encryption_metadata
    from sqlalchemy import text
    from .domain import ServiceError
    platform = build_platform_service(store._engine)
    store.platform = platform
    platform.billing = store.billing
    from .persistence.sessions import metadata as session_metadata
    original_initialize = store.initialize
    def initialize():
        original_initialize()
        with store._engine.begin() as conn:
            if conn.dialect.name == "postgresql":
                conn.execute(text("SELECT pg_advisory_xact_lock(13719329)"))
            platform_metadata.create_all(conn)
            billing_http_metadata.create_all(conn)
            encryption_metadata.create_all(conn)
            session_metadata.create_all(conn)
    store.initialize = initialize
    for method in ("authenticate", "resolve_principal"):
        original = getattr(store, method)
        def guarded(value, _original=original):
            principal = _original(value)
            return principal if principal is not None and platform.is_active(principal.org_id) else None
        setattr(store, method, guarded)
    dispatch = store.dispatch
    def guarded_dispatch(principal, operation, arguments):
        verified = store.resolve_principal(getattr(principal, "id", None))
        if verified is None:
            raise ServiceError("denied", "Account or identity unavailable")
        return dispatch(principal, operation, arguments)
    store.dispatch = guarded_dispatch
    return store
