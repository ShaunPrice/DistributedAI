<!-- SPDX-License-Identifier: Apache-2.0 -->
# Optional accounts, quotas and payments

Billing is **disabled by default**. Self-hosted installations remain unmetered unless `BILLING_ENABLED=true`. When enabled, the initial plan is free personal. Prices are operator configuration; no commercial price is built into the code.

| Plan | Users | Logical instances | Active connections | Logical memory quota |
| --- | ---: | ---: | ---: | ---: |
| Free personal | 1 | 1 | 2 | 10 MiB |
| Personal paid | 1 | 1 | 10 | 100 MiB |
| Organisation starter | 10 | 5 | 25 | 1 GiB |
| Organisation business | 100 | 25 | 250 | 10 GiB |
| Organisation enterprise | 1,000 | 100 | 2,500 | 100 GiB |

The organisation values and memory sizes are configurable defaults, not committed commercial offers. All tiers retain tenant isolation, project assignment, encryption and organisational access controls. An instance is a logical grouping of client connections inside a tenant; creating it does not provision a separate physical container or database. Dedicated deployment is an implementer option.

## Users and connections

A user is an active principal. A connection is a separately issued, revocable AI-client credential owned by one user and bound to one logical instance. Only its SHA-256 digest is persisted; the browser shows the credential once. Reconnecting does not consume another slot. Do not share one credential across multiple tools: arbitrary physical processes behind a shared credential cannot reliably be distinguished by the server.

Use **Connections & plan** in the organisation console to create an instance and issue/revoke connections. Each connection inherits its owner's current project access. Machine credentials cannot perform access-administration operations through MCP; use the management console. With billing enabled, principal browser tokens cannot access MCP directly. OAuth clients additionally require `.secrets/oidc_connections.json` mapping the verified subject to an existing eligible connection ID, alongside the normal subject-to-user mapping. This prevents OAuth bypassing connection limits.

After a downgrade, only the oldest active users/instances/connections within the new limits remain eligible for machine authentication. Nothing is deleted. The owner can still sign in to the management console to reconcile the account. Revocation frees a connection slot. Billing never creates or changes project grants.

## Storage accounting

The quota counts logical UTF-8 bytes, consistently before and after encryption: proposal content/provenance/findings, immutable memory history content/provenance, message bodies/findings, and job objectives/results/findings. Rejected proposals still occupy storage. The current canonical memory copy is excluded because its immutable history is already counted. Structural names, memory keys, access metadata, database indexes and ciphertext overhead are outside this logical-memory quota; apply separate deployment capacity limits for physical storage.

Every admission and storage charge locks the tenant usage row in the same transaction as the write. Existing payloads are counted when the usage row is first created, preventing a fresh allowance when billing is enabled on an old database. Offline `store.recalculate_storage(org_id)` reconciles the counter through authorised decryption. Quota errors return `quota_exceeded`; no automatic content deletion occurs.

## Configuration

Setup creates these read-only secret files:

- `.secrets/billing_plan_limits.json`: optional limit overrides keyed by plan, with `max_users`, `max_instances`, `max_connections`, `max_storage_bytes`; `null` means unlimited.
- `.secrets/billing_prices.json`: provider-qualified product references, for example `{"stripe:price_ABC":"personal_paid","paypal:P-XYZ":"org_business"}`.
- `.secrets/payment_providers.json`: configured adapters. Stripe requires `signing_secret` and, for checkout/portal, `api_key`. PayPal requires `client_id`, `client_secret`, `webhook_id` and optional `sandbox: true`. Supply actual values securely, never through Git or Terraform state.

Set `BILLING_ENABLED=true` and recreate the API after configuration. The public webhook address is `/billing/webhooks/stripe` or `/billing/webhooks/paypal` on the service HTTPS origin. Enable only subscription events required by the adapter; Stripe initial checkout also uses `checkout.session.completed`.

Stripe checkout and its customer portal are integrated into the console. Checkout uses only configured price IDs, fixed return URLs and a persisted server-generated account/session binding. A browser return never grants paid access. A signed completion plus an authenticated retrieval of the current matching Stripe subscription establishes the binding and entitlement. Existing subscription webhooks update it thereafter.

PayPal verifies signatures through PayPal's official verification API, using a fixed trusted API endpoint; it does not fetch the certificate URL supplied in an incoming request. Its subscription webhook interface is implemented. **PayPal hosted checkout and portal are not implemented**: provision its subscription through the provider and register the verified customer/subscription IDs using the trusted billing operator integration. Never expose that binding method as a tenant-controlled API.

The platform administrator can manage account status and configured plan entitlements without project-content access. Low-level trusted integration methods are `Store.assign_plan`, `Store.register_billing_subscription`, `Store.recalculate_storage`; none is a tenant MCP tool. Provider subscriptions must be bound server-side; webhook metadata cannot choose a tenant.

## Event handling and recovery

Stripe verifies timestamped webhook signatures; PayPal uses authenticated provider verification. Event IDs are persisted for replay protection. Older events do not undo newer decisions. Different events sharing a timestamp and unknown product IDs remove paid entitlements and flag reconciliation. Unknown/lapsed statuses fall back to the free plan; later verified, ordered events can restore the appropriate plan. Customer mismatches are rejected. Price mappings are namespaced by provider.

Ambiguous or cancelled/expired checkouts retain a pending record and require offline reconciliation before another checkout is created. This avoids automatically creating a second subscription after a timeout. This initial implementation has no automated dunning, tax configuration, refunds, reconciliation scheduler, directory signup, or customer-account recovery workflow. Configure those business processes before a public commercial launch. Registration and infrastructure provisioning remain controlled operator tasks.

Tests cover free/paid/org limits, concurrent PostgreSQL quota admission, signed event tampering/replay/order, checkout binding, conservative fallback, OAuth/opaque credential enforcement, suspension and encrypted UTF-8 accounting. All provider interactions in tests are mocked; no live payment was taken, and live merchant configuration remains unverified. [Stripe webhooks](https://docs.stripe.com/billing/subscriptions/webhooks) and [PayPal verification](https://developer.paypal.com/docs/api/webhooks/v1/#verify-webhook-signature_post) are the provider references.
