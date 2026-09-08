<!-- SPDX-License-Identifier: Apache-2.0 -->
# Indicative operating costs

Planning estimate prepared 8 September 2026. **Not a measured production bill or a vendor quote.** For a shared service with around 100 active users, budget roughly A$1–3 per active user/month in infrastructure initially.

| Active users | Monthly shared-service budget | Average per active user |
| --- | --- | --- |
| 10 | A$50–150 | A$5–15 |
| 100 | A$80–250 | A$0.80–2.50 |
| 1,000 | A$400–1,500 | A$0.40–1.50 |

Assumptions: around 1,000 MCP calls/user/day, 100 MB logical memory/user, shared PostgreSQL, one region, modest logs/backups, scale-to-zero compute, no HA/SLA or dedicated tenant infrastructure. These are AUD budget allowances, not currency-converted provider quotes. Use regional pricing calculators and a measured load profile before setting customer prices.

Compute is generally a small portion at this workload; database, private networking and operational baseline can dominate. More connections only increase costs when used; two versus ten credentials is not a fivefold infrastructure multiplier. Polling continuously, searching large histories, retention growth and larger responses can materially change these assumptions.

Excluded: AI model API tokens/subscriptions, support labour, payment processing/billing fees, taxes, dedicated databases, confidential computing and client-side encryption implementation. Regional pricing, paid directory features and required compliance controls can also increase costs. Separate AWS customer-managed KMS keys start at US$1/key/month plus requests (and possible rotation increments); random per-tenant data keys do not each require a separately billed KMS key. Organisation BYOK costs should be quoted per organisation.

Primary pricing references checked: [Cloud Run](https://cloud.google.com/run/pricing), [Cognito](https://aws.amazon.com/cognito/pricing/), [AWS KMS](https://aws.amazon.com/kms/pricing/), [Stripe Australia](https://stripe.com/au/pricing). Vendor free allowances are shared/account-dependent and not a guaranteed production budget. Stripe's page includes future-effective pricing; apply the rate effective on the transaction date.

Before commercial launch measure: p50/p95 latency including cold starts, requests/user/day, database CPU and connections, bytes stored and returned, KMS calls/request, secret reads, logs and egress. Reconcile actual monthly totals against active users. Request caps, memory ceilings and finite concurrency should remain configurable; do not sell unlimited automated polling based on this estimate.
