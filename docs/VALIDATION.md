# Validation record

Validated on 2026-09-08. This is an initial implementation, not a security certification.

## Completed

| Check | Result |
|---|---|
| Python unit/transport/management/import suite | 203 passed; 6 PostgreSQL tests skipped in the host-only run |
| Complete Docker suite with PostgreSQL 17.6 | **209 passed**, including all 6 PostgreSQL tests |
| PostgreSQL concurrent job claims across separate store instances | Exactly one winner; result submitted and reviewed through another instance |
| Concurrent first/existing memory version reviews | One accepted proposal and one conflict; no lost update |
| Concurrent accept/reject of the same proposal | One successful transition |
| Concurrent initial bootstrap across replicas | Exactly one initial organisation created |
| Real HTTP MCP collaboration | Distinct identities; unassigned project-code access denied; granted project resolved; reviewed memory retrieved; private message received; leased job completed |
| Real stdio adapter | MCP initialisation, tool listing and shared-memory retrieval passed against the running HTTP service |
| Management API | Secure cookie flags, CSRF rejection, explicit project grants, code-only denial, grant removal and active-session revocation tested |
| Browser inspection | Successful sign-in, project creation/code display, people/access view, test identity revocation visible; no console errors observed |
| Mobile layout | At 390px viewport, document and main element also measured 390px; no horizontal page overflow |
| Container install | Fresh installation and subsequent installer run succeeded; API and database healthy; host API binds only 127.0.0.1 |
| Terraform | AWS VM and AWS/Azure/GCP serverless modules passed `fmt` and `validate`; no cloud resources provisioned |
| Encryption and identity | AES-256-GCM payload/session tampering, tenant isolation, key rotation, mock cloud providers, OIDC claims/PKCE and platform separation covered by automated tests |
| Billing | Quotas, concurrent PostgreSQL reservations, connection revocation/downgrades, verified mock webhooks, checkout binding and metadata-only plan overrides covered |
| Lambda bootstrap | 4 additional unit tests passed for the secret-loading adapter |
| Dependency audit | 70 locked third-party Python versions inventoried; incomplete declarations and native/image review gaps documented |
| Security tools | Runtime-only pip-audit initially found no known vulnerabilities; GitHub subsequently identified development-only pytest CVE-2025-71176, prompting an upgrade to 9.1.1 and inclusion of development dependencies in scanning; Bandit reported no medium/high findings (one low finding remains) |
| Cloud installer dependency | Docker Compose v5.5.0 binary and checksum assets verified through Docker's GitHub release API |
| Code hygiene | Ruff and Git whitespace checks passed; generated secret values absent from staged source |

Earlier core-only idle sample on the development host (before the expanded encryption/billing build): API approximately **71 MiB**, PostgreSQL approximately **37 MiB**. These are one idle measurement, not load-tested capacity estimates. The Docker-reported application image size was approximately 98 MB at that checkpoint.

The expanded browser checks also confirmed that the connections/plan and encryption-key screens render correctly and the separate platform login displays account metadata. No live payment checkout or cloud key operation was performed. The local encrypted installation passed the real HTTP/stdio smoke checks again after the upgrade.

## Independent work and review

Claude implemented the persistence/security engine and core tests. Codex implemented the transport, management console, deployment, import adapter, integration tests and release packaging. Claude then reviewed the integrated code through a separate read-only session, with its review recorded in Cognitive-Memory communications.

Claude also implemented the initial billing engine. Codex reviewed and integrated it, correcting downgrade enforcement, provider-qualified prices, event ordering, storage accounting and connection authentication. The reported test counts are actual Codex-run results, not delegated claims.

Integration found and corrected PostgreSQL parent/audit insert ordering, enabled SQLite foreign-key enforcement, hardened first-version review and bootstrap concurrency, and made MCP output schemas explicit for structured client results. Claude's review prompted clearer management error statuses. Its concern that Compose v5.5.0 did not exist was disproved by checking the official release assets.

The existing Cognitive-Memory connection identified the worker as `unknown` despite explicit worker configuration, preventing formal lease claim/result submission. Collaboration and review were delivered through persisted job messages and actual Claude CLI work; a formally completed queue review is not claimed. The new service's identity/lease behaviour was tested independently. No changes were made to the original memory service or personal records.

## Not yet validated or included

- Actual AWS/Azure/GCP provisioning, DNS/certificate issuance, cloud KMS permissions, confidential computing, restore/failover or measured per-user cost. Terraform was not applied.
- Real Stripe/PayPal transactions, billing reconciliation under provider outages, or self-service user signup. PayPal hosted checkout/portal remains unsupported.
- Cryptographic isolation from a malicious infrastructure operator in the default server-decryption mode. Client-side encryption/confidential computing are documented implementer options, not completed integrations. Structural metadata is not payload-encrypted; infrastructure encryption and access controls remain required.
- A live external identity provider and complete OAuth consent flow in each hosted chatbot.
- End-to-end operation inside every named product (ChatGPT, Hermes, OpenClaw, Perplexity, Claude desktop, etc.). SDK protocol tests do not certify product-specific clients.
- Production load, denial-of-service resilience at scale, penetration testing or guaranteed injection detection.
- Multi-host network faults, database failover, independent database federation or offline synchronisation. Race tests use distinct instances against one PostgreSQL server.
- PostgreSQL row-level-security policies, managed identity lifecycle/SCIM, password signup, per-record retention/deletion policy, or automatic credential rotation.
- Automatic launch/scheduling of AI workers. Jobs/messages require a connected client to poll and act under its own authority.
- Semantic embeddings and the full temporal/graph/consolidation feature set of Cognitive-Memory; import is explicitly scoped proposals from reviewed exports.

The local installation contains an Integration Lab project and synthetic protocol-test records. The protocol test identity was revoked after validation. No personal memory export was imported.

## Interface refinement — 8 September 2026

The organisation and platform consoles now share a locally served SVG identity, navigation icons and responsive design system. Seven actual application screenshots were captured from an isolated fictional demonstration database and visually inspected; the README and console guide use those files directly. Documentation relative links resolve. At the 390px mobile breakpoint the workspace document and main element both measured 390px, with no horizontal page overflow. The focused management/platform/runtime suite passed 13 tests. This visual refinement does not change the outstanding security and live-integration limitations above.

Claude performed a read-only information hierarchy and product-claims review. Codex integrated the useful findings, consolidated the documentation index and narrowed the key-security wording. Claude's suggestion that runtime content encryption was optional was not adopted: configured production runtime requires encryption.

## Layer separation and web security — 8 September 2026

The refactored suite passed **225 tests in Docker**, including PostgreSQL concurrency checks and management/platform logout replay rejection across application instances; four Lambda adapter tests and Ruff also passed. The dependency inventory still matches the unchanged lockfile.

The local installation now runs separate web, application and PostgreSQL containers with its existing volume. Live checks passed for both login flows, CSRF rejection, copied-cookie logout rejection, pages, icon and security headers. Docker inspection confirmed that the web container has no application secrets or database network, and only web publishes a host port. The private application health endpoint works while its HTML route returns 404. Real HTTP/stdio MCP checks passed for separate identities, access denial, reviewed memory, messages and leased jobs; the synthetic client was revoked afterwards.

Live deployment validation found and corrected Caddy file-capability incompatibility with dropped container capabilities, temporary-mount YAML quoting, and preservation of the Host port for MCP origin validation. The web service now has an HTTP health check. CI includes the split deployment and real MCP smoke checks. This is local integration evidence, not cloud HA, ASVS certification or penetration-test completion.

## Ownership, backups and application redundancy — 8 September 2026

The access lifecycle suite passed **253 Docker tests**, including the additional PostgreSQL delete/create race. Host tests passed 246 with seven PostgreSQL opt-in skips. Browser checks in a fictional installation verified personal memory save/read and independent policy administration without another user’s content controls. Two additional genuine screenshots document those screens. The updated installed service passed HTTP/stdio protocol smoke checks and both login/CSRF/logout replay checks.

An isolated PostgreSQL 17 backup/restore drill reproduced all 25 database tables exactly and decrypted the restored authorised Unicode memory with retained recovery material. The archive was mode 0600; tampering was rejected before database invocation. The existing installation was not used as a restore target. An isolated two-API deployment sustained five consecutive health responses after one replica stopped. These drills do not establish multi-host, database or cloud failover, in-flight mutation recovery, or measured recovery objectives.
