# Validation record

Validated on 2026-09-08. This is an initial implementation, not a security certification.

## Completed

| Check | Result |
|---|---|
| Python unit/transport/management/import suite | 87 passed; 5 PostgreSQL tests skipped in the host-only run |
| Complete Docker suite with PostgreSQL 17.6 | **92 passed**, including all 5 PostgreSQL tests |
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
| Terraform | `fmt` and `validate` passed; provider initialisation succeeded without cloud provisioning |
| Cloud installer dependency | Docker Compose v5.5.0 binary and checksum assets verified through Docker's GitHub release API |
| Code hygiene | Ruff and Git whitespace checks passed; generated secret values absent from staged source |

Idle sample on the development host: API approximately **71 MiB**, PostgreSQL approximately **37 MiB**. These are one idle measurement, not load-tested capacity estimates. The Docker-reported application image size was approximately 98 MB at that checkpoint.

## Independent work and review

Claude implemented the persistence/security engine and core tests. Codex implemented the transport, management console, deployment, import adapter, integration tests and release packaging. Claude then reviewed the integrated code through a separate read-only session, with its review recorded in Cognitive-Memory communications.

Integration found and corrected PostgreSQL parent/audit insert ordering, enabled SQLite foreign-key enforcement, hardened first-version review and bootstrap concurrency, and made MCP output schemas explicit for structured client results. Claude's review prompted clearer management error statuses. Its concern that Compose v5.5.0 did not exist was disproved by checking the official release assets.

The existing Cognitive-Memory connection identified the worker as `unknown` despite explicit worker configuration, preventing formal lease claim/result submission. Collaboration and review were delivered through persisted job messages and actual Claude CLI work; a formally completed queue review is not claimed. The new service's identity/lease behaviour was tested independently. No changes were made to the original memory service or personal records.

## Not yet validated or included

- Actual AWS provisioning, DNS/certificate issuance and cloud restore/failover. Terraform was not applied.
- A live external identity provider and complete OAuth consent flow in each hosted chatbot.
- End-to-end operation inside every named product (ChatGPT, Hermes, OpenClaw, Perplexity, Claude desktop, etc.). SDK protocol tests do not certify product-specific clients.
- Production load, denial-of-service resilience at scale, penetration testing or guaranteed injection detection.
- Multi-host network faults, database failover, independent database federation or offline synchronisation. Race tests use distinct instances against one PostgreSQL server.
- PostgreSQL row-level-security policies, managed identity lifecycle/SCIM, password signup, UI OIDC redirects, per-record retention/deletion policy, or automatic credential rotation.
- Automatic launch/scheduling of AI workers. Jobs/messages require a connected client to poll and act under its own authority.
- Semantic embeddings and the full temporal/graph/consolidation feature set of Cognitive-Memory; import is explicitly scoped proposals from reviewed exports.

The local installation contains an Integration Lab project and synthetic protocol-test records. The protocol test identity was revoked after validation. No personal memory export was imported.
