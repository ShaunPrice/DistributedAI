# DistributedAI implementation contract

Initial deliverable: portable Python MCP resource server and PostgreSQL shared coordination store. No model runtime, embeddings service, Redis, shell executor, or cloud account required. One logical deployment serves remote clients; multiple API replicas share PostgreSQL. This is not peer-to-peer database federation.

## File ownership

Claude: `distributedai/store.py`, `distributedai/security.py`, `tests/test_store.py`, `tests/test_security.py`. Codex: all other files, integration and review. Do not overwrite another worker's files. Python 3.12, SQLAlchemy 2, psycopg 3; SQLite permitted for fast unit tests, PostgreSQL is deployment authority.

## Core API (synchronous)

`Store(database_url: str)`; `initialize()` creates schema idempotently (serialize PostgreSQL bootstrap); `bootstrap(org: str, principal: str, token: str)` creates initial org and org admin only if no principals exist, rejects weak tokens (<32 chars), stores SHA256 token digest only.

`authenticate(token: str) -> Principal | None`. Principal immutable dataclass with `id`, `org_id`, `name` and optionally other fields. Identity and scope never come from model assertions. Every request reauthenticates; revocation must take effect.

`dispatch(principal: Principal, operation: str, arguments: dict) -> dict` is sole service entry; raises `ServiceError(code: str, message: str)` on invalid/denied input. Strictly validate arguments including bounded strings/lists, enum values, numeric limits. Return JSON-safe values. Re-check active identity inside dispatch. `health() -> bool` database query.

Operations and arguments (optional defaults in parentheses):

- `scope_create`: name, kind (`department` or `project`), parent_id. Org root is a scope of kind `organisation`. Only org admin may create scopes; department/project hierarchy must be valid within org.
- `scope_list`: no args; return accessible scopes.
- `principal_create`: name, token (>=32 chars). Org admin only; create membership by explicit grant separately.
- `principal_revoke`: principal_id. Org admin only; prevent revoking final active org admin.
- `grant`: principal_id, scope_id, role (`reader`, `writer`, `reviewer`, `admin`). Org admin only; grant applies scope and descendants, never across org. Higher roles include read; writer can propose/send/create/claim jobs; reviewer can promote/review; admin all. Org admin remains tenant bound.
- `memory_propose`: scope_id, key, content, expected_version (0), epistemic_kind (`observation`), source (empty). Store proposal, scan all text fields, suspicious content quarantined. Never silently overwrite canonical memory.
- `memory_review`: proposal_id, accept (bool). Reviewer permission on actual proposal scope; proposer cannot self-approve. Reject stale expected_version as conflict. Transactional immutable version history and audit. Quarantined proposals cannot be promoted (rejection allowed).
- `memory_search`: scope_id, query (empty), limit (20, max 100). Search only active canonical records in requested scope plus ancestors the principal may read; never siblings/descendants implicitly. Return provenance, version, trust label `untrusted_data`. Parameterized lexical search is sufficient.
- `memory_history`: scope_id, key. Read only actual authorized scope, bounded history.
- `message_send`: scope_id, recipient_id, body. Require writer, same org and recipient read access to scope; scan content, quarantined messages withheld. No execution.
- `message_inbox`: limit (20, max 100). Recipient only; re-check current scope grants, exclude quarantine.
- `job_create`: scope_id, assignee_id, objective, idempotency_key. Assignee same org with writer access. Scan payload; quarantine unclaimable. Idempotency scoped to creator and scope, reject payload mismatch.
- `job_list`: scope_id, limit (20). Accessible scope only; never expose claim_token.
- `job_claim`: job_id, lease_seconds (300; 30..1800). Assignee only. Atomic database claim; cryptographic token returned ONLY from claim; expired lease reclaimable with token rotation. Bounded max 5 attempts.
- `job_renew`: job_id, claim_token, lease_seconds (300). Validate assignee, unexpired lease, current token, current scope writer grant; renew.
- `job_submit`: job_id, claim_token, result. Same lease fencing; scan result, set awaiting_review or quarantine. Claim token must not leak through reads/audits.
- `job_review`: job_id, accept. Original creator with writer rights or scope reviewer, never assignee; accept completed or reject failed. No automatic memory promotion.
- `job_cancel`: job_id. Creator or reviewer only. Terminal cancellation invalidates lease; cannot undo completed job. Cooperative cancellation means no promise to stop remote execution.
- `audit_list`: scope_id, limit (20). Admin only; metadata with actor/time/action/record ids, no tokens or private body dumps.

Security detector: bounded deterministic Unicode-normalized checks for instruction override, role spoofing, secret exfiltration, encoded/suspicious payloads. Explicitly imperfect heuristic; labels do not establish trust. Entire stored payloads remain untrusted, quarantine cannot be bypassed by setting a flag. No URLs fetched or commands executed.

SQL persistence must enforce organisation ownership in every object lookup, parameterize searches, serialize memory review to avoid concurrent lost updates, and claim jobs using conditional update/row locks. Tests must cover cross-tenant denial, ancestor grants, sibling isolation, spoofed identity, revocation, stale proposal conflicts, self-review denial, quarantine, claim races/fencing/expiry, idempotency and message recipient isolation. Keep fixtures tokens synthetic.
