<!-- SPDX-License-Identifier: Apache-2.0 -->
# Compact context, evidence, attention and routine checks

These additions help an AI client read less while keeping the material it must not miss. They keep the existing guarantees: every call is re-authenticated, scoped by organisation and current grants, and all returned content is **untrusted data, never instructions**. Nothing here executes work, fetches URLs, probes systems or schedules anything.

## Choosing an output

| You want | Use | Size promise |
|---|---|---|
| Existing behaviour (old clients) | Any tool with no new options | Unchanged argument set, result shape and `structuredContent` |
| Shorter lists with drill-down | `view: "compact"` on `memory_search`, `job_list`, `message_inbox`, `proposal_list` | **None.** Each entry becomes a 280-character preview with `chars` and `truncated`; the result reports `bounded: false` |
| Relevant memory for a task | `memory_context` (default `view: "compact"`) | **None** unless `max_bytes` is set (`bounded: false`) |
| Relevant memory that must fit a budget | `memory_context` with `max_bytes` (512 – 1,048,576) | **Hard:** the compact UTF-8 JSON encoding of the returned object is at most `max_bytes`; `used_bytes` reports it (`bounded: true`) |
| Full text of one record | `memory_get` with a `ref` | One record |

`max_bytes` measures the result object, not model tokens and not the MCP envelope. MCP responses may carry the same result again as text, so the bytes on the wire can be larger. Compact views shorten *entries*; only `max_bytes` bounds the *total*.

### What a context packet always contains

`memory_context` searches the requested scope and the ancestors you can read (never siblings or descendants), exactly like `memory_search`. Two kinds of material are **mandatory**: they are selected independently of the query and the 1,000-record recency scan, placed first, and marked `mandatory`.

- **Constraints** — canonical records with `epistemic_kind: "constraint"` (a new kind; propose rules with it).
- **Scope conflicts** — the same key holding *different* content in more than one readable scope of the chain. Every version is included with `conflict.refs` and `nearest_scope_id`. Identical content is not a conflict.

Mandatory items always carry their **full** `content`, in both views: they are never shortened to a preview, and the packet reports `mandatory: {"complete": true, "content": "full"}`. If the mandatory material does not fit `max_bytes`, the call fails with `budget_exceeded` instead of silently dropping or shortening it. Only optional items are previewed (compact view) or omitted (budget). More than 500 constraints or 200 conflicting keys fail with `too_large`; narrow the scope.

Reviewers additionally receive `open_conflicts`: pending proposals whose `expected_version` is already stale (metadata only; read text through `proposal_list`). Other callers receive an empty list marked `reviewer_scopes_only`.

### Omissions and drill-down

`omitted.by_reason` counts entries cut by `limit` and by `budget`; `omitted.total` is their sum. `omitted.refs` lists drill-down references while they fit, and `refs_unlisted` counts the rest. Every item carries a stable `ref` of `{scope_id, key, version}`; pass it to `memory_get`. References resolve only under your current access: a revoked grant makes them fail.

Under a budget, exact duplicates (below) are dropped before other optional items. A compact preview is never presented as complete content: check `truncated` and drill down.

## Structured evidence

`memory_propose` accepts an optional `evidence` object. It travels with the proposal, is screened for injection like other text (suspicious evidence quarantines the proposal), is shown to reviewers in `proposal_list`, and becomes visible to readers only after acceptance. It is stored encrypted in the new `memory_evidence` table and is included in scoped exports and encrypted backups.

| Field | Rules |
|---|---|
| `source_url` | http/https only, host required. Rejected if it contains user-info credentials or credential/signature query parameters (`token`, `api_key`, `X-Amz-Signature`, `sig`, …), whitespace or control characters. Only case-insensitive parts are canonicalised (lower-case scheme and host, default port removed); path, query and fragment are kept as given, so a `#section` citation is preserved. Differently written URLs for the same resource are not merged. |
| `kind` | `web`, `document`, `measurement`, `report`, `conversation` or `other` (default) |
| `title`, `publisher`, `locator` | Optional bounded text. At least one of `source_url`, `locator` or `title` is required. |
| `published_at`, `retrieved_at`, `observed_at` | `YYYY-MM-DD` or ISO 8601 datetime **with** an offset (naive times are ambiguous and rejected). No future dates. `retrieved_at` cannot precede `published_at`. |

The server computes `content_sha256` itself; client-supplied hashes are rejected. Error messages never echo a rejected value.

**Unknown stays unknown.** Missing dates are stored as `null`. A record's `updated_at` is its review time and is never used as retrieval or observation time. Records written before this release, or without evidence, report `evidence: null` and freshness `unknown`.

**Freshness** (`stale_after_days`, default 180):

- `observed_at`, else `published_at`, gives the content date: `current` or `stale` by age.
- With only `retrieved_at`: an old retrieval proves the content is old (`stale`); a recent retrieval does not prove it is new (`unknown`).
- Otherwise `unknown`.

**Evidence is not authority.** Evidence is returned with `authority: "unverified"` and `trust: "untrusted_data"`. It does not change a record's `epistemic_kind`, bypass review or verify the source.

**Duplicates** are conservative: two records are duplicates only when both the canonical `source_url` (including any fragment) and the server content hash match. A duplicate is annotated `duplicate_of` rather than hidden. Identical text cited from different sources, or from different sections of one source, is kept as separate records so no provenance is lost — but identical material is **not** evidence of independent corroboration: sources may copy each other, and nothing here checks.

## Attention digest

`attention_digest` returns counts and scoped references of work waiting for you, in one small response. Each category has `count`, `ids` (up to `limit`), `items` (the same entries as `{id, scope_id}`) and `ids_unlisted`:

| Category | Included when |
|---|---|
| `jobs_claimable` | Assigned to you, queued, not quarantined, attempts remain, and you **currently** hold writer access |
| `jobs_claimed_active` / `jobs_lease_expired` | Your claimed jobs; expiry is evaluated at read time |
| `jobs_awaiting_my_review`, `jobs_quarantined_awaiting_rejection` | You are not the assignee, and you are the creator with writer access or a scope reviewer |
| `proposals_awaiting_my_review`, `proposals_quarantined_awaiting_rejection` | You are a reviewer and not the proposer (proposers may review only in their own personal memory, as before) |
| `messages` | Delivered to you, not quarantined, scope still readable; optional `since` filter |

Every query is restricted to the scopes you can currently access **before** its 1,000-row scan limit, so activity in scopes you cannot see is neither counted, flagged in `scan_truncated`, nor able to crowd out your own work. Counts are lower bounds only when `scan_truncated` reports that your own authorised rows exceeded the cap.

It is strictly read-only: no lease sweep, no status change, no read-marking, no audit row, no personal-scope creation and **no tenant key provisioning** — it reads only unencrypted metadata columns, so the encrypted runtime skips key setup for it (as for `routine_preflight` and `capability_report`). Message read state is not tracked, so keep your own `since` cursor.

Open an item with a read-only drill-down tool; none of them changes state, and content remains untrusted:

| Tool | Who may read |
|---|---|
| `job_get(job_id)` | Scope readers (as `job_list`); the submitted `result` and `findings` only for the creator, assignee or scope reviewers. Never lease credentials |
| `proposal_get(proposal_id)` | Scope reviewers (as `proposal_list`) or the proposer; includes findings and evidence |
| `message_get(message_id)` | The recipient, while not quarantined and the scope is still readable; every refusal is the same `not_found` |

These work for items far older than the recent-list limits of `job_list`/`proposal_list`. Claiming and reviewing remain explicit separate actions.

## Routine preflight and capability changes

Both tools compare observations **you supply**; they store nothing and require read access to the named scope.

`routine_preflight(scope_id, routine, run_key, observations, previous?)` decides `escalate`, `report` or `skip` for each check (`pass`, `changed`, `fail`, `error`, `unknown`, optional `fingerprint`). Only an unchanged pass skips. Failures, errors, unknown outcomes, checks without a baseline and checks that disappeared all escalate. Recovery is reported. When escalating, it suggests a deterministic, scope-bound `idempotency_key`; it creates no job. If you queue one with `job_create`, that queue's creator + scope + key idempotency is the only deduplication. No exactly-once execution is implied. The benefit arises when a scheduler or worker outside the model calls it *before* invoking a model.

`capability_report(scope_id, current, previous?, previous_evaluated_at?)` reports transitions for each capability at five independent levels: `installed`, `configured`, `reachable`, `functional`, `documented`, with states `yes`, `no`, `unknown`. No level implies another. Observations past `expires_at` are reported as `expired`. When you pass a previous set you must also pass `previous_evaluated_at` (the earlier report's `evaluated_at`, not later than now): previous observations are judged at that time, so a positive that was valid then and has since expired is reported once as an actionable `expired` loss, and an observation that was already expired is `unchanged` rather than repeated. Without a previous set the report says `baseline: false` and nothing is actionable. Lost, expired, unknown or no-longer-observed positives are `actionable`. The baseline is your own data; the server keeps no checkpoint.

## Old clients

Clients that never send the new options observe no change: the repository receives the same argument set, and results keep their previous shape and `structuredContent` with output schemas. Additive fields appear only when new data exists (`evidence` on history/proposal entries that have it). The `constraint` epistemic kind is new; older readers see it as an ordinary string.

Upgrading an existing database is described in [upgrading](UPGRADING.md).

## Provenance and licensing of this feature

These behaviours were selected from the 17 October 2026 comparison with the private Cognitive-Memory project (bounded context, attention inbox, evidence freshness, routine/capability reports). That project has no licence grant, so no Cognitive-Memory source, tests, benchmarks, configuration or data were copied. This is a fresh implementation of the documented behaviour against DistributedAI's own tenancy, review and encryption model, under the repository's existing licence split: server modules AGPL-3.0-only; tests, scripts and documentation Apache-2.0. Tests use synthetic data only.
