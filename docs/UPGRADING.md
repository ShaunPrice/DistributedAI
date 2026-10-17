<!-- SPDX-License-Identifier: Apache-2.0 -->
# Upgrading an existing installation

## Schema versions

| Schema | Release | Difference |
|---|---|---|
| 0.1 | Up to commit `fec5178` | Baseline |
| 0.2 | Compact context, evidence and attention release | Adds one table, `memory_evidence`. No existing table, column or row changes |

The upgrade is additive. Existing ciphertext is not decrypted or re-encrypted, existing records receive no invented provenance (they report `unknown`), and the encryption keys and settings are unchanged. Normal server start (`distributedai init` / `initialize()`) already creates missing tables. The utility below lets operators inspect, back up and apply it explicitly, which is required where the service role cannot run DDL.

## 1. Preflight (dry run, no changes)

```sh
distributedai upgrade
```

The command needs only `DATABASE_URL` (or `DB_PASSWORD_FILE`/`DB_HOST`); it does not load the content master key. It prints JSON containing counts and names only, never content:

- `current_schema`: `empty`, `0.1`, `0.2` or `unknown`. An `unknown` (partial or unexpected) schema is refused.
- `actions`: what `--apply` would do.
- `counts`: encrypted/plaintext payload field counts, evidence rows, unencrypted evidence rows and orphaned evidence rows.
- `warnings`: e.g. plaintext payloads, which require the existing offline `distributedai encrypt-existing` step before serving.

## 2. Back up

Stop writers or schedule a maintenance window, then take and verify an encrypted whole-database backup as described in [backup and recovery](BACKUP_RECOVERY.md):

```sh
uv run python scripts/db_backup.py backup \
  --key-file /secure/backup-recipient.key \
  --output /backups/distributedai-before-0.2.pg.enc
```

Retain the content master key and every historical KMS key version separately; a backup without them cannot be decrypted.

## 3. Apply

```sh
distributedai upgrade --apply --confirm-backup
```

The change runs in one transaction under the same PostgreSQL advisory lock used for schema bootstrap, so concurrent replicas or repeated runs are safe. Re-running reports `changed: false`. It verifies the resulting schema and also deletes evidence rows whose memory proposal no longer exists (possible only after a code rollback; see below), reporting `pruned_orphan_evidence_rows`. Then deploy the new application version.

## Rollback and recovery

- **Code-only rollback (preferred):** deploy the previous version. It ignores `memory_evidence`. Any evidence for keys deleted while the old code runs is left behind; re-running `distributedai upgrade --apply --confirm-backup` after returning to 0.2 removes it, and the new code never attaches such rows to a later record that reuses a key.
- **Schema rollback to 0.1:** `distributedai upgrade --rollback --confirm-backup` drops `memory_evidence`. It refuses while evidence rows exist unless `--allow-evidence-loss` is also given. Running it on 0.1 changes nothing.
- **Failed upgrade:** the transaction rolls back automatically. If the database is in doubt, restore the pre-upgrade backup into a new empty database (see [backup and recovery](BACKUP_RECOVERY.md)), verify, then switch traffic.

## Client compatibility

Old MCP clients need no change. New outputs are opt-in (`view`, `memory_context`, `max_bytes`, `evidence`, `attention_digest`). See [compact context, evidence and attention](CONTEXT.md). The scoped Cognitive-Memory importer is unchanged and continues to write plain `source` strings without structured evidence.

## Validation

The upgrade tests start from `tests/fixtures/schema-0.1-synthetic.sql`, produced by released commit `fec5178` with fictional names, synthetic tokens and a test-only key-encryption key. They cover detection, the dry run, backup confirmation, idempotent apply, unchanged ciphertext, unknown legacy provenance, encrypted new evidence, rollback guards and orphan pruning; the PostgreSQL suite repeats detection and concurrent apply. These are not tests of your production data. Rehearse against a restored copy before upgrading a live installation.
