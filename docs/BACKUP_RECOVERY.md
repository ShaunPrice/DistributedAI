<!-- SPDX-License-Identifier: Apache-2.0 -->
# Backup and recovery

The offline operator tool `scripts/db_backup.py` backs up the complete PostgreSQL database as a custom-format `pg_dump`, then encrypts the stream with AES-256-GCM for a separate backup recipient. This is deployment operator authority, not a tenant content-reading API. Central management must invoke any automated whole-database backup through a restricted job with a preconfigured destination and recipient key; it must not accept or return that key in the web UI.

Organisation and project exports are different from whole-database disaster recovery. They must use the application's authenticated, scope-authorised export use case. An organisation administrator may export that organisation; a project administrator may export that project. A tenant export must never select another tenant, broaden a project export to its ancestors/siblings, include credentials, or become a raw SQL dump. Scoped imports require reviewed application-level restoration with new identity/grant decisions; do not pass them to `pg_restore`.

## Whole-database backup

Requirements: Python with the project's `cryptography` dependency, PostgreSQL client tools compatible with the server version, a protected destination, and a libpq connection configuration. Use `PGPASSFILE` or the provider's supported credential mechanism; do not put database URLs containing passwords in command arguments. `PGDATABASE` must be a database name. For remote PostgreSQL, set `PGSSLMODE=verify-full` and configure the appropriate trusted CA.

Generate a distinct backup-recipient key once, on the authorised backup worker. It is not `CONTENT_MASTER_KEY` or `MANAGEMENT_KEY`:

```sh
uv run python scripts/db_backup.py keygen --output /secure/backup-recipient.key
```

Configure `PGHOST`, `PGPORT`, `PGUSER`, `PGDATABASE`, and `PGPASSFILE` through the operator's secure environment. Then run:

```sh
uv run python scripts/db_backup.py backup \
  --key-file /secure/backup-recipient.key \
  --output /backups/distributedai-2026-09-08.pg.enc
```

The tool streams `pg_dump` directly into encryption without writing a plaintext dump. The encrypted archive is published atomically only after a successful dump. Existing output paths are never overwritten. Files are created with mode 0600. The authenticated format contains a version header, random 96-bit nonce, ciphertext and 128-bit GCM tag; the key is 256 bits. The default maximum dump payload is 32 GiB, below GCM's per-invocation bound; `--max-bytes` can lower it. Larger deployments should use a reviewed backup product/object-store envelope workflow rather than raising this bound.

`pg_dump` provides a consistent snapshot of one database. It includes the database's wrapped tenant data-encryption keys, key version metadata and encrypted content. It does not include plaintext deployment wrapping/master keys, cloud provider credentials or permissions, externally held keys, server-wide roles or external object stores. Preserve the required content master key and historical cloud KMS key versions separately under a recovery policy, or restored encrypted content will remain unreadable. Do not store backup archives and their recipient key together.

## Restore into a new empty database

Restore is an explicit offline operation. Provision a new empty database and point the libpq environment at it. Keep the target isolated from public application traffic during validation. Select a scratch directory on an encrypted volume with sufficient space for the decrypted custom dump:

```sh
uv run python scripts/db_backup.py restore \
  --archive /backups/distributedai-2026-09-08.pg.enc \
  --key-file /secure/backup-recipient.key \
  --scratch-dir /encrypted-scratch \
  --confirm-restore
```

The entire archive is decrypted and authenticated before any target database subprocess is invoked. Corrupted, truncated or wrong-key archives cannot reach PostgreSQL. The temporary dump has mode 0600 and is deleted on completion/failure; deletion is not guaranteed physical erasure, hence the encrypted scratch requirement. The tool cannot verify whether the chosen volume is encrypted.

A PostgreSQL catalog check rejects targets with existing user tables, views or sequences. `pg_restore` uses one transaction, exits on error, and does not use `--clean` or `--create`. No destructive overwrite of the running service is provided. Restore schema/content first, then configure matching deployment keys and verify tenant counts, canonical history, queued work, authentication, encryption and project grants before switching traffic. Restoring a historical database can revive older credentials, grants or job leases; rotate/revoke as appropriate and reconcile pending jobs and billing against current external state.

Archive encryption provides confidentiality and integrity, not source authenticity against someone holding the recipient key. Only restore trusted backups; PostgreSQL dumps can contain executable database definitions. Restrict the restore role and review the provenance of externally supplied archives.

## Validation and operations

`tests/test_db_backup.py` checks standard AES-GCM compatibility, streaming round trips, unique nonces, wrong-key/tamper/truncation rejection before database invocation, bounded sizes, permissions, failed-dump cleanup, empty-target checks and transactional restore arguments. PostgreSQL subprocesses are mocked in that suite. A separate live PostgreSQL 17 drill used a dedicated temporary container and two fresh databases: all 25 application tables matched by a canonical row-content fingerprint after restore, authorised Unicode memory decrypted correctly with the separately retained content key, the archive had mode 0600, and a tampered archive was rejected before any database subprocess. Temporary plaintext files and the test container were removed. This verifies the local recovery path; a production/cloud restoration and recovery-time exercise remains deployment-specific.

Set a retention schedule, copy encrypted archives off the primary host, monitor job completion, and perform regular restore drills. HA replication is not a backup: it can replicate accidental deletion or corrupt application state. Define and measure recovery-point and recovery-time objectives for the chosen deployment.
