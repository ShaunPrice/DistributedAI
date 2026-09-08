# Moving selected Cognitive-Memory context

DistributedAI is a separate service and database. It reuses Cognitive-Memory's concepts—reviewed proposals, attribution, scoped retrieval, leased work and explicit review—without copying a private database or exposing trusted-local legacy endpoints to the internet.

The original service's temporal entity graph, embedding index, consolidation and full API are not a drop-in schema match. Do not point DistributedAI at the existing Cognitive-Memory database or restore its dump into the new database.

For an explicit staged import:

1. Export only the context approved for the target organisation/project through the existing service's authorised tools. Keep source references and epistemic labels. Do not include tokens, private conversations or personal records merely because they are available.
2. Map each approved record into one JSON object per line with `key`, `content`, `source`, optional `epistemic_kind`, and optional `expected_version` (default 0 for a new key).
3. Create the destination project and an importer identity with writer access. Use an independent reviewer identity.
4. Run the dry run, then explicitly apply to the project's code using the importer token.

```sh
uv run python scripts/import_memories.py /private/export.jsonl
# Set DISTRIBUTEDAI_TOKEN_FILE in your environment to a private importer credential file.
uv run python scripts/import_memories.py /private/export.jsonl --project-code PROJECT_CODE --apply
```

The importer accepts at most 1000 records/10 MB per batch, requires provenance, screens content, and creates proposals. It never promotes imported data to canonical memory. Review the proposed records in the management console. Quarantined content cannot be accepted; correct and resubmit it. A later update must use the current expected version.

Imports are not an atomic batch and are not automatically retried. Save the per-line proposal receipts and reconcile them if a run stops. Re-running a partially successful batch may create duplicate pending proposals, so inspect receipts before retrying. No existing personal memory has been imported by the initial implementation work.
