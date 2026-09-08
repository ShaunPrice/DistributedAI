# Tenant content encryption

`distributedai.encryption.CryptoBox` supplies AES-256-GCM authenticated field encryption with independent random 256-bit data encryption keys per organisation. Fresh 96-bit nonces are generated for every field write. Authentication binds ciphertext to its organisation, record, field and key version, preventing ciphertext substitution between tenants or columns. Malformed, plaintext, unavailable-key and tampered inputs fail closed.

The data key is stored only as an encrypted envelope in `tenant_key_versions`. Local deployments wrap it using another AES-256-GCM key loaded from a protected deployment secret file. Keep that master key separate from the database and its backups; losing it loses access to every key it wraps. Never commit it or include it in logs, support bundles, Terraform state or API responses. Back up encrypted data and necessary key versions under separate access controls.

## Organisation-owned keys

Two integration paths exist:

- **Manual BYOK:** an authenticated organisation administrator supplies exactly 32 random bytes over TLS, preferably through an offline secure input channel. `rotate(org_id, provider, imported_key)` wraps the supplied key immediately. It never returns the key. Someone who manually supplies a key necessarily knows it; this is not a way to hide the key from its supplier.
- **Cloud key reference:** configure an organisation-specific, allowlisted provider alias backed by AWS KMS, Azure Key Vault, or Google Cloud KMS. The organisation manages a non-exportable wrapping key and delegates only necessary wrap/unwrap permissions to the service workload identity. The application receives an opaque provider reference; neither the organisation browser UI nor the central administration interface retrieves the provider's raw key. The service wraps a generated random AES-256 data key under that provider key.

Provider registration is trusted deployment configuration. Do not accept arbitrary endpoints, credentials, URLs or provider objects from a tenant request. Resolve submitted references against an organisation-specific allowlist with ownership verification. Global provider availability alone must never authorise one tenant to use another tenant's wrapping key. Use workload identity/default credentials rather than embedded cloud secrets.

The adapters use lazy optional imports: AWS `boto3`; Azure `azure-identity` and `azure-keyvault-keys`; GCP `google-cloud-kms`. Azure uses a **versioned RSA key** and RSA-OAEP-256 for envelope wrapping, while all content remains AES-256-GCM. AWS and GCP bind envelope context through provider authenticated data; Azure field authentication independently enforces organisation, record, field and version binding. Keep old key versions and provider aliases available after rotation. Rotation affects new writes; re-encryption of historical records requires a separate controlled migration. No key destruction API is provided.

## Administrative boundary

CryptoBox is an internal data-plane primitive, not an authentication API. All key configuration calls must reauthenticate the actor and require that actor's organisation-admin role for the exact organisation. Central service administrators may manage subscriptions, availability and tenant metadata; they must not receive tenant content endpoints, data-plane tokens, key export, impersonation or key-configuration privileges. Administrative HTTP handlers must not instantiate or expose CryptoBox.

Encryption protects stored ciphertext and helps enforce separation between application roles. It does **not** make this server zero-knowledge: authorised MCP operations require decryption in the data-plane process. A person controlling the host, runtime, deployment secrets, debugger or workload identity could obtain plaintext or use KMS decrypt permissions. Protection against that actor requires a separately controlled data plane, client-side encryption or attested confidential computing and independent key-release policy. A central application administrator lacking those infrastructure capabilities cannot read content through the supported management interface. Do not claim otherwise.

Structural and searchable metadata may remain visible depending on Store integration: tenant identifiers, relationships, timestamps, quotas, access grants and key-version/provider aliases. Protect complete database storage and backups with AES-256 disk/database encryption too. Review integration field coverage before claiming that all user content is encrypted; names, memory keys, provenance, review findings and audit text can also contain user content.

## Integration and verification

Initialise encryption metadata during database setup. Provision each tenant key **before** its first content transaction. Encrypt values on persistence and decrypt only after tenant authorisation, with the same stable row ID and field name. Never select/decrypt every tenant in a central-admin list operation. Existing plaintext rows require an explicit offline migration; decrypt never silently accepts legacy plaintext. Existing canonical records must retain stable IDs during encryption and updates.

Unit tests cover persistence, random ciphertext, tenant/record/field binding, wrong keys, tampering, fail-closed plaintext handling, manual BYOK wrapping, rotation history and mocked provider calls. Cloud SDK adapters have not been verified against live AWS, Azure or GCP accounts. Production deployment requires provider IAM, key policy, network and recovery tests in the target account.

## Configure this deployment

The default runtime requires `.secrets/content_master_key` (base64 of 32 random bytes); setup generates it once. New tenants obtain independent encrypted data keys before their first content operation. The storage integration encrypts memory proposal/current/history content, provenance, screening findings, message bodies and job objectives/results/findings. Structural names, memory key labels, IDs, relationships, timestamps and grants remain searchable metadata, so **AES-256 encrypted database disks and backups are also required**. The AWS VM template enables encrypted EBS; local operators must select encrypted host storage. Do not put secrets in names or labels. Decrypted memory search scans at most 1,000 authorised recent records, returns at most 100, and reports `search_truncated`; no plaintext content search index is created.

Use the organisation console's **Encryption keys** page for rotation. The central console has no key-management route. Manual input is cleared immediately from the form and never returned by the API. The service process necessarily handles the submitted key in memory to wrap it; use the KMS option if administrators must never possess raw key material.

For cloud keys, build `docker build --target cloud-keys -t distributedai:0.1.0 .` and deploy that image without rebuilding the default target. It adds the optional AWS/Azure/GCP SDKs; the default image does not include them. Configure `.secrets/key_providers.json` with trusted aliases:

```json
{
  "example-aws": {"type":"aws","key_id":"arn:aws:kms:REGION:ACCOUNT:key/KEY-ID"},
  "example-azure": {"type":"azure","key_id":"https://VAULT.vault.azure.net/keys/KEY/VERSION"},
  "example-gcp": {"type":"gcp","key_id":"projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY"}
}
```

Allow each organisation to select only its aliases in `.secrets/tenant_key_providers.json`:

```json
{"ORGANISATION_ID": ["example-aws"]}
```

Supply cloud workload identity and restrict its IAM/key permissions to these keys. Key IDs are references, never exported key material. Configuration is controlled by the deployment custodian; a central application admin cannot edit it through the platform API. One operation reuses its unwrapped keys only for that operation, avoiding a provider RPC per content field; no cross-request plaintext key cache is retained.

Provider references: [AWS KMS key concepts](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html), [Azure cryptography client](https://learn.microsoft.com/en-us/python/api/azure-keyvault-keys/azure.keyvault.keys.crypto.cryptographyclient?view=azure-python), [Google KMS authenticated data](https://cloud.google.com/kms/docs/additional-authenticated-data).

## Upgrade an existing installation

Back up the database and keep the new master key separately. Stop **all** API replicas/writers, prepare secrets, build the new image, then run:

```sh
docker compose stop api
docker compose run --rm --no-deps api distributedai encrypt-existing --confirm-writers-stopped
docker compose up -d api
```

The explicit migration widens provenance columns, creates key metadata and converts existing payloads in a database transaction. It verifies existing ciphertext rather than trusting a prefix; reruns are idempotent. Normal reads never accept plaintext legacy content. Retain all key versions required by database backups. Migration does not overwrite or remove the original Cognitive-Memory database.

## Implementer-selected stronger isolation

Confidential computing and client-side encryption are optional architecture choices for the solution implementer, not enabled product claims. A confidential data plane needs attestation-bound key release, independently controlled key policies and cloud-specific recovery procedures. Client-side encryption prevents the service from scanning or searching plaintext; clients must then perform injection screening and content search, and agree on key sharing/recovery. Both preserve the central/tenant administration separation but require additional deployment and client work. The supplied service implements the standard server-side encrypted mode.
