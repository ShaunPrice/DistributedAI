# Deployment and operations

## Local installation

Run `python3 scripts/setup.py`. All service data lives in the `distributedai_pgdata` Docker volume. The database has no host-published port. The API is bound to host loopback at port 8090 by default. The application container runs as UID 10001 with a read-only root filesystem and no added capabilities; Compose secret files are mounted read-only.

The setup script generates `.secrets/db_password`, `.secrets/bootstrap_token`, `.secrets/management_key` and `.secrets/oidc_subjects.json`. Keep the whole directory private; it is excluded from Git and Docker build context. Docker Compose file-based secrets are host files, not a remote secret vault. On a shared host, enforce equivalent filesystem permissions (including Windows ACLs).

`docker compose stop` stops the installation without removing data. `docker compose down` removes its containers/network but retains the named data volume. Do not add `--volumes` unless you intend to delete data. Back up before schema or image changes. This initial schema uses an explicit `distributedai init` command; future schema changes must ship versioned migrations before upgrading an existing deployment.

For local source development, `uv sync --frozen` and set `DATABASE_URL` to a dedicated PostgreSQL instance. SQLite is supported for tests, not recommended for distributed deployment.

## Organisation provisioning

The first bootstrap identity is the organisation administrator. Further organisations are provisioned by a trusted database operator, outside MCP. Use a new strong credential file and run the `distributedai organisation --name ... --principal ...` command with `BOOTSTRAP_TOKEN_FILE` set to that file. The command returns IDs, not the secret. It cannot re-bootstrap an existing organisation to replace its admin.

The management console handles project creation, identities, grants and revocation per organisation. For operators who prefer CLI credential issuance, `distributedai client --name ... --scope ... --role writer --token-out /private/new-token` authenticates using `DISTRIBUTEDAI_TOKEN_FILE` and writes a newly generated credential to a new 0600 file. If grant assignment fails after creation, the identity remains unprivileged: correct the grant using the console, or revoke that identity. Never reuse the initial administrator token in every client.

## Internet hosting with Docker

On a Linux host with Docker and a DNS name pointing to it:

1. Install/build the service locally on that host, or load a reviewed application image.
2. Create `.env` with `DOMAIN=memory.example.org`, `PUBLIC_URL=https://memory.example.org/mcp` and `ALLOWED_HOSTS=memory.example.org,127.0.0.1:*,localhost:*`.
3. Recreate the API using that configuration.
4. Run `docker compose -f compose.yaml -f compose.internet.yaml up -d`.

Caddy terminates TLS and obtains certificates once DNS and ports 80/443 are reachable. Port 8090 remains bound to loopback; PostgreSQL remains private on the Compose network. Restrict the host and administration access to your operators. Add edge/global throttling and operational monitoring appropriate to internet traffic; the built-in request budgets are per replica.

Use encrypted disks and protect database backups. Docker does not by itself encrypt database contents or secret files. A trusted local API host has database authority. For replication across hosts, use a private PostgreSQL endpoint with verified TLS (`sslmode=verify-full` and trusted CA), not a publicly exposed unauthenticated database.

## OAuth clients

DistributedAI verifies tokens; it does not run its own authorisation server. Use an existing standards-compatible OAuth/OIDC provider. Configure:

```dotenv
PUBLIC_URL=https://memory.example.org/mcp
OIDC_ISSUER=https://identity.example.org/realms/example
OIDC_JWKS_URL=https://identity.example.org/realms/example/protocol/openid-connect/certs
```

Put a JSON object mapping provider `sub` values to already-provisioned DistributedAI principal IDs in `.secrets/oidc_subjects.json`. The issuer is fixed by deployment configuration; claims cannot choose an organisation or roles. Tokens must have the exact MCP endpoint as their audience, valid `iss`, `sub`, `exp`, `iat`, and an RS256/ES256 signature. Configure provider discovery, client registration, PKCE and redirects for the actual client product. No real provider has been provisioned by this repository's tests. Synthetic signed-token tests cover the resource-server checks.

An opaque bearer deployment does not provide an interactive OAuth consent flow. The management console's initial sign-in accepts issued access tokens; password accounts, self-service signup, SCIM and a browser OIDC redirect flow are not implemented. Use your organisation's secure credential distribution process. Sessions last 30 minutes and require the underlying identity to remain active.

## AWS Terraform

`infra/aws` is a small single-host starting point: Amazon Linux 2023, Docker, PostgreSQL, API, Caddy, encrypted root disk, VPC/subnet/security group, static IP, no SSH ingress, SSM operator access, IMDSv2 and repository-scoped ECR pull permission. Credentials are generated on the host, not embedded in Terraform configuration or state. It is not a high-availability or managed-database design.

Before applying:

- Build and publish a reviewed **linux/amd64** runtime image to an existing private ECR repository in the selected region. Select the `runtime` build target (the `test` target includes development dependencies).
- Supply `image` pinned by digest, `repository_arn`, `domain` and region variables.
- Run `terraform init` and `terraform plan`; review its resources/cost implications.
- An authorised operator can then apply. Create the domain's A record for the output IP. Inspect cloud-init completion via SSM before considering deployment successful.

The cloud bootstrap script generates secrets under `/opt/distributedai/.secrets`, pulls the configured ECR image and starts the containers. Retrieve the initial admin token through a secure SSM session; do not paste it into shared logs. Configure your identity provider separately if needed.

The instance has `prevent_destroy` because its initial database volume is on the instance's root disk. User-data changes do not update a running application automatically. Back up and plan an explicit migration/upgrade before replacing the host. For production, add managed PostgreSQL or an appropriate HA database, tested backups/restores, edge protections, log retention and infrastructure monitoring. The template has been statically validated; cloud provisioning has not been applied or verified.

## Backups

```sh
mkdir -p outputs
docker compose exec -T db pg_dump -U distributedai -d distributedai -Fc > outputs/distributedai.dump
```

Protect and copy backups to your approved encrypted backup location. Test restores into a separate database/deployment before relying on them. Restoring also restores identities, token hashes and grants, so reassess revoked credentials before using a recovered database. Management session encryption keys and OAuth subject bindings need their own protected backup. Runtime health is exposed at `/healthz` without tenant content.
