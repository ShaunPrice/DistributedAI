# Serverless deployment options

The MCP data plane can scale its **compute** to zero between requests. Three reusable Terraform modules are provided under `infra/serverless`: AWS Lambda with API Gateway HTTP API, Azure Container Apps Consumption and Google Cloud Run. These modules deploy an existing immutable container image, connect existing infrastructure and reference existing secrets. They do not create databases, identities for customers, payment accounts or secret values, and they have not been applied to live cloud accounts.

| Platform | Compute profile | Secret delivery | Request boundary |
| --- | --- | --- | --- |
| AWS | Lambda container, 512 MB, no provisioned concurrency, maximum 10 concurrent invocations by default | Secrets Manager ARNs loaded at cold start using workload identity | Buffered HTTP responses; Lambda 28 seconds, gateway integration 29 seconds |
| Azure | Container Apps Consumption, 0–3 replicas, 0.5 CPU / 1 GiB | Key Vault references using an existing user-assigned identity | Short HTTP requests; clients poll for work |
| GCP | Cloud Run, 0–3 instances, request-based CPU allocation, 1 CPU / 512 MiB | Secret Manager version references using an existing service account | 30-second request timeout; clients poll for work |

Cloud Run supports zero minimum instances and request-based billing. Azure Container Apps supports zero replicas on its Consumption plan. AWS Lambda Web Adapter supports HTTP API events and ordinary container web servers; this module explicitly uses buffered mode. API Gateway HTTP APIs have a maximum integration timeout of 30 seconds. These choices suit the service's stateless MCP JSON responses, not indefinite streams. [Cloud Run minimum instances](https://docs.cloud.google.com/run/docs/configuring/min-instances), [Cloud Run billing](https://docs.cloud.google.com/run/docs/configuring/billing-settings), [Azure scaling](https://learn.microsoft.com/en-us/azure/container-apps/scale-app), [AWS adapter](https://github.com/aws/aws-lambda-web-adapter), [HTTP API quotas](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-quotas.html).

## Costs and operating behaviour

Scaling compute to zero does not make the complete service free. Managed PostgreSQL, backups, storage, KMS operations, secret retrieval, requests, identity services, monitoring and network paths may still incur charges. VPC connectors, NAT gateways and private endpoints can dominate a small deployment's bill. Compare those costs before selecting a platform or designing cross-cloud database access. No price or savings percentage is assumed here.

Cold starts add latency. Keep the database in the same region, size maximum replicas/concurrency against its connection limit, and use a compatible managed PostgreSQL connection pooler when necessary. The current SQLAlchemy pools multiply across instances; set conservative compute limits until load testing establishes a budget. Database health probes can keep connections active while an instance is running. Do not install periodic keep-warm requests if the objective is idle-cost reduction.

Jobs and messages remain durable in PostgreSQL while compute is stopped. Workers reconnect and poll; a queued job does not launch a worker or guarantee completion. The service does not execute submitted work in background threads after an HTTP response. External schedulers and queue triggers are optional future deployment additions, not installed by these modules. Long-running AI work runs in the client/worker and submits its result through a short request. Treat a network timeout on a mutation as uncertain; reconcile state before retrying.

## Prerequisites and secrets

Use an existing managed PostgreSQL database with TLS verification (`sslmode=verify-full` and trusted CA configuration where necessary), encrypted storage/backups and a private network path. Supply an application role with access to its own schema; perform schema provisioning separately using an appropriately authorised operator identity. These modules do not expose a PostgreSQL port publicly.

Each deployment requires managed secret references for `DATABASE_URL`, `CONTENT_MASTER_KEY` and `MANAGEMENT_KEY`. Values must use the application's existing formats: a PostgreSQL SQLAlchemy URL, a base64-encoded 32-byte content master key and a URL-safe base64-encoded 32-byte AES-256 management-session key. All replicas must resolve the same current key material. Additional referenced secrets can contain `LOGIN_CLIENT_SECRET`, `LOGIN_SUBJECTS`, `OIDC_SUBJECTS`, `KEY_PROVIDERS`, `TENANT_KEY_PROVIDERS`, `PLATFORM_ADMIN_TOKEN` `PLATFORM_SUBJECTS`, `BILLING_PLAN_LIMITS`, `BILLING_PRICES`, `PAYMENT_PROVIDERS` and `OIDC_CONNECTIONS`. Enable optional billing with the non-secret `BILLING_ENABLED` configuration value; omitting it leaves the application default in effect. Do not inject `BOOTSTRAP_TOKEN` into the public service; grant that secret only to a temporary setup job.

Provider aliases and tenant mappings remain server-controlled. Cloud key SDKs require the `cloud-keys` Docker target. Grant the workload identity access only to the referenced secrets and approved wrapping keys. Key material is available to the data plane in memory; infrastructure operators with control of its identity/runtime are outside the central application-admin confidentiality boundary described in [ENCRYPTION.md](ENCRYPTION.md).

Terraform receives resource references only. Do not add secret-value data sources, secret values in `.tfvars`, or credentials as module inputs. Even a Terraform `sensitive` flag does not remove a value from state. Supply cloud-provider credentials through supported workload identity or authenticated operator tooling. Protect state because it still contains resource identifiers and configuration.

## AWS Lambda

Build the normal service with cloud SDK dependencies, then the Lambda wrapper from the repository root:

```sh
docker build --target cloud-keys -t distributedai:cloud-keys .
docker build --platform linux/amd64 -f deploy/Dockerfile.lambda \
  --build-arg SERVICE_IMAGE=distributedai:cloud-keys -t distributedai:lambda .
```

Publish the resulting image to an existing ECR repository and pass its `@sha256:` digest to `infra/serverless/aws`. The adapter version is pinned to 1.0.1. For a release build, also supply an immutable digest for `SERVICE_IMAGE` and review/pin the adapter image digest in your image provenance process. The wrapper retains the non-root service image and fetches individually named secret ARNs at cold start. It rejects unsupported environment names and never logs provider exception details or secret contents.

Provide private subnet and security group IDs. Those subnets need a route to PostgreSQL, Secrets Manager and any external identity-provider discovery/token/JWKS endpoints. A Secrets Manager VPC endpoint alone does not provide access to an external OIDC issuer. The module creates a Lambda role with scoped secret/log permissions and the EC2 network-interface permissions required for VPC Lambda. Optional KMS ARN lists grant only the supplied keys. Configure the referenced resources' own policies accordingly. ECR image-pull access must also be permitted by the repository policy.

The default URL is the generated HTTPS API Gateway endpoint, and the module configures the application host allowlist accordingly. A custom `public_url` requires separate certificate, API custom-domain mapping and DNS setup. Neither long-lived SSE nor response streaming is promised by this HTTP API deployment. Secret rotation is picked up on cold start; recycle existing execution environments through a deployment after rotation when immediate adoption is required.

## Azure Container Apps

Use `infra/serverless/azure` with an existing Container Apps environment supporting the Consumption profile and private database networking. Supply the existing user-assigned identity ID and Key Vault secret URIs. Grant that identity secret-read access at the appropriate scope; if using a private ACR image, set `registry_server` and grant `AcrPull`. Azure retrieves Key Vault-backed secrets using the configured managed identity. [Azure secret references](https://learn.microsoft.com/en-us/azure/container-apps/manage-secrets).

Set `public_url` to your canonical HTTPS `/mcp` endpoint. Configure the certificate, custom domain and DNS outside this module before opening access. The module's output shows the provider-generated FQDN; a subsequent configuration may use that HTTPS FQDN instead of a custom domain. Authentication is enforced by DistributedAI; ingress is public HTTPS with insecure HTTP disabled.

## Google Cloud Run

Use `infra/serverless/gcp` with an existing service account, an existing VPC connector and Secret Manager secret/version references. Grant the account Secret Manager access only to those references and any necessary KMS permissions. Enable required APIs and allow access to the image registry. The module uses private-range VPC egress for database routing and request-based CPU allocation.

Set `public_url` and establish its custom-domain/TLS routing separately. The service URI is also returned for configuring the provider-generated HTTPS address in a subsequent deployment. The module permits public invocation at the transport layer because MCP and browser authentication are enforced inside the application; an organisation policy that prohibits `allUsers` requires an alternative authorised ingress arrangement. Do not remove application authentication to satisfy a cloud ingress check.

## Initialisation and verification

Before routing users to a fresh deployment, run the same immutable application image as an explicit one-off setup job inside the database network, using the same managed-secret references:

1. Run `distributedai init` to create the schema.
2. Run `distributedai bootstrap --org 'Organisation name' --principal operator` with a separate strong `BOOTSTRAP_TOKEN` secret available only to this setup job.
3. Remove the setup job's bootstrap-secret access. Configure provider sign-in and project assignments, then verify management and MCP access through the canonical HTTPS endpoint.

Cloud Run Jobs, Azure Container Apps Jobs or a controlled ephemeral container runner can perform those commands. These job resources are not provisioned by the compute modules. For AWS, use the Lambda image in a controlled container runner; its entrypoint loads the referenced secrets and can then execute the CLI command. Do not use a public HTTP request to initialise the database or create the first admin.

Terraform schema validation is separate from live deployment validation. Before production use, test cold start, cloud login and passkey policy, tenant isolation, key unwrap, database reconnection, billing webhook retries, MCP initialisation/tool calls, lease recovery, timeout reconciliation and provider scale-to-zero behaviour. Confirm that application payloads and credentials are absent from cloud logs. No live-cloud functionality or cost reduction is claimed until those checks pass in the target account.

Repository validation on 8 September 2026: `terraform fmt -check` and `terraform validate` passed for all three modules using the committed provider lock files (AWS 6.63.0, AzureRM 4.81.0 and Google 7.46.1). Four local secret-loader unit tests passed. The Lambda wrapper image has not yet been built or exercised against the Lambda runtime; Terraform validation does not validate IAM access, image startup, networking or a live MCP exchange.
