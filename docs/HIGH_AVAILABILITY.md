<!-- SPDX-License-Identifier: Apache-2.0 -->
# Optional availability configurations

`compose.ha.yaml` adds two stateless API replicas behind the separate web proxy, sharing PostgreSQL and the same deployment secrets. This is **application redundancy on one Docker host**. The host, web proxy and default PostgreSQL container remain single points of failure; this overlay does not establish a full HA cluster or an SLA.

After generating the usual secret files and building the service:

```sh
docker compose -f compose.yaml -f compose.split.yaml -f compose.ha.yaml up -d --build --wait web
```

The proxy resolves the `api` service's IPv4 addresses every five seconds and distributes requests round-robin. Passive failure tracking helps avoid a failed backend. Dynamic upstreams do not run active Caddy health checks; the application containers retain their Docker health checks. See [Caddy dynamic upstreams](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#dynamic-upstreams).

Automatic proxy retries are disabled because an MCP mutation may have committed before its response failed. Clients should reconcile operation state before retrying a write. Temporary failed requests during discovery/failure detection are possible. All replicas must share content/session keys, identity mappings, revocation storage, plan configuration and PostgreSQL; do not point them at independent databases. Rate limits remain per replica, so public deployments also need a global edge policy.

## Managed PostgreSQL HA

`compose.database-external.yaml` switches the API and setup jobs to a PostgreSQL URL read from an existing protected secret file, and disables startup of the local database service. It can be combined with the split/replicated application configuration:

```sh
export DATABASE_URL_SECRET_FILE=/secure/distributedai-postgresql-url

docker compose -f compose.yaml -f compose.split.yaml -f compose.ha.yaml \
  -f compose.database-external.yaml up -d --build --wait web
```

The file contains a PostgreSQL SQLAlchemy URL using `postgresql+psycopg`, the managed writer endpoint and TLS certificate verification (`sslmode=verify-full`). Mount a trusted CA file when the provider requires one. The URL is read as a Docker secret; it is not printed by the setup. Restrict the destination database role, use private networking, and retain independent encrypted backups.

Provision the database's HA mode separately, for example [Amazon RDS Multi-AZ PostgreSQL](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZSingleStandby.html), [Azure Database for PostgreSQL high availability](https://learn.microsoft.com/azure/postgresql/high-availability/concepts-high-availability), or a [regional Cloud SQL for PostgreSQL instance](https://docs.cloud.google.com/sql/docs/postgres/high-availability). The overlay does not provision these services or enable their failover policies. A multi-host/multi-zone application deployment additionally needs an orchestrator, redundant load balancing, secret distribution, rolling rollout rules and a tested database failover endpoint.

## Isolated application failover exercise

```sh
uv run python scripts/smoke_ha.py
```

This script creates a fresh randomly named `distributedai-ha-test-*` Compose project, starts two API replicas, checks ownership before stopping one, and requires five consecutive successful health responses from the survivor. It then removes only that generated project's containers and volumes. Existing setup secret files are reused, but its PostgreSQL volume is isolated. Defaults use port 18090 and a separate network subnet; use `--port`, `--subnet` and `--proxy-ip` if these conflict with local allocations.

The exercise does not test database failover, host loss, proxy loss, active requests, mutations or a real cloud deployment. Validate those separately under an approved recovery exercise. Configuration checks passed for the Compose overlays and Caddy configuration. The isolated live exercise passed on 8 September 2026: two API replicas started, one was stopped, and the surviving replica sustained five consecutive successful health responses.
