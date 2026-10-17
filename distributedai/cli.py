# SPDX-License-Identifier: AGPL-3.0-only
"""Operator commands. Database authority is deliberately separate from MCP tenant authority."""
import argparse
import json
import os
import secrets
from pathlib import Path

from .config import Settings, secret


def main():
    parser = argparse.ArgumentParser(prog="distributedai")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve", help="Run authenticated MCP HTTP server")
    sub.add_parser("proxy", help="Adapt remote MCP to local stdio")
    sub.add_parser("init", help="Initialise database schema")
    upgrade = sub.add_parser("upgrade", help="Detect schema version; dry run unless --apply or --rollback")
    upgrade.add_argument("--apply", action="store_true", help="Apply the additive schema upgrade")
    upgrade.add_argument("--rollback", action="store_true", help="Drop the 0.2 evidence table")
    upgrade.add_argument("--confirm-backup", action="store_true", help="Confirm a verified backup exists")
    upgrade.add_argument("--allow-evidence-loss", action="store_true", help="Permit rollback to drop evidence rows")
    migration = sub.add_parser("encrypt-existing", help="Offline conversion of pre-encryption payloads")
    migration.add_argument("--confirm-writers-stopped", action="store_true", required=True)
    boot = sub.add_parser("bootstrap", help="Provision initial organisation only on an empty database")
    boot.add_argument("--org", default="My Organisation")
    boot.add_argument("--principal", default="operator")
    org = sub.add_parser("organisation", help="Database operator: provision another isolated tenant")
    org.add_argument("--name", required=True)
    org.add_argument("--principal", required=True)
    client = sub.add_parser("client", help="Create a client and grant one scope; write token to a NEW file")
    client.add_argument("--name", required=True)
    client.add_argument("--scope", required=True)
    client.add_argument("--role", choices=["reader", "writer", "reviewer", "admin"], default="writer")
    client.add_argument("--token-out", required=True)
    args = parser.parse_args()
    if args.command == "proxy":
        from .proxy import main as proxy
        return proxy()
    if args.command == "serve":
        import uvicorn
        import logging
        audit_logger = logging.getLogger("distributedai.security")
        audit_logger.setLevel(logging.INFO)
        if not audit_logger.handlers:
            audit_logger.addHandler(logging.StreamHandler())
        audit_logger.propagate = False
        return uvicorn.run("distributedai.server:create_app", factory=True,
                           host=os.getenv("BIND_HOST", "127.0.0.1"), port=8090,
                           access_log=False, server_header=False,
                           proxy_headers=bool(os.getenv("TRUSTED_PROXY_IPS")),
                           forwarded_allow_ips=os.getenv("TRUSTED_PROXY_IPS", ""))
    if args.command == "upgrade":
        # Needs only the database URL: no master key, no service start, counts-only output.
        from sqlalchemy import create_engine
        from .persistence import upgrade as schema
        if args.apply and args.rollback:
            parser.error("choose --apply or --rollback, not both")
        engine = create_engine(Settings.from_env().database_url, hide_parameters=True)
        try:
            if args.apply:
                result = schema.apply(engine, confirm_backup=args.confirm_backup)
            elif args.rollback:
                result = schema.rollback(engine, confirm_backup=args.confirm_backup,
                                         allow_evidence_loss=args.allow_evidence_loss)
            else:
                result = schema.plan(engine)
        except schema.UpgradeError as exc:
            print(json.dumps({"error": str(exc)}))
            raise SystemExit(2) from None
        finally:
            engine.dispose()
        print(json.dumps(result, indent=2))
        return
    from .runtime import configured_store
    store = configured_store(Settings.from_env())
    if args.command == "encrypt-existing":
        from .storage_encryption import migrate_existing
        from sqlalchemy import text
        store.initialize()
        # Versioned additive schema upgrade for encrypted provenance strings.
        with store._engine.begin() as conn:
            if conn.dialect.name == "postgresql":
                for table in ("memory_records", "memory_versions", "memory_proposals"):
                    conn.execute(text(f"ALTER TABLE {table} ALTER COLUMN source TYPE TEXT"))
        print(json.dumps(migrate_existing(store, store.crypto)))
        return
    if args.command == "init":
        store.initialize()
        return
    if args.command in {"bootstrap", "organisation"}:
        token = secret("BOOTSTRAP_TOKEN")
        if len(token) < 32:
            parser.error("BOOTSTRAP_TOKEN_FILE must contain a strong token of at least 32 characters")
        if args.command == "bootstrap":
            result = store.bootstrap(args.org, args.principal, token)
        else:
            result = store.create_organisation(args.name, args.principal, token)
        print(json.dumps(result))
    elif args.command == "client":
        actor = store.authenticate(secret("DISTRIBUTEDAI_TOKEN"))
        if actor is None:
            parser.error("DISTRIBUTEDAI_TOKEN_FILE must identify an active organisation admin")
        token = secrets.token_urlsafe(48)
        # Reserve token file first, never overwrite a credential on retry.
        fd = os.open(Path(args.token_out), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as output:
            output.write(token + "\n")
        result = store.dispatch(actor, "principal_create", {"name": args.name, "token": token})
        principal_id = result.get("id") or result.get("principal_id")
        if not principal_id and isinstance(result.get("principal"), dict):
            principal_id = result["principal"]["id"]
        store.dispatch(actor, "grant", {"principal_id": principal_id,
                                        "scope_id": args.scope, "role": args.role})
        print(json.dumps({"principal": result, "token_file": args.token_out}))


if __name__ == "__main__":
    main()
