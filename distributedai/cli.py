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
        return uvicorn.run("distributedai.server:create_app", factory=True,
                           host=os.getenv("BIND_HOST", "127.0.0.1"), port=8090,
                           access_log=False, proxy_headers=False)
    from .store import Store
    store = Store(Settings.from_env().database_url)
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
