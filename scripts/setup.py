#!/usr/bin/env python3
"""Portable Compose setup; requires Docker Engine/Desktop with Compose v2.

Does not install a privileged Docker daemon, replace existing secrets, or expose ports publicly.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--generate-only", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    folder = root / ".secrets"
    folder.mkdir(mode=0o700, exist_ok=True)
    values = {"db_password": secrets.token_urlsafe(48),
              "bootstrap_token": secrets.token_urlsafe(48), "oidc_subjects.json": "{}",
              "management_key": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()}
    for name, value in values.items():
        try:
            fd = os.open(folder / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue
        with os.fdopen(fd, "w") as output:
            output.write(value + "\n")
    if args.generate_only:
        print("Secret files prepared; existing files preserved.")
        return
    subprocess.run(["docker", "compose", "version"], cwd=root, check=True)
    subprocess.run(["docker", "compose", "up", "-d", "--build", "--wait", "api"], cwd=root, check=True)
    result = subprocess.run(["docker", "compose", "run", "--rm", "bootstrap"],
                            cwd=root, check=True, capture_output=True, text=True)
    print(result.stdout.strip())
    print(json.dumps({"mcp_url": os.getenv("PUBLIC_URL", "http://127.0.0.1:8090/mcp"),
                      "operator_token_file": str(folder / "bootstrap_token")}))


if __name__ == "__main__":
    main()
