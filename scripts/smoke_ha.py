#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Isolated two-replica health/failover exercise. Requires existing setup secret files.

Creates only a fresh generated Compose project, stops one API container, and removes
that project's containers/volumes afterwards. It never targets the installed project.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import time
import urllib.error
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=18090)
    parser.add_argument("--subnet", default="172.30.249.0/24")
    parser.add_argument("--proxy-ip", default="172.30.249.10")
    args = parser.parse_args()
    project = "distributedai-ha-test-" + secrets.token_hex(5)
    root = Path(__file__).resolve().parents[1]
    env = {**os.environ, "PORT": str(args.port), "PUBLIC_URL": f"http://127.0.0.1:{args.port}/mcp",
           "APP_SUBNET": args.subnet, "WEB_PROXY_IP": args.proxy_ip}
    command = ["docker", "compose", "-p", project, "-f", "compose.yaml", "-f", "compose.split.yaml", "-f", "compose.ha.yaml"]
    def compose(*arguments):
        return subprocess.run([*command, *arguments], env=env, cwd=root, check=True, capture_output=True, text=True).stdout
    try:
        compose("up", "-d", "--build", "--wait", "--wait-timeout", "180", "web")
        containers = compose("ps", "-q", "api").split()
        if len(containers) != 2:
            raise RuntimeError("Expected two API replicas")
        inspection = json.loads(subprocess.run(["docker", "inspect", *containers], check=True,
                                               capture_output=True, text=True).stdout)
        if any(item["Config"]["Labels"].get("com.docker.compose.project") != project for item in inspection):
            raise RuntimeError("Container ownership mismatch")
        url = f"http://127.0.0.1:{args.port}/healthz"
        with urllib.request.urlopen(url, timeout=5) as response:
            if response.status != 200:
                raise RuntimeError("Initial health failed")
        subprocess.run(["docker", "stop", containers[0]], check=True, capture_output=True)
        deadline = time.monotonic() + 30
        successes = 0
        while time.monotonic() < deadline and successes < 5:
            try:
                with urllib.request.urlopen(url, timeout=3) as response:
                    successes = successes + 1 if response.status == 200 else 0
            except (urllib.error.URLError, TimeoutError, socket.timeout):
                successes = 0
            time.sleep(1)
        if successes != 5:
            raise RuntimeError("Surviving replica did not sustain health responses")
        print("Isolated two-replica health failover passed. Database/host/proxy HA and in-flight mutation recovery were not tested.")
    finally:
        compose("down", "--volumes", "--remove-orphans")


if __name__ == "__main__":
    main()
