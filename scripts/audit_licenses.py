# SPDX-License-Identifier: Apache-2.0
"""Inventory publisher-reported licenses for every exact PyPI version in uv.lock.

This is evidence collection, not a legal compatibility decision or an artifact/SBOM scan.
Network requests use only the official PyPI JSON API. No credentials are read or sent.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import tomllib
import zipfile
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ALIASES = {
    "MIT": "MIT", "MIT License": "MIT", "Apache 2.0": "Apache-2.0",
    "Apache-2.0": "Apache-2.0", "Apache License 2.0": "Apache-2.0",
    "Apache Software License": "Apache-2.0", "BSD-3-Clause": "BSD-3-Clause",
    "BSD-2-Clause": "BSD-2-Clause", "ISC": "ISC", "MPL-2.0": "MPL-2.0",
    "Python Software Foundation License": "PSF-2.0",
}


def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def memberships(packages):
    """Conservative closure includes all platform markers and requested extras."""
    by_name = {}
    for package in packages:
        by_name.setdefault(normalize(package["name"]), []).append(package)
    root = next(p for p in packages if p["name"] == "distributedai")
    groups = {"runtime": root.get("dependencies", [])}
    groups.update({"optional:" + name: deps for name, deps in root.get("optional-dependencies", {}).items()})
    groups.update({"development:" + name: deps for name, deps in root.get("dev-dependencies", {}).items()})
    result = {}
    for group, seeds in groups.items():
        pending = list(seeds)
        seen = set()
        while pending:
            dep = pending.pop()
            name = normalize(dep["name"])
            extras = tuple(sorted(dep.get("extra", [])))
            if (name, extras) in seen:
                continue
            seen.add((name, extras))
            for package in by_name.get(name, []):
                result.setdefault((package["name"], package["version"]), set()).add(group)
                pending.extend(package.get("dependencies", []))
                for extra in extras:
                    pending.extend(package.get("optional-dependencies", {}).get(extra, []))
    return result


def wheel_evidence(package):
    candidates = [w for w in package.get("wheels", []) if w.get("size", 99_000_000) < 20_000_000
                  and w["url"].startswith("https://files.pythonhosted.org/")]
    if not candidates:
        return {"status": "No bounded wheel available"}
    wheel = min(candidates, key=lambda w: w.get("size", 99_000_000))
    with urlopen(wheel["url"], timeout=30) as response:
        data = response.read(20_000_001)
    digest = hashlib.sha256(data).hexdigest()
    if len(data) > 20_000_000 or wheel["hash"] != "sha256:" + digest:
        raise ValueError("Wheel hash or size mismatch")
    files = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for member in archive.infolist():
            name = member.filename
            if member.file_size > 1_000_000 or not any(v in name.lower() for v in ("license", "licence", "copying", "notice")):
                continue
            raw = archive.read(member)
            files.append({"path": name, "sha256": hashlib.sha256(raw).hexdigest(),
                          "excerpt": raw.decode("utf-8", errors="replace")[:320]})
    return {"url": wheel["url"], "sha256": digest, "license_files": files,
            "status": "Lockfile hash verified; license files require interpretation"}


def fetch(package):
    name, version = package["name"], package["version"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name + version):
        raise ValueError("Unsupported package identifier")
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    record = {"name": name, "version": version, "source": url}
    try:
        request = Request(url, headers={"User-Agent": "DistributedAI-license-inventory/1.0"})
        with urlopen(request, timeout=30) as response:
            payload = response.read(4_000_001)
        if len(payload) > 4_000_000:
            raise ValueError("Metadata response exceeded limit")
        info = json.loads(payload)["info"]
        if normalize(info["name"]) != normalize(name) or info["version"] != version:
            raise ValueError("Metadata identifier mismatch")
        expression = info.get("license_expression") or ""
        legacy = info.get("license") or ""
        classifiers = [c for c in info.get("classifiers", []) if c.startswith("License ::")]
        normalized = expression or ALIASES.get(legacy.strip(), "")
        record.update({"license_expression": expression or None,
            "normalized_legacy_license": normalized if not expression else None,
            "legacy_license_excerpt": legacy[:240] or None,
            "legacy_license_sha256": hashlib.sha256(legacy.encode()).hexdigest() if legacy else None,
            "license_classifiers": classifiers, "metadata_sha256": hashlib.sha256(payload).hexdigest(),
            "manual_review": not normalized or "LicenseRef" in normalized,
            "declared_license": normalized or "UNRESOLVED",
            "evidence": "publisher-reported version-specific PyPI metadata"})
    except (HTTPError, URLError, TimeoutError, ValueError, KeyError) as exc:
        record.update({"declared_license": "UNRESOLVED", "manual_review": True,
                       "error": type(exc).__name__})
    if record["manual_review"]:
        try:
            record["wheel_evidence"] = wheel_evidence(package)
        except (HTTPError, URLError, TimeoutError, ValueError, zipfile.BadZipFile) as exc:
            record["wheel_evidence"] = {"error": type(exc).__name__}
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=Path("uv.lock"))
    parser.add_argument("--output", type=Path, default=Path("docs/dependency-licenses.json"))
    parser.add_argument("--check-lock", action="store_true", help="Offline: check recorded lock hash and exact package coverage")
    args = parser.parse_args()
    raw = args.lock.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    packages = tomllib.loads(raw.decode())["package"]
    targets = [p for p in packages if p.get("source", {}).get("registry")]
    if args.check_lock:
        audit = json.loads(args.output.read_text())
        expected = {(p["name"], p["version"]) for p in targets}
        actual = {(p["name"], p["version"]) for p in audit["packages"]}
        valid = audit["lock_sha256"] == digest and expected == actual
        print("License inventory matches lockfile" if valid else "License inventory is stale")
        return 0 if valid else 1
    groups = memberships(packages)
    with ThreadPoolExecutor(max_workers=6) as pool:
        records = list(pool.map(fetch, targets))
    for record in records:
        record["groups"] = sorted(groups.get((record["name"], record["version"]), {"lock-only"}))
    records.sort(key=lambda row: (row["name"], row["version"]))
    report = {"schema": "distributedai-license-inventory/v1",
        "generated_at": datetime.now(timezone.utc).isoformat(), "lock_sha256": digest,
        "scope": "All registry packages in uv.lock, including optional SDKs, development dependencies and platform variants; excludes native bundled libraries and container OS",
        "package_count": len(records), "metadata_failure_count": sum("error" in r for r in records),
        "manual_review_count": sum(r["manual_review"] for r in records),
        "packages": records}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"packages": len(records), "manual_review": report["manual_review_count"],
                      "output": str(args.output)}))
    return 2 if report["metadata_failure_count"] else 0


if __name__ == "__main__":
    sys.exit(main())
