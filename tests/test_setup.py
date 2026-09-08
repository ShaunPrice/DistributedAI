# SPDX-License-Identifier: Apache-2.0
"""Secrets must remain private on the host and readable by container UID 10001."""
from pathlib import Path
import json
import shutil
import subprocess
import sys


def test_setup_preserves_values_and_secures_parent_for_linux_bind_mount(tmp_path):
    scripts = tmp_path / 'scripts'
    scripts.mkdir()
    shutil.copyfile(Path(__file__).parents[1] / 'scripts/setup.py', scripts / 'setup.py')
    subprocess.run([sys.executable, str(scripts / 'setup.py'), '--generate-only'], check=True, capture_output=True)
    folder = tmp_path / '.secrets'
    original = (folder / 'content_master_key').read_bytes()
    assert folder.stat().st_mode & 0o777 == 0o700
    assert (folder / 'content_master_key').stat().st_mode & 0o777 == 0o444
    subprocess.run([sys.executable, str(scripts / 'setup.py'), '--generate-only'], check=True, capture_output=True)
    assert (folder / 'content_master_key').read_bytes() == original


def test_setup_support_defaults_preserve_override_and_validate(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    script = scripts / "setup.py"
    shutil.copyfile(Path(__file__).parents[1] / "scripts/setup.py", script)
    command = [sys.executable, str(script), "--generate-only"]
    subprocess.run(command + ["--solution-support-url", "https://solution.example/support",
        "--org-support-url", "https://org.example/help", "--solution-support-user", "staff"],
        check=True, capture_output=True)
    config = tmp_path / ".secrets/support_defaults.json"
    assert json.loads(config.read_text()) == {"solution_url": "https://solution.example/support",
        "org_url": "https://org.example/help", "solution_principals": ["staff"]}
    subprocess.run(command + ["--org-support-url", ""], check=True, capture_output=True)
    saved = config.read_text()
    assert json.loads(saved)["org_url"] == ""
    assert json.loads(saved)["solution_principals"] == ["staff"]
    subprocess.run(command, check=True, capture_output=True)
    assert config.read_text() == saved
    for invalid in ["javascript:alert(1)", "https://host:bad", "https://host/#fragment", "https://host\\path"]:
        result = subprocess.run(command + ["--solution-support-url", invalid], capture_output=True)
        assert result.returncode == 2
        assert config.read_text() == saved
