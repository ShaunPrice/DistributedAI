# SPDX-License-Identifier: Apache-2.0
"""Secrets must remain private on the host and readable by container UID 10001."""
from pathlib import Path
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
