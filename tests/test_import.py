# SPDX-License-Identifier: Apache-2.0
import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("import_memories", Path(__file__).parents[1] / "scripts/import_memories.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_import_requires_provenance_and_explicit_schema(tmp_path):
    file = tmp_path / "import.jsonl"
    file.write_text(json.dumps({"key": "decision", "content": "Reviewed context", "source": "approved-export:record-1"}))
    assert len(module.load_records(file)) == 1
    file.write_text(json.dumps({"key": "decision", "content": "Reviewed context"}))
    with pytest.raises(ValueError, match="provenance"):
        module.load_records(file)
    file.write_text(json.dumps({"key": "decision", "content": "Reviewed context", "source": "record", "scope_id": "other-tenant"}))
    with pytest.raises(ValueError, match="unexpected"):
        module.load_records(file)
