# SPDX-License-Identifier: Apache-2.0
"""Architectural contracts: application and HTTP adapters never depend on SQL adapters."""
import ast
from pathlib import Path
from distributedai.application.workspace import WorkspaceApplication
from distributedai.domain import Principal, ServiceError
import pytest


def test_layer_dependencies():
    root = Path(__file__).resolve().parents[1] / "distributedai"
    forbidden = {"sqlalchemy", "psycopg", "sqlite3", "persistence", "store", "runtime", "composition"}
    for layer in ("application", "presentation"):
        for file in (root / layer).glob("*.py"):
            tree = ast.parse(file.read_text())
            for node in ast.walk(tree):
                names = [node.module or ""] if isinstance(node, ast.ImportFrom) else [a.name for a in node.names] if isinstance(node, ast.Import) else []
                for name in names:
                    assert not forbidden.intersection(name.split(".")), (file, name)
                if isinstance(node, ast.Attribute):
                    assert node.attr not in {"_engine", "execute", "begin"}, (file, node.attr)


def test_application_with_non_database_repository():
    principal = Principal("person", "org", "Alex")
    class Repository:
        active = True
        calls = []
        def resolve_principal(self, value): return principal if self.active and value == principal.id else None
        def dispatch(self, actor, op, args):
            self.calls.append((actor, op, args))
            return {"scopes": []}
    repository = Repository()
    application = WorkspaceApplication(repository)
    assert application.dispatch(principal, "scope_list", {}) == {"scopes": []}
    assert not hasattr(application, "_engine")
    repository.active = False
    with pytest.raises(ServiceError):
        application.dispatch(principal, "scope_list", {})
    assert len(repository.calls) == 1
