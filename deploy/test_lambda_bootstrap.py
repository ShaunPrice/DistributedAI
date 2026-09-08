# SPDX-License-Identifier: Apache-2.0
"""Run with: python -m unittest discover -s deploy -p 'test_*.py'."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("lambda_bootstrap", Path(__file__).with_name("lambda_bootstrap.py"))
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


class SecretLoaderTests(unittest.TestCase):
    def references(self):
        return {name: "arn:aws:secretsmanager:region:account:secret:" + name
                for name in bootstrap.REQUIRED}

    def test_only_explicit_references_are_loaded(self):
        calls = []
        def get_secret_value(SecretId):
            calls.append(SecretId)
            return {"SecretString": "synthetic-value"}
        values = bootstrap.load_secrets(SimpleNamespace(get_secret_value=get_secret_value), self.references())
        self.assertEqual(set(values), bootstrap.REQUIRED)
        self.assertEqual(set(calls), set(self.references().values()))

    def test_unknown_names_and_non_arns_rejected(self):
        for references in [{}, {**self.references(), "PYTHONPATH": "arn:bad"},
                           {**self.references(), "DATABASE_URL": "https://attacker"}]:
            with self.assertRaises(ValueError):
                bootstrap.load_secrets(SimpleNamespace(), references)

    def test_failure_does_not_log_secret_or_exception_details(self):
        def fail(**kwargs):
            raise RuntimeError("sensitive-provider-response")
        fake = SimpleNamespace(client=lambda name: SimpleNamespace(get_secret_value=fail))
        output = io.StringIO()
        with patch.dict(sys.modules, {"boto3": fake}), patch.dict(os.environ,
                {"DISTRIBUTEDAI_SECRET_ARNS": json.dumps(self.references())}), contextlib.redirect_stderr(output):
            self.assertEqual(bootstrap.main(), 1)
        self.assertNotIn("sensitive", output.getvalue())

    def test_missing_binary_or_empty_secret_rejected(self):
        for result in [{"SecretBinary": b"hidden"}, {"SecretString": ""}]:
            fake = SimpleNamespace(get_secret_value=lambda **kwargs: result)
            with self.assertRaises(ValueError):
                bootstrap.load_secrets(fake, self.references())


if __name__ == "__main__":
    unittest.main()
