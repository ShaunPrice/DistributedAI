# SPDX-License-Identifier: Apache-2.0
"""Load explicit Secrets Manager references at cold start without writing/logging secrets."""
import json
import os
import sys

ALLOWED_SECRETS = frozenset({
    "DATABASE_URL", "CONTENT_MASTER_KEY", "MANAGEMENT_KEY", "LOGIN_CLIENT_SECRET",
    "LOGIN_SUBJECTS", "OIDC_SUBJECTS", "KEY_PROVIDERS", "TENANT_KEY_PROVIDERS",
    "PLATFORM_ADMIN_TOKEN", "PLATFORM_SUBJECTS", "BOOTSTRAP_TOKEN",
    "BILLING_PLAN_LIMITS", "BILLING_PRICES", "PAYMENT_PROVIDERS", "OIDC_CONNECTIONS",
})
REQUIRED = frozenset({"DATABASE_URL", "CONTENT_MASTER_KEY", "MANAGEMENT_KEY"})


def load_secrets(client, references):
    if not isinstance(references, dict) or not REQUIRED.issubset(references):
        raise ValueError("Required managed secret references are missing")
    if set(references) - ALLOWED_SECRETS:
        raise ValueError("Unsupported managed secret name")
    if any(not isinstance(arn, str) or not arn.startswith("arn:") or ":secretsmanager:" not in arn
           for arn in references.values()):
        raise ValueError("Expected a Secrets Manager ARN")
    values = {}
    for name, arn in references.items():
        value = client.get_secret_value(SecretId=arn).get("SecretString")
        if not isinstance(value, str) or not value:
            raise ValueError("Expected a nonempty secret string")
        values[name] = value
    return values


def main():
    try:
        import boto3
        values = load_secrets(boto3.client("secretsmanager"),
                              json.loads(os.environ["DISTRIBUTEDAI_SECRET_ARNS"]))
        os.environ.update(values)
        # Secret-file precedence must not accidentally mask the managed values.
        for name in values:
            os.environ.pop(name + "_FILE", None)
    except Exception:
        print("Managed secret initialization failed", file=sys.stderr)
        return 1
    os.execvp(sys.argv[1], sys.argv[1:])
    return 0


if __name__ == "__main__":
    sys.exit(main())
