# SPDX-License-Identifier: AGPL-3.0-only
"""Content-blind platform use cases; independent of HTTP and database technology."""
from dataclasses import asdict
from typing import Any, Protocol


class PlatformRepository(Protocol):
    def initialize(self) -> None: ...
    def is_active(self, org_id: str) -> bool: ...
    def account_rows(self, include_billing: bool) -> list[dict[str, Any]]: ...
    def assign_plan(self, org_id: str, plan: str, billing: Any) -> None: ...
    def set_suspended(self, org_id: str, suspended: bool) -> None: ...


class PlatformService:
    """Validate platform operations without exposing any tenant content authority."""

    def __init__(self, repository: PlatformRepository):
        self.repository = repository
        self.billing = None

    def initialize(self):
        self.repository.initialize()

    def is_active(self, org_id):
        return self.repository.is_active(org_id)

    def list_accounts(self):
        enabled = bool(self.billing and self.billing.enabled)
        rows = self.repository.account_rows(include_billing=enabled)
        result = []
        for row in rows[:1000]:
            account = {"account_id": row["id"], "created_at": row["created_at"].isoformat() + "Z",
                       "principal_count": row["principal_count"], "scope_count": row["scope_count"],
                       "suspended": bool(row["suspended"])}
            if enabled:
                active = row["status"] == "active" and not row["needs_reconciliation"]
                account.update(plan=row["plan"] if active and row["plan"] in self.billing.plans else self.billing.default_plan,
                               billing_status=row["status"] or "unregistered",
                               needs_reconciliation=bool(row["needs_reconciliation"]))
            result.append(account)
        return {"accounts": result, "truncated": len(rows) > 1000, "billing_enabled": enabled,
                "plans": {name: asdict(limits) for name, limits in self.billing.plans.items()} if enabled else {}}

    def set_plan(self, org_id, plan):
        if not self.billing or not self.billing.enabled:
            raise ValueError("Billing is disabled")
        if not isinstance(org_id, str) or len(org_id) != 32 or not isinstance(plan, str) or plan not in self.billing.plans:
            raise ValueError("Invalid account plan")
        self.repository.assign_plan(org_id, plan, self.billing)
        return {"account_id": org_id, "plan": plan}

    def set_suspended(self, org_id, suspended):
        if not isinstance(org_id, str) or len(org_id) != 32 or type(suspended) is not bool:
            raise ValueError("Invalid account operation")
        self.repository.set_suspended(org_id, suspended)
        return {"account_id": org_id, "suspended": suspended}


PlatformApplication = PlatformService
