# SPDX-License-Identifier: AGPL-3.0-only
"""Support routing and ticket access; no memory retrieval, external submission or AI calls."""
from typing import Protocol
from urllib.parse import urlsplit

from ..domain import Principal, ServiceError
from ..security import scan_payload


class SupportRepository(Protocol):
    def configuration(self, org_id): ...
    def configure(self, org_id, external_url, principal_ids, *, actor_id): ...
    def solution_configuration(self): ...
    def configure_solution(self, external_url, principal_ids): ...
    def subject(self, ticket_id, *, actor_id, solution_principals=()): ...
    def candidates(self, org_id, principal_ids=None, admins_only=False): ...
    def list_metadata(self, org_id=None, reporter_id=None, queue=None): ...
    def ticket_metadata(self, ticket_id): ...
    def create(self, org_id, reporter_id, queue, subject, body, page, idempotency_key): ...
    def get(self, ticket_id, *, actor_id, solution_principals=()): ...
    def reply(self, ticket_id, actor_id, body, status=None, *, solution_principals=()): ...
    def assign(self, ticket_id, principal_id, *, actor_id, solution_principals=()): ...


def _text(value, name, maximum, *, empty=False):
    if not isinstance(value, str) or len(value) > maximum or (not empty and not value.strip()):
        raise ServiceError("invalid_argument", f"Invalid {name}")
    return value


def external_url(value):
    _text(value, "support URL", 2048, empty=True)
    if not value:
        return ""
    try:
        parsed = urlsplit(value)
    except ValueError:
        raise ServiceError("invalid_argument", "Invalid support URL") from None
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.fragment or any(ord(char) < 33 or ord(char) == 127 for char in value)
            or "\\" in value):
        raise ServiceError("invalid_argument", "Support URL must be an absolute HTTPS link without credentials or fragment")
    try:
        parsed.port
    except ValueError:
        raise ServiceError("invalid_argument", "Invalid support URL") from None
    return value


class SupportApplication:
    def __init__(self, identities, repository: SupportRepository, *, solution_url="", solution_principals=(), org_url=""):
        self._identities, self._repository = identities, repository
        self.solution_url = external_url(solution_url)
        self.org_url = external_url(org_url)
        if not isinstance(solution_principals, (list, tuple)) or len(solution_principals) > 100 or any(
                not isinstance(value, str) or not value or len(value) > 64 for value in solution_principals):
            raise ValueError("Invalid solution support identities")
        self.solution_principals = tuple(solution_principals)

    def solution_configuration(self):
        stored = self._repository.solution_configuration()
        return stored if stored["configured"] else {"external_url": self.solution_url,
            "support_principal_ids": list(self.solution_principals), "version": 0, "configured": False}

    def configure_solution(self, arguments):
        """Trusted platform-composition entry point; never exposed by tenant dispatch."""
        if not isinstance(arguments, dict) or set(arguments) != {"external_url", "support_principal_ids"}:
            raise ServiceError("invalid_argument", "Invalid solution support configuration")
        url = external_url(arguments["external_url"])
        ids = arguments["support_principal_ids"]
        if not isinstance(ids, list) or len(ids) > 100 or any(not isinstance(v, str) or not v or len(v) > 64 for v in ids):
            raise ServiceError("invalid_argument", "Invalid support identities")
        if any(self._active(value) is None for value in ids):
            raise ServiceError("invalid_argument", "Solution support identities must be active users")
        self._repository.configure_solution(url, sorted(set(ids)))
        return {"configured": True}

    def public_options(self):
        url = self.solution_configuration()["external_url"]
        return {"route": {"kind": "external", "url": url} if url else {"kind": "sign_in_required"}, "ai_enabled": False}

    def _configuration(self, org_id):
        config = self._repository.configuration(org_id)
        if not config["configured"]:
            config["external_url"] = self.org_url
        return config

    def _assignees(self, actor, ticket):
        if not self._can_handle(actor, ticket):
            return []
        ids = self._solution_support() if ticket["queue"] == "solution" else (
            self._org_support(ticket["org_id"]) | set(self._repository.candidates(ticket["org_id"], admins_only=True)))
        values = [self._active(value) for value in sorted(ids)]
        return [{"principal_id": value.id, "name": value.name} for value in values if value is not None]

    def _ticket(self, actor, ticket):
        value = self._repository.get(ticket["id"], actor_id=actor.id, solution_principals=self.solution_principals)
        findings = sorted({finding for text in [value["subject"], value["body"], value["page"],
            *(row["body"] for row in value["replies"])] for finding in scan_payload(text)})
        return {**value, "screening_findings": findings, "trust": "untrusted_user_supplied_support_content",
                "ticket_id": ticket["id"], "can_reply": True, "can_assign": self._can_handle(actor, ticket),
                "assignees": self._assignees(actor, ticket)}

    def _active(self, principal_id):
        return self._identities.resolve_principal(principal_id)

    def _org_support(self, org_id):
        configured = self._repository.configuration(org_id)["support_principal_ids"]
        candidates = self._repository.candidates(org_id, configured) if configured else []
        active = {value for value in candidates if self._active(value) is not None}
        if not active:
            active = {value for value in self._repository.candidates(org_id, admins_only=True)
                      if self._active(value) is not None}
        return active

    def _solution_support(self):
        return {value for value in self.solution_configuration()["support_principal_ids"] if self._active(value) is not None}

    def _can_handle(self, actor, ticket):
        if ticket["queue"] == "solution":
            return actor.id in self._solution_support()
        return actor.org_id == ticket["org_id"] and (actor.is_org_admin or actor.id in self._org_support(actor.org_id))

    def _visible(self, actor, ticket):
        return ticket is not None and (actor.id == ticket["reporter_id"] or self._can_handle(actor, ticket))

    def _route(self, actor):
        if actor.is_org_admin:
            url = self.solution_configuration()["external_url"]
            return {"kind": "external", "url": url} if url else {"kind": "internal", "queue": "solution"}
        configured = self._configuration(actor.org_id)
        return {"kind": "external", "url": configured["external_url"]} if configured["external_url"] else {"kind": "internal", "queue": "organisation"}

    def dispatch(self, principal, operation, arguments):
        if not isinstance(principal, Principal):
            raise ServiceError("denied", "Authenticated user required")
        actor = self._active(principal.id)
        if actor is None or actor.org_id != principal.org_id or actor.name != principal.name:
            raise ServiceError("denied", "Identity unavailable")
        if not isinstance(arguments, dict):
            raise ServiceError("invalid_argument", "Expected an object")
        contracts = {
            "support_options": set(), "support_configure": {"external_url", "support_principal_ids"},
            "support_create": {"subject", "body", "page", "idempotency_key"}, "support_list": set(),
            "support_get": {"ticket_id"}, "support_reply": {"ticket_id", "body", "status"},
            "support_assign": {"ticket_id", "principal_id"}, "support_ai_context": {"ticket_id"},
        }
        if operation not in contracts or set(arguments) - contracts[operation]:
            raise ServiceError("invalid_argument", "Unsupported support request")
        if operation == "support_options":
            queue = "solution" if actor.is_org_admin else "organisation"
            result = {"route": self._route(actor), "can_configure": actor.is_org_admin,
                      "is_org_admin": actor.is_org_admin,
                      "is_org_support": actor.is_org_admin or actor.id in self._org_support(actor.org_id),
                      "is_solution_support": actor.id in self._solution_support(), "ai_enabled": False,
                      "assignees": self._assignees(actor, {"queue": queue, "org_id": actor.org_id})}
            if actor.is_org_admin:
                result["organisation"] = self._configuration(actor.org_id)
            return result
        if operation == "support_configure":
            if not actor.is_org_admin:
                raise ServiceError("denied", "Organisation administrator required")
            url = external_url(arguments.get("external_url", ""))
            ids = arguments.get("support_principal_ids", [])
            if not isinstance(ids, list) or len(ids) > 100 or any(not isinstance(v, str) or not v or len(v) > 64 for v in ids):
                raise ServiceError("invalid_argument", "Invalid support identities")
            if set(ids) != set(self._repository.candidates(actor.org_id, ids)):
                raise ServiceError("invalid_argument", "Support identities must be active users in this organisation")
            self._repository.configure(actor.org_id, url, sorted(set(ids)), actor_id=actor.id)
            return {"configured": True}
        if operation == "support_create":
            subject = _text(arguments.get("subject"), "subject", 200)
            body = _text(arguments.get("body"), "body", 8000)
            page = _text(arguments.get("page", ""), "page", 200, empty=True)
            idem = _text(arguments.get("idempotency_key"), "idempotency key", 128)
            route = self._route(actor)
            if route["kind"] == "external":
                return {"created": False, "route": route, "external_submission_required": True}
            return self._repository.create(actor.org_id, actor.id, route["queue"], subject, body, page, idem)
        if operation == "support_list":
            candidates = self._repository.list_metadata(reporter_id=actor.id)
            if actor.is_org_admin or actor.id in self._org_support(actor.org_id):
                candidates += self._repository.list_metadata(org_id=actor.org_id, queue="organisation")
            if actor.id in self._solution_support():
                candidates += self._repository.list_metadata(queue="solution")
            tickets = {row["id"]: row for row in candidates}
            ordered = sorted(tickets.values(), key=lambda row: (row["created_at"], row["id"]), reverse=True)
            listed = [{**row, "ticket_id": row["id"], "subject": self._repository.subject(row["id"],
                actor_id=actor.id, solution_principals=self.solution_principals)} for row in ordered[:100]]
            return {"tickets": listed, "truncated": len(ordered) > 100}
        ticket = None
        if arguments.get("ticket_id") is not None:
            tid = _text(arguments["ticket_id"], "ticket ID", 64)
            ticket = self._repository.ticket_metadata(tid)
            if not self._visible(actor, ticket):
                raise ServiceError("denied", "Ticket unavailable")
        elif operation != "support_ai_context":
            raise ServiceError("invalid_argument", "Ticket ID required")
        if operation == "support_get":
            return self._ticket(actor, ticket)
        if operation == "support_reply":
            body = _text(arguments.get("body"), "reply", 8000)
            status = arguments.get("status")
            if status not in {None, "open", "closed"}:
                raise ServiceError("invalid_argument", "Invalid ticket status")
            return self._repository.reply(ticket["id"], actor.id, body, status, solution_principals=self.solution_principals)
        if operation == "support_assign":
            if not self._can_handle(actor, ticket):
                raise ServiceError("denied", "Support handler required")
            pid = _text(arguments.get("principal_id"), "assignee", 64)
            assignee = self._active(pid)
            if assignee is None or not self._can_handle(assignee, ticket):
                raise ServiceError("invalid_argument", "Assignee is not eligible for this support queue")
            return self._repository.assign(ticket["id"], pid, actor_id=actor.id, solution_principals=self.solution_principals)
        return {"ai_enabled": False, "trust": "untrusted_user_supplied_support_content",
                "help": "Check project access, connection status and configured sign-in. Never include credentials, keys or private memories in support requests.",
                "ticket": ({"subject": (value := self._ticket(actor, ticket))["subject"], "body": value["body"],
                            "page": value["page"], "screening_findings": value["screening_findings"], "replies": [{"body": row["body"]} for row in value["replies"]]} if ticket else None),
                "memory_attached": False, "external_call_made": False}
