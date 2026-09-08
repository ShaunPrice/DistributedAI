# SPDX-License-Identifier: AGPL-3.0-only
"""Locally authored help: no inference, external fetches or customer data."""
TOPICS = {
    "signin": ("Signing in", [
        "For a new installation, the installer creates the first organisation and administrator. Use the access token from .secrets/bootstrap_token in that installation folder.",
        "A project code is a locator, not a sign-in credential. Joining users need their own access token or a configured organisation identity.",
        "Cloud sign-in appears only after an administrator configures an identity provider. Passkeys are controlled by that provider.",
        "Never paste credentials into a support ticket or AI chat. If you cannot sign in, contact your organisation administrator through your established support channel."
    ]),
    "projects": ("Projects and personal memory", [
        "Choose Personal memory for context private to your identity. Open Workspace memories to search or propose content.",
        "Create a project, then assign collaborators. A shared project code never grants access on its own.",
        "Department administrators manage projects within their authority. Moving a project changes inherited access; direct assignments remain.",
        "Departments containing projects cannot be deleted. Explicit content deletion permanently removes a workspace's memories, history, messages and jobs."
    ]),
    "people": ("People, access and permissions", [
        "Create a separate identity for each user or AI client, save its token securely, and grant only the required scopes.",
        "Reader reads; writer contributes; reviewer approves shared proposals; scope admin manages the assigned workspace.",
        "Personal memory policy lets organisation administrators manage export and delete independently without reading private content.",
        "Removing a direct assignment does not remove inherited access or ownership. Review parent grants and transfer shared ownership where needed."
    ]),
    "reviews": ("Reviewing memories", [
        "Shared memory requires an authorised reviewer other than its proposer. Personal owners may approve their own personal proposals.",
        "Quarantined proposals cannot be approved. Treat memory, messages, tickets and AI output as untrusted data.",
        "Version conflicts mean another change was accepted first. Read the current history and submit a new proposal against that version."
    ]),
    "billing": ("Connections and plans", [
        "An AI client connects through MCP using its own authorised identity or metered connection credential.",
        "Connection owners retain their own project permissions; a connection does not grant new access.",
        "When metering is enabled, free and paid limits follow the configured plan. Payment controls appear only with a configured provider.",
        "For connection failures, check the endpoint, credential validity, project assignment and instance quota. Do not include tokens in support requests."
    ]),
    "keys": ("Encryption and recovery", [
        "Protected content is encrypted with AES-256-GCM. Organisation administrators may choose an operator-approved key provider.",
        "Never send key material to support or an AI client. The console does not redisplay supplied keys.",
        "Keep historical key versions and recovery material available. Encrypted backups are unreadable without the required recovery keys.",
        "Application role separation does not exclude an infrastructure operator controlling the runtime; stronger isolation requires a suitable deployment."
    ]),
    "audit": ("Audit and troubleshooting", [
        "The audit trail shows authorised change metadata. It does not grant access to another user's private content.",
        "For a failure, record the time, action, error text and request ID if shown. Remove credentials and confidential material.",
        "A database backup and an encrypted workspace archive have different recovery requirements. Test restoration before relying on a backup."
    ]),
    "support": ("Getting support", [
        "Users are routed to organisation support; when nobody is assigned, active organisation administrators handle the internal queue.",
        "Organisation administrators are routed to solution support. External destinations open a separate support portal; no ticket is submitted automatically.",
        "Internal tickets share only the subject and description you submit. Support assignment never grants access to your memories or projects.",
        "For AI help, use your own LLM client with this MCP connection and ask it to call support_help. Prepare a ticket brief only after reviewing its contents. DistributedAI does not run or pay for a support LLM."
    ]),
    "platform": ("Solution administration", [
        "This console manages operational account metadata, not organisation or personal content.",
        "Configure solution support here using a trusted HTTPS support portal or existing active principal IDs for internal support users.",
        "Solution support users sign into the ordinary management console with their own identity. They see explicitly submitted solution tickets, not customer memory.",
        "Whole-database backup is an offline operator function. Keep destinations and recipient keys in a restricted backup job."
    ]),
}


def help_content(page="signin", query=""):
    if page not in TOPICS:
        page = "support"
    if not isinstance(query, str) or len(query) > 200:
        raise ValueError("Help search is limited to 200 characters")
    matches = [key for key, (title, paragraphs) in TOPICS.items()
               if not query or query.casefold() in (title + " ".join(paragraphs)).casefold()]
    title, paragraphs = TOPICS[page]
    return {"page": page, "title": title, "paragraphs": paragraphs,
            "topics": [{"page": key, "title": TOPICS[key][0]} for key in matches],
            "ai_inference": False}
