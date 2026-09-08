<!-- SPDX-License-Identifier: Apache-2.0 -->
# The DistributedAI console

Manage shared projects, people, AI connections and review workflows from one organisation workspace. Platform administration uses a separate console and credential.

**Experimental preview.** These are unaltered screenshots of the running application, captured on 8 September 2026 for the interface redesign following v0.1.0 commit `706d195`. All names, projects, account identifiers and records belong to an isolated fictional demonstration installation. No customer content or credentials appear. Screenshots illustrate the interface; they do not establish production readiness or live cloud/payment compatibility.

[Projects](#projects) · [People and access](#people-and-access) · [Memory reviews](#memory-reviews) · [Connections](#connections-and-plan) · [Encryption](#encryption-keys) · [Platform](#platform-administration)

## Projects

The overview shows the projects and departments visible to the signed-in identity. Select a workspace to retrieve its project code. A code locates the project; access still requires an assignment.

![Project overview with four projects, one department and the workspace directory](images/workspace.png)

## People and access

Create distinct identities, then assign a scope and role. Department and organisation assignments apply to descendants. Removing a project assignment does not remove inherited access.

![Organisation identities and explicit role assignments in the people and access console](images/people-access.png)

## Memory reviews

Select a workspace to inspect proposed context and its source. Pending proposals require an independent authorised reviewer. The screenshot shows the proposing administrator's view, so acceptance controls are absent.

![Two pending memory proposals with source information and demonstration research content](images/memory-reviews.png)

## Connections and plan

Group connections by instance and assign each to an owner. The owner’s project permissions determine access. This demonstration runs with billing disabled; payment controls are not shown because no provider is configured.

![Connection management showing a named research instance, its owner and optional subscription status](images/connections.png)

## Encryption keys

Inspect the active key version and choose an approved provider when rotating keys. Keys are not exported through the platform console. Stronger protection against infrastructure operators requires additional deployment or client-side isolation; see the [encryption guide](ENCRYPTION.md).

![Encryption management showing AES-256-GCM, a local key provider and the empty manual key field](images/encryption-keys.png)

## Platform administration

The separate platform console exposes account identifiers and aggregate metadata. It does not display organisation names, project content, credentials or key material. The [platform guide](PLATFORM.md) explains the precise boundary.

![Platform account administration showing aggregate counts and account suspension controls without tenant content](images/platform-admin.png)

## Sign-in

Use a credential issued by your administrator, or the organisation identity provider when configured. Provider-managed passkeys depend on that provider and deployment configuration.

![DistributedAI sign-in with an empty credential field and custom product icon](images/sign-in.png)

## Screenshot maintenance

Capture a fresh set after material interface changes. Use a separate local database with synthetic data, the browser's normal desktop viewport, and full-page captures where needed. Never capture one-time credential panels, populated key fields, payment details or personal records. Inspect every image before committing it, preserve descriptive alt text, and keep the experimental status visible. SVG site and navigation icons are served locally; the interface does not depend on an external font or icon service.
