<!-- SPDX-License-Identifier: Apache-2.0 -->
# Memory ownership and administration

Every provisioned identity has one personal memory space. Existing installations create missing personal spaces idempotently when the owner signs in or the organisation administrator opens the user directory. Personal content is private to that identity: organisation and department roles do not confer content access. Organisation administrators can manage a person's independent export and delete policies without reading their private memory.

Each project has a separate scope, memory keys and history. Project codes locate an already-authorised project; they never grant access. Shared searches may include authorised ancestor knowledge, but sibling projects are excluded. Personal searches do not inherit organisation content.

| Role | Authority |
| --- | --- |
| Personal owner | Propose, read and approve their own personal memory; export or delete only when the respective permission permits |
| Project administrator | Manage project collaborators, memory and permitted export/delete actions; take encrypted project archives |
| Department administrator | Create and manage projects in their department; delegate access within their authority |
| Organisation administrator | Manage users, departments and projects; move projects between departments; merge departments; set independent export/delete permissions; take encrypted organisation archives |
| Central platform administrator | Operational account metadata and restricted whole-database backup jobs; no tenant-content or decryption-key browsing |

## Structure changes

Projects cannot contain other projects. A department cannot be deleted while it contains projects or other child departments. Workspace deletion rejects retained content by default. An explicit delete-contents confirmation can purge that workspace’s memories, history, messages and jobs; it can never cascade into child projects or departments. Personal and organisation root containers are not deletable through the workspace API.

Moving a workspace requires administration of both source and destination. Moving changes inherited department access, while direct project assignments remain. Cycles, invalid parents and cross-organisation moves are rejected.

An organisation administrator can merge departments. Children and non-conflicting content move into the target; naming or memory-key conflicts reject the entire operation. Source-department grants are removed rather than granting their holders access to all existing target projects. Review access assignments before merging. Shared workspace ownership can be transferred by an organisation administrator; personal ownership cannot be transferred. Export/delete restrictions on the source are preserved conservatively on the target.

## Export and delete permissions

Export and delete are independent. Revoking delete leaves export available; revoking export leaves otherwise authorised deletion available. A permission flag does not create ownership or content access. Export revocation blocks the bulk-export function; it cannot stop a reader copying content they remain authorised to read. Ancestor restrictions also apply to shared descendant scopes, so a project override cannot bypass a department restriction.

In **People & access**, an organisation administrator can open **Personal memory policy** for a user. In a workspace's detail panel, **Export and delete permissions** manages policy for that workspace. Personal-owner approval is allowed for personal memories; shared projects retain independent review. Quarantined content cannot be approved in either case.

Memory export includes canonical records, full stored versions and proposals for the selected workspace. It is an explicit content export and the downloaded JSON must be protected. The current synchronous export is bounded to 10,000 payload rows and 8 MiB; exceeding either limit fails explicitly without returning a partial archive. Larger exports need a controlled offline process; there is no pagination or background export service yet.

Encrypted organisation/project archives are distinct from readable memory export. They preserve encrypted payloads and exclude credentials and plaintext key material. They retain structural identifiers and require the original organisation's key recovery material. They are not standalone PostgreSQL dumps and cannot be passed to pg_restore. See [backup and recovery](BACKUP_RECOVERY.md).

## Clustering

Application replicas share one authoritative PostgreSQL writer and compatible identity, session and content-key configuration. Optional application redundancy and external managed PostgreSQL configuration are described in [high availability](HIGH_AVAILABILITY.md). Multi-host orchestration, database failover, ingress redundancy and recovery drills remain deployment responsibilities.
