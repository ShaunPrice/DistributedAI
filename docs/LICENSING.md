<!-- SPDX-License-Identifier: Apache-2.0 -->
# Licensing

DistributedAI uses a component-based licence split, not a choice between two licences for the whole product:

| Authored component | Licence |
| --- | --- |
| Server code and its management UI under `distributedai/`, except the standalone proxy | **AGPL-3.0-only** |
| Standalone `distributedai/proxy.py` MCP transport client | **Apache-2.0** |
| Other authored files, including deployment templates, scripts, tests and documentation | **Apache-2.0** |

The repository's licence texts and per-file SPDX identifiers record this split. Third-party code, dependency distributions and their notices retain their own licences; generated dependency inventory entries do not relicense the referenced software. Files copied from elsewhere require their original attribution and a compatible grant, even when their destination directory otherwise carries Apache-2.0.

## Operating and modifying the server

AGPL permits commercial use. Operating a paid service does not exempt modifications from its terms. Section 13 addresses modified network-interactive versions: users interacting with such a version must receive a prominent opportunity to obtain its Corresponding Source without charge. Distribution also carries source, licence and notice requirements under the applicable sections. Consult the actual [GNU AGPL version 3 text](https://www.gnu.org/licenses/agpl.en.html); this page is operational guidance, not a replacement for those terms.

For a hosted release, publish a source offer that resolves to the **exact deployed version**, including modifications and the material needed to build and install it. Include the repository licence texts, relevant dependency notices, and the source/build information required by applicable component licences. A private repository link that customers cannot access is not an effective public source offer. Private repository visibility is a development setting; it does not change obligations associated with a covered deployment or distribution.

Tenant memories, customer communications, credentials and keys are data, not a source-release mechanism. Do not include them in source archives or support bundles. Prepare the source release from a clean checkout with synthetic configuration examples. The operator must verify that all required Corresponding Source is included while excluding operational secrets and user content.

## Apache components and third-party dependencies

The Apache-2.0 client and deployment material can be reused under their own terms, including its notice and modification requirements. They do not make the server Apache-licensed. The Apache Software Foundation explains the relationship between [Apache-2.0 and GPL version 3](https://www.apache.org/licenses/GPL-compatibility.html); actual combinations and dependency-specific requirements still need review.

A separate MCP client communicating through the protocol is not granted rights to copy server code merely because it can call the server. Keep the standalone proxy's implementation independent of AGPL-only server modules if distributing it under Apache-2.0 alone. Importing or copying server implementations requires reassessing the resulting combined distribution.

See [DEPENDENCY_LICENSES.md](DEPENDENCY_LICENSES.md) and the versioned [machine-readable inventory](dependency-licenses.json). The inventory records publisher declarations and selected hash-verified wheel evidence. It is not a blanket compatibility approval and does not replace notices or source-delivery obligations.

## Cognitive-Memory provenance

The repository describes its service as new code implementing proposal/review and leased-job patterns informed by Cognitive-Memory. The original local Cognitive-Memory checkout was inspected read-only during this audit: no root licence file or project licence declaration was found. This audit did not import its source, memories or private data.

That absence is not a licence grant. The repository's new-code statement and the implementation history do not constitute a forensic source-similarity or contributor-rights audit. The project owner should preserve provenance and verify rights before incorporating any original or third-party source. Conceptual inspiration must not be presented as permission to relicense copied implementation. No conclusion about ownership of the original checkout is inferred from its filesystem location.
