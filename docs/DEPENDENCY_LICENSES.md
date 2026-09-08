<!-- SPDX-License-Identifier: Apache-2.0 -->
# Dependency licence inventory

The 8 September 2026 audit covers **70 exact third-party Python package versions** in the current `uv.lock`, including runtime, optional AWS/Azure/GCP key-management SDKs, development dependencies and platform-conditional packages. The project itself is excluded. All 70 version-specific PyPI metadata requests succeeded; **eight entries have incomplete or ambiguous licence metadata** and remain flagged for manual review. Their selected wheels were downloaded from PyPI and matched against the lockfile SHA-256 before license-file evidence was recorded.

The authoritative inventory is [dependency-licenses.json](dependency-licenses.json), which includes the lockfile hash, package versions, publisher metadata URLs/hashes, conservative dependency-group membership and relevant wheel/license-file hashes. Group membership includes every platform marker in the lock rather than claiming every package is installed in every image. The inventory reports declared licences; it does not certify complete legal compatibility or third-party ownership.

## Findings requiring attention

- `psycopg` and `psycopg-binary` declare **LGPL-3.0-only**. Preserve their licences and fulfil applicable source, notice and replacement/relinking requirements when distributing images. Do not relabel these packages Apache-2.0. The binary wheel also requires inspection of bundled native-library licences; the top-level package declaration alone is insufficient.
- `certifi` declares **MPL-2.0**, which carries component-specific notice/source obligations. Other packages include multi-licence expressions such as `Apache-2.0 OR BSD-3-Clause`, `MIT AND PSF-2.0`, and `Apache-2.0 OR BSD-2-Clause`; preserve those distinctions.
- `pywin32` is platform-conditional. Its top-level `PSF` metadata is not an adequate aggregate licence expression: the inspected Windows wheel contains multiple notices, including an `adodbapi` **LGPL-2.1** licence text, Python/PSF history, MIT and other permissive notices. The exact scope and application of those texts requires component review before distributing a Windows bundle. The Linux service image does not install Windows-only packages.

### Incomplete metadata

| Package | Exact version | Evidence and remaining review |
| --- | --- | --- |
| azure-core | 1.41.0 | Hash-verified wheel contains an MIT licence; PyPI licence fields are empty. |
| azure-identity | 1.25.3 | Hash-verified wheel contains an MIT licence; PyPI licence fields are empty. |
| colorama | 0.4.6 | Metadata says generic BSD; wheel contains the actual redistribution conditions. Confirm exact BSD variant. |
| isodate | 0.7.2 | Legacy metadata embeds licence prose; wheel licence is recorded. Confirm exact BSD variant and notices. |
| protobuf | 7.36.1 | Legacy metadata says 3-Clause BSD; wheel licence recorded. Review native-wheel bundled components separately. |
| pyasn1-modules | 0.4.2 | Generic BSD metadata; wheel contains the specific redistribution conditions. Confirm exact variant. |
| python-dateutil | 2.9.0.post0 | Metadata says dual licence and lists Apache/BSD; preserve the wheel's complete licence and per-file history. |
| pywin32 | 312 | Multiple component licences; do not collapse the wheel to a single PSF declaration. |

## Exact Python inventory

`UNRESOLVED` means the automated metadata normaliser deliberately did not guess an SPDX expression. It does not mean that no licence file exists.

| Package | Version | Declared expression / normalised legacy label |
| --- | --- | --- |
| annotated-types | 0.8.0 | MIT |
| anyio | 4.15.1 | MIT |
| attrs | 26.1.0 | MIT |
| azure-core | 1.41.0 | UNRESOLVED |
| azure-identity | 1.25.3 | UNRESOLVED |
| azure-keyvault-keys | 4.11.2 | MIT |
| boto3 | 1.43.89 | Apache-2.0 |
| botocore | 1.43.89 | Apache-2.0 |
| certifi | 2026.7.22 | MPL-2.0 |
| cffi | 2.1.1 | MIT-0 |
| charset-normalizer | 3.5.1 | MIT |
| click | 8.5.0 | BSD-3-Clause |
| colorama | 0.4.6 | UNRESOLVED |
| cryptography | 50.0.1 | Apache-2.0 OR BSD-3-Clause |
| google-api-core | 2.36.0 | Apache-2.0 |
| google-auth | 2.57.1 | Apache-2.0 |
| google-cloud-kms | 3.16.0 | Apache-2.0 |
| googleapis-common-protos | 1.75.3 | Apache-2.0 |
| greenlet | 3.5.5 | MIT AND PSF-2.0 |
| grpc-google-iam-v1 | 0.14.5 | Apache-2.0 |
| grpcio | 1.83.1 | Apache-2.0 |
| grpcio-status | 1.83.1 | Apache-2.0 |
| h11 | 0.16.0 | MIT |
| httpcore | 1.0.9 | BSD-3-Clause |
| httpx | 0.28.1 | BSD-3-Clause |
| httpx-sse | 0.4.3 | MIT |
| idna | 3.19 | BSD-3-Clause |
| iniconfig | 2.3.0 | MIT |
| isodate | 0.7.2 | UNRESOLVED |
| jmespath | 1.1.0 | MIT |
| jsonschema | 4.26.0 | MIT |
| jsonschema-specifications | 2025.9.1 | MIT |
| mcp | 1.30.0 | MIT |
| msal | 1.38.0 | MIT |
| msal-extensions | 1.3.1 | MIT |
| opentelemetry-api | 1.44.0 | Apache-2.0 |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause |
| pluggy | 1.6.0 | MIT |
| proto-plus | 1.28.4 | Apache-2.0 |
| protobuf | 7.36.1 | UNRESOLVED |
| psycopg | 3.3.5 | LGPL-3.0-only |
| psycopg-binary | 3.3.5 | LGPL-3.0-only |
| pyasn1 | 0.6.4 | BSD-2-Clause |
| pyasn1-modules | 0.4.2 | UNRESOLVED |
| pycparser | 3.0 | BSD-3-Clause |
| pydantic | 2.13.5 | MIT |
| pydantic-core | 2.46.5 | MIT |
| pydantic-settings | 2.15.0 | MIT |
| pygments | 2.21.0 | BSD-2-Clause |
| pyjwt | 2.13.0 | MIT |
| pytest | 8.4.2 | MIT |
| pytest-asyncio | 1.4.0 | Apache-2.0 |
| python-dateutil | 2.9.0.post0 | UNRESOLVED |
| python-dotenv | 1.2.3 | BSD-3-Clause |
| python-multipart | 0.0.32 | Apache-2.0 |
| pywin32 | 312 | UNRESOLVED |
| referencing | 0.37.0 | MIT |
| requests | 2.34.2 | Apache-2.0 |
| rpds-py | 2026.6.3 | MIT |
| ruff | 0.16.6 | MIT |
| s3transfer | 0.19.2 | Apache-2.0 |
| six | 1.17.0 | MIT |
| sqlalchemy | 2.0.52 | MIT |
| sse-starlette | 3.4.11 | BSD-3-Clause |
| starlette | 1.6.0 | BSD-3-Clause |
| typing-extensions | 4.16.0 | PSF-2.0 |
| typing-inspection | 0.4.4 | MIT |
| tzdata | 2026.3 | Apache-2.0 |
| urllib3 | 2.7.0 | MIT |
| uvicorn | 0.52.4 | BSD-3-Clause |

## Container and infrastructure scope

This Python inventory is **not a complete container SBOM**. It does not enumerate Debian Bookworm packages, Python interpreter components, native libraries bundled inside wheels, Caddy, PostgreSQL, the uv installer, build-isolation dependencies such as Hatchling, or GitHub Actions dependencies. Those artifacts retain their own licences and require their own release inventory. The exact runtime image digest matters because base-image tags and operating-system package inventories can change independently of `uv.lock`.

The optional AWS Lambda Web Adapter project's published licence is [Apache-2.0](https://github.com/aws/aws-lambda-web-adapter/blob/main/LICENSE). The Dockerfile references version 1.0.1; the release image's embedded notices and native dependency inventory still need checking against the exact image digest rather than relying solely on the upstream main-branch licence.

The installed provider distributions used to validate these templates were inspected locally: AWS **6.63.0**, AzureRM **4.81.0**, and Google **7.46.1** each include an **MPL-2.0** `LICENSE.txt`. Their provider licences do not relicense these authored Terraform templates. Upstream provider licence sources are available for [AWS](https://github.com/hashicorp/terraform-provider-aws/blob/main/LICENSE), [AzureRM](https://github.com/hashicorp/terraform-provider-azurerm/blob/main/LICENSE) and [Google](https://github.com/hashicorp/terraform-provider-google/blob/main/LICENSE). These tools are downloaded by the deployment workflow, not copied into the Python service package.

The [Terraform CLI licence](https://github.com/hashicorp/terraform/blob/main/LICENSE) is Business Source License 1.1 with an additional-use grant and version-dependent change terms. It is distinct from the MPL-licensed providers and Apache-licensed templates. [OpenTofu uses MPL-2.0](https://github.com/opentofu/opentofu/blob/main/LICENSE) and is an alternative to assess where an entirely open-source provisioning toolchain is required. The current templates were validated with Terraform; OpenTofu compatibility has not been tested here.

For each release, produce an SPDX or CycloneDX SBOM from the **built immutable image**, inspect bundled licence/NOTICE files, preserve required notices and satisfy applicable source-delivery obligations. Include optional cloud-key and Lambda images separately because their dependencies differ. Match the source archive and notices to that release; do not treat this metadata-only audit as an image-distribution clearance.

## Reproducing the audit

Run from the repository root with Python 3.12 or later:

```sh
python scripts/audit_licenses.py
python scripts/audit_licenses.py --check-lock
```

The first command queries official PyPI endpoints and refreshes the tracked JSON. It downloads at most a bounded selected wheel for each unresolved metadata entry and verifies the lockfile hash before reading licence files; it neither installs packages nor executes their code. A metadata-fetch failure produces a nonzero result. Incomplete licence metadata remains a reported manual-review item, not an automatic failure or approval. The second command checks exact package coverage and the lockfile hash offline, so CI can detect a stale inventory without issuing network requests. A passing offline check establishes freshness only.

The Markdown findings and any manual legal/component review must be refreshed when dependencies change. Preserve original third-party licence files rather than relying on the abbreviated evidence excerpts in the JSON report.
