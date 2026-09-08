# Web security review

Review scope: source inspection of the working tree during the presentation/application/persistence separation. This is a bounded implementation review, not a penetration test, certification or proof of complete security. Existing regression tests below were inspected without duplicate execution by this reviewer. The coordinating run reports 225 Docker/PostgreSQL tests passed, including cross-instance logout replay tests; live split-deployment verification is a separate check. Changes made after that tested snapshot require the corresponding regression checks.

## Hardening changes and verification targets

| Earlier finding | Implemented treatment | Source and regression evidence |
| --- | --- | --- |
| Anonymous callers shared one credential rate bucket | Empty Authorization values no longer create a credential bucket. Individual IP limits remain; token login is limited to ten attempts per minute per client IP. | `distributedai/presentation/mcp.py::Limits`; `tests/test_web_security.py::test_anonymous_clients_do_not_share_credential_bucket`; `::test_login_budget_is_tighter_than_normal_requests` |
| Proxy clients collapsed into one shared address | Uvicorn accepts forwarded identity only when `TRUSTED_PROXY_IPS` is explicitly configured. The split deployment pins its web proxy IP, and that Caddy proxy overwrites X-Forwarded-For with the observed peer address. | `distributedai/cli.py:46`; `compose.split.yaml:15` and `:26`; `deploy/Caddyfile.web:46`; `tests/test_web_security.py::test_forwarded_identity_only_from_explicit_proxy` |
| Slow request bodies had no deadline | The request middleware adds a 15-second total body-read deadline, explicitly stops when time is exhausted, and retains the 128 KiB bound. | `distributedai/presentation/mcp.py::Limits`; `tests/test_web_security.py::test_slow_request_body_has_total_deadline` |
| Security response metadata and audit were incomplete | The outer boundary adds CSP, nosniff, frame denial, no-referrer, Permissions-Policy, no-store and request IDs to normal/error responses, plus HSTS for HTTPS deployments. Metadata-only logs include request IDs, status and hashed actors when the authentication adapter supplies them. | `distributedai/presentation/security.py::SecurityBoundary`; `distributedai/composition.py::create_app`; `presentation/management.py::identity`; `presentation/platform.py::identity`; `tests/test_web_security.py::test_security_headers_and_logs_exclude_secrets` |
| Copied cookies could survive logout | Logout now persists an opaque cookie hash in a shared revocation ledger; management and platform reject copied cookies across service instances. Raw cookies are not stored. | `distributedai/application/sessions.py`; `distributedai/persistence/sessions.py`; `tests/test_runtime_security.py::test_logout_rejects_copied_cookie_on_other_instance` |
| Transport and database code were intermingled | Presentation and application layers cannot import SQL adapters or access engine/transaction methods; repository commands retain atomic checks and mutations. | `tests/test_layers.py::test_layer_dependencies`; `::test_application_with_non_database_repository` |

These references describe implementation and regression coverage, not a fresh full-suite execution by this review. The coordinating validation run supplies current pass/fail evidence. The proxy regression exercises trusted versus untrusted peers in middleware; it does not establish the identity chain of a live cloud load balancer. Legacy or custom deployment paths still need explicit proxy configuration.

Raw Uvicorn access logging remains disabled, avoiding OAuth callback query strings in default access logs. Security events omit URLs, request bodies, authorization codes, tokens and encryption keys (`distributedai/cli.py`; `distributedai/presentation/security.py`).

## Implemented controls and regression evidence

| Area | Implementation | Relevant regression coverage |
| --- | --- | --- |
| Tenant and project isolation | Application re-resolves identities; repository commands revalidate within transactions. Encrypted search selects authorised scopes before decrypting candidates. | `application/workspace.py:43`; `persistence/workspace.py:503` and `:902`; `tests/test_runtime_security.py::test_encrypted_search_tenant_scope_and_database`; `tests/test_store.py` |
| Browser CSRF | Exact configured Origin and JSON content type are required for mutations, including sign-in. | `presentation/management.py:82`; `presentation/platform.py:52`; `tests/test_management.py::test_secure_login_csrf_and_cookie`; `tests/test_platform.py::test_suspension_metadata_csrf_and_audit` |
| XSS and framing | User values use DOM text nodes; restrictive CSP, no-store, nosniff, no-referrer and frame denial are applied to browser surfaces. Payment redirects are checked by the payment application. | `presentation/management.py:36`; `distributedai/static/app.js`; `distributedai/static/platform.js`; `tests/test_management.py::test_secure_login_csrf_and_cookie` |
| Session confidentiality | AES-256-GCM envelopes bind version, timestamp and purpose; cookies are HttpOnly, path-scoped, SameSite and Secure on HTTPS. Platform sessions use a separate derived key. | `session_crypto.py:23`; `presentation/management.py:62`; `presentation/platform.py:55`; `tests/test_session_crypto.py`; `tests/test_platform.py::test_platform_auth_is_separate_and_no_content_routes` |
| Cloud sign-in | Fixed issuer discovery, signature/audience validation, PKCE, nonce/state and explicit subject mapping. Platform subjects are separate from tenant subjects. | `presentation/oidc.py:70`; `tests/test_oidc.py`; `tests/test_platform.py::test_platform_cloud_identity_is_not_tenant_identity` |
| Revocation and metered credentials | Authentication and operations revalidate active identities, suspension and connection entitlements. Browser administrator tokens cannot bypass metered MCP slots. | `presentation/auth.py`; `presentation/mcp.py`; `tests/test_billing_security.py`; `tests/test_runtime_security.py::test_suspension_terminates_auth_dispatch_browser_and_keys` |
| Content encryption and key access | Persistence hooks encrypt protected payload fields; key application re-resolves an active organisation administrator. Central administration has no tenant key export or content route. | `persistence/storage_encryption.py:33`; `application/keys.py:19`; `tests/test_runtime_security.py::test_platform_never_gains_tenant_or_key_access`; `tests/test_key_management.py` |
| Payment authority | Signed provider events and server-persisted checkout bindings establish entitlements; browser return URLs and tenant-supplied metadata do not. | `application/billing.py:136`; `persistence/checkout.py`; `tests/test_billing_http.py`; `tests/test_billing_security.py::test_initial_checkout_uses_only_provider_qualified_prices` |
| Deployment baseline | Supplied internet proxy terminates TLS and sends HSTS. Application container uses a read-only filesystem, drops capabilities and disables privilege escalation; local port binds to loopback. | `deploy/Caddyfile`; `compose.yaml:36` and `:63` |

Implementation paths without a leading directory in this table are relative to `distributedai/`.

## Remaining limitations and implementer responsibilities

- **Central actor attribution has limits.** Cloud platform subjects produce distinct actor hashes; a shared platform token identifies the platform administrator role, not an individual person. Security logs and platform SQL audit tables are not immutable, externally retained or equipped with alerting. Some authentication events may have no actor until authentication succeeds. Configure restricted, tamper-resistant external retention and monitoring, and prefer individual cloud identities.
- **Passkeys and MFA are provider policies.** The application validates OIDC identity but does not enforce an authentication strength or prove that a passkey was used. Require the appropriate identity-provider policies for public administration; consider step-up authentication for key rotation and plan overrides.
- **Traffic protection is local to each replica.** There is no built-in global distributed rate limiter, DDoS protection or WAF. Configure edge budgets, connection limits and the complete trusted proxy chain. Never use wildcard proxy trust where clients can reach the application directly.
- **Infrastructure remains a trust boundary.** Central application roles cannot browse tenant content, but an operator controlling the runtime or available decryption keys can bypass that application boundary. Client-side encryption or attestation-gated confidential computing are deployment options when infrastructure operators must be excluded. Encrypt metadata, backups and logs with suitable cloud/disk controls.
- **Operations need independent validation.** Exercise key rotation, provider revocation, backup restoration, cloud identity policies, payment event handling and incident response in the intended deployment. Maintain dependency/container vulnerability scanning and an external web security assessment. Functional and licence checks are not vulnerability certification.

## OWASP ASVS verification target

Use [OWASP ASVS 5.0.0](https://owasp.org/www-project-application-security-verification-standard/) as the target verification framework. This is a thematic mapping for planning, not an assertion of compliance with an ASVS level or every individual requirement.

| Verification area | Current evidence | Remaining verification |
| --- | --- | --- |
| Authentication and session management | OIDC validation, encrypted sessions, CSRF and rate-limit tests | Provider-enforced authentication strength, deployment-specific identity recovery and externally managed session lifecycle |
| Access control and isolation | Tenant/project tests, explicit platform role, key and billing boundaries | Independent adversarial assessment and production identity lifecycle |
| Input handling and browser security | Bounded requests, strict operation schemas, CSP, safe DOM rendering, header tests | Broader malformed-input/fuzzing and browser/edge testing |
| Cryptography and data protection | AES-256-GCM payload/session tests, key rotation and tenant isolation tests | Cloud key-policy review, backup controls and stronger infrastructure isolation where needed |
| Logging, error handling and configuration | Metadata-only events, request IDs, generic outer error handling, trusted-proxy tests | External immutable retention, alerting, operational response and full cloud configuration assessment |

No penetration-test completion, ASVS compliance or security certification is claimed.
