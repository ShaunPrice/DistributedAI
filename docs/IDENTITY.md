# Cloud identity and passkeys

The management console supports provider-hosted OpenID Connect authorization-code login with PKCE S256. The identity provider handles passkey enrollment, recovery, device policy and authentication. DistributedAI stores no passkeys. Enable this option on local or public deployments; public URLs require HTTPS.

Use `LOGIN_MODE=oidc` to disable token-based browser login. `both` permits both methods and therefore does not enforce a passkey-only policy. `token` is the local default. Machine MCP credentials remain separate from browser ID tokens.

## Common configuration

Register a **web application** at your provider with this exact redirect URI:

```
https://memory.example.com/manage/oidc/callback
```

Set in `.env`:

```
LOGIN_MODE=oidc
LOGIN_PROVIDER=Your organisation
LOGIN_ISSUER=https://your-fixed-issuer
LOGIN_CLIENT_ID=your-web-application-client-id
```

Put the web application's client secret in `.secrets/login_client_secret`. Put an explicit mapping in `.secrets/login_subjects.json`:

```json
{"provider-immutable-subject-id": "existing-distributedai-principal-id"}
```

Provision users and assign projects in People & access first; obtain each immutable `sub` through the provider's trusted administrative tooling or a verified provider token. Email addresses, email domains, project codes, provider groups and unverified JWT claims never grant access. This version supports one browser issuer per deployment; multiple organisations can map users from that issuer. A trusted deployment operator maintains the mapping file. It is not an automatic signup or directory synchronization service.

Run `python3 scripts/setup.py --generate-only` to prepare missing files without changing existing values, then `docker compose up -d --force-recreate api`. Compose mounts these files as read-only secrets. The enclosing `.secrets` directory is 0700; mounted files are 0444 to permit the non-root container UID to read them on Linux. Protect backups and keep the directory outside source control. After manually replacing a file, rerun the setup preparation to restore its mount permissions.

## AWS

Use a Cognito User Pool with **managed login**, an app client allowing authorization code flow and `openid`, and an exact callback allowlist. `LOGIN_ISSUER` is `https://cognito-idp.REGION.amazonaws.com/USER_POOL_ID`; the managed-login domain is discovered separately. Set `LOGIN_PROVIDER=AWS Cognito`.

Enable WebAuthn/passkeys in the user pool's supported feature tier, configure the relying-party domain correctly and choose the required user-verification policy. Passkey availability and enforcement are Cognito settings, not a promise made by an ordinary OIDC ID token. See [Cognito authentication](https://docs.aws.amazon.com/cognito/latest/developerguide/authentication.html), [WebAuthn configuration](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_WebAuthnConfigurationType.html) and [authorization/PKCE](https://docs.aws.amazon.com/cognito/latest/developerguide/authorization-endpoint.html).

## Azure

Use a single-tenant Microsoft Entra ID web application for workforce access. `LOGIN_ISSUER=https://login.microsoftonline.com/TENANT_ID/v2.0`, `LOGIN_PROVIDER=Microsoft Entra`. Register the web callback and a client secret. Do not use `common` or turn off issuer validation.

Enable passkeys through the tenant's authentication-method policies. Where supported, require the appropriate authentication strength through Conditional Access. For customer accounts, Entra External ID supports hosted customer passkey flows; use the exact issuer from that external tenant's discovery document and configure its user flow. See [workforce passkeys](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-passkeys-fido2) and [External ID passkeys](https://learn.microsoft.com/en-us/entra/external-id/customers/how-to-sign-in-with-passkey). Guest/federation capabilities differ; validate the chosen flow in that tenant.

## GCP

Create an OAuth web client in a Google Cloud project, configure its consent screen/audience and callback, then use `LOGIN_ISSUER=https://accounts.google.com`, `LOGIN_PROVIDER=Google`. Google accounts, including managed Workspace/Cloud Identity accounts, can use provider-managed passkeys. Workspace administrators configure password-skipping policies where appropriate.

This is **Sign in with Google OIDC**, backed by Google identity; it does not claim that Google Cloud Identity Platform provides native passkey enrollment. See [Google OIDC](https://developers.google.com/identity/openid-connect/openid-connect), [managed-account passkeys](https://support.google.com/a/answer/13529161), and [Google account passkeys](https://support.google.com/accounts/answer/13548313).

## Security and validation

The callback verifies the signed ID token against the configured issuer's JWKS, browser client audience, expiration, issue time, nonce, and authorized party. PKCE binds code redemption to the browser flow. The five-minute encrypted flow cookie binds `state` and uses Secure/HttpOnly/SameSite=Lax; the resulting encrypted browser session uses SameSite=Strict and lasts at most 30 minutes or the ID-token expiry. Provider authorization codes must be single use; repeated redemption fails. Provider errors and tokens are not returned in errors. Application access logging is disabled to avoid logging callback codes; keep query strings out of reverse-proxy logs too.

Every request checks the current configured subject mapping and active local principal. Local revocation is immediate; provider-side revocation may take until the short session expires. No refresh token is requested or stored. Sign out terminates the local session, not the provider session. Passkey-only authentication must be required at the provider; this service does not infer it from a successful generic login.

Signed-token tests exercise the three issuer profiles, successful login, PKCE/state/nonce, invalid issuer/audience/expiry/subject, cookie forgery, replayed authorization codes, mapping removal and token-login disablement. Live provider registration, passkey devices and cloud deployment remain operator acceptance checks; no cloud credentials were supplied or changed.
