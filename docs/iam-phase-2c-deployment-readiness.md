# Phase 2C deployment-readiness checklist

## Status

**Not approved for production deployment.** This document is a pre-deployment
runbook, not authorization to change the live service. The Phase 2C branch
must be merged and separately approved before any production rollout.

## Required configuration

Phase 2C login fails closed unless all three settings are present:

- `AEGIS_AUTH_THROTTLE_HMAC_KEY`: independent random secret, at least 32
  UTF-8 bytes.
- `AEGIS_CSRF_SIGNING_KEY`: a different independent random secret, at least
  32 UTF-8 bytes.
- `AEGIS_IAM_ALLOWED_ORIGINS`: exact HTTPS origin(s), comma-separated.
  Include the public dashboard scheme, hostname, and non-default port where
  applicable. Do not include a path, wildcard, trailing application route, or
  plain HTTP origin.

Generate the two secrets on the deployment host using a cryptographically
secure generator, for example:

```sh
openssl rand -hex 32
openssl rand -hex 32
```

Use a separate invocation for each key. Enter the values directly into the
deployment secret store or the protected local `.env` file. Never commit
`.env`, paste secrets into GitHub issues/PRs, or send them in ChatGPT.
Do not reuse the audit-checkpoint signing key, legacy analyst/approver API
tokens, session tokens, or each other.

Set `AEGIS_SESSION_COOKIE_SECURE=true`. This is mandatory for the
`__Host-aegis_session` cookie. The dashboard must be accessed over HTTPS;
do not weaken the Secure cookie attribute to make plain-HTTP access work.

## Deployment blockers to resolve first

### 1. HTTPS termination and network exposure

The current Compose file publishes port 8000 on the host and does not provide
TLS termination itself. Production access must be placed behind a maintained
HTTPS reverse proxy or equivalent TLS ingress. Restrict direct access to the
application port so clients cannot bypass that ingress. Confirm that the
public dashboard and API share the exact origin configured in
`AEGIS_IAM_ALLOWED_ORIGINS`.

Do not enable credentialed cross-origin CORS as a workaround. The browser
client is designed for same-origin requests.

### 2. Trusted reverse-proxy client address

The login throttler uses the ASGI connection address and deliberately ignores
`X-Forwarded-For` and `Forwarded`. When a reverse proxy is introduced,
`request.client.host` may therefore be the proxy address for every user.
That can make all users share one IP throttle bucket and allow one user's
failures to block other users.

The application supports an explicit `AEGIS_TRUSTED_PROXY_CIDRS` allowlist.
Set it to comma-separated IP addresses or CIDR networks belonging only to
your ingress/reverse proxies (for example, `10.20.0.10/32,2001:db8:20::/64`).
Leave it empty when no trusted proxy is present; in that state all forwarding
headers are ignored.

Only `X-Forwarded-For` is considered. The immediate TCP peer must match a
configured trusted network. The application validates the entire bounded
header (maximum 20 hops and 1024 characters), then walks the chain from
right to left and selects the first untrusted hop. Invalid or excessive
headers fall back to the immediate peer. IPv4 and IPv6 are supported.
Malformed CIDR configuration causes login to fail closed with HTTP 503.

**Ingress requirement:** configure the proxy to remove any inbound
client-supplied `X-Forwarded-For` header and write a canonical chain itself.
Restrict direct access to the application port so clients cannot bypass the
trusted ingress. Do not add broad private networks unless every host in those
networks is an administratively trusted proxy.

Do not enable Uvicorn proxy-header trust for all addresses (for example,
`--forwarded-allow-ips='*'`). Verify the effective client address with
integration tests through the actual ingress before production.

### 3. Existing legacy authentication

Keep the existing analyst and approver bearer-token environment variables
configured and distinct while legacy API clients and approver operations
depend on them. Phase 2C does not migrate browser approvals to cookie sessions.
Do not disable or rotate the legacy tokens as part of this deployment without
a separate compatibility and operator-access plan.

### 4. Database and application compatibility

The deployed database must already have IAM migrations v1 and v2 applied.
Phase 2C adds no migration and must not trigger one at startup. Confirm the
application image includes the new route modules and dashboard assets before
starting it. Do not replace the persistent `/data` volume or audit-checkpoint
directory.

## Pre-deployment verification

Complete and record each item before authorizing rollout:

- [ ] PR #18 reviewed, merged, and target commit SHA recorded.
- [ ] All required GitHub Actions checks pass on the exact merge commit.
- [ ] Independent CSRF and throttling keys stored in the protected secret
      store; neither is present in source control or logs.
- [ ] Exact HTTPS origin confirmed from the production browser address.
- [ ] TLS ingress configured; direct public access to port 8000 blocked.
- [ ] Trusted-proxy/client-IP behavior resolved and tested.
- [ ] Legacy analyst and approver credentials remain available and distinct.
- [ ] Existing database backup and signed audit-checkpoint inventory verified.
- [ ] IAM schema check reports v1/v2 current with no pending migration.
- [ ] Rollback image and deployment configuration are available.
- [ ] A maintenance window and operator with host access are available.

## Post-deployment smoke tests

Use a provisioned analyst account. Do not use an approver account for this
browser-login test.

1. Open the dashboard through the configured HTTPS origin.
2. Confirm an unauthenticated visitor sees the sign-in form and cannot read
   protected API data.
3. Sign in with the active analyst account.
4. Confirm the session cookie is Secure, HttpOnly, Path=/, SameSite=Lax, and
   has no Domain attribute. Do not copy or disclose its value.
5. Confirm the dashboard loads protected data and no bearer token is stored in
   localStorage or sessionStorage.
6. Confirm an unsafe cookie-authenticated request without a valid CSRF token
   is rejected.
7. Sign out and confirm the session is revoked; refresh the dashboard and
   confirm the sign-in form returns.
8. Confirm an approver account is rejected by the new password-login route.
9. Confirm legacy approver bearer authentication still works for the existing
   approved workflow.
10. Confirm the health endpoint, SQLite integrity, foreign-key check, IAM
    migration history, and signed audit-checkpoint chain remain healthy.

Never include passwords, cookies, CSRF tokens, or API bearer tokens in test
logs, screenshots, issue reports, or support messages.

## Rollback principles

If smoke tests fail, stop the rollout and restore the previously approved
application image and configuration. Do not delete, recreate, or initialize
the persistent data volume. Do not roll back the database schema: Phase 2C
does not add a migration. Preserve audit-checkpoint files and verify the
audit chain after rollback. Revoke any newly issued test sessions through the
application or controlled IAM operator procedure.

## Explicitly outside this runbook

This document does not authorize:
- merging PR #18;
- writing production secrets or changing the live `.env`;
- stopping/recreating the running container;
- changing the production image or Compose deployment;
- applying database migrations;
- modifying the persistent data volume or audit-checkpoint history.
