# IAM Phase 2C — Authentication Integration Design

## Status

Design baseline for `security/iam-phase-2c-authentication-integration`.
This document does not change runtime behavior, database schema, deployment
configuration, or the live AEGIS service.

## Existing boundaries confirmed on main

- `app.auth` authenticates the legacy analyst and approver bearer tokens.
- The dashboard is served from `/dashboard` and its current JavaScript uses
  the legacy token-based flow.
- Phase 2A provides local invitations, Argon2id passwords, account activation,
  password changes, and account status services.
- Phase 2B provides hashed server-managed sessions, cookie/CSRF helpers,
  persistent HMAC-fingerprinted throttling, and migration v2.
- IAM primitives are not yet connected to public HTTP routes.
- Password-authenticated sessions have `mfa_verified_at = NULL`.
- Response approval authorization currently relies on the legacy approver
  bearer identity. This must not be weakened by Phase 2C.

## Phase 2C scope

1. Add a dedicated IAM authentication service and router.
2. Add username/password login for active analyst accounts only.
3. Verify unknown users using a precomputed dummy Argon2id hash to reduce
   username-enumeration timing differences.
4. Use generic login failures for unknown, inactive, locked, and incorrect
   credentials.
5. Apply persistent throttling to both source-IP and normalized
   username-plus-source-IP buckets. Never trust forwarded IP headers unless a
   separately reviewed trusted-proxy configuration exists.
6. Issue opaque server-managed sessions using the existing session service.
   Persist only the session-token digest.
7. Set the existing `__Host-aegis_session` cookie with Secure, HttpOnly,
   Path=/, and SameSite=Lax. Fail closed if required signing secrets or the
   exact HTTPS dashboard origin are not configured.
8. Add session inspection that returns server-derived user identity and role,
   plus a CSRF token for subsequent unsafe browser requests.
9. Add logout that revokes the presented session and clears the cookie.
10. Keep legacy bearer authentication available for existing API clients and
    the current approver workflow until later, separately tested migrations.
11. Do not allow analyst cookie sessions to perform approver actions.
12. Do not expose invitation, activation, account administration, or
    registration endpoints publicly.

## HTTP contract (proposed)

- `POST /api/v1/iam/login`: JSON username/password; exact HTTPS Origin
  required; generic 401 for invalid credentials; 429 with Retry-After for
  active throttle blocks; on success set the session cookie and return
  non-secret identity/session metadata and a CSRF token.
- `GET /api/v1/iam/session`: validate cookie session and return identity,
  role, expiry metadata, and a derived CSRF token. No bearer token is returned.
- `POST /api/v1/iam/logout`: validate Origin and CSRF token when a valid
  session exists, revoke it, and clear the cookie. The operation is
  idempotent for absent/invalid sessions and must not reveal session validity.

## Security requirements

- No default or generated-at-runtime fallback for
  `AEGIS_CSRF_SIGNING_KEY` or `AEGIS_AUTH_THROTTLE_HMAC_KEY`; both must be
  independent secrets of at least 32 bytes.
- Exact HTTPS origin allowlist; no wildcard, null, or arbitrary Origin.
- No raw passwords, cookies, session tokens, CSRF tokens, or HMAC keys in logs,
  database events, responses, or test failure output.
- Account role/status is always loaded from the database. Never accept actor
  identity or role from request JSON, headers, or query parameters.
- Phase 2C analyst sessions remain non-MFA. They must not satisfy any
  approver/MFA step-up requirement.
- Existing audit actor strings and response audit-chain canonical payloads
  remain unchanged.
- Login failure accounting must be atomic and committed even when credentials
  are invalid. Successful authentication clears only its exact matching
  throttle buckets.
- Do not trust `X-Forwarded-For` or `Forwarded` without explicit proxy trust.
- No schema migration is expected for this phase.

## Dashboard migration is a separate, coordinated substep

The static dashboard currently contains a legacy token-entry flow. Do not
remove or bypass it until the cookie API routes are complete and independently
tested. Dashboard JavaScript must use `credentials: "same-origin"`, obtain
and retain the CSRF token in memory, send it on unsafe cookie-authenticated
requests, handle 401 by returning to the login screen, and call logout on
sign-out. It must never read the HttpOnly session cookie or store credentials
in localStorage/sessionStorage.

## Test plan

- Correct analyst login, incorrect password, unknown username, inactive user,
  invited user, and approver account rejection.
- Generic error body for all credential failures.
- Dummy-hash verification path for unknown users.
- IP and username-plus-IP throttle threshold, persistence, expiry, reset,
  Retry-After, and no forwarded-header trust.
- Missing/weak secrets and invalid/missing/non-HTTPS Origin fail closed.
- Cookie attributes, no-store headers, CSRF derivation and verification.
- Session expiry, renewal, revocation, disabled-account invalidation, and
  password-change invalidation.
- Session inspection returns server-derived identity only.
- Cookie analyst session cannot access approver-only operations.
- Existing legacy bearer tests and all existing backend tests remain green.
- Tests use isolated temporary SQLite databases and test-only secrets. No
  test connects to the live Docker volume.

## Deployment boundary

This branch is not deployed. No live database, Docker image, Docker volume,
environment file, or running service may be modified by this phase's GitHub
work. Deployment will require a separate review and explicit authorization.
