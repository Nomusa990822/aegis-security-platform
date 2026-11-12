# AEGIS IAM — Phase 2B

Phase 2B adds server-managed session, browser-security, and persistent
authentication-throttling primitives. These are service/helper modules, not
public login or logout endpoints. Legacy bearer authentication is unchanged.

## Phase 2B implementation

### Server-managed sessions

- Opaque 256-bit random session tokens; only SHA-256 digests are stored.
  SHA-256 is used only for uniformly random, high-entropy tokens, not passwords.
- Session issuance is restricted to active IAM accounts.
- Password-authenticated session issuance always sets \`mfa_verified_at\` to
  \`NULL\`. No Phase 2B helper can mark a session MFA-verified.
- Idle and absolute expiry are checked on every validation. Activity renews
  only the idle expiry and can never extend the absolute expiry.
- Revocation is idempotent; user-wide revocation and retention-based cleanup
  are available. Existing password-change and disable/lock services revoke
  sessions.
- Session validation fails closed for malformed, unknown, revoked, expired,
  or inactive-account sessions.

### Browser security

- The cookie helper uses the \`__Host-aegis_session\` prefix, Secure, HttpOnly,
  Path=/, no Domain attribute, and SameSite=Lax by default. SameSite=Strict is
  supported; SameSite=None and insecure cookies are rejected.
- Cookie deletion uses the same security attributes.
- CSRF tokens are HMAC-SHA256 values bound to the session token and a separate
  secret of at least 32 bytes. Verification uses constant-time comparison.
- Origin validation requires an exact allowlisted HTTPS origin and rejects
  null, userinfo, paths, queries, fragments, and untrusted ports.
- These helpers do not install routes, configure CORS, or automatically add
  CSRF checks to existing endpoints. Route integration must require CSRF
  validation on unsafe cookie-authenticated methods and must validate Origin
  independently; SameSite is defense in depth, not a replacement.

### Persistent authentication throttling

- SQLite migration version 2 adds an indexed, persistent throttling table.
- Bucket identifiers are HMAC-SHA256 fingerprints; raw usernames and IP
  addresses are not stored.
- Failure increments use a single atomic SQLite UPSERT with RETURNING, so
  concurrent workers cannot perform a read/increment/write race.
- Successful authentication clears only the matching bucket. Expired records
  can be purged.
- Use separate buckets for source IP and a username+source-IP pair. Do not
  impose a long global username-only lockout: that creates an account-denial
  of-service primitive. Throttling must not change the IAM account status.
- Client IP must come from the ASGI connection scope unless a trusted-proxy
  configuration has been explicitly implemented. Never trust arbitrary
  X-Forwarded-For or Forwarded headers.

## Required deployment secrets

Generate independent random values of at least 32 bytes for:
- \`AEGIS_CSRF_SIGNING_KEY\` — CSRF token derivation.
- \`AEGIS_AUTH_THROTTLE_HMAC_KEY\` — opaque throttle-bucket fingerprints.

Keep both outside source control and outside the audit-checkpoint signing-key
purpose. Do not reuse the session token, password, TOTP encryption, or audit
signing key. The service functions accept the key explicitly; a future
authentication-route integration must load it from the deployment secret
store and fail closed if it is absent or weak. Do not add fallback defaults.

The session cookie must be Secure in every deployment. Local development
should use HTTPS rather than weakening the cookie policy. Configure the exact
dashboard origin in the future route layer; do not use wildcard origins with
credentialed cookies.

## Migration and operation

Migration version 2 is additive and creates \`iam_auth_rate_limits\` plus its
cleanup index. It does not modify version 1 or any existing AEGIS tables.
Migrations remain explicit and are never run at application startup.

Before applying version 2 to the live database, follow the existing guarded
migration procedure: stop the application, verify a restorable cold backup and
the signed audit-checkpoint inventory, run the read-only preflight, then apply
with all required operator attestations. Verify SQLite integrity, foreign keys,
migration history, and service health afterward. This PR does not apply the
migration to any live database.

## Explicitly deferred

- Public IAM login, logout, refresh, password-change, or session-inspection
  HTTP routes.
- Switching dashboard or API authentication from legacy bearer tokens to
  cookie sessions.
- CORS policy changes, trusted-proxy configuration, and route-level CSRF
  enforcement; the helpers are ready for that integration but do not perform it.
- TOTP enrollment/verification, recovery codes, MFA step-up, and approval
  authorization integration.
- Account recovery/reset, reactivation, and external identity providers.

No existing endpoint, middleware behavior, dashboard token handling, startup
migration behavior, database file, Docker volume, response audit chain, or
running service is changed by these primitives.
