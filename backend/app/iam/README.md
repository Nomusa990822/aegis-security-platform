# AEGIS IAM — Phase 2A

Phase 2A adds local password and account-lifecycle primitives. It does not add
HTTP routes, change legacy bearer authentication, issue sessions, or run IAM
migrations during application startup.

## Implemented

- Argon2id hashing with an explicit production profile: 19 MiB memory, two
  iterations, one lane, 32-byte output, and 16-byte salt.
- Password verification, rehash detection, and verified rehash generation.
- Long passphrases: at least 15 characters and at most 1,024 UTF-8 bytes.
  Passwords are not silently trimmed or Unicode-normalized.
- Controlled local-operator account invitations.
- Cryptographically random, one-time activation tokens with a public UUID
  selector and an Argon2id hash of the secret; plaintext tokens are never stored.
- Atomic invitation activation, expiry checks, replay protection, and
  recipient-selected passwords.
- Active-account password changes with current-password verification.
- Account disable/lock operations and session revocation.
- Privacy-conscious security events that reject credential-like metadata.
- A local CLI: `python -m app.iam.admin`.

## Operator commands

Run these from the backend working directory, against an existing database
whose IAM schema is current:

- `python -m app.iam.admin invite --username analyst.one --role analyst`
- `python -m app.iam.admin activate`
- `python -m app.iam.admin disable --user-id UUID`
- `python -m app.iam.admin lock --user-id UUID`

The invitation token is printed once for secure out-of-band delivery. The
activation token and password are requested with hidden prompts, not command
line arguments. The CLI refuses missing or symlink database paths and checks
database integrity and migration history before opening it for writes. It
does not create a database or apply migrations.

## Security boundaries and deferred work

The CLI is a local-operator trust boundary; protect access to the host/container
and its terminal. Invitation and status service functions must not be exposed
through public HTTP routes until a later authorization milestone supplies a
trusted operator principal.

Activation is restricted to accounts in the invited state. This phase does
not implement public registration, account reactivation, administrator
password-reset tokens, or password-reset email. Those require a separately
reviewed authenticated administrative workflow.

Password changes and disable/lock operations revoke all unrevoked IAM sessions.
Session issuance, validation, idle/absolute expiry, cookies, CSRF protection,
and persistent authentication throttling are implemented in Phase 2B. MFA
enrollment, TOTP verification, recovery codes, and step-up authorization
remain later milestones. Password authentication alone never marks a session
MFA-verified.

No database migration is added or applied by Phase 2A. Existing schema version
1 is used as-is; live database, startup behavior, legacy bearer authentication,
and response audit history remain unchanged.

---

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
