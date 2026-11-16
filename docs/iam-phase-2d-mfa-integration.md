# Phase 2D — MFA integration design

## Status and dependency

This is a stacked change based on `security/iam-phase-2c-authentication-integration`.
Phase 2C must be reviewed and merged before this branch can be merged. This phase
does not deploy, apply migrations to a live database, alter Docker volumes, or
change production secrets.

The IAM v1 schema already contains the foundational tables and columns:
`iam_mfa_factors`, `iam_recovery_codes`, `iam_auth_challenges`, and
`iam_sessions.mfa_verified_at`. Phase 2D must implement and test their use;
it must not silently run migrations at application startup.

## Security objectives

1. A password alone never authenticates an account that has an active TOTP factor.
2. Approver accounts cannot receive a normal authenticated browser session until
   a valid second factor has been verified.
3. MFA enrollment is staged: an encrypted pending TOTP secret is created first,
   and becomes active only after a valid TOTP is confirmed.
4. TOTP verification is time-window bounded and replay resistant. Updating the
   accepted time-step and consuming a challenge/recovery code must be atomic.
5. Recovery codes are high-entropy, shown only once, and stored only as
   Argon2id hashes. Each code is consumed once.
6. MFA verification state is server-owned. A browser cannot submit a role,
   actor, factor status, or `mfa_verified` flag.
7. Privileged approver decisions require a server-authenticated approver
   principal with a recent MFA verification. A normal analyst cookie session
   cannot satisfy this requirement.
8. MFA secrets use authenticated encryption at rest with a dedicated,
   independently provisioned key. The encryption key is not reused for audit
   checkpoints, CSRF, throttling, session tokens, or password hashing.
9. Enrollment, confirmation, disablement, recovery-code regeneration, failed
   verification, and step-up are recorded as privacy-safe security events.
   Secret material, TOTP values, recovery codes, challenge tokens, and
   provisioning URIs must never enter logs or audit metadata.
10. Existing bearer authentication and response audit actor strings remain
    compatible. Legacy bearer approver credentials are not silently promoted
    to MFA-verified browser sessions.

## Browser authentication flow

### Login

- Password login remains origin-checked and throttled.
- If an account has no active TOTP factor and is an analyst, Phase 2C's
  analyst-only cookie session behavior remains unchanged.
- If an account has an active TOTP factor, password success creates a short-lived
  `login_mfa` challenge, not a full session. The challenge token is random,
  stored only as a digest, single-use, expiry-bounded, and rate-limited.
- Approver password success always requires the MFA challenge flow; approvers
  without an active TOTP factor are denied generic login and must be enrolled
  through a controlled local operator workflow before browser access.
- A successful challenge consumes the challenge and issues a session with
  `mfa_verified_at` set by server-side code in the same transaction.
- Invalid, expired, replayed, or consumed challenges fail closed with generic
  responses. Challenge attempts are bounded.

### Enrollment and factor lifecycle

- Enrollment requires an authenticated session, CSRF validation, exact HTTPS
  Origin validation, and recent password re-authentication.
- A pending factor's secret is encrypted using an authenticated cipher and
  associated data binding the factor and user IDs.
- The provisioning URI is returned only to the authenticated enrolling
  browser, with `Cache-Control: no-store`; it is never persisted or logged.
- Confirmation validates TOTP and atomically activates the pending factor,
  recording the accepted step to prevent replay.
- Recovery codes are generated only after successful factor confirmation,
  returned once, and hashed before persistence.
- Disabling MFA requires recent password re-authentication and a valid current
  TOTP or unused recovery code. Approver accounts cannot disable their final
  factor through the browser; a separate audited local operator recovery
  procedure is required.
- Recovery-code regeneration requires recent MFA step-up and atomically
  replaces the prior unused set.

### Step-up and approvals

- A dedicated endpoint verifies a fresh TOTP or recovery code against the
  current authenticated session and updates `iam_sessions.mfa_verified_at`
  server-side.
- The freshness window is short (five minutes by default), and the timestamp
  is not accepted from request data.
- Approver browser authorization resolves an IAM session principal from the
  HttpOnly cookie and checks both the account role and recent server-side MFA
  timestamp. The existing legacy bearer path remains available only under its
  pre-existing configured-token semantics until a separately approved
  retirement milestone; no claim is made that legacy static tokens provide
  interactive MFA.
- Approval endpoints continue to use the existing audit actor identity and
  prohibit self-approval.

## Cryptographic and operational controls

- Use a vetted AEAD implementation (AES-256-GCM or ChaCha20-Poly1305) with a
  fresh random nonce per encryption and strict key-length validation.
- Configure `AEGIS_MFA_ENCRYPTION_KEY` independently, fail closed if missing,
  malformed, or weak, and support an explicit key identifier for rotation.
- TOTP uses RFC 6238 / HMAC-SHA1 compatibility, 30-second steps, six digits,
  and a narrow clock-drift window. The accepted time-step is monotonically
  advanced using a conditional database update.
- Use Argon2id for recovery-code hashes; never use fast unsalted hashes for
  human-entered recovery codes.
- Use a database write transaction/conditional updates for challenge
  consumption, TOTP replay prevention, recovery-code consumption, and factor
  activation. Concurrent duplicate submissions must have at most one winner.
- Avoid exposing whether a username has an MFA factor. Use generic login and
  challenge errors and no-store responses.
- Never put provisioning URIs, raw secrets, recovery codes, TOTP values, or
  challenge tokens in telemetry, exception messages, test snapshots, or CI
  artifacts.

## Tests required

- RFC 6238 known-answer vectors; invalid formats; bounded drift; clock
  handling; replay rejection; concurrent/repeated acceptance.
- AEAD round-trip, tamper detection, wrong key, wrong associated data, nonce
  uniqueness, key-ID handling, and fail-closed configuration.
- Pending enrollment cannot authenticate; successful confirmation activates
  exactly one factor; abandoned pending factor expiry/cleanup behavior.
- Recovery code entropy, one-time display, Argon2id storage, single-use
  consumption under concurrency, invalid code, and regeneration invalidation.
- Password-only approver login cannot issue a session; challenge expiry,
  replay, attempt limits, and challenge consumption are atomic.
- MFA-verified sessions are created/updated only by server-side verification;
  client-supplied MFA/role/actor fields are rejected.
- Approver endpoints reject analyst sessions, unverified approver sessions,
  stale MFA timestamps, and forged request data; accept only a recent verified
  approver session.
- Existing analyst cookie flows, CSRF/origin protections, legacy bearer tests,
  audit actor stability, and all existing backend regression tests continue
  passing.
- All database tests use isolated temporary SQLite databases. CI only; no
  live database, Docker volume, deployment, or production secret changes.

## Out of scope

No public registration, public administrator provisioning, email/SMS MFA,
WebAuthn/passkeys, production key generation or rotation, live migration,
deployment, Docker rebuild/restart, legacy bearer-token retirement, or
changes to the response execution safety model.
