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
whose IAM migration version 1 is current:

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
and persistent authentication throttling remain Phase 2B. MFA enrollment,
TOTP verification, recovery codes, and step-up authorization remain later
milestones. Password authentication alone never marks a session MFA-verified.

No database migration is added or applied by Phase 2A. Existing schema version
1 is used as-is; live database, startup behavior, legacy bearer authentication,
and response audit history remain unchanged.
