# AEGIS IAM — Phase 2E Production Readiness and Deployment Runbook

**Status:** Planning and documentation only  
**Baseline:** `main` at `1a8d73d2774812dd304e3b45a5de5b4764b8faa8`  
**Scope:** Readiness assessment, deployment gates, backup/restore planning, and operational verification  
**Explicit exclusions:** No production secret access, live database operation, Docker/container change, volume operation, migration, or deployment is performed by this phase.

## 1. Executive assessment

Phase 2C and Phase 2D are merged. The merged code has browser password authentication, server-managed sessions, TOTP MFA, recovery codes, and recent-MFA checks for approver actions made through browser sessions. The current IAM migration registry contains versions 1 and 2. Phase 2C and Phase 2D add no schema migration; the MFA factor, recovery-code, challenge, and session-MFA fields are part of IAM migration version 1. Version 2 adds persistent authentication throttling.

The repository is **not yet cleared for production deployment**. The following are deployment gates, not optional polish:

1. The legacy approver bearer-token path is retired by this Phase 2E change. `AEGIS_APPROVER_TOKEN` is no longer loaded or accepted; a token previously configured under that name receives HTTP 401. `get_approver_actor` accepts only an IAM browser session with a server-owned MFA verification timestamp no older than five minutes. Analyst bearer authentication remains available. Production must deploy this change before claiming that all approver decisions require MFA.
2. The Compose file publishes host port `8000` without a loopback bind restriction and does not terminate TLS. Production must put the service behind maintained HTTPS ingress and prevent direct public access to the application port.
3. MFA encryption key custody and recovery must be established before enrolling production accounts. Losing the configured key makes existing encrypted TOTP factors unusable. The current implementation does not provide a multi-key decryption keyring or automated TOTP-key rotation.
4. A production-grade, tested backup/restore procedure must preserve a consistent set of SQLite data, audit checkpoint files, and the corresponding cryptographic keys.
5. The production host, ingress, secret store, monitoring, retention, and incident-response ownership must be identified and tested.

A healthy `/api/v1/health` response is not proof that authentication configuration, MFA key access, TLS ingress, or the signed audit-checkpoint chain is healthy.

## 2. Verified implementation facts

### 2.1 Authentication and authorization

- Browser login is served by the IAM routes. The dashboard uses same-origin cookies and does not store bearer tokens in browser local/session storage.
- The session cookie is named `__Host-aegis_session`; it is Secure, HttpOnly, Path=/, has no Domain attribute, and uses SameSite=Lax.
- Unsafe cookie-authenticated requests require the session-bound CSRF header and an exact allowlisted HTTPS Origin.
- MFA-enabled accounts complete a short-lived password-plus-TOTP/recovery-code challenge before a session is issued.
- Browser approver actions require a server-set MFA timestamp no older than five minutes.
- Analyst bearer authentication remains available for existing integrations. The legacy approver bearer token is retired: `AEGIS_APPROVER_TOKEN` is ignored and cannot authenticate any API request. Approver identities are issued by IAM browser sessions after password plus TOTP/recovery-code login. Approver-only actions require `auth_method=browser_session` and a server-owned MFA timestamp no older than five minutes. A bearer actor with a forged `role=approver` is rejected.
- Public registration, public invitation, and public administrative provisioning endpoints are not provided. Account invitation, activation, MFA enrollment, reset, disable, and lock operations are local-operator CLI workflows.
- Passwords use Argon2id. Recovery codes are single-use and stored as Argon2id hashes.

### 2.2 Database and migrations

- IAM migration version 1 creates the IAM account, credentials, MFA factors, recovery codes, sessions, challenges, activation-token, access-token, and security-event tables.
- IAM migration version 2 adds persistent authentication throttling storage and its index.
- The migration registry currently contains versions 1 and 2.
- Application startup calls the ordinary application database initializers; it does not call the IAM migration runner. IAM migrations are explicit.
- Phase 2C and Phase 2D add no new IAM migration. A deployment of the merged Phase 2C/2D code against the already-current v1/v2 IAM schema should not need an IAM migration.
- The migration CLI opens only an existing regular database, rejects symlink paths, supports a read-only `--check`, and requires explicit `--backup-verified`, `--audit-inventory-verified`, and `--application-stopped` attestations for `--apply`.
- The migration runner checks SQLite integrity, foreign keys, migration version order, and migration checksums. It does not create a missing database.

### 2.3 MFA encryption key

- `AEGIS_MFA_ENCRYPTION_KEY` must decode from URL-safe Base64 (without padding) to exactly 32 bytes.
- `AEGIS_MFA_ENCRYPTION_KEY_ID` must be configured and must match the key ID stored with each active factor.
- TOTP secrets are encrypted with AES-256-GCM; the database stores ciphertext, nonce material, and key ID, not plaintext TOTP secrets.
- Decryption currently requires the configured key ID to match the factor's stored key ID. There is no supported previous-key keyring or in-place re-encryption/rotation utility.
- Keep the MFA key in an approved secret manager and in a separately protected, recoverable key backup. Do not rotate it casually. If it is lost, affected factors cannot be decrypted; affected users need a controlled recovery/re-enrollment process.
- The MFA key is separate from the audit-checkpoint signing key, CSRF signing key, authentication-throttle HMAC key, analyst API token, and session tokens.
- Remove the retired `AEGIS_APPROVER_TOKEN` and `AEGIS_APPROVER_ID` entries from deployment configuration after this release is deployed and no external consumer depends on them. The application ignores both settings in this release.

### 2.4 Container and network

- The Docker image runs as the non-root `aegis` user.
- Compose enables a read-only container filesystem, a temporary `/tmp`, `no-new-privileges`, drops Linux capabilities, and mounts a named persistent volume at `/data`.
- The database path is `/data/aegis.db`; the checkpoint directory is `/data/audit_checkpoints`.
- Compose currently declares `8000:8000`, which publishes the application port on host interfaces by default. It has no built-in TLS termination.
- The container health check calls `/api/v1/health`. That endpoint checks database connectivity only.
- The deployment image should be identified by an immutable digest for each release. Do not treat the mutable `local` tag as a release identifier.

## 3. Configuration inventory

Provision each value through the production secret manager or protected deployment configuration. Never put real values in Git, PRs, tickets, screenshots, shell transcripts, or ChatGPT.

| Variable | Requirement |
|---|---|
| `AEGIS_ANALYST_TOKEN` | Required by legacy API auth; at least 32 characters/bytes as enforced by code. |
| `AEGIS_ANALYST_ID` | Optional analyst bearer actor identifier; defaults to `analyst`. Approver identity comes from the IAM user record. |
| `AEGIS_AUDIT_CHECKPOINT_KEY` | Active audit-checkpoint signing key; preserve the current key and any configured legacy/previous keys needed to verify historical checkpoints. |
| `AEGIS_AUDIT_CHECKPOINT_KEY_ID` | Active checkpoint key identifier. Preserve key-ID history. |
| `AEGIS_AUDIT_CHECKPOINT_DIR` | Persistent checkpoint directory; production path should remain `/data/audit_checkpoints`. |
| `AEGIS_DATABASE_PATH` | Persistent SQLite path; production path should remain `/data/aegis.db`. |
| `AEGIS_AUTH_THROTTLE_HMAC_KEY` | Independent random secret of at least 32 UTF-8 bytes. |
| `AEGIS_CSRF_SIGNING_KEY` | Independent random secret of at least 32 UTF-8 bytes; do not reuse the throttle key. |
| `AEGIS_IAM_ALLOWED_ORIGINS` | Exact HTTPS browser origin(s), comma-separated; scheme, hostname, and non-default port only. No path or wildcard. |
| `AEGIS_SESSION_COOKIE_SECURE` | Must remain `true`. |
| `AEGIS_TRUSTED_PROXY_CIDRS` | Exact ingress proxy IPs/CIDRs only. Empty means forwarded headers are ignored. |
| `AEGIS_MFA_ENCRYPTION_KEY` | Independent URL-safe Base64 key that decodes to exactly 32 bytes. |
| `AEGIS_MFA_ENCRYPTION_KEY_ID` | Stable key identifier matching the factors encrypted with this key. |

The optional threat-intelligence provider key is not an IAM prerequisite. Configure it only if the corresponding enrichment integration is deliberately enabled.

### Secret-generation and custody rules

- Generate every secret independently with a cryptographically secure generator. Do not derive one key from another or reuse the audit key, API tokens, CSRF key, throttle key, or MFA key.
- Use a secret manager with access control and audit logging. Restrict read access to the deployment identity and authorised operators.
- Back up the audit signing key and MFA encryption key in a separate, encrypted, access-controlled recovery location. Test that authorised recovery personnel can retrieve them without exposing them in logs.
- Record key IDs, creation dates, owners, and recovery location references; never record key values in the inventory.
- Do not rotate the MFA encryption key until a supported re-encryption/keyring process exists or all affected factors have been deliberately re-enrolled under a tested change plan.
- Preserve audit signing keys for as long as any retained checkpoint depends on them. Follow `docs/security/AUDIT_CHECKPOINT_KEY_ROTATION.md`.

## 4. Network and ingress deployment gates

Before production traffic is enabled:

1. Terminate TLS at a maintained reverse proxy or managed HTTPS ingress. Enforce modern TLS and redirect HTTP to HTTPS at the ingress.
2. Ensure the browser dashboard and API are served from the same exact origin configured in `AEGIS_IAM_ALLOWED_ORIGINS`.
3. Restrict direct access to container port 8000. If the proxy runs on the same host, bind the published port to loopback (for example, `127.0.0.1:8000:8000`) and firewall it. If the proxy is another container, prefer a private Docker network and do not publish the app port publicly. Choose the arrangement that matches the actual topology; do not blindly change the Compose port mapping.
4. Configure ingress to remove client-supplied `X-Forwarded-For` and write a canonical forwarding chain. Configure `AEGIS_TRUSTED_PROXY_CIDRS` with only the immediate trusted proxy networks.
5. Verify the ASGI peer address is the expected proxy address and that the resolved client IP is correct for direct, proxied, and spoofed-header test requests.
6. Do not enable Uvicorn proxy-header trust for all addresses and do not use a wildcard trusted-proxy CIDR.
7. Do not add permissive credentialed CORS. The browser app is designed for same-origin requests.
8. Verify that the health endpoint and all application routes are reachable only through the intended ingress policy.

The trusted-proxy implementation accepts only `X-Forwarded-For`, validates bounded chains, and walks the chain right-to-left across configured trusted hops. Invalid forwarding headers fall back to the immediate peer; invalid CIDR configuration causes login to fail closed.

## 5. Accounts and MFA bootstrap

Perform account setup only after the production database and secrets have been provisioned and verified, and while an authorised operator has a protected interactive terminal.

1. Create an invited analyst and approver using the local-only CLI. Do not create a public registration endpoint.
2. Deliver each one-time activation token out of band using an approved secure channel. Avoid shell logging and ticketing systems.
3. Activate accounts with strong passphrases using the hidden CLI prompts.
4. Enrol every approver in TOTP using the local `mfa-enroll` command before enabling browser approver use. Store the one-time recovery codes in the approved secure recovery store.
5. Enrol analysts in MFA according to the organisation's policy. MFA-enabled analyst accounts will be challenged at login.
6. Verify that the authenticator works and that a recovery code is usable under a controlled test before closing the bootstrap task.
7. The MFA enrollment CLI writes provisioning material and recovery codes only to an attached terminal; run it with a protected interactive TTY. Do not pipe or redirect sensitive output.
8. Keep the local operator CLI and its host/container access restricted. The `mfa-reset` command revokes factors, unused recovery codes, and all sessions; it is a recovery action, not a routine login mechanism.

The legacy bearer approver token remains a separate authorization path and does not gain MFA by enrolling the browser account. This is the production MFA coverage blocker described in Section 1.

## 6. Backup and restore requirements

A backup is not considered valid merely because a file copy completed. AEGIS state is a coordinated set:

- SQLite database at `/data/aegis.db`;
- signed response-audit checkpoint files at `/data/audit_checkpoints`;
- audit-checkpoint active, legacy, and previous signing keys plus key IDs;
- MFA encryption key plus key ID;
- deployment configuration and immutable application image digest;
- any other external secret/configuration required to authenticate and operate the deployment.

### Before each deployment or migration

1. Announce a maintenance window and stop writes using the approved maintenance procedure.
2. Stop the AEGIS application before making a cold file-level copy of SQLite. Do not copy only the main database file while SQLite is actively writing.
3. Create an encrypted, access-controlled backup containing the database and the entire checkpoint directory as one consistent recovery point. Back up required keys separately in the approved secret-recovery system.
4. Record the backup timestamp, image digest, database file identity/size, checkpoint inventory summary, and key IDs. Do not record secret values.
5. Verify the backup is readable and restorable in an isolated environment. Run SQLite `PRAGMA integrity_check` and `PRAGMA foreign_key_check`; run the official checkpoint inventory against the restored database and restored checkpoint directory using the matching audit signing-key configuration.
6. Confirm checkpoint signature validity, checkpoint/database matching, hash-chain and lifecycle validity, and no unexplained pending intents, orphan files, quarantine evidence, temporary files, or unrecognised files.
7. Preserve the pre-deployment image digest and deployment configuration.

### Restore principles

- Restore the database and checkpoint directory from the same recovery point. Do not mix a newer database with older checkpoint files or vice versa.
- Restore the matching audit signing keys and MFA encryption key/key IDs before starting the application.
- Restore to an isolated target first. Verify SQLite integrity, foreign keys, IAM migration history, checkpoint inventory, and application health before routing traffic.
- Preserve the failed environment as evidence until recovery is verified.
- Never delete or recreate the named Docker volume as an improvised restore step. Never use `docker compose down -v`, `docker volume rm`, or volume-pruning commands.
- Do not regenerate signing keys or checkpoint files to silence a verification failure.

The existing `docs/operations/DOCKER_RECOVERY_RUNBOOK.md` is a local container/image recovery procedure, not by itself a complete production backup/restore programme. Production backup retention, off-host copies, encryption, recovery-point objectives, recovery-time objectives, and periodic restore exercises must be defined by the deployment owner.

## 7. Pre-deployment read-only preflight

Run these checks against the intended release and a verified copy/staging environment first. Commands below are examples for the existing Compose service/container names; adapt only after verifying the actual deployment topology.

### Repository and image

- Confirm the exact release commit and all required GitHub Actions checks are successful.
- Build and scan the candidate image in CI; record its immutable image digest and SBOM.
- Confirm the candidate image contains the expected IAM routes, dashboard assets, migration registry, and operator CLI.
- Review the effective Compose configuration without exposing resolved secret values in shared logs. Protect any output that includes interpolated environment values.
- Confirm the named volume mounted at `/data` is the expected existing volume.

### Database and audit state

With the intended application image and database path, run the read-only IAM preflight:

```bash
docker exec aegis-security-platform python -m app.iam.migrate --check
```

Expected: `IAM schema is current; no pending migrations.` This command also checks SQLite integrity, foreign keys, and IAM migration-history checksums. It is read-only.

Run the official checkpoint inventory:

```bash
docker exec aegis-security-platform \
  python -m app.response.checkpoint_inventory \
  --database /data/aegis.db
```

Expected: valid database/checkpoint correspondence, valid signatures and chain/lifecycle state, and no unexplained errors or pending recovery evidence. The command requires the container's configured audit signing-key environment; do not print or expose it.

If the database is not at IAM versions 1 and 2, stop. Do not apply a migration merely because a deployment is planned. A future migration requires its own reviewed change, verified backup, audit inventory, stopped application, explicit operator approval, and post-migration verification.

### Configuration and network

- Verify every required environment variable is present without displaying its value.
- Verify the analyst and approver legacy tokens are distinct and sufficiently strong without printing them.
- Verify the CSRF and throttle keys are independently provisioned and at least 32 UTF-8 bytes.
- Verify the MFA key decodes to exactly 32 bytes and its key ID matches the factors in the target database.
- Verify the audit signing key and key ID can verify all retained checkpoints.
- Verify exact HTTPS origin, Secure cookies, proxy CIDRs, ingress header sanitisation, firewall, and direct-port blocking.
- Verify no secrets appear in Git status, image layers, CI logs, application logs, or deployment output.

## 8. Deployment sequence (future approved change window)

This is a controlled sequence for a future, separately authorised production deployment. It is not an instruction to run it now.

1. Obtain explicit deployment approval, identify the operator, record the maintenance window, and confirm the rollback decision-maker.
2. Freeze the candidate commit and image digest. Do not deploy a mutable tag such as `local` without verifying its digest.
3. Verify production secret availability and key recovery before taking the service down.
4. Capture and independently verify the coordinated backup described in Section 6.
5. Capture the pre-deployment SQLite integrity, IAM migration history, checkpoint inventory, container configuration, volume identity, health, and image digest.
6. Stop the application cleanly for the maintenance window. Do not delete the container volume.
7. If IAM schema is already v1/v2, do not run `--apply`. If a future release genuinely requires a migration, follow that migration's separately reviewed procedure and explicit approval; the migration CLI requires all three attestations.
8. Deploy the pinned candidate image with the approved ingress configuration and the original persistent volume.
9. Verify the running container uses the expected image digest, non-root user, read-only filesystem, dropped capabilities, no-new-privileges, and original `/data` volume.
10. Verify health, IAM schema, SQLite integrity, foreign keys, audit-checkpoint inventory, browser login, MFA challenge, logout, CSRF rejection, session expiry/revocation, and role boundaries.
11. Verify the approver browser path requires recent MFA. Verify that the retired `AEGIS_APPROVER_TOKEN` receives HTTP 401 and cannot read protected API routes or make decisions. Verify analyst bearer integrations still work.
12. Confirm no secrets or one-time credentials were written to logs. Record outcome and image digest, then close the maintenance window only after all gates pass.

## 9. Post-deployment smoke tests

Use dedicated test accounts and controlled test events. Do not use a production approver account as a disposable test identity.

- Unauthenticated dashboard access shows the sign-in page and cannot retrieve protected data.
- Valid analyst password login creates the secure HttpOnly session cookie.
- MFA-enabled login requires a valid TOTP or recovery code; invalid, expired, replayed, and reused credentials are rejected.
- Logout revokes the session and clears the cookie.
- Unsafe cookie-authenticated requests without a valid CSRF token or exact allowed Origin are rejected.
- Analyst sessions cannot invoke approver-only operations.
- Browser approver actions are denied without recent MFA and succeed only within the five-minute step-up window.
- Account disable/lock and password changes revoke active sessions.
- Login and MFA throttling operate and do not disclose whether a username exists.
- The trusted-proxy client address is correct and spoofed forwarding headers cannot select an attacker-controlled address.
- The health endpoint reports database connectivity.
- IAM migration check reports no pending migration.
- SQLite integrity and foreign-key checks pass.
- Audit checkpoint inventory reports valid signatures, database matching, hash chain, and lifecycle.
- The retired legacy approver bearer token is rejected with HTTP 401; analyst bearer compatibility remains intact.

## 10. Rollback and failure handling

### Application-only rollback

If the deployment has not changed the database schema, and the prior image is compatible with the current schema:

1. Stop the rollout and preserve logs/evidence.
2. Restore the previously approved image digest and deployment configuration.
3. Keep the original named data volume and checkpoint directory.
4. Restore the prior secret configuration only if the change itself was the cause and only after verifying key compatibility.
5. Re-run health, SQLite integrity, IAM migration check, and checkpoint inventory.
6. Revoke test sessions created during the failed rollout through the supported IAM procedure.

Do not assume that restoring an old image means restoring an old database.

### Migration or data rollback

- Do not attempt to reverse SQLite schema changes by hand.
- If a migration has been applied, use only a separately tested, coordinated restore/forward-recovery plan.
- Restore the database, checkpoint directory, signing keys, MFA encryption key, and deployment configuration as one consistent recovery point.
- A database restore may discard later legitimate events or approvals. Preserve the failed state and assess the audit/incident implications before restoring.
- If audit verification fails, stop response operations and preserve evidence. Never regenerate checkpoints to make the system appear healthy.

### Stop conditions

Stop and escalate if any of the following occurs:

- Backup cannot be restored or the backup's checkpoint inventory is invalid.
- Database integrity, foreign-key checks, or migration-history checks fail.
- Checkpoint signatures, hash chain, lifecycle, or database matching fail.
- Required secret/key is missing, malformed, mismatched, or unavailable.
- The ingress cannot block direct public access to port 8000.
- The actual trusted proxy topology cannot be demonstrated.
- The candidate image digest, volume mapping, or container security settings differ from the approved plan.
- MFA cannot be verified for approver browser actions.
- An unauthorised legacy bearer approval path is discovered or the organisation has not accepted its residual risk.
- Any unexpected data loss, unexplained audit event, or credential exposure occurs.

## 11. Operational ownership still required

Before production approval, the service owner must assign named roles (without storing personal secrets in this document) for:

- production host and Docker administration;
- ingress/TLS and network firewall;
- secret-manager and key-backup custody;
- IAM account invitation, activation, MFA enrollment, and recovery;
- backup monitoring and restore exercises;
- audit-checkpoint integrity review;
- security incident response and approval-path monitoring;
- release approval and rollback decision.

Define service-level objectives, backup frequency, retention, RPO/RTO, log retention, alerting, patch cadence, vulnerability response, and a periodic disaster-recovery exercise. These operational commitments are not supplied automatically by the application code.

## 12. Phase 2E completion criteria

Phase 2E documentation is ready for review when the following are confirmed by the deployment owner:

- [ ] Production topology and HTTPS ingress are documented and tested.
- [ ] Direct access to application port 8000 is blocked.
- [ ] Trusted proxy CIDRs and X-Forwarded-For sanitisation are verified.
- [ ] All required independent secrets are provisioned and recoverable.
- [ ] MFA encryption key backup and recovery have been tested.
- [ ] The retired approver bearer token is rejected with HTTP 401, and approver decisions require a browser session with recent MFA.
- [ ] Production accounts and approver MFA bootstrap are planned.
- [ ] Database plus checkpoint backup/restore is tested as a coordinated recovery point.
- [ ] IAM schema and audit inventory preflight pass on staging.
- [ ] Immutable image digest and rollback image are recorded.
- [ ] Smoke tests, monitoring, ownership, RPO/RTO, and maintenance window are agreed.
- [ ] A production deployment is separately and explicitly authorised.

**No production deployment is authorised by completion of this document or by merging a documentation PR.**
