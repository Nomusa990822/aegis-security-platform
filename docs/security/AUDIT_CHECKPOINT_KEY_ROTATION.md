# AEGIS Audit Checkpoint Key Management and Rotation Runbook

## 1. Purpose

This document describes how to configure, rotate, verify, and protect the cryptographic keys used by AEGIS audit checkpoints.

AEGIS uses HMAC-SHA256 signatures to protect audit checkpoint files stored outside the SQLite database.

The implementation supports:

- Version 2 checkpoints with explicit signing key IDs.
- Previous signing keys for verification during rotation.
- Legacy version 1 checkpoint verification.
- Sequential checkpoint advancement.
- Atomic checkpoint writes.
- File locking across Linux processes.
- Rejection of missing, invalid, or tampered checkpoints.

**Important:** Checkpoint verification is not equivalent to a fully independent immutable audit service. Protect the checkpoint directory and signing keys separately from the application database.

## 2. Environment Variables

Configure the following environment variables through a secure environment or secrets manager.

| Variable | Purpose |
|---|---|
| `AEGIS_AUDIT_CHECKPOINT_KEY` | Active signing secret; minimum 32 characters |
| `AEGIS_AUDIT_CHECKPOINT_KEY_ID` | Identifier for the active signing key; defaults to `default` |
| `AEGIS_AUDIT_CHECKPOINT_PREVIOUS_KEYS` | JSON object containing previous key IDs and their secrets |
| `AEGIS_AUDIT_CHECKPOINT_LEGACY_KEY` | Secret used to verify version 1 checkpoints; defaults to the active secret |
| `AEGIS_AUDIT_CHECKPOINT_DIR` | Directory containing signed checkpoint files |

Key IDs must contain 1–64 letters, digits, periods, underscores, or hyphens.

All active and previous signing secrets must contain at least 32 characters.

Never commit signing secrets to GitHub or store them in application source code.

## 3. Initial Configuration

Generate a strong random secret:

```bash
openssl rand -hex 32
```

Configure the resulting secret as `AEGIS_AUDIT_CHECKPOINT_KEY`.

For an initial version 2 deployment, configure:

```env
AEGIS_AUDIT_CHECKPOINT_KEY=<generated-secret>
AEGIS_AUDIT_CHECKPOINT_KEY_ID=aegis-2026-01
AEGIS_AUDIT_CHECKPOINT_PREVIOUS_KEYS={}
AEGIS_AUDIT_CHECKPOINT_LEGACY_KEY=<legacy-secret-if-required>
AEGIS_AUDIT_CHECKPOINT_DIR=<protected-checkpoint-directory>
```

If version 1 checkpoints exist, `AEGIS_AUDIT_CHECKPOINT_LEGACY_KEY` must contain the original secret used to sign them.

If no version 1 checkpoints exist, the legacy key can initially use the active secret. Preserve it explicitly if the active key is subsequently rotated.

The checkpoint directory must be persistent and protected from unauthorized modification.

## 4. Standard Key Rotation Procedure

Assume the current active key is:

- Key ID: `aegis-2026-01`
- Secret: `OLD_SECRET`

The replacement key will be:

- Key ID: `aegis-2026-02`
- Secret: `NEW_SECRET`

### Step 1 — Generate the Replacement Key

Generate a new secret:

```bash
openssl rand -hex 32
```

Store it securely.

Do not overwrite or discard the old secret.

### Step 2 — Preserve the Previous Key

Configure the new active key and retain the old key in the previous-key configuration:

```env
AEGIS_AUDIT_CHECKPOINT_KEY=NEW_SECRET
AEGIS_AUDIT_CHECKPOINT_KEY_ID=aegis-2026-02
AEGIS_AUDIT_CHECKPOINT_PREVIOUS_KEYS={"aegis-2026-01":"OLD_SECRET"}
```

Preserve the original legacy key separately if version 1 checkpoints may still exist:

```env
AEGIS_AUDIT_CHECKPOINT_LEGACY_KEY=ORIGINAL_LEGACY_SECRET
```

Do not put literal placeholder values into a production environment.

### Step 3 — Restart or Reload the Application

Ensure the running application receives the new environment configuration.

Do not modify or delete existing checkpoint files.

### Step 4 — Verify Existing Checkpoints

Use the authenticated audit-integrity endpoint:

```http
GET /api/v1/response/{response_id}/audit-integrity
```

The endpoint requires approver authentication.

For existing records, verify:

- `valid` is `true`.
- `chain_valid` is `true`.
- `checkpoint_valid` is `true`.
- No integrity errors are returned.

Test records containing checkpoints signed by previous keys, as well as current-key and legacy records where applicable.

### Step 5 — Verify Checkpoint Advancement

When a legitimate new audit event is recorded for a response, its checkpoint should advance using the active key.

Inspect the resulting checkpoint file and confirm:

```json
{
  "payload": {
    "schema_version": 2,
    "key_id": "aegis-2026-02"
  }
}
```

The complete checkpoint also contains the response ID, event count, and final hash.

Re-run the audit-integrity endpoint and confirm that verification succeeds.

Do not create artificial audit events merely to force checkpoint advancement.

## 5. Legacy Version 1 Checkpoint Compatibility

Version 1 checkpoints do not contain a key ID.

They are verified using:

```env
AEGIS_AUDIT_CHECKPOINT_LEGACY_KEY
```

The legacy key must remain available while version 1 checkpoints still exist.

When a version 1 checkpoint advances through a legitimate new audit event, the replacement checkpoint is written using the active version 2 signing key.

Do not rotate or discard the legacy key until all version 1 checkpoints have been migrated and independently verified.

The current implementation supports one legacy signing secret. It does not provide a multi-key legacy keyring.

## 6. Previous-Key Retirement Policy

**Never remove a previous signing key merely because a new key has become active.**

An existing checkpoint can continue to depend on an old signing key indefinitely if its response has not generated another audit event.

Before retiring a previous key:

1. Identify every checkpoint signed using that key ID.
2. Confirm that each checkpoint has been migrated to a newer signing key.
3. Verify every migrated checkpoint through the audit-integrity endpoint.
4. Preserve the old key securely according to the organisation's retention policy.
5. Only then remove the retired key from the previous-key configuration.

The current implementation does not include a bulk checkpoint migration or re-signing utility.

Until such a utility exists, retain previous keys whenever the migration of all affected checkpoints cannot be demonstrated.

Apply the same principle to the legacy version 1 signing key.

## 7. Rollback Procedure

If a newly activated key causes verification or checkpoint advancement failures:

1. Stop further response operations while investigating.
2. Preserve the database, checkpoint files, and application logs.
3. Restore the previous active signing key and its key ID.
4. Retain the replacement key as a previous key if any checkpoints were already written using it.
5. Restart or reload the application.
6. Verify affected checkpoints using the audit-integrity endpoint.

For example, if the old key is being restored as active:

```env
AEGIS_AUDIT_CHECKPOINT_KEY=OLD_SECRET
AEGIS_AUDIT_CHECKPOINT_KEY_ID=aegis-2026-01
AEGIS_AUDIT_CHECKPOINT_PREVIOUS_KEYS={"aegis-2026-02":"NEW_SECRET"}
```

Preserve the original legacy-key configuration.

Do not delete, regenerate, or overwrite a checkpoint simply because verification fails.

## 8. Lost or Compromised Signing Keys

If a signing key is lost:

- Attempt recovery from the authorised secret manager or secure backup.
- Preserve all existing checkpoint files.
- Preserve the SQLite database and audit records.
- Do not generate a replacement checkpoint to conceal the verification failure.
- Record the incident and investigate the affected audit history.

If a key is compromised:

- Restrict access to the affected environment.
- Preserve evidence before making configuration changes.
- Generate a replacement signing key.
- Retain the old key temporarily where necessary to investigate and verify historical checkpoints.
- Follow the rotation and retirement procedures above.

A newly generated key cannot recreate the trust relationship of a lost signing key.

## 9. File and Secret Protection

The application writes checkpoint and temporary files with restrictive permissions.

Operational controls should also include:

- Restrict access to the checkpoint directory.
- Protect checkpoint backups from modification.
- Keep signing keys outside the repository.
- Restrict access to environment secrets.
- Avoid printing secrets in terminal logs or CI output.
- Back up signing keys securely.
- Protect the application host and deployment environment.
- Monitor failed checkpoint verification and checkpoint-write errors.

The checkpoint lock files are used to serialize concurrent writers. Do not manually delete active lock files while the application is operating.

## 10. Configuration Validation and Failure Behaviour

The application rejects:

- Missing or weak active signing secrets.
- Missing or weak legacy signing secrets.
- Invalid key IDs.
- Active key IDs duplicated in the previous-key configuration.
- Invalid previous-key JSON.
- Non-object previous-key configuration.
- Weak previous signing secrets.
- Duplicate JSON keys, including nested duplicate keys.

Checkpoint verification fails when:

- The checkpoint file is missing.
- The checkpoint signature is invalid.
- The signing key is unavailable.
- The checkpoint response ID does not match.
- The event count does not match.
- The final hash does not match.
- The checkpoint schema version is unsupported.

A failed checkpoint write after a successful database commit must be treated as an operational integrity warning. The committed response must not be mistaken for a rolled-back operation.

## 11. Operational Verification Checklist

Before considering a rotation complete:

- [ ] New signing key generated securely.
- [ ] New key ID configured.
- [ ] Previous signing key retained.
- [ ] Legacy key preserved where required.
- [ ] Application restarted or reloaded.
- [ ] Existing checkpoints verified.
- [ ] New checkpoint advancement verified.
- [ ] Audit-integrity endpoint returns valid results.
- [ ] Checkpoint directory and secret permissions reviewed.
- [ ] Old keys retained until migration is demonstrated.
- [ ] Rotation recorded in operational documentation.

## 12. Current Implementation Limitations

The AEGIS checkpoint implementation provides cryptographic integrity checks, but it is not yet a complete enterprise key-management service.

The following capabilities are not provided by this implementation:

- Hardware Security Module integration.
- Cloud KMS integration.
- Automatic key rotation scheduling.
- Bulk checkpoint re-signing.
- Automatic discovery of every checkpoint using a retired key.
- Remote immutable or write-once checkpoint storage.
- Enterprise secret-manager integration.

These should be considered future security engineering milestones.

---

**Document:** AEGIS Audit Checkpoint Key Management and Rotation Runbook  
**Component:** Response Audit Checkpoint Protection  
**Cryptographic algorithm:** HMAC-SHA256  
**Current checkpoint schema:** Version 2  
**Legacy checkpoint schema:** Version 1
