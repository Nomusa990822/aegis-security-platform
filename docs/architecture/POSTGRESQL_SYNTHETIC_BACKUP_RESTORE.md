# Synthetic SQLite Backup and Restore Rehearsal

**Status:** Synthetic-only validation. This implementation does not authorize or perform a production backup, restore, or migration.

## Purpose

Exercise SQLite's online backup API against a newly generated in-memory fixture, restore the backup into a fresh in-memory database, and prove that the restored copy retains relational data and tamper-evident response audit evidence.

## Safety boundary

The rehearsal utility:

- Accepts only an already-open in-memory SQLite source connection.
- Does not read application configuration, environment variables, default database paths, or deployed volumes.
- Writes its temporary SQLite backup only inside a private TemporaryDirectory.
- Reopens that temporary artifact read-only and restores it into a fresh in-memory SQLite database.
- Removes the temporary directory when the operation exits, including on failure.
- Does not accept a caller-supplied backup path, run DDL/migrations, or modify a persistent database.
- Does not access external audit checkpoint directories, encryption keys, credentials, or MFA secrets.

The test suite separately proves that a file-backed SQLite source is rejected.

## Verification performed

Before creating the backup, the rehearsal:

1. Confirms the source is in-memory SQLite.
2. Runs PRAGMA integrity_check and PRAGMA foreign_key_check.
3. Confirms the exact expected table inventory.
4. Calculates deterministic SHA-256 table digests using the existing transfer digest primitives.
5. Runs the canonical response audit-chain verifier and compares each response's event count and final hash with its persisted chain head.

After the backup is written and restored, it repeats integrity, foreign-key, table inventory, digest, and audit-chain checks. The source and restored table manifests and audit summaries must match exactly.

The returned report contains only non-secret evidence: temporary backup size and SHA-256 checksum, table row counts/digests, integrity outcomes, and audit event/response counts. The backup artifact itself is deleted before the function returns.

## Automated test matrix

| Scenario | Expected result |
|---|---|
| Valid synthetic records and audit chain | Backup and restore reconcile successfully |
| Unicode and non-contiguous IDs | Values and identifiers remain unchanged |
| Modified audit event | Source audit verification rejects the rehearsal |
| Foreign-key violation | Source integrity gate rejects the rehearsal |
| File-backed source | Rejected before backup |
| Temporary backup artifact | Removed after success or failure |

## What this does not prove

This is a controlled API and data-integrity rehearsal, not a production disaster-recovery exercise. It does not test:

- A live SQLite database with concurrent writers or WAL checkpoint coordination.
- Durable backup storage, access controls, retention, off-site copies, or encryption at rest.
- Crash/power-loss behavior during filesystem writes.
- Backup restoration of production-sized data or measured recovery time objectives.
- External audit checkpoint/intent file backup, restore, or cryptographic verification.
- Application startup or service cutover against a restored production-like dataset.

Those require a separately approved non-production environment, a consistent backup procedure, secure storage, restore drills, and explicit operational authorization. No production backup or restore is part of this phase.
