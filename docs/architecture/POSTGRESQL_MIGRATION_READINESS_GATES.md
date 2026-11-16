# PostgreSQL Migration Readiness Gates

**Status:** Readiness assessment only. Production migration is not authorized.

## 1. Purpose and safety boundary

This document defines the evidence required before AEGIS may generate an authoritative Alembic baseline or plan a production SQLite-to-PostgreSQL cutover.

Current verification runs against temporary SQLite fixtures and a disposable PostgreSQL service in CI. The explicit-path preflight utility is implemented but must only be run against a database after its owner authorizes that inspection. No production database, deployed volume, credentials, MFA material, signing keys, or external checkpoint files were accessed to prepare this document.

A successful schema report is not a migration approval.

## 2. Schema verification evidence

The verification suite now checks:

| Contract | Evidence |
|---|---|
| Table and column inventory | Exact parity test against the application initializer and IAM/idempotency migrations |
| SQLite type affinity | Deep contract test for INTEGER, TEXT, BLOB and REAL affinity |
| Nullability | PRAGMA table_info comparison, with SQLite primary-key semantics handled separately |
| Primary keys | Column membership and ordinal checks |
| Defaults | Normalized comparison, treating explicit DEFAULT NULL as equivalent to no explicit default |
| Foreign keys | Source/target columns and ON DELETE action |
| Indexes | Declared index presence and column order |
| Unique constraints | Unique index contract and column order |
| Partial indexes | WHERE predicate comparison for SQLite partial indexes |

The checks above do not yet establish complete constraint parity. The following still require explicit review and dedicated tests before a baseline:

- CHECK expressions and their enforcement semantics across SQLite and PostgreSQL.
- Composite primary-key order and all composite unique constraints.
- Collations, case sensitivity, expression indexes, generated columns, triggers and views.
- Deferrability and transaction-time foreign-key behavior.
- PostgreSQL identifier-length and naming-convention collisions.
- Timestamp/text representation and JSON-as-TEXT semantics.
- Integer identity/sequence behavior for every auto-incrementing table.

## 3. Read-only SQLite preflight

The function `app.db_preflight.inspect_sqlite_schema_read_only(path)` is an explicit-path inspection utility.

Safety properties:

- It has no default path and does not read `AEGIS_DATABASE_PATH` or `AEGIS_DATABASE_URL`.
- It requires an existing regular file and rejects symlinks.
- It opens SQLite using `mode=ro` and enables `PRAGMA query_only`.
- It does not select application rows or emit secret-bearing values.
- It performs a SQLite quick check and foreign-key check.
- It returns schema inventory, per-column compatibility findings, and limitations.
- It does not run migrations, alter schema, create files, or connect to PostgreSQL.

Example invocation from the backend directory:

```python
from app.db_preflight import inspect_sqlite_schema_read_only

report = inspect_sqlite_schema_read_only("/explicit/authorized/path/aegis.db")
print(report["compatible_for_baseline"])
print(report["findings"])
```

Do not point it at a deployed database until a separate inspection authorization and backup decision have been made. The current report intentionally labels itself schema-only and does not claim to verify application audit hashes or external checkpoints.

## 4. Audit-chain and external checkpoint preservation

The relational transfer and external audit evidence are separate workstreams.

Before any production cutover:

1. Freeze response writers for the approved migration window or use a separately designed consistent snapshot protocol.
2. Verify the SQLite response audit chain using the application's canonical verifier before backup.
3. Record non-secret evidence: response event count, per-response chain-head count, final hash values, verifier version and verification timestamp.
4. Create a transactionally consistent database backup using a documented SQLite backup procedure; do not copy a live database file without accounting for WAL state.
5. Inventory external checkpoint and intent files separately, including file names, sizes, timestamps and cryptographic checksums. Never include encryption keys or secret contents in the report.
6. Back up checkpoint/intent evidence byte-for-byte using an approved secure backup destination and access controls. Do not regenerate checkpoints as part of migration.
7. Transfer relational audit rows and chain heads without rewriting IDs, event order, previous hashes or event hashes.
8. Re-run the canonical verifier on PostgreSQL and compare event counts, chain heads and final hashes with the pre-transfer evidence.
9. Verify the separately restored external checkpoint files against their recorded checksums and the application's checkpoint verification procedure.
10. Retain the original source backup and checkpoint evidence read-only until the migration is accepted and the rollback-retention period expires.

The transfer must stop if source audit verification fails, chain heads disagree, checkpoint inventory is incomplete, or post-transfer verification differs. External checkpoint directories and cryptographic keys are explicitly excluded from the synthetic transfer code.

## 5. Backup, restore and rollback rehearsal specification

A future production runbook must pass these exercises in a non-production environment before a cutover is considered:

### Backup gate
- Capture database and WAL state consistently.
- Record file sizes and SHA-256 checksums.
- Verify the backup can be opened independently.
- Run SQLite integrity and foreign-key checks on the restored copy.
- Capture audit-chain verification evidence.
- Securely preserve external checkpoints as a separate artifact set.

### Restore gate
- Restore into a clean isolated environment.
- Verify database integrity, schema revision, table counts and representative relationships.
- Verify IAM state is intact without printing password/token/MFA values.
- Verify response audit chains and checkpoint evidence.
- Confirm the restored application can start in a network-isolated validation environment.

### Rollback gate
- Define a clear cutover point and an explicit write-freeze boundary.
- Preserve the original SQLite source as read-only.
- If any post-cutover smoke test or integrity gate fails, stop PostgreSQL writes and restore service from the verified source backup.
- Never attempt an automatic reverse replication or lossy PostgreSQL-to-SQLite conversion.
- Record operator, timestamps, decision, checksums and verification outcomes.
- Require explicit authorization before switching production traffic or reopening writes.

No production backup, restore, rollback, traffic switch or migration is performed by this phase.

## 6. Go/no-go criteria

A future migration can be proposed only when every item below is evidenced and independently reviewed.

| Gate | Go criterion | Current status |
|---|---|---|
| Schema inventory and column parity | All expected tables/columns match | Automated fixture checks pass |
| Type/nullability/default parity | Every difference reviewed and accepted | Initial automated coverage passes; full review outstanding |
| Constraints and indexes | CHECK, UNIQUE, FK, partial and expression semantics validated | Partial; CHECK and advanced semantics outstanding |
| PostgreSQL DDL | Alembic baseline reviewed against PostgreSQL 17 | Clean-schema baseline implemented; PostgreSQL 17 upgrade/downgrade CI passes; adoption of existing schemas remains outstanding |
| Transfer | Full synthetic transfer and rollback/mismatch cases pass | 27-table synthetic transfer passes with deterministic reconciliation; canonical audit-chain and chain-head verification now enforced; additional failure modes remain |
| Audit integrity | Canonical chain verifier passes before and after transfer | Canonical verifier runs on source and destination transfer rows; per-response event counts and chain heads are reconciled in synthetic CI; external checkpoint verification remains outstanding |
| External checkpoints | Separate secure backup/restore and checksum rehearsal passes | Not started |
| Backup/restore | Independently restored backup passes all integrity checks | Not started |
| Rollback | Timed rollback rehearsal and decision criteria approved | Not started |
| Operational plan | Downtime, freeze, owners, monitoring and acceptance criteria approved | Not started |
| Authorization | Explicit approval for production backup and migration window | Not granted |

**No-go conditions:** any unexplained schema difference, unverified audit chain, missing checkpoint evidence, failed reconciliation, untested restore, incomplete rollback plan, or absent explicit authorization.

## 7. Decision

Phase 2F.12 adds stronger schema-contract tests, an explicit-path read-only preflight and documented audit/backup/restore/rollback gates. Phase 2F.14 adds the clean-schema Alembic baseline, validated against PostgreSQL 17 in an isolated schema. Phase 2F.15 adds canonical response audit-chain verification to synthetic transfers, including chain-head reconciliation and fail-closed handling of missing or altered evidence.

It does not create or execute the production Alembic baseline. It does not migrate production data or change deployment configuration. Production migration remains a no-go until every outstanding gate above has passed and the owner explicitly authorizes the operation.
