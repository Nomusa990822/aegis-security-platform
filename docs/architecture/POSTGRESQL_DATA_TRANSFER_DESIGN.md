# PostgreSQL Data Transfer Design and Rehearsal Plan

**Status:** Design approved for synthetic rehearsal only. No production transfer tooling is authorized by this document.

## 1. Objective

Define a repeatable, auditable transfer from the existing SQLite data model to PostgreSQL while preserving application identity, security state, investigation history, and tamper-evident audit evidence.

The first executable rehearsal must use newly generated synthetic SQLite and PostgreSQL databases. It must not read the configured application database, deployed volumes, production credentials, encryption keys, or external audit-checkpoint directories.

## 2. Non-negotiable invariants

1. **Source is read-only.** Open SQLite using a read-only URI, enable query-only mode, and reject missing paths rather than creating an empty source.
2. **Destination is explicitly isolated.** Accept only a PostgreSQL URL whose database and host are explicitly designated for tests/rehearsal. Reject SQLite, production-like names, and implicit defaults.
3. **No implicit migration.** Schema creation is a separate, explicit prerequisite. The transfer utility must never run Alembic or create/alter tables.
4. **Preserve primary keys.** Copy integer IDs and UUID/text IDs verbatim. Do not regenerate IDs or rewrite foreign-key values.
5. **Preserve stored values.** Do not normalize timestamp strings, JSON text, hashes, token hashes, password hashes, MFA ciphertext, or binary values during transfer.
6. **Respect relationships.** Transfer parent tables before dependent tables, with all rows inserted in one destination transaction.
7. **Preserve audit evidence.** Copy response audit events in their original ID order, including `previous_hash` and `event_hash`; copy chain heads exactly. Verify chain continuity and stored hashes independently before and after transfer.
8. **External checkpoints are separate evidence.** Do not copy, rewrite, regenerate, or access checkpoint files or encryption keys as part of the relational transfer. Their preservation requires a separately approved backup/restore procedure.
9. **Fail closed.** Any schema mismatch, duplicate key, FK violation, row-count mismatch, checksum mismatch, or audit verification failure aborts the destination transaction.
10. **No production mutation.** No production migration, deployment change, database write, or live-data extraction is part of this phase.

## 3. Transfer inventory

The transfer inventory is derived from the staged SQLAlchemy metadata and must be revalidated against the authoritative SQLite schema immediately before a rehearsal.

| Domain | Tables / records | Preservation requirements |
|---|---|---|
| Events and alerts | security_events, security_alerts | Integer IDs, source identity, timestamps, event payload text |
| Investigations | incident_notes, incident_timeline, incident_evidence, alert_audit_log | IDs, alert/event relationships, chronology, analyst attribution |
| Correlations | security_correlations, security_correlation_alerts, correlation_notes, correlation_timeline, correlation_audit_log | Case IDs, alert links, counts, status and timeline |
| Threat intelligence | ip_intelligence_assessments, ip_intelligence_provider_results | Assessment IDs, provider relationships, serialized categories/details, scores |
| IAM | iam_users, iam_credentials, iam_mfa_factors, iam_recovery_codes, iam_access_tokens, iam_sessions, iam_auth_challenges, iam_activation_tokens, iam_security_events, iam_auth_rate_limits, iam_schema_migrations | UUIDs, username identity, Argon2 hashes, encrypted TOTP bytes and key IDs, recovery-code hashes, token/session hashes, expiry/revocation state, migration history |
| Response and audit | response_records, response_audit_log, response_audit_chain_heads | Response IDs, execution/approval state, event IDs/order, hash fields, exact chain-head values |

The final table order must be generated from and validated against foreign-key dependencies; the table listing above is a domain inventory, not an instruction to rely on a manually guessed order.

## 4. Transfer algorithm

### Preflight (read-only)

- Resolve and validate the source file as an existing regular file; reject symlinks.
- Open SQLite read-only and set query-only mode.
- Run SQLite integrity and foreign-key checks.
- Confirm exact table and column inventory against the approved metadata revision.
- Confirm required audit hash columns and chain-head table exist.
- Verify each response audit chain using the application's canonical hash-verification implementation.
- Record source table counts and deterministic per-table content digests.
- Refuse to proceed if any required precondition fails.

### Copy (single destination transaction)

- Require an already-created PostgreSQL schema at the expected migration revision.
- Derive a deterministic parent-before-child table order from SQLAlchemy foreign-key metadata; detect cycles and fail rather than silently omit tables.
- Read source rows in stable primary-key order.
- Insert explicit column values, including primary keys; do not rely on destination defaults for copied rows.
- Preserve bytes as bytes and preserve text values exactly.
- Do not commit per table. One transaction owns the entire transfer.
- After insertion, reset PostgreSQL identity/serial sequences to a value greater than the maximum imported ID for each integer identity column. Sequence changes must be in the same transaction where supported and verified afterward.
- Roll back the entire destination transaction on any exception.

### Reconciliation (before commit)

- Compare row counts for every table.
- Compare deterministic content digests computed over stable primary-key order and a type-tagged, unambiguous encoding of each stored value.
- Verify all foreign-key relationships.
- Compare key security records and IAM state without exposing secret values in logs.
- Re-run response audit-chain verification and compare event counts, final hashes, and chain-head values with the source.
- Emit a manifest containing source/destination identifiers, schema revision, per-table counts and digests, verification outcomes, and tool version. Do not include passwords, tokens, MFA ciphertext, recovery codes, or connection URLs.
- Commit only if every reconciliation check succeeds.

## 5. Deterministic digest format

The rehearsal implementation must define and test a canonical row encoding before it is used for reconciliation:

- Include column names in metadata-defined order.
- Prefix each value with an explicit type marker.
- Distinguish NULL, empty text, empty bytes, integer zero, and floating-point zero.
- Encode text as UTF-8 without parsing or normalizing it.
- Encode binary values as their raw bytes.
- Encode integers and floating-point values with an unambiguous, documented representation.
- Hash each encoded row with SHA-256, then hash the ordered row-digest stream for the table.
- Include the table name and column inventory in the table digest domain separator.

This digest is a transfer-integrity check, not a replacement for the application's cryptographic audit chain.

## 6. Synthetic rehearsal matrix

| Scenario | Expected result |
|---|---|
| Empty source tables | Successful no-op transfer with zero counts |
| Full synthetic dataset across all domains | Exact counts and digests match |
| Non-contiguous integer IDs | IDs preserved; destination sequence advances beyond maximum |
| Unicode and empty text | Exact stored text preserved |
| NULL versus empty text/bytes | Values remain distinguishable |
| MFA ciphertext and binary payloads | Byte-for-byte equality |
| IAM password/token/recovery hashes | Exact stored hash strings preserved |
| Parent/child relationships | All foreign keys validate |
| Deliberately missing parent row | Destination transaction rolls back |
| Duplicate primary key in destination | Destination transaction rolls back |
| Modified source audit event | Audit verification rejects transfer |
| Incorrect source chain head | Audit verification rejects transfer |
| Altered destination row during test | Digest reconciliation rejects transfer |
| Destination interruption before commit | No partial table transfer remains |
| Source path missing or symlinked | Preflight rejects without creating/opening a new DB |
| Destination URL absent or non-test | Preflight rejects |

## 7. Recovery and repeatability

- A rehearsal is repeatable only against a freshly provisioned synthetic destination or an explicitly reset disposable test schema.
- Never make the transfer silently resumable. A failed transaction is rolled back; rerun only after recording the failure and recreating a clean destination.
- Preserve the failed run's non-sensitive manifest and test logs.
- A production runbook, backup verification, external checkpoint inventory, restore rehearsal, downtime plan, and operator approval are separate mandatory gates. This design does not authorize any of them.

## 8. Implementation sequence

1. Complete metadata review for types, defaults, nullability, constraints, and identity semantics.
2. Add deterministic digest and table-dependency-order unit tests.
3. Add a synthetic fixture builder covering all modeled domains and sensitive-field shapes.
4. Implement a read-only SQLite to isolated PostgreSQL transfer adapter behind explicit test-only safeguards.
5. Add rollback, interruption, mismatch, and audit-chain negative tests.
6. Run the complete backend suite and PostgreSQL integration suite in CI.
7. Review the rehearsal manifest and documented recovery procedure.
8. Only after independent review, decide whether a separately scoped production migration plan should be prepared.

## 9. Explicit exclusions

This phase does not:
- connect to or inspect the deployed SQLite database;
- read or transfer real user, credential, session, token, or MFA records;
- access encryption keys or signed checkpoint files;
- generate or execute the production Alembic baseline;
- change Docker Compose, volumes, secrets, deployment configuration, or the running application;
- authorize a production cutover.

**Decision:** Proceed to synthetic-only implementation after the schema and identity semantics have been reviewed. Production transfer remains prohibited until separately designed, rehearsed, reviewed, backed up, and explicitly approved.
