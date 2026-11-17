# PostgreSQL Schema Parity and Migration Readiness

**Status:** Assessment in progress; no Alembic baseline generated.

## Scope and safety

This assessment compares the staged SQLAlchemy Core metadata with the existing SQLite schema assembled by the application initializer and the versioned IAM migration registry. The reference database used by automated parity tests is temporary and isolated.

This work does not connect to the deployed SQLite database, read or copy production records, access audit checkpoint files or encryption keys, execute Alembic, or change deployment configuration.

## Authoritative SQLite schema sources

The reference schema is assembled from:

- `app.database.initialize_database()`: operational events, alerts, investigations, correlations, threat-intelligence tables, and response-table initialization.
- `app.iam.migrations.apply_migrations()`: IAM tables, constraints, and versioned IAM indexes.
- `app.idempotency.initialize_idempotency_schema()`: event-source identity columns and the partial unique index.
- `app.response.audit_chain_storage.initialize_audit_chain_storage()`: audit hash columns and response chain-head storage.

The SQLite runtime schema is therefore not represented by a single DDL file. A parity test must invoke all four sources in a temporary database before comparing it with SQLAlchemy metadata.

## Discrepancies found and model corrections

The initial comparison identified the following omissions in the staged models. The domain models have now been updated to represent these structures:

| Area | Existing SQLite structure | Model correction |
|---|---|---|
| Event ingestion | `security_events.source_system`, `external_event_id` | Added both columns |
| Event idempotency | Partial unique index on `(source_system, external_event_id)` where external ID is not null | Added dialect-specific partial-index predicates for SQLite and PostgreSQL |
| MFA | One-active-TOTP-per-user partial unique index | Added the partial unique index |
| MFA | Composite `(user_id, status)` index | Replaced the incomplete user-only index |
| Recovery codes | Composite `(user_id, used_at)` index | Corrected index definition |
| Access tokens | Composite `(user_id, revoked_at, expires_at)` index | Corrected index definition |
| Sessions | Composite `(user_id, revoked_at, idle_expires_at, absolute_expires_at)` index | Corrected index definition |
| MFA challenges and activation tokens | User/expiry/consumption indexes | Added both indexes |
| Auth throttling | Updated-at cleanup index | Added index |
| Correlation cases | Source-IP index and case/alert lookup indexes | Added missing indexes |

## Audit-chain and response storage

The SQLite response initializer adds `previous_hash` and `event_hash` to `response_audit_log` and creates `response_audit_chain_heads`. The SQLAlchemy response model already includes those fields and the chain-head table.

The production checkpoint and intent files are external to the relational schema. They must remain byte-for-byte preserved during any later migration. A relational database copy alone is not a complete audit-evidence backup.

## Parity test coverage added

The new test module builds the reference SQLite schema in a temporary directory and verifies:

1. Exact application table inventory against SQLAlchemy metadata.
2. Exact column inventory for every modeled table.
3. Presence of every explicitly declared domain index.
4. Foreign-key source/target columns and delete actions.

These checks are intended to fail closed if a future SQLite initializer change is not reflected in the staged schema model.

## Remaining migration-readiness gates

A passing schema parity test is necessary but not sufficient to authorize a baseline or production migration. Before the baseline is generated, we still need:

- Review of all column types, defaults, nullability, primary keys, unique constraints, check constraints, and partial-index semantics across both dialects.
- PostgreSQL-specific validation of generated DDL and constraint/index naming.
- A data-transfer design preserving integer IDs, UUID identifiers, timestamps, serialized JSON text, MFA ciphertext, token hashes, and IAM migration history.
- An explicit strategy for preserving response audit event order, hashes, chain heads, and external signed checkpoints.
- Repeatable offline migration rehearsal, row-count reconciliation, foreign-key validation, audit-chain verification, and restore rehearsal using synthetic fixtures.
- A separately approved production backup and migration window.

**Decision:** Do not generate or execute a production Alembic baseline yet. The parity tests must pass first, and the remaining migration gates require separate implementation and review.
