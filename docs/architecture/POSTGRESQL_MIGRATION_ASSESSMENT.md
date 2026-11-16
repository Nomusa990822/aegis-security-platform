# PostgreSQL Migration Assessment and Architecture Decision

**Status:** Proposed architecture; assessment only  
**Production impact:** None. This document does not authorize or perform a production migration.

## 1. Executive decision

AEGIS should move to PostgreSQL before further database-heavy feature development. PostgreSQL will become the authoritative database for application development, integration testing, CI and the eventual production release.

SQLite remains the source format for the existing database and may remain useful for isolated, fast unit tests where the tested code is genuinely dialect-independent. It will not remain an equally supported production backend. The complete backend regression and integration suite must run against PostgreSQL.

### Recommended technology

- PostgreSQL as the database server.
- SQLAlchemy 2.x Core as the database engine, connection-pool and transaction boundary.
- Alembic for versioned schema migrations.
- Psycopg 3 as the PostgreSQL DB-API driver.
- Explicit, operator-invoked migration and data-transfer commands; no schema migration at application startup.
- PostgreSQL service containers in GitHub Actions for authoritative integration testing.

SQLAlchemy Core is preferred over an ORM rewrite. It provides dialect-aware SQL execution, transaction management and pooling while allowing AEGIS to retain explicit SQL and repository boundaries. Alembic gives the schema a single ordered migration history instead of accumulating independent startup-time schema creation and subsystem-specific migration mechanisms.

## 2. Current-state findings

The current main branch is commit f0234f9e99b61327de5167c74e1e375f432a235e.

The current implementation is SQLite-specific in multiple layers:

| Area | Current implementation | Migration implication |
|---|---|---|
| Connection management | backend/app/database.py imports sqlite3, opens file paths and configures SQLite PRAGMAs | Replace with SQLAlchemy engine/factory, pooling and explicit transaction ownership |
| Schema creation | Core tables are created idempotently during application lifespan | Move schema ownership to explicit Alembic migrations; startup must not silently mutate schema |
| Schema inspection | PRAGMA table_info, sqlite_master, integrity_check, foreign_key_check | Replace with Alembic version checks and PostgreSQL catalog/constraint verification |
| SQL parameters | DB-API positional question-mark placeholders | Convert repository statements to SQLAlchemy named binds; do not introduce a fragile global placeholder-rewriting shim |
| Generated identifiers | SQLite AUTOINCREMENT and cursor lastrowid | Use PostgreSQL identity columns and explicit INSERT ... RETURNING id where generated IDs are consumed |
| Duplicate ingestion | INSERT OR IGNORE and a partial unique index | Use PostgreSQL INSERT ... ON CONFLICT DO NOTHING with explicit conflict target and preserve duplicate-resolution semantics |
| IAM schema | Custom versioned SQLite migration statements, SQLite JSON checks and SQLite connection types | Port IAM schema to Alembic while preserving constraints, partial indexes, replay prevention and migration-history evidence |
| Audit storage | Audit-chain schema/backfill and conflict handling use SQLite-specific schema inspection and SQL | Preserve event ordering, hash inputs, event IDs, chain heads and checkpoint intent lifecycle |
| Application health | Health handler catches sqlite3.Error | Use database-library-neutral exceptions and a real connection/pool health check |
| Container | Compose mounts aegis-data and sets AEGIS_DATABASE_PATH=/data/aegis.db | Add PostgreSQL service, private network, durable database volume, health/dependency checks and secret-based credentials |
| CI | Tests install the current lock and use isolated SQLite files | Add PostgreSQL service-backed integration tests and make these authoritative |

The IAM migration command currently checks SQLite integrity and migration history explicitly. This safety model is valuable and should be retained in a database-neutral form; it should not be replaced by automatic startup migrations.

The response audit implementation also maintains an external signed checkpoint lifecycle. Database migration must preserve the relationship between database audit records and those external checkpoint files and keys. Moving database rows alone is not sufficient.

## 3. Design principles and non-negotiable invariants

1. No production mutation during this work. No production database, Docker container, volume, secret, checkpoint directory or deployment is to be accessed or changed.
2. No automatic schema changes on application startup. A missing or outdated schema must produce a clear readiness failure and an operator-facing migration instruction.
3. PostgreSQL is the authoritative integration target. CI must exercise the complete backend suite against PostgreSQL before the database migration is accepted.
4. Preserve audit evidence exactly. Do not re-serialize, normalise or regenerate historical audit details, hashes, event ordering or checkpoint files during data transfer.
5. Preserve identity and relationships. Retain primary keys, foreign keys, unique constraints, timestamps, nullable values, binary values and event idempotency identities.
6. Make migrations repeatable and inspectable. Schema migration and data transfer must support read-only preflight, explicit execution, post-migration verification and a documented stop/rollback procedure.
7. Use one transaction owner. Repositories must not unexpectedly commit transactions owned by their callers. Connection and transaction boundaries must be consistent across services.
8. No dual-production-database mode. Supporting two production dialects indefinitely would multiply testing and migration complexity without a current requirement.

## 4. Target architecture

The proposed database boundary is:

    FastAPI routes / services
              |
              v
        Domain repositories
              |
              v
    AEGIS database access boundary
    (SQLAlchemy Core + explicit transactions)
              |
              v
    PostgreSQL (authoritative)
              |
              +-- schema lifecycle: Alembic
              +-- connection pool and health checks
              +-- backups / restore verification
              +-- observability and query performance

The application should receive database connections through a single configured engine/factory. Repositories should use named bind parameters and return mapping-style records where mapping access is required. SQL should be explicit and portable where practical; PostgreSQL-specific features must be isolated and documented.

Recommended initial connection controls:

- Use a PostgreSQL URL from environment/secret configuration; never commit credentials.
- Configure bounded connection and pool timeouts, pool health checks and connection recycling as appropriate.
- Set an application name for database observability.
- Require TLS when connecting across an untrusted network.
- Use a least-privilege runtime database role; migration privileges should be separate from application privileges.
- Configure transaction isolation deliberately; use READ COMMITTED initially unless a specific workflow requires stronger isolation.
- Use explicit lock ordering and bounded retry for recognised transient transaction conflicts only.
- Do not retry arbitrary database exceptions or non-idempotent operations blindly.

## 5. Schema and SQL compatibility work

The migration inventory must cover all application and test SQL, not only database.py.

### Required SQL changes

- Replace positional question-mark placeholders with named SQLAlchemy binds.
- Replace lastrowid dependencies with explicit RETURNING clauses and returned mapping values.
- Replace INSERT OR IGNORE with targeted PostgreSQL ON CONFLICT handling.
- Replace SQLite PRAGMA schema inspection with Alembic-managed schema state and PostgreSQL catalog checks.
- Replace sqlite_master lookups with Alembic/catalog-based checks.
- Review CURRENT_TIMESTAMP, text timestamps and timezone assumptions.
- Review every ON CONFLICT ... DO UPDATE statement for equivalent PostgreSQL semantics.
- Review partial indexes and check constraints for equivalent PostgreSQL definitions.
- Replace SQLite-specific JSON validation with PostgreSQL constraints appropriate to the chosen storage type.
- Review boolean-like integer columns and choose explicit, consistent PostgreSQL types.
- Replace exception handling that currently depends on sqlite3.Error, sqlite3.IntegrityError or SQLite-specific error codes.
- Review test assertions that inspect PRAGMAs or rely on SQLite-only integrity commands.

### Data representation strategy

For the first PostgreSQL release, prefer conservative representation over opportunistic redesign:

- Preserve timestamp meaning and precision. Convert to timezone-aware PostgreSQL timestamps only after an explicit inventory proves that all historical values can be interpreted safely; otherwise retain canonical UTC text during the first transfer and schedule type normalisation separately.
- Preserve JSON payload semantics and exact audit payload bytes. JSONB may be introduced for queryable, non-cryptographic application data in a later, separately tested change. Do not convert signed/hash-covered audit payloads in a way that changes canonicalisation.
- Preserve encrypted MFA ciphertext as binary data and retain key identifiers. Do not decrypt or re-encrypt secrets as part of the database engine migration.
- Preserve hash strings, token digests and all external event identities exactly.
- Preserve primary key values and explicitly reset PostgreSQL identity sequences to values above the imported maxima.

## 6. Audit-chain and IAM migration requirements

These are high-risk migration areas and require dedicated tests.

### Response audit and checkpoints

Before and after migration, verify:

- Every response record and audit event is present.
- Event order, IDs, actors, timestamps and details are unchanged.
- Every previous_hash, event_hash, chain head, event count and final hash matches the source.
- Every response lifecycle passes the existing audit validator.
- Signed checkpoint files, checkpoint inventory, key identifiers and key-usage metadata are preserved outside the database and still verify against the migrated records.
- Checkpoint intents and recovery/quarantine records remain consistent.
- A deliberately altered row is detected by integrity verification after migration.

The migration must not regenerate a historical audit chain to make it pass. A source integrity failure is a stop condition requiring investigation.

### IAM and MFA

Verify preservation of:

- User identities, usernames, roles and statuses.
- Argon2id password hashes without rehashing or plaintext exposure.
- TOTP ciphertext, encryption key IDs, factor status and replay-prevention step.
- Hashed recovery codes and their used timestamps.
- Session digests, revocation state and MFA verification timestamps.
- Activation tokens, access-token digests, expiry and revocation state.
- Authentication throttling state and security events.
- All foreign keys, uniqueness constraints, checks and partial indexes.

Do not print or export plaintext passwords, TOTP secrets, recovery codes, session tokens or access tokens during migration.

## 7. Proposed implementation sequence

| Work item | Deliverable | Acceptance gate |
|---|---|---|
| 2F.1 | Complete database dependency inventory | Every SQLite-specific import, SQL statement, schema operation, test and deployment reference is catalogued |
| 2F.2 | Database architecture boundary | Engine/factory, mapping results, transaction ownership and error handling tested |
| 2F.3 | Alembic baseline and schema migrations | Fresh PostgreSQL database can be created entirely from versioned migrations; startup performs no schema mutation |
| 2F.4 | Repository and service port | All application SQL uses the new boundary; generated IDs, uniqueness and concurrency semantics preserved |
| 2F.5 | PostgreSQL integration CI | Complete backend suite runs against a pinned PostgreSQL service image |
| 2F.6 | SQLite-to-PostgreSQL transfer tooling | Read-only source preflight, explicit export/import, identity preservation and resumable diagnostics |
| 2F.7 | Migration verification suite | Counts, relationships, indexes, constraints, IAM, event idempotency and audit/checkpoint integrity verified |
| 2F.8 | Local development topology and operations docs | Secure Compose profile, health checks, backup/restore instructions and troubleshooting guide |
| 2F.9 | Architecture acceptance | No unresolved SQLite runtime dependency; all required tests and security checks pass |

The first implementation PR should be deliberately limited to the architecture boundary and dependency inventory. It should not attempt to port every repository in one large change.

## 8. Data migration procedure (future release only)

The eventual SQLite-to-PostgreSQL conversion should use a separate, explicit operator workflow:

1. Freeze the release candidate and identify the exact source database and checkpoint inventory.
2. Produce a verified, restorable backup of the SQLite database and the complete external audit-checkpoint/key inventory.
3. Run read-only source preflight: SQLite integrity, foreign keys, schema/migration history, table counts and audit/checkpoint verification.
4. Create a clean PostgreSQL database and apply the reviewed Alembic migrations.
5. Export/import in dependency order, preserving primary keys and exact values. Use a consistent source snapshot.
6. Reset identity sequences and validate all unique constraints, foreign keys and indexes.
7. Compare per-table row counts and deterministic content digests; investigate every mismatch.
8. Run the complete application regression, authorization, concurrency, event-idempotency, audit-chain and checkpoint tests against the imported database.
9. Perform a controlled application cutover only after explicit approval.
10. Keep the verified source backup and a documented rollback path until the release is accepted.

A migration must stop on any unexplained row-count/content mismatch, failed constraint, audit-chain mismatch, checkpoint verification failure or IAM/MFA data discrepancy.

## 9. Testing and acceptance criteria

The PostgreSQL migration is not complete until all of the following are true:

- A clean PostgreSQL instance can be provisioned from repository configuration.
- Alembic can create the complete schema from an empty database.
- The application refuses readiness when the schema is missing or behind.
- No application startup path creates or alters schema.
- The complete backend test suite passes against PostgreSQL.
- Concurrency tests cover simultaneous duplicate event ingestion, audit appends and relevant IAM replay-sensitive operations.
- Transaction rollback tests prove atomicity across related writes.
- Generated IDs and identity sequences remain correct after import.
- All foreign keys and uniqueness constraints are valid.
- IAM and MFA records remain usable without secret disclosure or re-encryption.
- Audit hashes, chain heads and external signed checkpoints verify before and after import.
- Backup restoration is demonstrated, not merely documented.
- Docker image, dependency lock, vulnerability scans and security workflows pass.
- PostgreSQL credentials and migration privileges are separated and no secrets are committed.

## 10. Scope boundary

This assessment does not:

- Connect to or inspect the live production database.
- Create, modify or delete production data.
- Change production secrets or environment variables.
- Start, stop or recreate containers or volumes.
- Apply migrations to any deployed environment.
- Authorise a production cutover.

**Conclusion:** PostgreSQL migration should precede the next major feature-development wave. First establish the database boundary, migration strategy and PostgreSQL-backed CI; then port the application incrementally with the existing security and audit guarantees treated as acceptance criteria.
