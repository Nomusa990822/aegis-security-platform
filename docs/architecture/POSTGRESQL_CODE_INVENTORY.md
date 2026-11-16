# PostgreSQL Migration: SQLite Dependency Inventory

**Status:** Initial source-code inventory; implementation has not started  
**Reviewed branch:** main  
**Reviewed commit:** f0234f9e99b61327de5167c74e1e375f432a235e  
**Related assessment:** [POSTGRESQL_MIGRATION_ASSESSMENT.md](POSTGRESQL_MIGRATION_ASSESSMENT.md)

This inventory records the SQLite coupling found during the initial code review. It is a migration worklist, not a claim that the code has already been ported. New SQLite-specific use discovered during implementation must be added here.

## 1. Central database lifecycle

| File | Observed coupling | Required change |
|---|---|---|
| `backend/app/database.py` | Imports sqlite3; path-based database configuration; custom SQLite connection subclass; SQLite busy timeout; row_factory; foreign-key and busy-timeout PRAGMAs; creates core tables and alters schema during initialization | Replace with configured SQLAlchemy engine/factory and explicit transaction boundary. Move every CREATE/ALTER/INDEX operation to Alembic. Startup must verify schema version, not mutate it. |
| `backend/app/main.py` | Imports sqlite3; application lifespan calls initialize_database and initialize_idempotency_schema; health handling is coupled to SQLite exceptions | Replace startup initialization with engine lifecycle and schema/readiness check. Health must distinguish process liveness from database readiness and use database-neutral exceptions. |
| `backend/app/idempotency.py` | Uses PRAGMA table_info, SQLite row mappings, ALTER TABLE and partial unique index creation at runtime | Move columns and partial unique index into Alembic; use PostgreSQL conflict-target semantics for duplicate event ingestion. |
| `backend/app/telemetry/adapter.py` | Uses the database service boundary indirectly; verify SQL and transaction ownership during repository port | Keep adapter domain-focused; database writes go through the new repository/database boundary. |

## 2. Repository and API surfaces

| File | Observed coupling | Required change |
|---|---|---|
| `backend/app/alerts.py` | Imports sqlite3; repository-style SQL on SQLite connection; generated note/evidence IDs read through cursor.lastrowid | Use SQLAlchemy connections/mappings and INSERT ... RETURNING for generated IDs. Replace SQLite exception handling with portable constraint/error handling. |
| `backend/app/correlations.py` | Uses shared SQLite connection and SQL; generated note ID uses lastrowid | Port to named binds and returned mappings; preserve correlation and case transaction semantics. |
| `backend/app/intelligence/repository.py` | Uses get_connection, positional question-mark binds and cursor.lastrowid | Port all statements to SQLAlchemy Core and RETURNING; preserve provider-result atomicity with assessment row. |
| `backend/app/response/repository.py` | Creates response/audit tables, inspects columns with PRAGMA, alters tables, uses SQLite DDL and SQL | Remove schema DDL from repository/runtime; migrate all response tables/indexes through Alembic; preserve response/audit transaction atomicity. |
| `backend/app/response/audit_chain_storage.py` | Uses PRAGMA table_info, SQLite ALTER TABLE and SQLite-specific row handling while backfilling audit chain | Move schema changes to Alembic. Preserve exact event ordering, canonical hash inputs, chain heads and verification behaviour. |
| `backend/app/response/checkpoint_inventory.py` | Imports sqlite3, accepts sqlite3.Connection, opens direct SQLite read-only connection, sets row_factory and PRAGMA query_only | Replace with read-only SQLAlchemy connection/transaction; retain read-only semantics and integrity checks using PostgreSQL catalog/constraint verification. |
| `backend/app/iam/repository.py` | Typed against sqlite3.Connection/sqlite3.Row; question-mark placeholders; savepoints | Port to SQLAlchemy Connection and mapping results; preserve transaction-neutral repository contract and savepoint atomicity. |
| `backend/app/iam/auth_throttling.py` | Typed against sqlite3.Connection; SQL and row access | Port atomic throttling updates and counters; add PostgreSQL concurrency tests to prove limits cannot be bypassed under parallel requests. |
| `backend/app/iam/sessions.py` | Typed against sqlite3.Connection; savepoints and conditional updates | Port session creation, revocation and single-use state transitions; verify concurrency and race behaviour. |
| `backend/app/iam/security_events.py` | Typed against sqlite3.Connection; SQL writes | Port without weakening event ordering or auditability. |
| `backend/app/iam/migrate.py` | Direct sqlite3 connections, PRAGMA integrity and foreign-key checks, sqlite_master migration-history inspection, SQLite savepoint and error types | Replace with an explicit Alembic operator command and PostgreSQL pre/postflight checks. Keep operator attestations, read-only preflight and fail-closed behaviour. |
| `backend/app/iam/migrations.py` | SQLite-specific migration SQL, sqlite3 typing and checksummed custom migration registry | Translate the schema into ordered Alembic revisions. Preserve schema constraints and a traceable record of legacy IAM migration versions during import. |

## 3. Audit and security-sensitive data

The following data must be treated as high-risk during the port:

- `response_records`, `response_audit_log`, `response_audit_chain_heads`.
- Audit event `previous_hash` and `event_hash` values and their canonical source fields.
- External signed checkpoint files, checkpoint inventory, key identifiers, key usage, intent and quarantine/recovery records.
- IAM users, password hashes, encrypted TOTP ciphertext and key IDs, replay-prevention counters, recovery-code hashes, session/token digests, revocation state and authentication throttling records.
- Event source identity fields and the partial unique index that provides ingestion idempotency.

The external checkpoint directory and key material are not simply relational rows. The database migration must not rewrite, regenerate or re-key these files. A source checkpoint verification failure is a migration stop condition.

## 4. SQL and driver patterns to locate and remove

The port must search application, scripts and tests for all of the following, not only imports:

- `sqlite3`, `sqlite3.Connection`, `sqlite3.Row`, `sqlite3.Error`, `sqlite3.IntegrityError`.
- `PRAGMA`, `sqlite_master`, `sqlite_sequence`, `PRAGMA integrity_check`, `PRAGMA foreign_key_check`.
- `lastrowid`, `INSERT OR IGNORE`, `INSERT OR REPLACE`, SQLite `AUTOINCREMENT`.
- Positional DB-API `?` placeholders and SQLite connection context-manager assumptions.
- `executescript`, `row_factory`, SQLite URI `mode=ro`, `BEGIN IMMEDIATE`, SQLite busy timeout.
- DDL embedded in application lifespan, repository constructors or request handlers.
- Tests asserting PRAGMA output or relying on SQLite's typing, locking or conflict behaviour.

A blind textual replacement of question-mark placeholders is not acceptable: SQL string literals, JSON, comments and operators can contain question marks. Convert statements deliberately to SQLAlchemy named binds.

## 5. Test and configuration surfaces

| Surface | Current state | Required change |
|---|---|---|
| `backend/tests/conftest.py` | Creates one temporary SQLite database per test by monkeypatching DATABASE_PATH; calls database.initialize_database; approver fixture applies custom SQLite IAM migrations | Introduce a PostgreSQL test database fixture with isolated schema/database lifecycle. Keep SQLite-only unit fixtures only for tests explicitly proven dialect-independent. |
| Backend tests | Many tests directly use connection.execute, SQLite row objects and PRAGMA assertions | Port database fixtures and assertions; add transaction, locking, concurrency and PostgreSQL constraint coverage. |
| `backend/requirements.txt` and `backend/requirements.lock` | No SQLAlchemy, Alembic or Psycopg dependency | Add pinned, reviewed SQLAlchemy 2.x, Alembic and Psycopg 3 dependencies and regenerate/validate the lock. |
| `compose.yaml` | Single application service, SQLite file path, shared `aegis-data` volume | Add a PostgreSQL service on a private network with health checks and a dedicated persistent volume; use separate runtime and migration credentials. Preserve the audit checkpoint volume and container hardening. |
| GitHub Actions | Backend suite currently provisions SQLite files | Add pinned PostgreSQL service and run the complete backend suite against PostgreSQL. Do not claim migration acceptance based only on SQLite tests. |
| `.env.example` and docs | SQLite path configuration | Document a secret-backed PostgreSQL URL and migration command; never include real credentials. |

## 6. Transaction and concurrency contracts to preserve

The current SQLite connection context manager commits/rolls back on exit and closes the connection. Several repositories either own their connection or accept one from a caller. IAM methods use savepoints and are intentionally transaction-neutral.

Before converting code, define and test these contracts:

1. The service/use-case layer owns the outer transaction for a multi-repository operation.
2. A repository never commits a caller-owned transaction.
3. A repository that creates its own connection must own and close its transaction and connection.
4. Multi-row operations such as intelligence assessment plus provider results and response plus audit append are atomic.
5. IAM single-use recovery-code consumption, TOTP replay prevention, session revocation and throttling remain race-safe under concurrent transactions.
6. Event idempotency uses a database unique constraint as the final concurrency guard, not a check-then-insert alone.
7. Audit append ordering and chain-head update remain atomic.

## 7. Recommended next implementation order

1. Agree and implement the SQLAlchemy Core database access boundary with no repository-wide rewrite in the same PR.
2. Add Alembic configuration and a reviewed PostgreSQL schema baseline; remove runtime schema creation only when the migration path is ready.
3. Port a small low-risk repository as a reference implementation and validate its transaction semantics.
4. Port remaining repositories and IAM/response security-sensitive paths in separate reviewable batches.
5. Move CI to PostgreSQL and run the complete suite.
6. Implement the offline SQLite export/import and verification tool only after the PostgreSQL schema and application are stable.

## 8. Explicit exclusions

This inventory work has not connected to or changed the production database, Docker containers, persistent volumes, secrets, audit-checkpoint files or deployment. It does not perform data migration or authorise a production cutover.
