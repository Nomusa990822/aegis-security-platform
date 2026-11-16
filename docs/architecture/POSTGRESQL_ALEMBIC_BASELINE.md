# Initial PostgreSQL schema baseline

Revision: `20261117_01` (initial Alembic revision)

## Scope

The baseline creates the 27 reviewed SQLAlchemy Core domain tables in an
**empty target schema**. It is deliberately fail-closed: table creation uses
`checkfirst=False`, so an existing table causes the migration to fail rather
than being silently adopted or overwritten.

The revision uses the reviewed central metadata in
`app.db_schema`. Treat that metadata as the schema contract for this initial
baseline. Any future schema change must be introduced as a new forward
Alembic revision; do not edit this baseline after it has been adopted by an
environment.

## Existing installations

Do not run `upgrade head` against the current SQLite deployment or against a
PostgreSQL schema that already contains application tables. This baseline is
for a clean PostgreSQL schema. Adoption of an existing database requires a
separate, reviewed process: full schema/data parity, backup and restore
rehearsal, explicit Alembic stamping only after parity is proven, and a
rollback/cutover plan. No such adoption or cutover is performed here.

The existing SQLite database, Docker volume, audit checkpoint files, external
checkpoint keys, credentials and deployment resources are outside this
migration's scope.

## Commands for disposable development only

From `backend/`, with a disposable PostgreSQL database configured:

```bash
AEGIS_DATABASE_URL='postgresql+psycopg://…/aegis_test' \
AEGIS_ALEMBIC_ALLOW_MIGRATIONS=1 \
alembic upgrade head
```

The explicit opt-in is mandatory. The application does not run migrations at
startup. Do not place production credentials in shell history or repository
files.

Downgrade is destructive to the 27 domain tables in the selected schema:

```bash
AEGIS_DATABASE_URL='postgresql+psycopg://…/aegis_test' \
AEGIS_ALEMBIC_ALLOW_MIGRATIONS=1 \
alembic downgrade base
```

Only use downgrade in a disposable environment after confirming the target
URL and schema. CI exercises both directions inside a randomly named schema
and drops that schema afterward.

## Validation contract

The PostgreSQL CI test applies the real Alembic revision, verifies all 27
tables, columns, foreign-key counts and indexes against metadata, downgrades
to base, and confirms that no domain tables remain. It uses the dedicated
`AEGIS_TEST_POSTGRES_URL` service URL and a per-test schema; it does not use
`AEGIS_DATABASE_URL` supplied by any deployment.
