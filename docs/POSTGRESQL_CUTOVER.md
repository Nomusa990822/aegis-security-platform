# PostgreSQL runtime and SQLite cutover runbook

This runbook separates schema creation from data transfer. The API refuses to
start against an unmigrated PostgreSQL database. It never runs Alembic or
creates production tables as a side effect of application startup.

## What is included

- PostgreSQL 17 with psycopg 3 is the Compose runtime database.
- Alembic revision \`20261117_01\` creates the reviewed 27-table schema.
- \`app.sqlite_to_postgres\` creates a SQLite backup, copies the legacy data,
  reconciles every table using deterministic SHA-256 digests, resets serial
  sequences, and verifies response audit chains and signed checkpoints.
- The original SQLite database and audit-checkpoint directory are never
  modified or deleted by the transfer command.

SQLite remains in the test suite and as the legacy source format. It is not the
Compose runtime database.

## Required preparation

1. Keep the existing \`aegis-data\` Docker volume. It contains the old
   \`/data/aegis.db\` and signed audit checkpoints.
2. Keep the original \`.env\` values for analyst authentication, audit
   checkpoint signing, IAM, and MFA. Add the PostgreSQL variables shown in
   \`.env.example\`; do not rotate the checkpoint key during the migration.
3. Confirm that \`AEGIS_DATABASE_URL\` uses
   \`postgresql+psycopg://\` and points to the Compose host \`postgres\`.
4. Build the new image before running the migration commands.
5. Schedule a maintenance window. Stop the old AEGIS API before transferring
   data. Do not run old and new AEGIS writers concurrently.

Never paste database URLs, passwords, signing keys, MFA keys, or the contents
of \`.env\` into chat, issues, or logs.

## One-time cutover

Run these commands from the repository root on the host that owns the existing
Docker volume:

\`\`\`bash
docker compose build aegis
docker compose stop aegis
docker compose up -d postgres
docker compose --profile migration run --rm migrate
\`\`\`

The migration profile applies the Alembic baseline to the new, empty PostgreSQL
database. It does not copy application data.

Then run the guarded transfer. Choose a new backup filename; the command refuses
to overwrite an existing backup.

\`\`\`bash
docker compose run --rm aegis python -m app.sqlite_to_postgres \\
  --source /data/aegis.db \\
  --backup /data/backups/aegis-pre-postgresql-2026-11-17.db \\
  --confirm "MIGRATE AEGIS SQLITE DATA TO POSTGRESQL"
\`\`\`

The command also copies the configured signed audit-checkpoint directory to a
sibling backup directory named
\`aegis-pre-postgresql-2026-11-17.db.audit_checkpoints\`.

The transfer fails closed if any of the following is true:

- the SQLite schema does not match the reviewed PostgreSQL baseline;
- SQLite foreign-key checks report violations;
- the PostgreSQL database is not at Alembic revision \`20261117_01\`;
- any PostgreSQL application table already contains records;
- response audit lifecycle validation, hash-chain verification, or signed
  checkpoint verification fails;
- row counts or deterministic per-table SHA-256 digests differ.

All inserts and sequence adjustments occur in one PostgreSQL transaction. A
failure rolls back that transaction. The SQLite source remains unchanged.

## Start and verify

Only after the transfer command returns \`"status": "verified"\`:

\`\`\`bash
docker compose up -d aegis
docker compose ps
docker compose logs --tail=100 aegis
curl --fail http://localhost:8000/api/v1/health
\`\`\`

The health response must report a healthy application and a connected database.
Also sign in through the configured HTTPS ingress and verify the dashboard,
alert history, correlation cases, intelligence history, IAM accounts, MFA,
response history, audit chains, and signed checkpoints.

Keep all of the following until a separate backup-and-restore test succeeds:

- the original SQLite database;
- the generated SQLite backup and its SHA-256 value;
- the original audit-checkpoint directory;
- the copied audit-checkpoint backup;
- the original \`.env\` secrets and signing-key identifiers.

Do not run \`docker compose down -v\`. Do not delete the SQLite file or rotate
audit signing keys as part of this cutover.

## Recovery boundary

If the transfer fails, do not start the PostgreSQL-backed API and do not delete
the source or backups. The PostgreSQL transfer transaction is rolled back; the
SQLite source is still authoritative. Diagnose the reported schema or
integrity issue, correct it in a reviewed change, and repeat with a new backup
filename.

This repository change prepares and tests the cutover procedure. It does not
claim that a live host has been migrated. The final cutover must be executed
and verified on the deployment host where the existing SQLite volume and
checkpoint keys are available.
