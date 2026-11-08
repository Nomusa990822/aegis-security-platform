# AEGIS Test Status Register

Last updated: 2026-11-08

## Current rule

Tests are being prepared while the GitHub Codespace is being configured. **No test listed as deferred below has been run against the current commits.** Do not treat implementation or static review as a passing test result.

When the Codespace is ready, pull `main` and run the command batch below.

## Deferred test batch supplied by the project owner

Run from the Codespaces terminal:

```bash
cd /workspaces/aegis-security-platform

git pull origin main

cd backend

printf '\n========== TARGETED AUDIT TESTS ==========\n'

./.venv/bin/python -m pytest \
    tests/test_response_audit_checkpoint_integration.py \
    tests/test_response_concurrency.py \
    tests/test_response_audit_integrity.py -v

printf '\n========== COMPLETE BACKEND TEST SUITE ==========\n'

./.venv/bin/python -m pytest -q
```

Status: **NOT RUN — waiting for Codespace readiness.**

## Deferred test modules

- `tests/test_response_audit_checkpoint_integration.py` — entire module, including existing checkpoint creation, advancement, tampering, key rotation, integrity-gate, and checkpoint-failure scenarios.
- `tests/test_response_concurrency.py` — entire module.
- `tests/test_response_audit_integrity.py` — entire module.
- Complete backend test suite — all tests collected by `pytest -q`.

## Newly added or changed checkpoint-failure and recovery tests — NOT RUN

In `tests/test_response_audit_checkpoint_integration.py`:

- `test_checkpoint_write_failure_does_not_undo_committed_response` — verifies request creation remains committed, reports HTTP 202, and retains its signed intent when checkpoint publication fails.
- `test_approval_reports_committed_checkpoint_failure` — verifies approval is committed and reported as checkpoint-pending when publication fails.
- `test_simulation_reports_committed_checkpoint_failure` — verifies simulation is committed and reported as checkpoint-pending when publication fails.
- `test_signed_checkpoint_intent_supports_safe_recovery` — verifies dry-run recovery, explicit publication, intent removal, and final integrity.
- `test_recovery_refuses_tampered_checkpoint_intent` — verifies a modified intent signature cannot be used to publish a checkpoint.
- `test_recovery_refuses_database_rewrite_after_intent_was_signed` — verifies a rewritten database chain cannot be checkpointed using an earlier signed intent.
- `tests/test_checkpoint_bootstrap.py::test_bootstrap_does_not_bypass_a_pending_signed_intent` — verifies the legacy bootstrap path refuses to sign a response that has a pending signed intent.

All are authored but unverified.

## New manual recovery procedure — NOT RUN

Only use this when inventory identifies a pending intent and the database and intent need to be reconciled. Stop the API server first.

Load the local environment first (do not print or share the secret values):

```bash
cd /workspaces/aegis-security-platform/backend
set -a
source .env
set +a
```

Dry run:

```bash
./.venv/bin/python -m app.response.checkpoint_recovery
```

Review the eligible response IDs and the report carefully. Apply only after confirming the selected intent corresponds to the expected committed response:

```bash
./.venv/bin/python -m app.response.checkpoint_recovery --apply --response-id RESPONSE_ID
```

Replace `RESPONSE_ID` with the actual numeric ID. The recovery command uses a read-only SQLite connection and changes checkpoint files only. Invalid signatures, mismatched database heads, invalid lifecycle histories, and predecessor-checkpoint mismatches must be refused.

Do not run `--apply` on an orphan or invalid intent. Stale intents from transactions that never committed require separate investigation; they are not automatically discarded.

## Other checks to record when the Codespace is ready

- Confirm the application imports and starts after the latest router/repository changes.
- Run the targeted audit tests before the full backend suite.
- Record the exact pytest summary, failures, skips, and errors. Do not mark a module passed if collection or setup failed.
- After any fixes, rerun the affected targeted tests and then the full backend suite.

## Historical note

Earlier checkpoint inventory/bootstrap tests passed before the latest fail-closed and checkpoint-failure-reporting changes. Those earlier results do not verify the current commits, and the full backend suite remains deferred.


## Stale checkpoint-intent quarantine — NOT RUN

New module: `backend/app/response/checkpoint_intent_quarantine.py`.

Safety conditions for quarantine:

- The intent signature must validate with an available retained signing key.
- No response record, chain-head row, or audit event may exist for that response ID.
- The intent must describe the initial event only (predecessor count zero and genesis hash); a continuation intent is preserved for investigation even if its predecessor checkpoint is missing.
- No checkpoint file may exist for that response ID.
- The operator must explicitly pass `--apply` and a non-empty `--reason`.
- The original signed intent is moved unchanged into `audit_checkpoints/quarantine/`; a separate manifest records its SHA-256, timestamp, reason, signed payload, and database checks.
- The database connection is read-only. Stop the API server before any apply operation.
- Corrupt, unverifiable, database-referenced, or checkpoint-associated intents are preserved in place for investigation. This is not a repair or deletion operation.

When Codespaces is ready, inspect first:

```bash
cd /workspaces/aegis-security-platform/backend
set -a
source .env
set +a
./.venv/bin/python -m app.response.checkpoint_intent_quarantine
```

Only after reviewing the dry-run report and confirming the API server is stopped, quarantine one explicitly selected orphan:

```bash
./.venv/bin/python -m app.response.checkpoint_intent_quarantine \
    --apply \
    --response-id RESPONSE_ID \
    --reason "Confirmed abandoned pre-commit intent; no matching database artifacts."
```

New regression tests — all authored but NOT RUN:

- `tests/test_checkpoint_bootstrap.py::test_stale_orphan_intent_is_dry_run_then_quarantined_with_evidence`
- `tests/test_checkpoint_bootstrap.py::test_quarantine_refuses_intent_when_database_response_exists`
- `tests/test_checkpoint_bootstrap.py::test_quarantine_refuses_invalid_signed_intent`
- `tests/test_checkpoint_bootstrap.py::test_quarantine_refuses_intent_with_missing_predecessor_checkpoint`

The checkpoint inventory now recognizes the `quarantine/` evidence directory and reports its evidence-file count instead of flagging that directory as unrecognized.


## Checkpoint signing-key rotation inventory — NOT RUN

New module: `backend/app/response/checkpoint_key_usage.py`.

The read-only inventory:

- Lists configured key IDs and signing-key IDs referenced by active checkpoints, pending intents, and quarantined intent evidence.
- Verifies signatures where the required key is available.
- Reports missing key IDs and invalid/unverifiable signed documents.
- Identifies configured non-active keys with no references in the inspected checkpoint directory.
- Never prints key material and never edits environment variables or checkpoint files.
- Treats retirement as review-required even when a key has no local references, because backups and external copies may still depend on it. Any malformed or unverifiable document blocks a clean retirement assessment.

When Codespaces is ready, load the environment and inspect:

```bash
cd /workspaces/aegis-security-platform/backend
set -a
source .env
set +a
./.venv/bin/python -m app.response.checkpoint_key_usage
```

Rotation rule: add the old key ID and secret to `AEGIS_AUDIT_CHECKPOINT_PREVIOUS_KEYS` when switching the active key. Keep the old key until the inventory shows no references in checkpoints, pending intents, or quarantined evidence, and backup/retention copies have also been checked. A pending intent signed by an old key must remain verifiable so recovery can publish the resulting checkpoint under the new active key.

New regression test file — all authored but NOT RUN:

- `tests/test_checkpoint_key_usage.py::test_key_usage_inventory_tracks_old_checkpoint_and_pending_intent`
- `tests/test_checkpoint_key_usage.py::test_pending_intent_survives_rotation_and_publishes_with_new_key`
- `tests/test_checkpoint_key_usage.py::test_key_usage_inventory_blocks_retirement_when_old_key_is_missing`

Run this module separately during the deferred verification session:

```bash
./.venv/bin/python -m pytest tests/test_checkpoint_key_usage.py -v
```

- `tests/test_checkpoint_key_usage.py::test_key_usage_inventory_retains_quarantined_intent_key_reference`
- `tests/test_checkpoint_key_usage.py::test_key_usage_inventory_accounts_for_legacy_checkpoint_signing_key`
