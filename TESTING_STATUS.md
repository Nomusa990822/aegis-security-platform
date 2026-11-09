# AEGIS Test Status Register

Last updated: 2026-11-09

## Current rule

## Database audit-event tampering blocks simulation — PASSED

- The focused regression test passed.
- The complete response audit-checkpoint integration test module passed.
- The complete backend test suite passed.
- Confirmed that database audit-event tampering causes simulation to be rejected with HTTP 409.
- Confirmed that the response remains approved, is not simulated or executed, and the tampered evidence remains available for inspection.
- Confirmed the expected distinction: overall integrity is invalid and the hash chain is invalid, while the unchanged signed checkpoint remains cryptographically valid.

A focused API regression test approves a dry-run response, modifies an existing database audit event without updating its cryptographic hash, and attempts simulation. It verifies that AEGIS returns HTTP 409, leaves the response approved and unexecuted, preserves both audit events (including the tampered value for forensic visibility), and reports invalid chain/checkpoint integrity.

Run from the Codespaces terminal:

```bash
git pull --ff-only origin main

cd /workspaces/aegis-security-platform/backend

./.venv/bin/python -m pytest tests/test_response_audit_checkpoint_integration.py -k hash_chain_tampering_blocks_simulation_without_mutation -v

./.venv/bin/python -m pytest tests/test_response_audit_checkpoint_integration.py -v

./.venv/bin/python -m pytest -q
```

**Verification state: NOT RUN.** Mark passed only after the focused test, full checkpoint integration module, and full backend suite pass.



## Tampered signed checkpoint blocks simulation without mutation — PASSED

The project owner confirmed that all three verification runs passed:
- Focused regression test: `test_tampered_checkpoint_blocks_simulation_without_mutation`.
- Complete `test_response_audit_checkpoint_integration.py` module.
- Complete backend test suite.

The regression confirms that a tampered checkpoint signature blocks simulation, leaves the response approved and unexecuted, preserves the existing audit events, and does not silently rewrite the tampered checkpoint.

**Status: OWNER-CONFIRMED PASSED.**

A focused API regression test corrupts the signed checkpoint signature after a response has been approved, then attempts simulation. It verifies that the API fails closed, the response remains approved, neither simulated nor executed becomes true, the two existing audit events remain unchanged, and the tampered checkpoint is not silently rewritten.

Run from the Codespaces terminal:

```bash
cd /workspaces/aegis-security-platform

git pull --ff-only origin main

cd backend

./.venv/bin/python -m pytest tests/test_response_audit_checkpoint_integration.py -k tampered_checkpoint_blocks_simulation_without_mutation -v

./.venv/bin/python -m pytest tests/test_response_audit_checkpoint_integration.py -v

./.venv/bin/python -m pytest -q
```

**Verification state: NOT RUN.** Do not mark this task passed until the focused regression test, complete checkpoint integration module, and full backend suite have all passed.



The initial Codespace run exposed four failures. Those defects were corrected, and the project owner subsequently confirmed that the targeted tests and complete backend suite all passed. See the final verification section below. The original failure results are retained as historical records.

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

Status: **PASSED on 2026-11-09 after corrective commits; see final verification below.**


## Final Codespace verification — 2026-11-09

<badge>Owner-confirmed passing</badge>

The project owner confirmed that all tests passed after pulling the simulator-identity correction commits.

Confirmed:
- Targeted audit, concurrency, and integrity batch: **37 passed**.
- Checkpoint bootstrap/quarantine batch: **10 passed**.
- Complete backend test suite: **all tests passed**.
- The earlier failure `test_wrong_simulation_actor_is_detected` was resolved by recording `simulated_by` in signed audit-event details and validating it against the event actor.
- The new alternate-simulator regression test passed as part of the successful complete suite.

The exact final `pytest -q` pass count was not included in the owner's message; do not infer or fabricate it.

**Status: FULL BACKEND TEST SUITE PASSED.** The automated test verification milestone is complete. The manual read-only operational inspections and any optional key-rotation preflight remain separate operational checks; they are not implied by the pytest result.

## First Codespace verification run — 2026-11-09

Environment:
- Python 3.14.2
- pytest 9.2.0
- Pulled commit: `36d7c7d` (working tree was clean before pull).

Observed results before corrective commits:
- `test_response_audit_checkpoint_integration.py`: 22 passed.
- `test_response_concurrency.py`: 2 passed, 1 failed.
- `test_response_audit_integrity.py`: 12 passed.
- Combined targeted audit batch: **36 passed, 1 failed** (37 collected).
- `test_checkpoint_bootstrap.py`: 7 passed, 3 failed.
- `test_checkpoint_key_usage.py`: **5 passed**.
- `test_checkpoint_key_rotation.py`: **5 passed**.
- Complete backend suite: **570 passed, 4 failed** (574 collected).
- Warnings: Starlette TestClient/httpx deprecation; one pytest collection warning for helper class `TestProvider`.

Failure analysis:
1. `test_concurrent_simulation_runs_only_once` exposed an incorrect lifecycle rule: the validator required the simulation actor to equal the original requester. The simulation actor is the analyst who actually performs the operation; the audit event already records that actor and common validation requires it to be non-empty. The validator rule has been corrected in the audit module. This is a behaviour fix, not a test expectation change.
2. Three quarantine tests accessed `AEGIS_AUDIT_CHECKPOINT_DIR` without requesting the `isolated_database` fixture. That fixture is responsible for setting the temporary database, test signing key, and per-test checkpoint directory. The three tests now request the fixture. This fixes test isolation; it does not require sourcing the user's real `.env`.

Corrective commits:
- Audit lifecycle correction: see the commit immediately preceding the test-fixture correction on `main`.
- Quarantine test isolation correction: see the latest test-fixture commit on `main`.

Historical status: this was subsequently rerun after the corrective commits and passed; see final verification below.

## Second Codespace verification run — 2026-11-09

After the first corrective commits (`4d76fd5`, `c92f742`, and `f63d7d2`), the project owner reran the tests.

Confirmed results:
- Targeted audit/concurrency/integrity batch: **37 passed**, 1 Starlette deprecation warning.
- Checkpoint bootstrap/quarantine: **10 passed**, 1 Starlette deprecation warning.
- Complete backend suite: **573 passed, 1 failed** (574 collected).
- The remaining failure was `tests/test_response_audit_consistency.py::test_wrong_simulation_actor_is_detected`.

Analysis: the previous validator correction correctly allowed a simulator to be a different analyst from the original requester, as demonstrated by the concurrency test, but removed the independent actor-consistency assertion. The corrected design records `simulated_by` in the simulation event details and validates that it matches the event's `actor`. This allows legitimate alternate analysts while detecting an actor field altered independently. Historical simulation events without `simulated_by` remain accepted for compatibility.

New regression coverage:
- `test_wrong_simulation_actor_is_detected` — changes only the event actor and must fail.
- `test_different_authorised_simulator_is_valid_when_identity_matches` — changes both the event actor and its recorded simulator identity and must pass.

Corrective commits on `main`:
- `bb3376e` — restore simulation actor consistency validation.
- `c062c10` — record simulator identity in signed audit details.
- `6e29c19` — add/update simulator identity regression tests.

Historical status: the project owner subsequently confirmed that the targeted tests and complete backend suite passed after these commits; see final verification below.

## Test module execution status

The project owner confirmed the following tests were run and passed after the corrective commits:

- `tests/test_response_audit_checkpoint_integration.py`
- `tests/test_response_concurrency.py`
- `tests/test_response_audit_integrity.py`
- `tests/test_checkpoint_bootstrap.py`
- `tests/test_checkpoint_key_usage.py`
- `tests/test_checkpoint_key_rotation.py`
- `tests/test_response_audit_consistency.py`
- Complete backend test suite (`pytest -q`).

The individual test counts from the final full-suite run were not included in the confirmation, so this register does not invent a final total.

## Newly added or changed checkpoint-failure and recovery tests — PASSED in targeted/full-suite verification

In `tests/test_response_audit_checkpoint_integration.py`:

- `test_checkpoint_write_failure_does_not_undo_committed_response` — verifies request creation remains committed, reports HTTP 202, and retains its signed intent when checkpoint publication fails.
- `test_approval_reports_committed_checkpoint_failure` — verifies approval is committed and reported as checkpoint-pending when publication fails.
- `test_simulation_reports_committed_checkpoint_failure` — verifies simulation is committed and reported as checkpoint-pending when publication fails.
- `test_signed_checkpoint_intent_supports_safe_recovery` — verifies dry-run recovery, explicit publication, intent removal, and final integrity.
- `test_recovery_refuses_tampered_checkpoint_intent` — verifies a modified intent signature cannot be used to publish a checkpoint.
- `test_recovery_refuses_database_rewrite_after_intent_was_signed` — verifies a rewritten database chain cannot be checkpointed using an earlier signed intent.
- `tests/test_checkpoint_bootstrap.py::test_bootstrap_does_not_bypass_a_pending_signed_intent` — verifies the legacy bootstrap path refuses to sign a response that has a pending signed intent.

These tests were included in the successful targeted audit batch and subsequent successful full-suite run.

## Interrupted checkpoint-publication artifacts — PASSED in targeted/full-suite verification

`checkpoint_recovery.py` now inventories checkpoint and pending-intent temporary files, including symlinked temporary artifacts, but deliberately does not parse, publish, delete, or quarantine them. A final checkpoint is written through a temporary file followed by an atomic replace; a leftover temporary file is therefore an interrupted staging artifact, not authoritative evidence. Preserve it for manual forensic review. A corrupt final checkpoint is also preserved: recovery only publishes through a valid signed intent and refuses when the existing checkpoint is not the expected target or verified predecessor.

New regression test — authored but NOT RUN:

- `tests/test_response_audit_checkpoint_integration.py::test_recovery_inventories_and_preserves_interrupted_temporary_files`

The existing targeted audit test batch included this test, and the project owner confirmed that batch passed.

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


## Stale checkpoint-intent quarantine — PASSED in targeted/full-suite verification

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

Regression tests — included in the successful checkpoint bootstrap/quarantine run:

- `tests/test_checkpoint_bootstrap.py::test_stale_orphan_intent_is_dry_run_then_quarantined_with_evidence`
- `tests/test_checkpoint_bootstrap.py::test_quarantine_refuses_intent_when_database_response_exists`
- `tests/test_checkpoint_bootstrap.py::test_quarantine_refuses_invalid_signed_intent`
- `tests/test_checkpoint_bootstrap.py::test_quarantine_refuses_intent_with_missing_predecessor_checkpoint`

The checkpoint inventory now recognizes the `quarantine/` evidence directory and reports its evidence-file count instead of flagging that directory as unrecognized.


## Checkpoint signing-key rotation inventory — PASSED in targeted/full-suite verification

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

Regression tests — included in the successful key-usage test run:

- `tests/test_checkpoint_key_usage.py::test_key_usage_inventory_tracks_old_checkpoint_and_pending_intent`
- `tests/test_checkpoint_key_usage.py::test_pending_intent_survives_rotation_and_publishes_with_new_key`
- `tests/test_checkpoint_key_usage.py::test_key_usage_inventory_blocks_retirement_when_old_key_is_missing`
- `tests/test_checkpoint_key_usage.py::test_key_usage_inventory_retains_quarantined_intent_key_reference`
- `tests/test_checkpoint_key_usage.py::test_key_usage_inventory_accounts_for_legacy_checkpoint_signing_key`

Standalone command for future regression checks:

```bash
./.venv/bin/python -m pytest tests/test_checkpoint_key_usage.py -v
```



## Checkpoint key-rotation preflight — PASSED in targeted/full-suite verification

New module: `backend/app/response/checkpoint_key_rotation.py`.

This read-only preflight validates a proposed signing-key configuration against every recognized local checkpoint, pending intent, and quarantined intent evidence file. It verifies each document with the proposed keyring and proposed legacy key. It does not modify the active environment, rotate keys, rewrite checkpoints, or delete evidence.

The proposed configuration is supplied through temporary environment variables (never commit these values):

- `AEGIS_AUDIT_CHECKPOINT_NEXT_KEY`
- `AEGIS_AUDIT_CHECKPOINT_NEXT_KEY_ID`
- `AEGIS_AUDIT_CHECKPOINT_NEXT_PREVIOUS_KEYS` (JSON object)
- `AEGIS_AUDIT_CHECKPOINT_NEXT_LEGACY_KEY`

When Codespaces is ready, first configure the proposed values in the local shell or ignored local `.env` file. Retain every old key needed by the inventory. Then run:

```bash
cd /workspaces/aegis-security-platform/backend
set -a
source .env
set +a
./.venv/bin/python -m app.response.checkpoint_key_rotation
```

A successful local preflight means all inspected local signed evidence verifies under the proposed configuration. It does not prove that backups, exported evidence, or external archives are covered. Do not activate the new configuration if the preflight fails.

Regression tests — included in the successful key-rotation test run:

- `tests/test_checkpoint_key_rotation.py::test_preflight_accepts_rotation_that_retains_all_required_keys`
- `tests/test_checkpoint_key_rotation.py::test_preflight_rejects_rotation_that_drops_a_required_previous_key`
- `tests/test_checkpoint_key_rotation.py::test_preflight_rejects_wrong_legacy_key`
- `tests/test_checkpoint_key_rotation.py::test_preflight_rejects_tampered_checkpoint_signature`
- `tests/test_checkpoint_key_rotation.py::test_preflight_checks_quarantined_intent_evidence`

Standalone command for future regression checks:

```bash
./.venv/bin/python -m pytest tests/test_checkpoint_key_rotation.py -v
```


## Checkpoint quarantine recovery integrity — PASSED (owner-confirmed 2026-11-09)

New module: `backend/app/response/checkpoint_quarantine_recovery.py`.

The quarantine writer now uses a two-stage manifest protocol:
1. Atomically persist a schema-v2 manifest with `status="prepared"` before moving the signed intent.
2. Atomically move the exact signed intent bytes into the quarantine evidence directory and fsync both directories.
3. Atomically update the manifest to `status="completed"`.

This makes both interruption windows detectable:
- Prepared manifest + original intent still present: recovery can finish the move after revalidating the signed intent and database state.
- Prepared manifest + evidence already moved: recovery can validate the evidence and complete the manifest.

Recovery safeguards:
- Dry-run by default; `--apply` requires at least one explicit `--response-id`.
- SQLite is opened read-only by the CLI.
- Rechecks the manifest, source/evidence paths, SHA-256, HMAC signature, database references, and checkpoint absence under the per-response lock.
- Only initial orphan intents are eligible (event count 1, predecessor count 0, genesis predecessor hash).
- Rejects missing/invalid signing keys, malformed or duplicate-key JSON, mismatched manifest metadata, symlinks, both source and evidence existing, changed database references, and unexpected checkpoints.
- Does not delete evidence, overwrite evidence, invent a manifest for an orphan evidence file, or process temporary manifest files.
- Orphan evidence without a manifest and interrupted manifest temp files are inventoried and preserved.
- Historical schema-v1 completed manifests remain readable.

Read-only dry run (stop the API server first and load the local environment without displaying secrets):

```bash
cd /workspaces/aegis-security-platform/backend
set -a
source .env
set +a
./.venv/bin/python -m app.response.checkpoint_quarantine_recovery
```

Explicit recovery of a reviewed response ID:

```bash
./.venv/bin/python -m app.response.checkpoint_quarantine_recovery \
    --apply \
    --response-id RESPONSE_ID
```

New tests — authored and **PASSED in the owner's test run**:
- `test_quarantine_recovery_finishes_prepared_manifest_before_move`
- `test_quarantine_recovery_completes_manifest_after_atomic_move`
- `test_quarantine_recovery_refuses_modified_evidence`
- `test_quarantine_recovery_inventories_orphan_evidence_and_manifest_temps`
- `test_quarantine_recovery_apply_requires_explicit_response_id`
- `test_quarantine_writer_interruption_after_move_is_recoverable`

The existing `test_stale_orphan_intent_is_dry_run_then_quarantined_with_evidence` was updated to require a schema-v2 completed manifest.

Run the focused tests:

```bash
./.venv/bin/python -m pytest tests/test_checkpoint_bootstrap.py -v
```

Then run the full backend suite:

```bash
./.venv/bin/python -m pytest -q
```

**Verification state: PASSED.** The project owner confirmed that all tests passed after pulling the implementation. The exact focused and full-suite counts were not provided, so no totals are inferred. This verifies automated tests only; it does not mean the operational recovery command was run. Do not run the recovery command with `--apply` against real quarantine evidence without first reviewing the dry-run report.

Implementation commit trail:
- `bbe439b` — add quarantine recovery inspection and explicit recovery.
- `2cec518` — write prepared manifest before moving evidence and completed manifest after.
- `7647f0a` — add recovery tests for both interruption windows, tampering, orphan evidence, and temporary manifests.
- `34a7e1e` — require explicit response IDs for apply and revalidate manifest under lock.
- `52ed5e3` — strengthen assertions and test scoped apply.
- `e91ce4d` — validate initial-orphan provenance and manifest metadata.
- `6a7fc9c` — exercise an actual interruption after the evidence move.
- `64f2ab4` — tighten recovery apply reporting.
- `b22d969` — register the final interruption test.




## Threat-intelligence provider timeout isolation — PASSED (owner-confirmed 2026-11-09)

The enrichment service now enforces a finite, positive per-provider timeout (default: 12 seconds) using `asyncio.wait_for`.

Expected behaviour:
- A provider that exceeds its deadline is recorded as `UNAVAILABLE`, not as a successful or malicious result.
- The timeout is isolated to that provider; subsequent providers are still queried.
- If every provider times out or fails, the assessment remains failed/unknown with no threat-score inflation from the timeout.
- If another provider succeeds, the overall assessment is partial and retains only the successful provider's categories and scoring contribution.
- Invalid timeout configuration (zero, negative, non-finite values, or booleans) is rejected at service construction.
- Cancellation of the overall enrichment task is not swallowed by the provider exception handler.

Default timeout is a service-level ceiling. The AbuseIPDB HTTP client retains its own lower-level network timeout as an additional bound.

New tests — authored and **PASSED in the owner's test run**:
- `test_provider_timeout_becomes_unavailable_without_crashing_enrichment`
- `test_timed_out_provider_does_not_discard_successful_provider_result`
- `test_provider_timeout_configuration_must_be_finite_and_positive` (six cases, including an oversized integer)
- `test_cancelling_enrichment_propagates_cancellation_to_provider`

Run the focused intelligence tests:

```bash
./.venv/bin/python -m pytest tests/test_intelligence.py -v
```

Then run the complete backend suite:

```bash
./.venv/bin/python -m pytest -q
```

**Verification state: PASSED.** The project owner confirmed that the focused intelligence tests and complete backend test suite passed after the pytest parameter-ID correction (`8540b98`). The exact pass count was not provided. No live AbuseIPDB requests were needed; the timeout tests use local asynchronous test providers.

Implementation commits: `c7fdd04` (provider deadline), `3411ee3` (timeout isolation tests), `bab4122` (timeout validation edge cases), `52eb4b9` (cancellation and oversized-value tests), and `8540b98` (explicit pytest parameter IDs for Python 3.14 compatibility).

## Response transaction rollback on audit-event append failure — PASSED (owner-confirmed 2026-11-09)

Two repository-level failure-injection tests now verify that an audit append failure inside a response lifecycle transaction does not leave a partial state change:

- `test_decision_rolls_back_when_audit_event_append_fails` — a failed approval audit append must leave the response pending, preserve the original audit events, and retain the original chain head.
- `test_simulation_rolls_back_when_audit_event_append_fails` — a failed simulation audit append must leave the response approved and un-simulated, preserve the original audit events, and retain the original chain head.

These tests inject a local exception at the audit append boundary. They do not contact external services and do not execute firewall, operating-system, or network actions.

Run the focused integrity tests:

```bash
./.venv/bin/python -m pytest tests/test_response_audit_integrity.py -v
```

Then run the complete backend suite:

```bash
./.venv/bin/python -m pytest -q
```

**Verification state: PASSED.** The project owner confirmed that the focused integrity module and complete backend test suite passed after pulling the implementation. Exact test counts were not provided and are not inferred.

Implementation commit: `93e6374`.


## Response transaction rollback on checkpoint-intent preparation failure — PASSED (owner-confirmed 2026-11-09)

Two repository-level failure-injection tests now verify that failure while preparing the signed checkpoint intent rolls back the surrounding response lifecycle transaction:

- `test_decision_rolls_back_when_checkpoint_intent_preparation_fails` — a failed intent preparation during approval must leave the response pending, preserve the original audit events, and retain the original chain head.
- `test_simulation_rolls_back_when_checkpoint_intent_preparation_fails` — a failed intent preparation during simulation must leave the response approved and un-simulated, preserve the original audit events, and retain the original chain head.

These tests inject a local exception before transaction commit. They do not contact external services and do not execute firewall, operating-system, or network actions.

Run the focused integrity tests:

```bash
./.venv/bin/python -m pytest tests/test_response_audit_integrity.py -v
```

Then run the complete backend suite:

```bash
./.venv/bin/python -m pytest -q
```

**Verification state: PASSED.** The project owner confirmed that both the focused response audit-integrity module and the complete backend test suite passed after pulling the implementation. Exact test counts were not provided and are not inferred.

Implementation commit: `796ef5f`.


## Response transaction rollback on database state-update failure — PASSED (owner-confirmed 2026-11-09)

Two SQLite-trigger failure-injection tests verify that a database-level rejection of the response state update leaves no partial lifecycle change:

- `test_decision_rolls_back_when_database_state_update_fails` — a rejected approval update must leave the response pending, preserve the audit events, and retain the original chain head.
- `test_simulation_rolls_back_when_database_state_update_fails` — a rejected simulation update must leave the response approved and un-simulated, preserve the audit events, and retain the original chain head.

The tests use temporary SQLite triggers in the isolated test database. They do not alter the user's working database or execute real response actions.

Run the focused integrity tests:

```bash
./.venv/bin/python -m pytest tests/test_response_audit_integrity.py -v
```

Then run the complete backend suite:

```bash
./.venv/bin/python -m pytest -q
```

**Verification state: PASSED.** The project owner confirmed that both the focused response audit-integrity module and the complete backend test suite passed after pulling the implementation. Exact test counts were not provided and are not inferred.

Implementation commit: `6335db2`.

