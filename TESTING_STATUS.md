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

## Newly added or changed checkpoint-failure tests — NOT RUN

In `tests/test_response_audit_checkpoint_integration.py`:

- `test_checkpoint_write_failure_does_not_undo_committed_response` — updated to expect HTTP 202 and verify that request creation remains committed while checkpoint status is pending.
- `test_approval_reports_committed_checkpoint_failure` — verifies approval is committed and reported as checkpoint-pending when publication fails.
- `test_simulation_reports_committed_checkpoint_failure` — verifies simulation is committed and reported as checkpoint-pending when publication fails.

These tests are authored but unverified.

## Other checks to record when the Codespace is ready

- Confirm the application imports and starts after the latest router/repository changes.
- Run the targeted audit tests before the full backend suite.
- Record the exact pytest summary, failures, skips, and errors. Do not mark a module passed if collection or setup failed.
- After any fixes, rerun the affected targeted tests and then the full backend suite.

## Historical note

Earlier checkpoint inventory/bootstrap tests passed before the latest fail-closed and checkpoint-failure-reporting changes. Those earlier results do not verify the current commits, and the full backend suite remains deferred.
