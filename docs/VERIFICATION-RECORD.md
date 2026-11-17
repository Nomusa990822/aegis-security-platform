# AEGIS Verification Record

**Evidence checkpoint:** 11 November 2026  
**Repository:** `Nomusa990822/aegis-security-platform`  
**Release context:** `v0.4.0` pre-release  
**Classification:** Portfolio-grade engineering prototype; not production-ready.

This record consolidates evidence observed during the 10–11 November 2026 engineering sessions. It distinguishes automated test results, runtime observations, synthetic demonstrations, and outstanding work. Each result applies only to the specific check performed.

## 1. Automated test and CI evidence

| Check | Recorded result | Interpretation |
|---|---:|---|
| Complete backend pytest suite | **715 passed** | Full suite passed at the recorded checkpoint |
| Response-focused tests | **45 passed** | Subset of the full suite |
| Audit-focused tests | **167 passed** | Subset of the full suite |
| `pip check` | No broken requirements | Installed dependency metadata was consistent |
| Trivy HIGH/CRITICAL fixable vulnerability gate | Passed | Subject to the checked-in `.trivyignore` exception |
| Gitleaks full-history workflow | Passed | Recorded workflow completed successfully |
| OWASP ZAP API baseline | Passed | Safe/passive baseline against an isolated CI instance, not an active penetration test |
| CodeQL Python and JavaScript/TypeScript | Passed | Static-analysis workflows completed successfully |

The focused test counts are subsets of the 715-test full suite; do not add them to the full-suite count. These checks should not be repeated merely to reproduce this record. Rerun only after a relevant source change or when investigating a specific regression.

Recorded successful GitHub Actions runs:

| Workflow | Run ID |
|---|---:|
| Backend regression tests | `42920027729` |
| Container security and SBOM | `42920027765` |
| API security baseline | `42920027781` |
| Secret scanning | `42920027677` |
| CodeQL | `42920027792` |

The container workflow generated and uploaded a CycloneDX SBOM artifact. The `v0.4.0` pre-release was published on 10 November 2026. Workflow success applies to those specific runs; it is not an independent security assessment.

## 2. Container and deployment observations

The running Docker Compose service was observed healthy. Inspection of the application container confirmed:

- The process runs as the dedicated non-root `aegis` user.
- The container root filesystem is read-only.
- Linux capabilities are dropped.
- `no-new-privileges` is enabled.
- `/tmp` is provided as temporary storage.
- Application data is mounted at `/data` using a named Docker volume.

These are observations of the inspected container configuration. They do not independently secure the host, Docker daemon, network, or persistent volume.

## 3. SQLite and persistence

A read-only database integrity check returned:

- SQLite integrity: `ok`
- Foreign-key violations: `[]`

The database and audit-checkpoint directory were present in the persistent `/data` volume. The inspected checkpoint and lock-file permissions were restrictive.

**A persistent Docker volume is not an independent backup.** A separate backup procedure and a successful restore test have not yet been demonstrated.

## 4. Selected API authentication and authorization observations

| Request context | Observed result | What it establishes |
|---|---:|---|
| No token on protected investigation read | HTTP 401 | Authentication is required |
| Analyst token on investigation read | HTTP 200 | Analyst can read the investigation |
| Approver token on investigation read | HTTP 200 | Approver can read the investigation |
| Analyst attempts approval | HTTP 403 | Analyst cannot approve |
| Approver attempts simulation | HTTP 403 | Approver cannot invoke the analyst-only simulation route |
| No token on audit-integrity read | HTTP 401 | Authentication is required |
| Analyst on audit-integrity read | HTTP 403 | Audit-integrity inspection is approver-restricted |
| Approver on audit-integrity read | HTTP 200 | Approver can inspect audit integrity |
| Analyst note request for nonexistent alert | HTTP 404 | Authenticated request reached resource lookup |
| Approver attempts analyst-only note operation | HTTP 403 | Role restriction is enforced |

This is a selected endpoint/role sample, not a complete route-by-route authorization matrix. The full matrix remains outstanding.

## 5. Response audit-integrity observation

Response record `1` was inspected through the approver-protected audit-integrity endpoint:

| Field | Observed value |
|---|---|
| Response status | `rejected` |
| Overall valid | `true` |
| Hash chain valid | `true` |
| Signed checkpoint valid | `true` |
| Audit event count | `1` |
| Integrity errors | `[]` |

The response was a policy-rejected `block_ip` dry-run request involving `198.51.100.42`, a reserved documentation TEST-NET address. It was ineligible for simulation under the globally-routable-unicast policy.

**No response action was executed:** `simulated=false` and `executed=false`. This confirms integrity verification for the rejected request; it does not demonstrate a successful approval-and-simulation lifecycle or real containment.

## 6. Synthetic event-to-alert-to-investigation demonstration

A live, read-only API inspection was completed on 11 November 2026:

1. `GET /api/v1/events?limit=5` returned five synthetic authentication-failure events (IDs 1–5).
2. The events used source `aegis-demo`, username `demo_admin`, and source IP `198.51.100.42`.
3. `GET /api/v1/alerts?limit=5` returned one high-severity alert:
   - Alert ID: `1`
   - Rule: `AEGIS-AUTH-001`
   - Description: five failed authentication attempts within five minutes
   - MITRE parent: `T1110` — Brute Force
   - Status at inspection: `investigating`
4. `GET /api/v1/alerts/1/investigation` confirmed five linked evidence records, MITRE technique `T1110.001` (Password Guessing), Credential Access tactic `TA0006`, an analyst investigation note, and an investigation timeline.
5. The timeline showed open-to-investigating, evidence links and a note being added, followed by a later resolved-to-investigating transition. The current status remained `investigating`.

The source IP `198.51.100.42` is reserved for documentation (TEST-NET). These records are synthetic demonstration data, not evidence of a real attack, malicious traffic, or production monitoring. This demonstration verifies that the inspected event, alert, evidence, MITRE-context, note, and timeline records were retrievable and linked. It does not measure detection effectiveness.

## 7. Outstanding verification and operational work

The following items remain open and must not be described as completed:

- **Independent backup and restore:** define a backup procedure for the SQLite database and audit checkpoints, protect backup copies and signing keys separately, and perform a restore test.
- **Complete authorization matrix:** verify route-specific permissions systematically across analyst, approver, and unauthenticated contexts.
- **Response lifecycle demonstration:** the recorded response was rejected by policy. A successful approved dry-run lifecycle has not been established by this evidence checkpoint. Real containment is not implemented.
- **Codespaces port visibility:** browser-visible access to the forwarded application port was not independently confirmed in the recorded checks.
- **Remote-device access:** safe access from a separate device/network was not confirmed.
- **Detection effectiveness:** no labelled, representative real-world dataset or independent evaluation has established production detection performance.
- **Independent security assessment:** no independent penetration test is recorded.

## 8. Verification discipline

- Preserve this as a dated snapshot; update it only when new evidence is obtained.
- Do not rerun checks solely to make the record look current.
- When a source change affects a verified behaviour, run the narrow relevant regression first and the full suite when justified.
- Keep synthetic demonstrations clearly distinguished from real-world operational evidence.
- Do not claim production readiness, real containment, independent backup/restore, full route authorization coverage, or real-world detection efficacy without new supporting evidence.

---

**Last consolidated:** 11 November 2026  
**Status:** Partial verification evidence recorded; operational and assurance gaps remain.
