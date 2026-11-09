<div align="center">

# AEGIS Security Platform
### Autonomous Threat Detection • Intelligence • Controlled Response

---

<!-- =========================
     CORE STATUS
========================= -->
<p>
<img src="https://img.shields.io/badge/Status-Active%20Development-020617?style=for-the-badge&logo=github&logoColor=8ef1e5" />
<img src="https://img.shields.io/badge/Build-Automated%20Tests-020617?style=for-the-badge&logo=githubactions&logoColor=8ef1e5" />
<img src="https://img.shields.io/badge/Architecture-Modular-020617?style=for-the-badge&logo=databricks&logoColor=8ef1e5" />
<img src="https://img.shields.io/badge/Domain-Cybersecurity-020617?style=for-the-badge&logo=shield&logoColor=8ef1e5" />
</p>

<!-- =========================
     TECH STACK
========================= -->
<p>
<img src="https://img.shields.io/badge/Python-3.14-0f172a?style=for-the-badge&logo=python&logoColor=7c9cff" />
<img src="https://img.shields.io/badge/FastAPI-Backend-0f172a?style=for-the-badge&logo=fastapi&logoColor=7c9cff" />
<img src="https://img.shields.io/badge/Pydantic-Validation-0f172a?style=for-the-badge&logo=pydantic&logoColor=7c9cff" />
<img src="https://img.shields.io/badge/SQLite-Database-0f172a?style=for-the-badge&logo=sqlite&logoColor=7c9cff" />
<img src="https://img.shields.io/badge/JavaScript-Dashboard-0f172a?style=for-the-badge&logo=javascript&logoColor=7c9cff" />
<img src="https://img.shields.io/badge/HTML5-Interface-0f172a?style=for-the-badge&logo=html5&logoColor=7c9cff" />
<img src="https://img.shields.io/badge/CSS3-Styling-0f172a?style=for-the-badge&logo=css3&logoColor=7c9cff" />
<img src="https://img.shields.io/badge/Pytest-Regression%20Testing-0f172a?style=for-the-badge&logo=pytest&logoColor=7c9cff" />
</p>

<p>
<img src="https://img.shields.io/badge/Threat%20Intelligence-IP%20Enrichment-1e293b?style=for-the-badge&logo=virustotal&logoColor=8ef1e5" />
<img src="https://img.shields.io/badge/MITRE%20ATT%26CK-Technique%20Mapping-1e293b?style=for-the-badge&logo=target&logoColor=7c9cff" />
<img src="https://img.shields.io/badge/Audit%20Security-Signed%20Checkpoints-1e293b?style=for-the-badge&logo=letsencrypt&logoColor=8ef1e5" />
</p>

<!-- =========================
     GITHUB META
========================= -->
<p>
<img src="https://img.shields.io/github/stars/Nomusa990822/aegis-security-platform?style=for-the-badge&color=020617" />
<img src="https://img.shields.io/github/forks/Nomusa990822/aegis-security-platform?style=for-the-badge&color=020617" />
<img src="https://img.shields.io/github/issues/Nomusa990822/aegis-security-platform?style=for-the-badge&color=020617" />
<img src="https://img.shields.io/github/last-commit/Nomusa990822/aegis-security-platform?style=for-the-badge&color=020617" />
<img src="https://img.shields.io/github/repo-size/Nomusa990822/aegis-security-platform?style=for-the-badge&color=020617" />
</p>

---

**Engineered for visibility. Built for investigation. Designed for controlled response.**

*From raw security telemetry to actionable, auditable security decisions.*

</div>

---

## Overview

AEGIS is a **modular, API-driven security operations platform** built to demonstrate core workflows found in modern security monitoring and incident response systems.

It brings together event ingestion, detection engineering, alert investigation, threat-intelligence enrichment, MITRE ATT&CK context, and a controlled response workflow backed by tamper-evident audit evidence.

AEGIS is designed as a hands-on cybersecurity engineering project: the emphasis is not only on identifying suspicious activity, but also on preserving the reasoning, decisions, and evidence behind an investigation.

> **Project classification:** Portfolio-grade engineering prototype. AEGIS is not a production SIEM, EDR, XDR, identity provider, or managed security service. Response execution is simulated; no real firewall or host-level changes are made.

---

## Core Capabilities

### 1. Security Telemetry Ingestion

A structured API entry point for security events, with a lightweight log adapter.

- Authenticated event submission
- Strict request validation and normalisation
- External event identity and duplicate handling
- Linux OpenSSH authentication-log parsing
- Nginx combined access-log parsing
- Deterministic per-file-line event identities for safe replay
- Dry-run parsing before submission
- Request-body size enforcement and transaction-safe persistence

### 2. Detection Engineering

A modular detection engine evaluates incoming telemetry against registered rules.

| Rule ID | Detection capability |
|---|---|
| `AEGIS-AUTH-001` | Brute-force authentication |
| `AEGIS-AUTH-002` | Password spraying |
| `AEGIS-AUTH-003` | Distributed password guessing across source IPs |
| `AEGIS-AUTH-004` | Successful authentication after repeated failures |
| `AEGIS-AUTH-005` | Successful authentication to one account from multiple source IPs |
| `AEGIS-NET-001` | Network port scanning |
| `AEGIS-NET-002` | Horizontal network scanning |
| `AEGIS-NET-003` | Broad network service discovery |
| `AEGIS-NET-004` | Suspicious network beaconing |
| `AEGIS-NET-005` | Remote-service connection fan-out across common administration ports |

Detection logic includes threshold and time-window handling, with adversarial and regression tests for boundary conditions, duplicate telemetry, noisy activity, and overlapping patterns.

### 3. Alert Management & Investigation

Detections can become actionable investigation records.

- Alert lifecycle and status management
- Analyst notes and evidence linking
- Investigation timelines
- Related-event context
- Audit history
- Correlation of related alerts into cases

### 4. Threat Intelligence & Risk Assessment

AEGIS enriches supported public IP assessments using its threat-intelligence provider integration.

- External IP reputation enrichment
- Provider failure isolation and timeout handling
- Persisted enrichment assessments
- Risk scoring and confidence context
- Intelligence context available to investigations

Provider results depend on external service availability, configuration, and API limits.

### 5. MITRE ATT&CK Context

Detection rules are associated with a curated MITRE ATT&CK catalogue.

Current catalogue: **10 technique and sub-technique entries**, including:

- T1110 — Brute Force
- T1110.001 — Password Guessing
- T1110.003 — Password Spraying
- T1078 — Valid Accounts
- T1021 — Remote Services
- T1046 — Network Service Discovery
- T1071 — Application Layer Protocol
- T1071.001 — Web Protocols
- T1595 — Active Scanning
- T1595.001 — Scanning IP Blocks

This is a deliberately limited subset, not full ATT&CK coverage. Technique associations provide analytical context; they do not independently prove that a technique occurred.

### 6. Controlled Response Workflow

A guarded response lifecycle designed around policy and accountability.

- Response previews and policy checks
- Analyst / approver role separation
- Approval and rejection decisions
- Dry-run response simulation
- Tamper-evident response audit events
- Signed audit checkpoints and integrity verification
- Checkpoint quarantine and recovery safeguards

The `BLOCK_IP` action is a workflow capability only. AEGIS does not apply real firewall rules or execute operating-system containment commands.

### 7. API Security & Access Control

- Bearer-token authentication
- Analyst and approver role boundaries
- Strict API request schemas
- Constant-time token comparison
- Request-body limits
- API rate limiting
- Health checks and database availability reporting

Authentication currently uses environment-configured static role tokens. MFA, OTP, SSO, and full user lifecycle management are not implemented.

### 8. Analyst Dashboard

A browser-based interface for interacting with AEGIS through its authenticated API.

- Served from the backend at `/dashboard`
- Analyst authentication
- Security operations and investigation workflows
- API-backed data rather than hardcoded actor identities

---

## System Architecture

AEGIS is organised as a modular security workflow:

```text
       Security Event Sources
                 |
                 v
       Authenticated Ingestion API
                 |
                 v
     Validation / Normalisation
                 |
                 v
       Detection & Correlation
                 |
          +------+------+
          |             |
          v             v
     Threat Intel    Detection
      Enrichment      Findings
          |             |
          +------+------+
                 |
                 v
        Alerts & Investigations
                 |
                 v
       Response Policy & Approval
                 |
                 v
         Dry-Run Simulation
                 |
                 v
       Signed, Verifiable Audit
                 |
                 v
          SQLite Persistence

        Analyst Dashboard
                 |
          Authenticated API
                 |
               AEGIS
```

### Engineering Principles

1. **Evidence before action** — response workflows are gated by policy and approval.
2. **Integrity is part of the workflow** — audit evidence is verified before sensitive response operations.
3. **Failure must be contained** — provider failures and database errors should not silently become successful outcomes.
4. **Security controls need regression tests** — concurrency, malformed input, tampering, and authorisation boundaries are tested.
5. **Be explicit about limitations** — prototype capabilities are not presented as production guarantees.

---

## Quality & Verification

The backend includes regression coverage for:

- Authentication and role-based authorisation
- Strict input validation and request-size limits
- API rate limiting
- Duplicate event handling and ingestion atomicity
- Detection thresholds and adversarial cases
- Threat-intelligence enrichment failures
- Concurrent database and response operations
- Audit-chain and signed-checkpoint integrity
- Checkpoint recovery and quarantine behaviour
- End-to-end API workflows

The complete backend test suite can be run locally with:

```bash
cd backend
python -m pytest -q
```

Automated regression tests are configured through GitHub Actions:

[Backend Tests Workflow](https://github.com/Nomusa990822/aegis-security-platform/actions/workflows/backend-tests.yml)

A passing test suite demonstrates the tested behaviours; it is not a substitute for an independent penetration test, formal security audit, or real-world detection evaluation.

---

## Technical Documentation

| Resource | Description |
|---|---|
| `README.md` | Project overview, setup, capabilities, and limitations |
| `TESTING_STATUS.md` | Regression test batches and verification status |
| `docs/security/AUDIT_CHECKPOINT_KEY_ROTATION.md` | Audit checkpoint signing-key rotation guidance |
| `backend/app/telemetry/cli.py` | Linux SSH and Nginx log import command |

---

## Run AEGIS Locally

### Requirements

- Python 3.14
- Git

### 1. Clone the repository

```bash
git clone https://github.com/Nomusa990822/aegis-security-platform.git
cd aegis-security-platform/backend
```

### 2. Create the environment

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

On Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

### 3. Configure credentials

AEGIS requires separate analyst and approver tokens, plus a signing key for response audit checkpoints. Generate unique secrets locally:

```bash
export AEGIS_ANALYST_TOKEN="$(openssl rand -hex 32)"
export AEGIS_APPROVER_TOKEN="$(openssl rand -hex 32)"
export AEGIS_ANALYST_ID="analyst-local"
export AEGIS_APPROVER_ID="approver-local"

export AEGIS_AUDIT_CHECKPOINT_KEY="$(openssl rand -hex 32)"
export AEGIS_AUDIT_CHECKPOINT_KEY_ID="local-v1"
export AEGIS_AUDIT_CHECKPOINT_DIR="$PWD/audit_checkpoints"
```

Keep these values private and out of source control. Preserve the signing key and key ID when you need to verify checkpoints from an earlier run.

Optional threat-intelligence provider configuration:

```bash
export ABUSEIPDB_API_KEY="your-provider-api-key"
```

### 4. Start the application

From the `backend/` directory:

```bash
uvicorn app.main:app --reload
```

### 5. Import representative security logs

From the `backend/` directory, configure an analyst token and preview a log before ingestion:

```bash
read -rsp "AEGIS analyst token: " AEGIS_ANALYST_TOKEN
export AEGIS_ANALYST_TOKEN
printf '\\n'

python -m app.telemetry.cli /path/to/auth.log --format sshd --dry-run
python -m app.telemetry.cli /var/log/nginx/access.log --format nginx --dry-run
```

Submit parsed events through the existing authenticated API:

```bash
python -m app.telemetry.cli /path/to/auth.log --format sshd --year 2026
python -m app.telemetry.cli /var/log/nginx/access.log --format nginx
```

The importer uses the existing API URL by default (`http://127.0.0.1:8000/api/v1/events`). Override it with `AEGIS_API_URL` or `--api-url`. Supply `AEGIS_ANALYST_TOKEN` in the environment; never place tokens in command-line arguments or source control. The importer reports unsupported lines as ignored. SSH syslog timestamps have no year or timezone, so the adapter assumes UTC and the current year unless `--year` is supplied.

| Service | Local URL |
|---|---|
| Analyst Dashboard | http://127.0.0.1:8000/dashboard |
| API Health | http://127.0.0.1:8000/api/v1/health |
| Interactive API Docs | http://127.0.0.1:8000/docs |

The local SQLite database is created under `backend/aegis.db`.

---

## Docker Compose Demo Deployment

The repository includes a single-container Docker Compose deployment for a reproducible local demonstration. It persists the SQLite database and signed response-audit checkpoints in a named Docker volume.

### Requirements

- Docker Engine
- Docker Compose v2

### 1. Create local credentials

From the repository root, generate a private environment file once:

```bash
cat > .env <<EOF
AEGIS_ANALYST_TOKEN=$(openssl rand -hex 32)
AEGIS_APPROVER_TOKEN=$(openssl rand -hex 32)
AEGIS_ANALYST_ID=analyst-local
AEGIS_APPROVER_ID=approver-local
AEGIS_AUDIT_CHECKPOINT_KEY=$(openssl rand -hex 32)
AEGIS_AUDIT_CHECKPOINT_KEY_ID=local-v1
AEGIS_AUDIT_CHECKPOINT_DIR=/data/audit_checkpoints
AEGIS_DATABASE_PATH=/data/aegis.db
EOF
```

Keep `.env` private. Preserve it between restarts: changing the checkpoint signing key can prevent verification of checkpoints signed with the previous key. Do not commit the file or paste its contents into issue trackers.

### 2. Build and start AEGIS

```bash
docker compose up --build -d
docker compose ps
```

### 3. Open the services

| Service | URL |
|---|---|
| Analyst Dashboard | http://localhost:8000/dashboard |
| API Health | http://localhost:8000/api/v1/health |
| Interactive API Docs | http://localhost:8000/docs |

Use the analyst token from your local `.env` file when the dashboard requests authentication. Keep the approver token separate for approval-only operations.

### 4. Stop and restart

```bash
docker compose down
docker compose up -d
```

The named `aegis-data` volume survives `docker compose down`. **Do not use `docker compose down -v`** unless you intentionally want to delete the persisted database and audit checkpoints. Back up the volume and retain the matching signing credentials.

This Compose configuration is for a local, single-container demonstration. It does not make SQLite or the process-local rate limiter suitable for multi-worker or public production deployment. Do not expose the service directly to the public internet.

---

## Security Scope & Current Limitations

AEGIS focuses on a defined set of security operations workflows. It does not attempt to claim complete enterprise security coverage.

| Area | Current position |
|---|---|
| Authentication | Static environment-configured analyst and approver tokens |
| MFA / OTP | Not implemented |
| SSO / OAuth / OIDC / SAML | Not implemented |
| Detection | Ten registered rules |
| MITRE ATT&CK | Curated ten-entry subset |
| Telemetry collection | API-based event submission; no endpoint agent |
| Packet inspection | Not implemented |
| Syslog / Sysmon collectors | Not implemented |
| Threat intelligence | Configurable external provider integration |
| Response | Approval workflow and simulation only |
| Rate limiting | Process-local; not shared across multiple workers |
| Database | SQLite for local and single-process use |
| Malware sandbox / EDR | Not implemented |

### Deployment Considerations

SQLite is suitable for local development and a single-process demonstration. A multi-worker or production deployment would require a shared database such as PostgreSQL, shared rate limiting, managed secrets, hardened identity/session handling, backups, monitoring, and a reviewed deployment architecture.

Do not expose the development server directly to the public internet.

---

## Next Engineering Milestones

The core detection, investigation, threat-intelligence, MITRE-context, controlled-response, and Linux SSH/Nginx telemetry-adapter workflows are implemented and covered by the current regression suite. Remaining work should focus on making the prototype easier to demonstrate and operate:

1. Improve the dashboard's visibility into detection evidence, MITRE mappings, and any unmapped detection rules.
2. Prepare a reproducible demonstration deployment with persistent storage, managed secrets, backups, and explicit single-process constraints.
3. Evaluate PostgreSQL and shared rate limiting only when moving beyond the local, single-process prototype.

MFA and stronger identity management remain a separate security milestone. Large endpoint agents, malware sandboxes, full ATT&CK ingestion, unsupported machine-learning claims, and real automated containment remain outside the current low-cost prototype scope.

---

## What AEGIS Demonstrates

- Security event pipeline design
- Detection engineering and adversarial testing
- API authentication and authorisation
- Threat-intelligence enrichment
- Incident investigation workflows
- MITRE ATT&CK contextual mapping
- Controlled response and approval design
- Audit integrity, signed checkpoints, and recovery
- Concurrency and database reliability engineering
- Automated backend regression testing

---

<div align="center">

**AEGIS — Autonomous Threat Detection and Response Platform**

*Observe. Detect. Investigate. Verify.*

</div>
