# AEGIS Security Platform

**Autonomous Threat Detection and Response Platform** — a portfolio-grade, API-driven mini-SOC built with FastAPI and SQLite.

AEGIS demonstrates how security telemetry can be ingested, normalised, evaluated against detection logic, enriched with threat intelligence, turned into alerts and investigations, and passed through a controlled response workflow with tamper-evident audit evidence.

> **Project status:** Engineering prototype / portfolio project. AEGIS is not a production SIEM, EDR, XDR, identity provider, or managed security service. Response actions are simulated; the project does not change real firewall or operating-system configuration.

## What AEGIS does

- **Security event ingestion:** authenticated API ingestion of structured security events, input validation, event identity/deduplication, and bounded request-body size.
- **Detection engineering:** six registered rule families covering brute-force authentication, password spraying, port scanning, horizontal scanning, broad service discovery, and suspicious network beaconing.
- **Alert management:** create and track detections as alerts, update investigation status, add analyst notes, attach event evidence, and review timelines/audit history.
- **Correlation:** group related alerts into investigation cases and manage case assignment, notes, status, and history.
- **Threat intelligence:** enrich public IP assessments through the configured provider integration (including AbuseIPDB when an API key is supplied), isolate provider failures, and calculate a risk assessment.
- **MITRE ATT&CK context:** a deliberately curated catalogue of eight technique/sub-technique entries, with rule associations. This is a small demonstrator subset, not comprehensive ATT&CK coverage.
- **Controlled response workflow:** policy checks, analyst/approver separation, approval decisions, dry-run response simulation, and signed audit evidence. No real blocking is performed.
- **Audit integrity:** hash-linked response audit events, signed checkpoints, key-usage inspection, checkpoint inventory/recovery tooling, and fail-closed integrity checks.
- **API protections:** bearer-token authentication, role-based access, strict request models, a 1 MiB request-body limit, and process-local rate limiting.
- **Dashboard:** browser-based analyst interface served at `/dashboard`.

## Detection rules

The current registry contains six rules:

| Rule ID | Detection |
|---|---|
| `AEGIS-AUTH-001` | Brute-force authentication |
| `AEGIS-AUTH-002` | Password spraying |
| `AEGIS-NET-001` | Network port scanning |
| `AEGIS-NET-002` | Horizontal network scanning |
| `AEGIS-NET-003` | Broad network service discovery |
| `AEGIS-NET-004` | Suspicious network beaconing |

Detection quality is evaluated with adversarial and synthetic regression tests. The current synthetic benchmark is small and does not establish real-world detection rates.

## Architecture

```text
Security telemetry source
        |
        v
FastAPI event-ingestion API
        |
        v
Validation, normalisation and deduplication
        |
        v
Detection engine and correlation
        |
        +------> Threat-intelligence enrichment
        |
        v
Alerts and investigation workflow
        |
        v
Controlled response preview / approval / simulation
        |
        v
Hash-linked audit events and signed checkpoints

Analyst dashboard <---- authenticated API ----> AEGIS backend
                                      |
                                      v
                                SQLite database
```

### Technology

- Python 3.14-compatible codebase
- FastAPI and Pydantic
- SQLite for local development and single-process demonstrations
- HTTPX for external threat-intelligence requests
- Pytest and FastAPI TestClient for automated regression tests
- HTML, CSS and JavaScript dashboard

## Run locally

### 1. Requirements

- Python 3.14 (the project is developed and tested with Python 3.14)
- Git

### 2. Clone and install

```bash
git clone https://github.com/Nomusa990822/aegis-security-platform.git
cd aegis-security-platform/backend

python -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements.txt
```

On Windows PowerShell, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

### 3. Configure credentials and audit signing

The API requires separate analyst and approver bearer tokens. Use unique, randomly generated values of at least 32 characters. The response audit subsystem also requires a checkpoint signing key of at least 32 characters and a checkpoint directory.

Example for a local Linux/macOS shell:

```bash
export AEGIS_ANALYST_TOKEN="$(openssl rand -hex 32)"
export AEGIS_APPROVER_TOKEN="$(openssl rand -hex 32)"
export AEGIS_ANALYST_ID="analyst-local"
export AEGIS_APPROVER_ID="approver-local"

export AEGIS_AUDIT_CHECKPOINT_KEY="$(openssl rand -hex 32)"
export AEGIS_AUDIT_CHECKPOINT_KEY_ID="local-v1"
export AEGIS_AUDIT_CHECKPOINT_DIR="$PWD/audit_checkpoints"
```

Keep these values private. Do not commit real tokens, signing keys, production secrets, or populated audit checkpoint files. For repeat use, store secrets in your local secret manager or shell environment rather than in source control. The example above generates new credentials each time it is run; keep the same signing key and key ID when you need to verify checkpoints created by an earlier run.

Optional threat-intelligence provider configuration:

```bash
export ABUSEIPDB_API_KEY="your-own-provider-api-key"
```

Without a provider key, the integration reports that the provider is unavailable; core ingestion and detection can still be demonstrated.

### 4. Start the API

From the `backend/` directory:

```bash
uvicorn app.main:app --reload
```

Useful local URLs:

- Dashboard: http://127.0.0.1:8000/dashboard
- API health: http://127.0.0.1:8000/api/v1/health
- OpenAPI documentation: http://127.0.0.1:8000/docs
- API root: http://127.0.0.1:8000/

The database is created at `backend/aegis.db`. It is excluded from Git.

## Demonstrate event ingestion

Use the analyst token configured in your shell:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/events \
  -H "Authorization: Bearer $AEGIS_ANALYST_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "authentication_failed",
    "source_system": "demo-auth",
    "external_event_id": "demo-auth-0001",
    "source_ip": "198.51.100.25",
    "username": "admin",
    "outcome": "failure",
    "description": "Demonstration failed authentication event"
  }'
```

Submit several distinct failed-authentication events to exercise the brute-force detection rule. Use a unique `external_event_id` for each event; replaying the same source-system/event-ID pair is treated as a duplicate.

Authenticate the dashboard using the analyst token. Approval operations require the separate approver token/role. The tokens are static environment-configured credentials for this prototype, not a full user-management system.

## Run the tests

From `backend/`:

```bash
python -m pytest -q
```

The test suite uses isolated temporary SQLite databases. It does not require a live threat-intelligence API key and does not perform real response actions.

GitHub Actions runs the backend regression suite on pushes and pull requests. See [Backend tests workflow](.github/workflows/backend-tests.yml).

## Security model and important limitations

AEGIS includes useful security engineering controls, but these should not be confused with a production identity or security operations stack.

- **Authentication:** static analyst and approver bearer tokens configured through environment variables. No user registration, password authentication, MFA/TOTP/OTP, recovery codes, SSO, OAuth/OIDC, or SAML.
- **Rate limiting:** in-process memory only. Limits are not shared between multiple workers or replicas; use a shared gateway or store for a multi-worker deployment.
- **Database:** SQLite is appropriate for a local, single-process prototype. It supports concurrent readers but only one active writer. Use PostgreSQL and revisit deployment architecture before multi-worker production use.
- **Telemetry:** events are submitted to the API. AEGIS does not currently ship endpoint agents, packet capture, Sysmon/Syslog collectors, or broad cloud/SaaS integrations.
- **Detection coverage:** six registered rules and a curated MITRE mapping are not comprehensive threat coverage. Rule associations are contextual hypotheses, not proof of adversary technique execution.
- **Response:** `BLOCK_IP` is a controlled workflow label and response simulation only. AEGIS does not install firewall rules or execute host-level containment.
- **Threat intelligence:** external provider data depends on provider availability, API limits, configuration, and the quality of the source data.
- **IP geolocation:** any future network map must be interpreted as approximate network attribution, not the physical location of a person or device.

Do not expose the development server directly to the public internet. Before any real deployment, add a production-grade identity/session system, secret management, TLS termination, trusted-proxy configuration, shared rate limiting, backups, monitoring, deployment hardening, and a security review.

## Roadmap

The current focus is on making the prototype reproducible and demonstrable:

1. Documentation and automated CI.
2. A small number of high-value detections backed by realistic, well-defined telemetry.
3. Better visibility into the existing MITRE mapping and its coverage gaps.
4. Optional lightweight telemetry adapters and notifications.
5. Production architecture changes only when there is a concrete deployment requirement.

Large EDR agents, malware sandboxes, full ATT&CK ingestion, machine-learning anomaly detection without representative data, and real automated containment are intentionally out of scope for the low-cost prototype.

## License

See [LICENSE](LICENSE).
