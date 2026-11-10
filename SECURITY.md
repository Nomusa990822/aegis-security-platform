# Security Policy

<p>
  <img
    alt="Project status: educational prototype"
    src="https://img.shields.io/badge/Status-Educational%20Prototype-0f172a?style=for-the-badge&logo=github&logoColor=8ef1e5"
  />
  <img
    alt="Security support: best effort"
    src="https://img.shields.io/badge/Security%20Support-Best%20Effort-0f172a?style=for-the-badge&logo=letsencrypt&logoColor=8ef1e5"
  />
  <a href="https://github.com/Nomusa990822/aegis-security-platform/actions/workflows/backend-tests.yml">
    <img
      alt="Backend tests"
      src="https://github.com/Nomusa990822/aegis-security-platform/actions/workflows/backend-tests.yml/badge.svg?branch=main"
    />
  </a>
</p>
**Quick links:** [Report a vulnerability](#reporting-a-vulnerability) · [Supported versions](#supported-versions) · [Security controls](#implemented-security-controls) · [Deployment guidance](#deployment-and-configuration) · [Known limitations](#known-limitations)

---

## Contents

- [Project Status](#project-status)
- [Supported Versions](#supported-versions)
- [Reporting a Vulnerability](#reporting-a-vulnerability)
- [Implemented Security Controls](#implemented-security-controls)
- [Deployment and Configuration](#deployment-and-configuration)
- [Known Limitations](#known-limitations)
- [Security Testing](#security-testing)
- [Responsible Use](#responsible-use)

---

## Project Status

AEGIS Security Platform is an educational and portfolio-grade cybersecurity engineering prototype. It demonstrates security monitoring, threat detection, investigation, threat-intelligence enrichment, audit integrity, and controlled response workflows.

> [!IMPORTANT]
> AEGIS is **not a production-hardened SIEM, EDR, or XDR platform**. It has not been represented as independently penetration-tested, security-certified, or suitable for deployment in environments requiring production-grade security guarantees.
>
> Do not rely on AEGIS as the sole security control protecting systems, networks, or sensitive information.

---

## Supported Versions

Security fixes are intended for the latest version on the repository's `main` branch. No formal long-term support or release-maintenance guarantees are currently provided.

| Version | Security support |
|---|---|
| Latest `main` | Best-effort security fixes |
| Older commits | Not actively maintained |
| Unreleased development versions | No support guarantee |

---

## Reporting a Vulnerability

> [!CAUTION]
> Please **do not** disclose exploitable vulnerabilities, credentials, tokens, personal information, or sensitive proof-of-concept material in public GitHub issues.

### How to report

Use GitHub's **Private vulnerability reporting** feature to submit
security vulnerabilities confidentially.

**[Submit a private vulnerability report](https://github.com/Nomusa990822/aegis-security-platform/security/advisories/new)**

If private vulnerability reporting is unavailable, contact the
repository maintainer through a private GitHub communication channel.

Do not submit vulnerability details through public issues, pull
requests, discussions, or other public channels.

### What a useful report includes

- A concise description of the vulnerability
- The affected component, endpoint, or file
- The conditions required to reproduce the issue
- The potential security impact
- Relevant logs or a minimal proof of concept, with secrets and
  personal information removed
- Any suggested mitigation, if known

### Acknowledgement and remediation

Reports will be reviewed on a best-effort basis.

Where appropriate, the maintainer will investigate the report,
assess its impact, and work towards a corrective change.

There is currently no guaranteed acknowledgement, response,
or remediation timeframe.

Security researchers are encouraged to coordinate disclosure
with the maintainer before publicly disclosing an unresolved
vulnerability.

### What a useful report includes

- A concise description of the vulnerability
- The affected component, endpoint, or file
- The conditions required to reproduce the issue
- The potential security impact
- Relevant logs or a minimal proof of concept, with secrets and personal information removed
- Any suggested mitigation, if known

### Reporting process

```mermaid
%%{init: {
  "theme": "base",
  "themeVariables": {
    "fontFamily": "Inter, Segoe UI, Helvetica, Arial, sans-serif",
    "primaryTextColor": "#0f1b2e",
    "lineColor": "#5b6b85"
  },
  "flowchart": { "curve": "basis", "nodeSpacing": 30, "rankSpacing": 40, "htmlLabels": true }
}}%%
flowchart LR
    A(["<b>Vulnerability<br/>found</b>"]) --> B["<b>Private report</b><br/>GitHub private reporting<br/>or private maintainer contact"]
    B --> C["<b>Investigation</b>"]
    C --> D["<b>Remediation</b><br/>best effort"]
    D --> E(["<b>Public disclosure</b><br/>after reasonable time"])
    A -. "never" .-> X["<b>Public GitHub issue</b>"]

    classDef start  fill:#0f1b2e,stroke:#0f1b2e,color:#ffffff;
    classDef step   fill:#eaf3ff,stroke:#1e8cff,stroke-width:1.5px,color:#0f1b2e;
    classDef final  fill:#e6fbff,stroke:#17a8d4,stroke-width:2px,color:#0f1b2e;
    classDef avoid  fill:#fee2e2,stroke:#dc2626,stroke-width:1.5px,color:#0f1b2e;
    class A start;
    class B,C,D step;
    class E final;
    class X avoid;
    linkStyle default stroke:#5b6b85,stroke-width:1.6px
```

Please allow reasonable time for investigation and remediation before publicly disclosing an unresolved vulnerability.

> [!NOTE]
> There is currently no guaranteed response or remediation service-level agreement.

---

## Implemented Security Controls

The security controls documented below are implemented in the
application codebase. The following source files provide direct
implementation references.

| Security area | Implementation |
|---|---|
| Authentication and authorization | [`backend/app/auth.py`](backend/app/auth.py) |
| Request-size validation | [`backend/app/request_limits.py`](backend/app/request_limits.py) |
| API rate limiting | [`backend/app/rate_limiting.py`](backend/app/rate_limiting.py) |
| Audit-chain storage | [`backend/app/response/audit_chain_storage.py`](backend/app/response/audit_chain_storage.py) |
| Audit checkpoint integrity | [`backend/app/response/audit_checkpoint.py`](backend/app/response/audit_checkpoint.py) |
| Response audit validation | [`backend/app/response/audit.py`](backend/app/response/audit.py) |
| Response authorization policy | [`backend/app/response/policy.py`](backend/app/response/policy.py) |

### Authentication and authorization

| Control | Detail |
|---|---|
| **Bearer-token authentication** | API authentication uses HTTP Bearer tokens |
| **Separate credentials** | Analyst and approver credentials are configured separately |
| **Minimum token length** | Both credentials must be at least 32 characters long |
| **Distinct tokens** | The application rejects identical analyst and approver tokens |
| **Distinct identities** | Analyst and approver identities must also be distinct |
| **Constant-time comparison** | Credential comparisons use `hmac.compare_digest` |
| **Role enforcement** | Role-specific dependencies restrict analyst and approver operations |

These mechanisms provide application-level role separation. They do not replace a full identity-management platform.

### Request protection

| Control | Detail |
|---|---|
| **Request-size validation** | Implemented through request middleware |
| **API rate limiting** | Implemented for event ingestion |
| **Rate-limit identity** | Ingestion limits use both bearer-token fingerprints and client IP addresses |
| **Token fingerprinting** | Fingerprints are generated with SHA-256, so raw bearer tokens are not retained as rate-limit identities |

> [!NOTE]
> Rate limiting and client IP identification depend on the deployment environment. Reverse proxies and forwarded client addresses must be configured and trusted carefully.

### Audit integrity

The response audit subsystem includes:

- Cryptographically linked audit events
- Audit-chain consistency verification
- HMAC-signed audit checkpoints
- Checkpoint key identifiers and support for previous signing keys
- Checkpoint validation and recovery safeguards

These mechanisms help detect certain forms of audit-record alteration and inconsistency. They do **not** guarantee tamper-proof storage. An attacker with sufficient control over the application, database, checkpoint files, and signing keys may be able to compromise the integrity evidence.

For stronger assurance, signing keys and checkpoint copies should be protected independently from the application host.

### Controlled response

The response workflow implements:

```mermaid
%%{init: {
  "theme": "base",
  "themeVariables": {
    "fontFamily": "Inter, Segoe UI, Helvetica, Arial, sans-serif",
    "primaryTextColor": "#0f1b2e",
    "lineColor": "#5b6b85"
  },
  "flowchart": { "curve": "basis", "nodeSpacing": 30, "rankSpacing": 40, "htmlLabels": true }
}}%%
flowchart LR
    A["<b>Analyst-initiated<br/>response request</b>"] --> B["<b>Lifecycle<br/>validation</b>"]
    B --> C{"<b>Separate approver<br/>authorization</b>"}
    C -->|"Approve"| D["<b>Approval record</b>"]
    C -->|"Reject"| E["<b>Rejection record</b>"]
    D --> F["<b>Explicit dry-run<br/>simulation</b>"]
    F --> G(["<b>No real containment<br/>executed</b>"])

    classDef step  fill:#eaf3ff,stroke:#1e8cff,stroke-width:1.5px,color:#0f1b2e;
    classDef gate  fill:#e6fbff,stroke:#17a8d4,stroke-width:2px,color:#0f1b2e;
    classDef rec   fill:#f1f5f9,stroke:#475569,stroke-width:1.5px,color:#0f1b2e;
    classDef final fill:#0f1b2e,stroke:#0f1b2e,color:#ffffff;
    class A,B,F step;
    class C gate;
    class D,E rec;
    class G final;
    linkStyle default stroke:#5b6b85,stroke-width:1.6px
```

- Analyst-initiated response requests
- Separate approver authorization
- Approval and rejection records
- Response lifecycle validation
- Explicit dry-run simulation

> [!WARNING]
> **AEGIS does not execute real endpoint containment or operating-system response commands.** Its response workflow is a controlled simulation, not an automated containment system.

---

## Deployment and Configuration

### Secrets

Create a local `.env` file using `.env.example` as the template. Before running the application:

- [ ] Replace all placeholder credentials with unique, randomly generated secrets
- [ ] Use separate analyst and approver tokens
- [ ] Configure a strong audit checkpoint signing key
- [ ] Keep `.env` private and outside version control
- [ ] Never publish tokens, signing keys, API keys, or database credentials
- [ ] Rotate credentials if they are exposed or suspected to be compromised

The example configuration is not intended to provide production secrets.

### Docker deployment

The supplied Docker configuration includes several container-hardening measures:

| Measure | Purpose |
|---|---|
| Dedicated non-root application user | Avoids running the application as root |
| Read-only container root filesystem | Limits writes inside the container |
| Temporary filesystem for `/tmp` | Provides scratch space without a writable root |
| Dropped Linux capabilities | Removes unneeded kernel privileges |
| `no-new-privileges` | Prevents privilege escalation inside the container |
| Persistent storage | Keeps application data and audit checkpoints |
| Container health check | Reports service health |

These measures reduce certain container risks but do not independently secure the host, Docker daemon, network, persistent volumes, or deployment environment.

> [!CAUTION]
> The Compose configuration publishes the application on port `8000`. Restrict network access appropriately. Do not expose an unauthenticated or unprotected development deployment to the public internet.

### Data protection

The application uses SQLite and persistent storage for its database and audit checkpoints. Operators are responsible for:

- Protecting database and checkpoint files
- Restricting filesystem permissions
- Maintaining secure backups
- Protecting backup copies and signing keys
- Testing recovery procedures
- Avoiding the inclusion of sensitive information in demonstration data

Do not use real production credentials or sensitive operational data in demonstrations.

---

## Known Limitations

AEGIS is an evolving cybersecurity engineering prototype.
The following limitations should be considered when evaluating
or deploying the platform.

| Area | Current limitation |
|---|---|
| Identity management | Authentication relies on configured Bearer tokens rather than a dedicated identity-management platform. |
| Multi-factor authentication | MFA and enterprise identity federation are not currently implemented. |
| Human identity assurance | Separate application roles do not independently verify the identities of the people using shared credentials. |
| Database architecture | SQLite is used instead of a distributed database architecture. |
| Audit storage | Audit checkpoints are stored locally and are not independently administered by an external security authority. |
| Audit integrity | Cryptographic verification cannot protect against every compromise of the application host, database, or signing keys. |
| Rate limiting | Rate-limit effectiveness depends partly on deployment configuration, particularly client IP identification and reverse-proxy trust. |
| Response execution | Response operations are simulated. Real endpoint containment and operating-system command execution are not implemented. |
| Security assurance | Automated regression tests do not replace independent security assessments. |

These limitations define the current scope of the project and
should not be interpreted as guarantees of security.
---

## Security Testing

AEGIS includes an automated regression test suite covering
application functionality, security-related behaviour, and
critical application workflows.

### Continuous integration

The backend regression suite is executed through GitHub Actions.

**[View Backend Tests Workflow](https://github.com/Nomusa990822/aegis-security-platform/actions/workflows/backend-tests.yml)**

The workflow runs against changes submitted to the repository
and provides an automated regression check.

### Recorded test baseline

**Baseline: 10 November 2026**

| Metric | Result |
|---|---:|
| Passed | 702 |
| Failed | 0 |
| Skipped | 0 |
| Warnings | 0 |

These figures represent a recorded test execution, not a
permanent guarantee of the current test count or application
security.

### Testing limitations

Automated tests help identify regressions in implemented
behaviour. However, passing tests do not establish that the
application is free from security vulnerabilities.

The test suite is not a substitute for:

- Independent penetration testing
- Security-focused code review
- Threat modelling
- Dependency vulnerability assessments
- Deployment-specific security assessments

---

## Responsible Use

Use AEGIS only on systems, networks, and data for which you have appropriate authorization. Do not use the platform to conduct unauthorized monitoring, access, disruption, or testing.

Contributions that improve security, reliability, validation, audit integrity, and defensive capabilities are welcome.
