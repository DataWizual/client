# 🛡 Sentinel Core — Deterministic Security Gate for CI/CD

Sentinel Core is a **deterministic security enforcement engine** designed to operate as a **physical security gate** across both local development environments and CI/CD pipelines.

Unlike traditional scanners that only *report* risk, Sentinel enforces binary engineering invariants:

> **ALLOW or BLOCK — no ambiguity, no silent bypass.**

Sentinel is built for organizations that require:

- Zero telemetry
- Offline-first execution
- Immutable enforcement logic
- Centralized administrative control
- Guaranteed pipeline blocking

---

# 🚀 What Sentinel Protects

Sentinel evaluates project security posture at the artifact level:

- **Dockerfiles** → supply chain integrity (no `:latest`, unsafe bases)
- **CI/CD workflows** → SHA pinning enforcement, secret exposure prevention
- **Infrastructure as Code** → Kubernetes + Terraform posture rules
- **Secrets** → hardcoded credential detection
- **AI Advisory Layer (optional)** → remediation insights (never auto-allow)

---

# ✅ Deterministic Enforcement Model

Every Sentinel execution results in exactly one authoritative decision:

| Decision | Meaning |
|---------|---------|
| **ALLOW (0)** | No blocking violations detected |
| **BLOCK (1)** | Critical policy violation found — pipeline stops |

> WARN states only exist through explicit audited overrides.

---

# 🏢 Official Deployment Model (Admin Provisioning Only)

Sentinel Core is deployed exclusively through a **single corporate bootstrap script**:

> `start.sh`

⚠️ Developers do not install Sentinel manually.

⚠️ Tokens are never entered by engineers.

⚠️ Activation is performed only by an authorized Security Administrator.

This guarantees:

- Centralized enforcement governance
- Token secrecy
- Deterministic rollout
- Zero developer-side configuration

---

# Phase 1 — Access Provisioning (Security Administrator)

Sentinel operates under a strict **administrator-controlled credential model**.

The Security Administrator must generate the following minimal-scope secrets.

---

## Required GitHub Personal Access Tokens

### 1. `SENTINEL_INSTALL_TOKEN`
**Scope:** `contents:read`

Used only for:

- allowing CI runners and worker machines to pull Sentinel Core from the private Shield repository

This token must never grant write access.

---

### 2. `SENTINEL_ALERT_TOKEN`
**Scope:** `issues:write`

Used by Sentinel to:

- open enforcement violation alerts
- report blocked policies
- maintain an immutable audit trail inside the Admin Shield repository

---

## Optional Advisory Key (AI Layer)

### 3. `SENTINEL_AI_KEY` *(optional)*

Used only if AI remediation suggestions are enabled.

> AI never influences enforcement decisions — it only enriches reports.

---

# Phase 2 — Shield Initialization (Private Corporate Mirror)

Sentinel enforcement must originate from a private organizational repository:

```
sentinel-core (Admin Shield)
```

This repository becomes the **single source of truth** for all enforcement logic.

---

## Step 1 — Create the Shield Repository

Inside your GitHub Organization, create a new **Private Repository**, for example:

```
sentinel-core
```

---

## Step 2 — Store Secrets in the Shield Repository

Inside the Shield repo, the administrator must create the following GitHub Actions secrets:

- `SENTINEL_INSTALL_TOKEN`
- `SENTINEL_ALERT_TOKEN`
- `SENTINEL_AI_KEY` *(if enabled)*

These secrets allow:

- controlled engine distribution
- centralized violation reporting
- optional AI advisory enrichment

---

## Step 3 — Restrict Secret Exposure (Repository Access Control)

When creating these secrets, GitHub must be configured under:

```
Repository access → Only select repositories
```

The administrator must explicitly allow access only to:

- the Shield repository itself
- authorized client/project repositories protected by Sentinel

This prevents accidental organization-wide leakage of enforcement credentials.

---

## Step 4 — Mirror Secrets into Protected Project Repositories

Each client/project repository that will be protected by Sentinel must also contain the same secrets:

- `SENTINEL_INSTALL_TOKEN`
- `SENTINEL_ALERT_TOKEN`
- `SENTINEL_AI_KEY` *(if applicable)*

This ensures:

- Sentinel workflows inside the project can authenticate correctly
- project-level CI gates can report violations back into the Shield
- both repositories remain cryptographically linked

---

## Step 5 — Push Sentinel Engine into the Shield

On a secure administrative machine:

```bash
git init

git remote add origin https://github.com/YourOrg/sentinel-core.git
git branch -M main

git add .
git commit -m "feat: initialize corporate Sentinel Shield"

git push -u origin main
```

Once complete, this repository becomes the authoritative enforcement source.

---

# Phase 3 — Worker Machine Activation (Admin Provisioning via `start.sh`)

In Sentinel V2, project onboarding follows a strict **Hardware-Bound Licensing** workflow. 
Activation is performed directly by an authorized administrator using the provisioning script.

---

## Licensing Workflow (Pre-Activation)

1. **Collect Machine ID**: Run the provided `get_id.py` script on the target machine.
2. **Request License**: Send the **16-character Machine ID** to the provider (DataWizual Security).
3. **Receive Key**: Obtain a unique **License Key** bound to that specific machine.

## Worker Machine Prerequisites

- **Python 3.10+** (Recommended for optimized engine performance)
- **Git** (Required for hooks and repo synchronization)

---

## One-Step Provisioning

1. Admin copies `start.sh` into the root directory of the project to be protected.
2. **Insert License Key**: Paste the unique key into the `SENTINEL_LICENSE_KEY` variable inside `start.sh`.
3. Fill in required environment variables (tokens, repo location).
4. Execute:

```bash
chmod +x start.sh
./start.sh
```

This operation automatically verifies the hardware license, installs the engine, and activates all security hooks and CI/CD workflows.

---

## Deployment Complete

After execution:

```
✅ DEPLOYMENT COMPLETE: Project is now under Sentinel Shield.
```

Sentinel is now active and cannot be bypassed.

---

# 📄 Reports

Every scan generates professional audit artifacts:

- HTML Report
- JSON Evidence
- Markdown Summary

Stored automatically in:

```
/reports/
  sentinel_report_<timestamp>.html
  sentinel_report_<timestamp>.json
  sentinel_report_<timestamp>.md
```

---

# 🧬 Policy Configuration

Sentinel enforcement is governed by `sentinel.yaml`.

Example:

```yaml
severity:
  SEC-001: BLOCK
  SUPPLY-001: BLOCK
  INFRA-001: BLOCK

overrides: []
ignore:
  - venv/*
  - node_modules/*
```

Overrides require justification:

```yaml
overrides:
  - rule_id: SUPPLY-001
    justification: "Legacy base image required for compatibility"
```

---

# 🏢 Administrative Monitoring

All violations are automatically reported into the corporate Shield repository:

- GitHub Issues become the centralized threat feed
- Sentinel never reports externally beyond the authorized admin perimeter

---

# ✅ Security Checklist (Admin Before Deployment)

- [ ] PATs generated with minimal scopes
- [ ] Secrets stored in Shield repo
- [ ] Repository access restricted to selected repos
- [ ] Secrets mirrored into protected project repos
- [ ] Worker machine provisioned only via `start.sh`
- [ ] `start.sh` securely deleted after provisioning

---

# ✅ Sentinel Core — Scope & Responsibility

Sentinel Core is a deterministic CI/CD security enforcement gate designed to detect and block unsafe actions before they reach production. It helps teams identify policy violations, exposed secrets, insecure supply-chain changes, and deployment configuration risks early in the pipeline lifecycle. Sentinel enforces binary decisions (ALLOW/BLOCK) to prevent risky artifacts from progressing toward release. Sentinel reduces operational risk but does not guarantee breach prevention. Final responsibility for overrides, remediation, and security outcomes remains with the deploying organization. Full terms are defined in TERMS_OF_USE.md.

---

© 2026 DataWizual Security — Sentinel Shield System

