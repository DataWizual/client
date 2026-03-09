# 🛡️ Sentinel Core — Deterministic Security Enforcement System

**DataWizual Security Labs** · eldorzufarov66@gmail.com

---

Sentinel Core is an enterprise-grade security enforcement system for development teams. It automatically inspects every commit and CI/CD pipeline for vulnerabilities, secret exposures, and unsafe configurations — and **blocks dangerous changes before they reach production**.

At its core, Sentinel runs an embedded **Auditor Core** engine with AI-powered analysis via Google Gemini, which verifies threats and eliminates false positives.

> **ALLOW or BLOCK — no ambiguity, no silent bypass.**

---

## What Sentinel Protects

- **Secrets** — passwords, API keys, tokens hardcoded in source files
- **CI/CD Configurations** — GitHub Actions, GitLab CI, Jenkinsfile
- **Infrastructure** — Kubernetes, Terraform, Docker
- **Python Source Code** — command injection, insecure cryptography, SQL injection
- **Supply Chain** — unpinned dependencies, unsafe base images

---

## How It Works

```
Developer runs git commit
        ↓
Sentinel intercepts (pre-commit hook)
        ↓
Auditor Core scans changed files
        ↓
Gemini AI verifies and classifies threats
        ↓
ALLOW → commit proceeds
BLOCK → commit rejected + alert created in GitHub Issues
```

---

## Step 1 — Obtain Your Machine ID

Before installation, each machine requires a unique License Key bound to its hardware.
Run the following script on every machine where Sentinel will be deployed:

```bash
python3 get_id.py
```

Output:
```
==================================================
  Sentinel Core — Machine ID
==================================================
  Machine ID: 81CE1239487E2EA172FF41BC4DD13BED
==================================================

  Send this ID to: eldorzufarov66@gmail.com
  to receive your License Key.
```

Send the Machine ID by email. You will receive a **License Key** unique to that machine.

> ⚠️ Each machine has its own key. A key issued for one machine will not work on another.

---

## Step 2 — Prepare GitHub Tokens

Sentinel requires two GitHub Personal Access Tokens. Create them at:

`GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens`

### SENTINEL_INSTALL_TOKEN
Used to install the Sentinel package from the private repository.

```
Repository access: sentinel-core (your admin repo)
Permissions:
  Contents: Read-only ✓
```

### SENTINEL_ALERT_TOKEN
Used to post enforcement alerts as GitHub Issues.

```
Repository access: your admin repository
Permissions:
  Issues: Read and write ✓
```

---

## Step 3 — Install via start.sh

Copy `start.sh` into the root of the project you want to protect and run:

```bash
bash start.sh 2>&1 | tee install.log
```

The script guides you through all configuration steps interactively:

```
Type YES to accept terms and proceed: YES

Enter Install Token (PAT with repo scope): <SENTINEL_INSTALL_TOKEN>
Enter License Key:                         <your License Key>
Enter Google Gemini API Key:               <AIza...>
Enter Gemini Model [gemini-2.5-flash]:     [Enter to keep default]
Enter GitHub Alert Token:                  <SENTINEL_ALERT_TOKEN>
Enter Admin Repo [YourOrg/sentinel-core]:  <your/repo>
Enter License Salt (AUDITOR_LICENSE_SALT): <provided by DataWizual>
```

Successful installation output:
```
✅ License verified for Machine ID: 81CE1239487E2EA172FF41BC4DD13BED
✅ sentinel.yaml initialized
✅ GitHub Workflow initialized
✅ Pre-commit hook installed
------------------------------------------------------------
✅ SENTINEL CORE DEPLOYED SUCCESSFULLY
------------------------------------------------------------
```

---

## Step 4 — Verify the Installation

After installation, run a test commit to confirm Sentinel is active:

```bash
echo 'password = "admin123"' > test_vuln.py
git add test_vuln.py
git commit -m "test"
```

Expected result — commit is blocked:
```
🔍 Sentinel is verifying commit security...
❌ Found 1 security violations!
- [CRITICAL] SEC-001: Hardcoded Password in test_vuln.py at line 1.
🚀 Remote Alert Sent Successfully!
❌ Terminating: 1 CRITICAL threats found.
```

Clean up the test file:
```bash
rm test_vuln.py
```

---

## Project Structure After Installation

```
your-project/
├── start.sh                    ← provisioning script
├── audit-config.yml            ← Auditor Core configuration
├── sentinel.yaml               ← Sentinel enforcement rules
├── .env                        ← credentials (never commit this file)
├── .github/
│   └── workflows/
│       └── sentinel.yml        ← CI/CD pipeline protection
├── reports/
│   └── report_*.json           ← scan reports
└── venv/                       ← Python virtual environment
```

---

## Policy Configuration (sentinel.yaml)

```yaml
severity:
  SEC-001: BLOCK        # Hardcoded secrets
  SUPPLY-001: BLOCK     # Supply chain integrity
  INFRA-K8S-001: BLOCK  # Kubernetes misconfigurations
  CICD-001: BLOCK       # CI/CD security issues

overrides: []
ignore:
  - venv/*
  - node_modules/*
```

To temporarily allow a specific violation with a documented justification:

```yaml
overrides:
  - rule_id: SUPPLY-001
    justification: "Legacy base image required for compatibility — reviewed by security team"
```

---

## Enforcement Alerts

Every violation automatically creates an Issue in your admin repository:

```
Target Admin Repo: YourOrg/sentinel-core
Status: 🔴 BLOCK
Environment: 💻 Local Development
Machine: worker-pc-01
Triggered by: developer_username
```

The administrator has full visibility into all incidents. Developers have no access to the enforcement dashboard.

---

## Requirements

| Component | Version |
|-----------|---------|
| Python | 3.10+ |
| Git | any |
| OS | Linux / macOS / Windows |
| Gemini API Key | optional (enables AI analysis) |

Optional external tools for extended scanning coverage:

- `gitleaks` — secret scanning across git history
- `semgrep` — advanced multi-language SAST analysis
- `bandit` — installed automatically with Sentinel

---

## Frequently Asked Questions

**Q: Can a developer bypass Sentinel?**
A: A developer can run `git commit --no-verify` locally. However, the CI/CD pipeline will catch the push, block it, and send an alert to the administrator with the developer's identity.

**Q: Does Sentinel slow down commits?**
A: Basic scanning takes 2–5 seconds. With Gemini AI analysis enabled — 15–30 seconds depending on project size.

**Q: What happens if the Gemini API is unavailable?**
A: Sentinel continues operating without AI enrichment. All core enforcement rules (SEC-001, SUPPLY-001, etc.) run fully offline at all times.

**Q: How do I update Sentinel on a machine?**
A: Run `start.sh` again. It will update the package while preserving the existing `.env` configuration.

**Q: Is developer activity logged?**
A: Yes. Every blocked commit is recorded as a GitHub Issue with machine identity, username, timestamp, and violation details — creating an immutable audit trail.

---

## Support

For installation, licensing, and configuration assistance:

📧 **eldorzufarov66@gmail.com**

Please include in your message:
- Machine ID (from `python3 get_id.py`)
- Description of the issue
- OS version and Python version

---

© 2026 DataWizual Security Labs. All rights reserved.
Use of this software is governed by `TERMS_OF_USE.md`.