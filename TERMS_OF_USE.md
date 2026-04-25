# Terms of Use — Auditor Core

**DataWizual Security Labs**
Last updated: 2026

---

## Definitions

- **"Software"** means Auditor Core, including all components, modules, scripts,
  configuration files, and documentation provided by the Vendor.
- **"Vendor"** means DataWizual Security Labs, the developer and licensor of the Software.
- **"Customer"** means the organization or individual that installs, deploys, or uses the Software.
- **"License"** means the non-exclusive, non-transferable right to use the Software
  granted under these Terms.
- **"AI Advisory"** means threat analysis, verdicts, and remediation suggestions generated
  by third-party AI services integrated with the Software.
- **"SPI"** means Security Posture Index, a calibrated risk score computed by the Software
  using the Weighted Security Posture Model (WSPM).
- **"Chain Analysis"** means the deterministic process by which the Software identifies
  and scores multi-step attack paths formed by two or more correlated findings.
- **"Chain"** means a group of two or more findings identified by Chain Analysis as
  forming a combined attack path, assigned a shared chain identifier and a resulting
  risk level as defined by the applicable chaining rule.
- **"AI Verdict"** means a finding-level classification produced by the AI Advisory
  component, expressed as one of the following statuses: `SUPPORTED`, `NOT_SUPPORTED`,
  or `REQUIRES REVIEW`. These statuses are defined in Section 2 below.

---

## 1. Product Description

Auditor Core is a deterministic security auditing engine designed to produce reproducible
static analysis findings and engineering-focused security posture reports, including a
calibrated Security Posture Index (SPI) based on a mathematically defined Weighted
Security Posture Model (WSPM v2.2.1).

The Software helps teams identify vulnerabilities, exposed secrets, insecure configurations,
vulnerable dependencies, CI/CD weaknesses, attack chains, and systemic exposure patterns
early in the development lifecycle.

The Software reduces security blind spots and operational risk. However, it does not
replace human review, does not guarantee exploitability assessment accuracy, and does
not provide immunity from security breaches.

All remediation decisions, risk acceptance, deployment choices, and operational security
outcomes remain the sole responsibility of the Customer.

---

## 2. AI Advisory Disclaimer

The Software optionally integrates with third-party AI services (including Google Gemini
and Groq) to provide remediation guidance and threat context.

**AI analysis is advisory only.** AI-generated output:

- Does not influence detection, severity scoring, SPI calculation, or audit decisions
- Does not constitute a guarantee of security or absence of vulnerabilities
- Must not be used as the sole basis for any security, operational, or business decision
- Is subject to the terms and limitations of the underlying AI provider

### AI Verdict Statuses

When AI Advisory is enabled, each finding receives one of the following verdict statuses:

- **SUPPORTED** — The AI Advisory has reviewed the finding and assessed it as consistent
  with the reported vulnerability class. This status indicates that the AI analysis
  corroborates the static detection signal. It does not constitute confirmation of
  exploitability or a guarantee that the finding represents an active security risk
  in the Customer's specific environment.

- **NOT_SUPPORTED (AI DISMISSED)** — The AI Advisory has reviewed the finding and
  assessed that the available code context does not clearly demonstrate the reported
  vulnerability. Findings with this status are retained in the report and remain
  subject to human review. Dismissal by the AI Advisory does not exclude the
  possibility that a vulnerability exists; it indicates that the AI was unable to
  confirm it based on the available context.

- **REQUIRES REVIEW** — The AI Advisory did not produce a verdict for this finding,
  either because AI Advisory was disabled, the finding was excluded from AI analysis,
  or the AI provider was unavailable. Findings with this status require manual
  security review.

Findings participating in a Chain (see Section 2a) receive an enriched AI Advisory
prompt that includes the full chain context. The AI Advisory is expected to evaluate
the combined attack path in addition to the individual finding. Where the AI Advisory
does not reference the chain context, the confidence of its verdict is reduced
automatically by the Software as a quality control measure.

**AI Hallucination Notice.** AI systems may generate inaccurate, incomplete, fabricated,
or misleading outputs, commonly referred to as "hallucinations." The Vendor makes no
representation regarding the correctness, completeness, or reliability of any AI-generated
analysis or recommendation produced by the Software.

Failure, inaccuracy, or unavailability of any AI component does not affect the
deterministic audit output. The Vendor bears no liability for consequences arising
from reliance on AI-generated output.

---

## 2a. Chain Analysis Disclaimer

The Software includes a Chain Analysis capability that automatically correlates findings
to identify multi-step attack paths. The following applies to Chain Analysis output:

**Chain Analysis is deterministic but not exhaustive.** Chain detection is based on
configurable rule sets defined by the Customer or supplied by the Vendor. The absence
of a detected chain does not indicate the absence of correlated risk in the codebase.

**Severity escalation is a risk signal, not a confirmed exploit.** When the Software
escalates the severity of a finding due to its participation in a chain, this reflects
the increased potential impact if the chain were exploited. It does not confirm that
the chain is actively exploitable, that all findings in the chain are genuine
vulnerabilities, or that exploitation has occurred or is imminent.

**Chain suppression is all-or-nothing.** Chains may be suppressed in their entirety
via the baseline configuration. Individual findings within a chain cannot be suppressed
independently while the chain remains active. The Customer is responsible for ensuring
that chain suppressions are reviewed and approved by qualified security personnel.

**Chain rules are Customer-configurable.** The Vendor supplies default chaining rules
as reference configurations. The Customer may add, modify, or remove rules. The Vendor
bears no liability for chains detected or missed as a result of Customer-defined rules
or modifications to the default rule set.

---

## 3. Deterministic Scoring Disclaimer

The SPI and all WSPM-based risk scores are computed deterministically using rule-based
mathematical models. These scores represent a calibrated engineering signal and:

- Are not a guarantee of absolute security
- Do not constitute a formal compliance assessment or audit opinion
- Must be interpreted by qualified security personnel in the context of the
  Customer's specific environment and risk tolerance

Where Chain Analysis is active, the SPI and severity distribution reflect escalated
severity levels for findings participating in chains. This is by design and represents
the Software's assessment of combined exploit risk.

---

## 4. Framework and Compliance References

The Software may annotate findings with references to widely used security frameworks
and standards (including but not limited to ISO 27001, SOC 2, OWASP, NIST) for
contextual engineering guidance only.

Such references are informational metadata and do not constitute compliance certification,
regulatory approval, audit attestation, or formal audit evidence. The Software is not a
certified compliance auditing product and does not replace formal third-party audits or
regulatory assessments.

---

## 5. Hardware-Bound Licensing

Each License issued under this Agreement is cryptographically bound to a specific machine
hardware identifier (Machine ID). The following conditions apply:

- A License is valid only on the machine for which it was issued
- Transferring, copying, or reusing a License key on a different machine is strictly prohibited
- The Software performs hardware verification at every initialization
- Attempting to circumvent hardware binding constitutes a material breach of this Agreement
  and shall result in immediate License termination without notice or refund

The Vendor reserves the right to revoke and terminate any License found to be used in
violation of these terms, without prior notice and without obligation to issue a refund.

---

## 6. Machine ID and Data Collection

To enable hardware-bound licensing, the Software generates a Machine ID derived from
system identifiers using a one-way cryptographic hash function. This identifier:

- Does not contain personal data within the meaning of applicable data protection law
- Cannot be used to reconstruct underlying hardware details
- Is used solely for license verification purposes
- Is not transmitted to any external server during normal operation
- Is shared with the Vendor only at the explicit request of the Customer's administrator
  during the licensing process

For organizations subject to the General Data Protection Regulation (GDPR) or similar
legislation, the collection of the Machine ID constitutes a contractual necessity for
license issuance and is processed on the legal basis of Article 6(1)(b) of the GDPR.

---

## 7. Professional Use Requirement

The Software is designed exclusively for use by qualified security professionals.
By deploying the Software, the Customer represents and warrants that:

- The Software will be deployed, configured, and operated by personnel with appropriate
  technical expertise in information security
- The Customer's security team retains full professional responsibility for all
  configuration decisions, audit scope, findings interpretation, chain rule configuration,
  and remediation outcomes
- The Vendor supplies a security auditing tool and assumes no responsibility for outcomes
  resulting from improper deployment, misconfiguration, inadequate expertise, or misuse
  by the Customer's personnel

The Software is intended solely for lawful security auditing within environments the
Customer is authorized to assess. Any use outside this intended purpose is at the
Customer's sole risk and responsibility.

---

## 8. Human Responsibility

The Software may raise findings, compute risk signals, detect attack chains, or classify
posture under its deterministic logic. The Customer acknowledges that:

- Final decisions to ignore findings, override policies, accept risk, suppress chains,
  or remediate issues remain entirely with authorized personnel of the Customer
- The Vendor provides analytical visibility — not operational control
- Security outcomes and remediation are the sole responsibility of the Customer
- AI Advisory verdicts and Chain Analysis output are decision-support tools and do not
  substitute for qualified human security judgment

---

## 9. No Warranty

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE, UNINTERRUPTED OPERATION, OR COMPLETE DETECTION OF ALL SECURITY VULNERABILITIES
OR ATTACK CHAINS.

The Vendor does not warrant that the Software will identify every security issue or
attack path present in a codebase, prevent all security incidents, or operate without
interruption in all technical environments. The Software is a risk reduction tool and
does not guarantee the prevention of security vulnerabilities, breaches, or unauthorized
access.

---

## 10. Limitation of Liability

TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, THE VENDOR SHALL NOT BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES ARISING
FROM THE USE OR INABILITY TO USE THE SOFTWARE, INCLUDING BUT NOT LIMITED TO SECURITY
INCIDENTS, DATA BREACHES, UNAUTHORIZED ACCESS, PRODUCTION FAILURES, DOWNTIME, BUSINESS
INTERRUPTION, DATA LOSS, OR FINANCIAL LOSSES.

**Liability Cap.** In all cases where liability cannot be fully excluded under applicable
law, the Vendor's total aggregate liability to the Customer shall not exceed the total
License fees paid by the Customer to the Vendor during the twelve (12) months immediately
preceding the event giving rise to the claim.

**Carve-Out.** Nothing in this Agreement excludes or limits the Vendor's liability for:

(a) fraud or fraudulent misrepresentation;
(b) willful misconduct;
(c) gross negligence causing death or personal injury;
(d) any liability that cannot be lawfully excluded or limited under applicable law.

---

## 11. Indemnification

The Customer agrees to indemnify, defend, and hold harmless the Vendor and its officers,
employees, and agents from and against any claims, damages, losses, and expenses
(including reasonable legal fees) arising out of or relating to:

- The Customer's use or misuse of the Software
- Violation of any term of this Agreement by the Customer
- Security incidents or failures occurring within the Customer's environment
- Any claim by a third party arising from the Customer's deployment or operation
  of the Software

---

## 12. Permitted Use

The Software is licensed, not sold. The License grants the Customer the non-exclusive,
non-transferable right to install and operate the Software solely for the purpose of
conducting authorized security audits within the Customer's own environment.

The following are expressly prohibited without prior written consent from the Vendor:

- Redistribution, resale, or sublicensing of the Software or any License
- Reverse engineering, decompilation, or disassembly of the Software,
  except where such restriction is prohibited by applicable law
- Use of the Software to audit systems the Customer is not authorized to assess
- Use of the Software as part of a commercial service offering to third parties

---

## 13. Third-Party Components

The Software integrates third-party open-source tools including, without limitation,
Gitleaks, Bandit, and Semgrep. These components are distributed under their respective
open-source licenses (including MIT, Apache 2.0, and others). The Vendor makes no
representations regarding the availability, security, accuracy, or continued operation
of third-party tools or services.

Third-party AI services are subject to their own terms of service. The Customer is
responsible for ensuring compliance with applicable third-party terms.

---

## 14. Export Control

The Software, including AI integration components, may be subject to export control
and sanctions laws and regulations of the United Kingdom, the United States, the European
Union, and other applicable jurisdictions.

The Customer agrees not to export, re-export, transfer, or make available the Software
in violation of applicable export control or sanctions laws.

---

## 15. Termination

This License is effective until terminated. The Vendor may terminate this License
immediately and without notice if the Customer violates any material term of this
Agreement. Upon termination, the Customer must immediately cease all use of the Software
and destroy all copies in its possession.

---

## 16. Governing Law and Dispute Resolution

This Agreement shall be governed by and construed in accordance with the laws of
**England and Wales**, without regard to conflict of law principles.

Any dispute arising out of or relating to this Agreement shall be referred to and
finally resolved by binding arbitration under the Rules of the London Court of
International Arbitration (LCIA). The seat of arbitration shall be London, England.
The language of arbitration shall be English.

---

## 17. Acceptance

By installing, executing, or deploying the Software — including by running any
provisioning script, installation command, or initialization procedure — the Customer
confirms that they have read, understood, and unconditionally accept these Terms of Use.

---

© 2026 DataWizual Security Labs. All rights reserved.
