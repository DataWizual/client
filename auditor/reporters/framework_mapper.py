"""
Framework Mapper - Auditor Enterprise Suite.
Maps security findings to industry compliance frameworks:
  - SOC 2 Trust Services Criteria (TSC)
  - CIS Controls v8
  - ISO/IEC 27001:2022 Annex A

Usage:
    from auditor.reporters.framework_mapper import FrameworkMapper
    mapper = FrameworkMapper()
    mapping = mapper.map(rule_id="B602", cwe="CWE-78", severity="HIGH")
"""

from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# SOC 2 Trust Services Criteria (AICPA TSC 2017)
# ---------------------------------------------------------------------------
_SOC2: Dict[str, Dict] = {
    "CC6.1": {
        "title": "Logical and Physical Access Controls",
        "description": "Restrict logical access to systems and data.",
    },
    "CC6.6": {
        "title": "External Threat Mitigation",
        "description": "Prevent and detect threats from external sources.",
    },
    "CC6.7": {
        "title": "Data Transmission Protection",
        "description": "Protect against unauthorized data disclosure in transit.",
    },
    "CC7.1": {
        "title": "Vulnerability Detection",
        "description": "Detect and monitor vulnerabilities in system components.",
    },
    "CC7.2": {
        "title": "Anomaly & Threat Monitoring",
        "description": "Monitor for anomalies and potential threats.",
    },
    "CC8.1": {
        "title": "Change Management",
        "description": "Authorize, design, develop, test and implement changes.",
    },
    "CC9.2": {
        "title": "Third-Party Risk Management",
        "description": "Assess and manage risks from third-party vendors.",
    },
    "A1.2": {
        "title": "Availability — Capacity & Performance",
        "description": "Manage capacity and system performance.",
    },
    "PI1.2": {
        "title": "Processing Integrity",
        "description": "Ensure complete, valid and accurate processing.",
    },
    "C1.1": {
        "title": "Confidentiality Identification",
        "description": "Identify and maintain confidentiality of information.",
    },
    "C1.2": {
        "title": "Confidentiality Disposal",
        "description": "Dispose of confidential information securely.",
    },
}

# ---------------------------------------------------------------------------
# CIS Controls v8 (top-level safeguards most relevant to code / SAST findings)
# ---------------------------------------------------------------------------
_CIS: Dict[str, Dict] = {
    "CIS-2.3": {
        "title": "Address Unauthorized Software",
        "description": "Ensure only authorized software is installed.",
    },
    "CIS-3.3": {
        "title": "Configure Data Access Control Lists",
        "description": "Restrict access to sensitive data via ACLs.",
    },
    "CIS-3.11": {
        "title": "Encrypt Sensitive Data at Rest",
        "description": "Encrypt sensitive data stored on systems.",
    },
    "CIS-3.12": {
        "title": "Segment Data Processing & Storage",
        "description": "Segment environments to limit data exposure.",
    },
    "CIS-4.1": {
        "title": "Establish Secure Configuration Process",
        "description": "Establish and maintain secure configurations.",
    },
    "CIS-4.7": {
        "title": "Manage Default Accounts",
        "description": "Manage default accounts on enterprise assets.",
    },
    "CIS-5.3": {
        "title": "Disable Dormant Accounts",
        "description": "Delete or disable dormant accounts.",
    },
    "CIS-7.3": {
        "title": "Perform Automated OS Patch Management",
        "description": "Remediate vulnerabilities through patch management.",
    },
    "CIS-7.5": {
        "title": "Perform Automated Vulnerability Scans",
        "description": "Perform automated application vulnerability scans.",
    },
    "CIS-8.2": {
        "title": "Collect Audit Logs",
        "description": "Collect audit logs to detect security events.",
    },
    "CIS-12.2": {
        "title": "Establish Network Infrastructure Configurations",
        "description": "Establish and maintain secure network configs.",
    },
    "CIS-14.1": {
        "title": "Establish Security Awareness Programme",
        "description": "Train workforce on security awareness.",
    },
    "CIS-16.1": {
        "title": "Establish Secure Application Development Process",
        "description": "Establish and maintain a secure SDLC process.",
    },
    "CIS-16.2": {
        "title": "Establish Process for Receiving Reports on SW Vulnerabilities",
        "description": "Maintain a process for software vulnerability disclosure.",
    },
    "CIS-16.3": {
        "title": "Perform Root Cause Analysis on Security Vulnerabilities",
        "description": "Perform root cause analysis on security findings.",
    },
    "CIS-16.7": {
        "title": "Use Standard Hardening Configuration Templates",
        "description": "Use hardening configuration templates for applications.",
    },
    "CIS-16.12": {
        "title": "Implement Code-Level Security Checks",
        "description": "Implement static and dynamic code security checks.",
    },
}

# ---------------------------------------------------------------------------
# ISO/IEC 27001:2022 Annex A Controls
# ---------------------------------------------------------------------------
_ISO: Dict[str, Dict] = {
    "A.5.15": {
        "title": "Access Control",
        "description": "Rules to control physical and logical access.",
    },
    "A.5.17": {
        "title": "Authentication Information",
        "description": "Manage authentication credentials securely.",
    },
    "A.5.23": {
        "title": "Information Security for Cloud Services",
        "description": "Manage cloud service information security.",
    },
    "A.8.4": {
        "title": "Access to Source Code",
        "description": "Restrict and monitor access to source code.",
    },
    "A.8.8": {
        "title": "Management of Technical Vulnerabilities",
        "description": "Obtain information about vulnerabilities and take action.",
    },
    "A.8.9": {
        "title": "Configuration Management",
        "description": "Manage configuration of hardware, software and networks.",
    },
    "A.8.11": {
        "title": "Data Masking",
        "description": "Mask sensitive data in accordance with policy.",
    },
    "A.8.12": {
        "title": "Data Leakage Prevention",
        "description": "Prevent unauthorized disclosure of sensitive data.",
    },
    "A.8.19": {
        "title": "Installation of Software on Operational Systems",
        "description": "Control software installation on operational systems.",
    },
    "A.8.24": {
        "title": "Use of Cryptography",
        "description": "Define and implement rules for cryptographic controls.",
    },
    "A.8.25": {
        "title": "Secure Development Lifecycle",
        "description": "Establish rules for secure software development.",
    },
    "A.8.26": {
        "title": "Application Security Requirements",
        "description": "Identify and approve information security requirements.",
    },
    "A.8.27": {
        "title": "Secure System Architecture and Engineering",
        "description": "Establish and apply principles for secure systems.",
    },
    "A.8.28": {
        "title": "Secure Coding",
        "description": "Apply secure coding principles to software development.",
    },
    "A.8.29": {
        "title": "Security Testing in Development and Acceptance",
        "description": "Define and implement security testing processes.",
    },
}

# ---------------------------------------------------------------------------
# Master mapping table: rule_id prefix / keyword → frameworks
# Each entry: { "soc2": [...], "cis": [...], "iso": [...] }
# ---------------------------------------------------------------------------
_RULE_MAP: List[Dict] = [
    # --- Injection / Command execution ---
    {
        "match": [
            "B602",
            "B603",
            "B604",
            "B605",
            "B606",
            "shell=True",
            "COMMAND_INJECTION",
            "OS_COMMAND",
            "RCE",
        ],
        "soc2": ["CC6.6", "CC7.1"],
        "cis": ["CIS-16.1", "CIS-16.12", "CIS-7.5"],
        "iso": ["A.8.28", "A.8.26", "A.8.29"],
        "risk": "Remote code execution via unsanitized shell command.",
    },
    # --- SQL Injection ---
    {
        "match": ["B608", "SQL_INJECTION", "sqli", "CWE-89"],
        "soc2": ["CC6.1", "CC6.6", "CC7.1"],
        "cis": ["CIS-16.12", "CIS-16.1", "CIS-7.5"],
        "iso": ["A.8.28", "A.8.26"],
        "risk": "Database compromise via SQL injection.",
    },
    # --- Secrets / Hardcoded credentials ---
    {
        "match": [
            "SECRET",
            "HARDCODED",
            "B105",
            "B106",
            "B107",
            "CWE-798",
            "CWE-259",
            "HIGH_ENTROPY",
            "API_KEY",
            "TOKEN",
            "PASSWORD",
            "CREDENTIAL",
        ],
        "soc2": ["CC6.1", "CC6.7", "C1.1"],
        "cis": ["CIS-3.11", "CIS-4.7", "CIS-16.1"],
        "iso": ["A.5.17", "A.8.12", "A.8.24"],
        "risk": "Credential exposure allowing unauthorized access.",
    },
    # --- Cryptography ---
    {
        "match": [
            "B303",
            "B304",
            "B305",
            "B306",
            "WEAK_CRYPTO",
            "MD5",
            "SHA1",
            "DES",
            "RC4",
            "CWE-327",
            "CWE-326",
            "INSECURE_CIPHER",
            "WEAK_HASH",
        ],
        "soc2": ["CC6.7", "C1.1", "C1.2"],
        "cis": ["CIS-3.11", "CIS-16.7"],
        "iso": ["A.8.24", "A.8.28"],
        "risk": "Weak cryptography enabling data decryption or collision attacks.",
    },
    # --- Path traversal / File access ---
    {
        "match": [
            "B101",
            "PATH_TRAVERSAL",
            "CWE-22",
            "CWE-73",
            "DIRECTORY_TRAVERSAL",
            "FILE_INCLUSION",
        ],
        "soc2": ["CC6.1", "CC6.6"],
        "cis": ["CIS-3.3", "CIS-16.12"],
        "iso": ["A.8.4", "A.8.26"],
        "risk": "Unauthorized file system access via path traversal.",
    },
    # --- XSS ---
    {
        "match": [
            "XSS",
            "CROSS_SITE_SCRIPTING",
            "CWE-79",
            "B501",
            "TEMPLATE_INJECTION",
        ],
        "soc2": ["CC6.6", "CC7.1"],
        "cis": ["CIS-16.12", "CIS-16.1"],
        "iso": ["A.8.28", "A.8.26"],
        "risk": "Client-side code injection enabling session hijacking.",
    },
    # --- SSRF ---
    {
        "match": ["SSRF", "CWE-918", "SERVER_SIDE_REQUEST"],
        "soc2": ["CC6.6", "CC9.2"],
        "cis": ["CIS-12.2", "CIS-16.12"],
        "iso": ["A.8.26", "A.8.27"],
        "risk": "Internal network exposure via server-side request forgery.",
    },
    # --- XXE ---
    {
        "match": [
            "XXE",
            "CWE-611",
            "XML_EXTERNAL",
            "B313",
            "B314",
            "B315",
            "B316",
            "B317",
            "B318",
            "B319",
            "B320",
        ],
        "soc2": ["CC6.6", "CC7.1"],
        "cis": ["CIS-16.12"],
        "iso": ["A.8.28"],
        "risk": "XML external entity injection enabling file disclosure.",
    },
    # --- Insecure deserialization ---
    {
        "match": [
            "DESERIALIZ",
            "CWE-502",
            "B301",
            "B302",
            "PICKLE",
            "YAML_LOAD",
            "MARSHAL",
        ],
        "soc2": ["CC6.6", "CC7.1"],
        "cis": ["CIS-16.12", "CIS-16.1"],
        "iso": ["A.8.28", "A.8.26"],
        "risk": "Arbitrary code execution via insecure deserialization.",
    },
    # --- Open network / IAC misconfiguration ---
    {
        "match": [
            "IAC_GENERAL_OPEN_NETWORK",
            "OPEN_SECURITY_GROUP",
            "0.0.0.0/0",
            "CWE-284",
            "UNRESTRICTED_INGRESS",
            "IAC_OPEN",
            "NETWORK_EXPOSURE",
        ],
        "soc2": ["CC6.6", "CC6.1", "CC7.2"],
        "cis": ["CIS-12.2", "CIS-4.1"],
        "iso": ["A.8.9", "A.8.27"],
        "risk": "Unrestricted network exposure via misconfigured security group.",
    },
    # --- Dependency / SCA vulnerabilities ---
    {
        "match": ["CVE-", "VULN_DEP", "DEPENDENCY", "SCA_", "OUTDATED", "CWE-1104"],
        "soc2": ["CC7.1", "CC8.1"],
        "cis": ["CIS-7.3", "CIS-7.5", "CIS-2.3"],
        "iso": ["A.8.8", "A.8.19"],
        "risk": "Known exploitable vulnerability in third-party dependency.",
    },
    # --- Logging / Audit trail ---
    {
        "match": [
            "LOGGING",
            "AUDIT",
            "B110",
            "CWE-778",
            "CWE-117",
            "LOG_INJECTION",
            "MISSING_LOG",
        ],
        "soc2": ["CC7.2", "CC8.1"],
        "cis": ["CIS-8.2"],
        "iso": ["A.8.15", "A.8.16"],
        "risk": "Insufficient audit trail hindering incident investigation.",
    },
    # --- CI/CD pipeline security ---
    {
        "match": [
            "CICD",
            "PIPELINE",
            "GITHUB_ACTIONS",
            "WORKFLOW",
            "DEPLOY_KEY",
            "CI_SECRET",
        ],
        "soc2": ["CC8.1", "CC6.1"],
        "cis": ["CIS-16.1", "CIS-4.1"],
        "iso": ["A.8.25", "A.8.9"],
        "risk": "Insecure CI/CD pipeline enabling supply chain compromise.",
    },
    # --- License / Legal risk ---
    {
        "match": ["LICENSE", "GPL", "AGPL", "COPYLEFT"],
        "soc2": ["CC9.2"],
        "cis": ["CIS-2.3"],
        "iso": ["A.5.23"],
        "risk": "Copyleft license creating legal obligation to disclose source code.",
    },
]

# CWE → framework mapping (secondary lookup when rule_id match fails)
_CWE_MAP: Dict[str, Dict] = {
    "CWE-78": {"soc2": ["CC6.6"], "cis": ["CIS-16.12"], "iso": ["A.8.28"]},
    "CWE-79": {"soc2": ["CC6.6"], "cis": ["CIS-16.12"], "iso": ["A.8.28"]},
    "CWE-89": {"soc2": ["CC6.1", "CC6.6"], "cis": ["CIS-16.12"], "iso": ["A.8.28"]},
    "CWE-22": {"soc2": ["CC6.1"], "cis": ["CIS-3.3"], "iso": ["A.8.4"]},
    "CWE-259": {"soc2": ["CC6.1"], "cis": ["CIS-4.7"], "iso": ["A.5.17"]},
    "CWE-284": {"soc2": ["CC6.1", "CC6.6"], "cis": ["CIS-12.2"], "iso": ["A.8.9"]},
    "CWE-326": {"soc2": ["CC6.7"], "cis": ["CIS-3.11"], "iso": ["A.8.24"]},
    "CWE-327": {"soc2": ["CC6.7"], "cis": ["CIS-3.11"], "iso": ["A.8.24"]},
    "CWE-502": {"soc2": ["CC6.6"], "cis": ["CIS-16.12"], "iso": ["A.8.28"]},
    "CWE-611": {"soc2": ["CC6.6"], "cis": ["CIS-16.12"], "iso": ["A.8.28"]},
    "CWE-798": {"soc2": ["CC6.1", "C1.1"], "cis": ["CIS-4.7"], "iso": ["A.5.17"]},
    "CWE-918": {"soc2": ["CC6.6"], "cis": ["CIS-12.2"], "iso": ["A.8.26"]},
}


class FrameworkMapper:
    """
    Maps a security finding (rule_id + cwe + severity) to:
      - SOC 2 TSC criteria
      - CIS Controls v8 safeguards
      - ISO/IEC 27001:2022 Annex A controls

    Returns a dict ready for embedding into JSON/HTML/PDF reports.
    """

    def map(
        self,
        rule_id: str = "",
        cwe: str = "",
        severity: str = "LOW",
        description: str = "",
    ) -> Dict:
        rule_upper = (rule_id or "").upper()
        cwe_upper = (cwe or "").upper()
        desc_upper = (description or "").upper()
        search_str = f"{rule_upper} {cwe_upper} {desc_upper}"

        matched_soc2: List[str] = []
        matched_cis: List[str] = []
        matched_iso: List[str] = []
        risk_note = ""

        # Primary: rule_id keyword match
        for entry in _RULE_MAP:
            if any(kw.upper() in search_str for kw in entry["match"]):
                matched_soc2 = entry["soc2"]
                matched_cis = entry["cis"]
                matched_iso = entry["iso"]
                risk_note = entry.get("risk", "")
                break

        # Secondary: CWE fallback
        if not matched_soc2 and cwe_upper in _CWE_MAP:
            cm = _CWE_MAP[cwe_upper]
            matched_soc2 = cm.get("soc2", [])
            matched_cis = cm.get("cis", [])
            matched_iso = cm.get("iso", [])

        # Default for anything not matched
        if not matched_soc2:
            matched_soc2 = ["CC7.1"]
            matched_cis = ["CIS-16.12"]
            matched_iso = ["A.8.29"]
            risk_note = "Security finding requires manual review and classification."

        return {
            "soc2": [
                {**{"id": k}, **_SOC2.get(k, {"title": k, "description": ""})}
                for k in matched_soc2
            ],
            "cis": [
                {**{"id": k}, **_CIS.get(k, {"title": k, "description": ""})}
                for k in matched_cis
            ],
            "iso27001": [
                {**{"id": k}, **_ISO.get(k, {"title": k, "description": ""})}
                for k in matched_iso
            ],
            "risk_note": risk_note,
            "severity": severity.upper(),
        }

    def build_framework_summary(self, findings_with_mapping: List[Dict]) -> Dict:
        """
        Aggregates per-finding mappings into a report-level summary:
        which SOC2 / CIS / ISO controls are covered and how many findings map to each.
        """
        soc2_counts: Dict[str, int] = {}
        cis_counts: Dict[str, int] = {}
        iso_counts: Dict[str, int] = {}

        for f in findings_with_mapping:
            cm = f.get("compliance_mapping", {})
            for item in cm.get("soc2", []):
                k = item["id"]
                soc2_counts[k] = soc2_counts.get(k, 0) + 1
            for item in cm.get("cis", []):
                k = item["id"]
                cis_counts[k] = cis_counts.get(k, 0) + 1
            for item in cm.get("iso27001", []):
                k = item["id"]
                iso_counts[k] = iso_counts.get(k, 0) + 1

        def _enrich(counts, ref):
            return [
                {
                    "id": k,
                    "title": ref.get(k, {}).get("title", k),
                    "count": v,
                }
                for k, v in sorted(counts.items(), key=lambda x: -x[1])
            ]

        return {
            "soc2_controls": _enrich(soc2_counts, _SOC2),
            "cis_controls": _enrich(cis_counts, _CIS),
            "iso27001_controls": _enrich(iso_counts, _ISO),
            "total_soc2_criteria_triggered": len(soc2_counts),
            "total_cis_safeguards_triggered": len(cis_counts),
            "total_iso_controls_triggered": len(iso_counts),
        }
