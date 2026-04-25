"""
IaC Scanner - Auditor Cloud Suite.
Analyzes Terraform, Docker, and Kubernetes configurations for security misconfigurations.
"""

import re
import logging
import os
from pathlib import Path
from typing import List, Optional

from auditor.detectors.plugin_base import DetectorPlugin, PluginMetadata
from auditor.core.engine import Finding

logger = logging.getLogger(__name__)


class IacScanner(DetectorPlugin):
    """
    Scanner for Infrastructure as Code files with hardened path filtering.
    Detects misconfigurations in Terraform, Docker, and K8s.
    """

    def __init__(self):
        super().__init__()
        self.name = "IacScanner"
        # Original patterns preserved as requested
        self.iac_patterns = {
            "terraform": [
                (
                    r'(password|secret_key|access_key)\s*=\s*["\'][^"\']+["\']',
                    "CRITICAL",
                    "IAC_HARDCODED_CREDENTIAL",
                ),
                (r"publicly_accessible\s*=\s*true", "HIGH", "IAC_PUBLIC_RESOURCE"),
                (
                    r'cidr_blocks\s*=\s*\[\s*["\']0\.0\.0\.0/0["\']\s*\]',
                    "HIGH",
                    "IAC_OPEN_ACCESS",
                ),
                (r"encrypted\s*=\s*false", "HIGH", "IAC_ENCRYPTION_DISABLED"),
                (r'acl\s*=\s*["\']public-read["\']', "HIGH", "IAC_S3_PUBLIC_ACL"),
                (
                    r'acl\s*=\s*["\']public-read-write["\']',
                    "CRITICAL",
                    "IAC_S3_PUBLIC_WRITE_ACL",
                ),
                (
                    r'mfa_delete\s*=\s*["\']?[Dd]isabled["\']?',
                    "MEDIUM",
                    "IAC_S3_MFA_DELETE_DISABLED",
                ),
                (r"skip_final_snapshot\s*=\s*true", "MEDIUM", "IAC_NO_FINAL_SNAPSHOT"),
                (
                    r"enable_deletion_protection\s*=\s*false",
                    "MEDIUM",
                    "IAC_DELETION_PROTECTION_OFF",
                ),
            ],
            "dockerfile": [
                (r"USER\s+root", "MEDIUM", "DOCKER_RUN_AS_ROOT"),
                (
                    r"ENV\s+(.*(?:PASSWORD|SECRET|TOKEN|KEY|PASS).*)=.+",
                    "CRITICAL",
                    "DOCKER_ENV_SECRET",
                ),
                (r"FROM\s+.+:latest", "LOW", "DOCKER_LATEST_TAG"),
                (r"^ADD\s+https?://", "MEDIUM", "DOCKER_ADD_REMOTE_URL"),
                (r"^ADD\s+(?!https?://)", "LOW", "DOCKER_ADD_INSTEAD_OF_COPY"),
                (r"curl\s+.*\|\s*(bash|sh)", "CRITICAL", "DOCKER_CURL_PIPE_BASH"),
                (r"wget\s+.*\|\s*(bash|sh)", "CRITICAL", "DOCKER_WGET_PIPE_BASH"),
                (
                    r"apt-get\s+install\s+(?!.*--no-install-recommends)",
                    "LOW",
                    "DOCKER_APT_NO_RECOMMENDS",
                ),
            ],
            "kubernetes": [
                (r"privileged:\s*true", "HIGH", "K8S_PRIVILEGED_CONTAINER"),
                (
                    r"allowPrivilegeEscalation:\s*true",
                    "MEDIUM",
                    "K8S_PRIVILEGE_ESCALATION",
                ),
                (r"hostNetwork:\s*true", "HIGH", "K8S_HOST_NETWORK"),
                (r"hostPID:\s*true", "HIGH", "K8S_HOST_PID"),
                (r"hostIPC:\s*true", "MEDIUM", "K8S_HOST_IPC"),
                (r"readOnlyRootFilesystem:\s*false", "MEDIUM", "K8S_WRITABLE_ROOT_FS"),
                (r"runAsNonRoot:\s*false", "HIGH", "K8S_RUN_AS_ROOT"),
                (
                    r"automountServiceAccountToken:\s*true",
                    "MEDIUM",
                    "K8S_AUTOMOUNT_SA_TOKEN",
                ),
            ],
        }

    @property
    def metadata(self) -> PluginMetadata:
        """Returns metadata for the IaC scanning plugin."""
        return PluginMetadata(
            name="iac_scanner",
            version="1.3.0",
            vendor="DataWizual Lab - Auditor Core",
            description="Analyzes IaC files (TF, Docker, K8s) with enterprise path filtering",
        )

    def scan(
        self,
        project_path: str,
        files: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> List[Finding]:
        """
        Scans for IaC files in the project directory, respecting exclusions.
        """
        findings = []
        iac_exts = {".tf", ".tfvars", ".dockerfile", ".yaml", ".yml"}

        try:
            target_abs = Path(project_path).resolve()

            for root, dirs, files in os.walk(str(target_abs)):
                # Filter directories based on exclude list
                if exclude:
                    dirs[:] = [d for d in dirs if d not in exclude]

                # Self-analysis protection to avoid scanning the auditor itself
                auditor_root = str(Path(__file__).resolve().parent.parent)
                if str(Path(root).resolve()).startswith(auditor_root):
                    continue

                for file in files:
                    path_obj = Path(root) / file
                    # Check extension OR specific filename (Dockerfile)
                    if (
                        path_obj.suffix.lower() in iac_exts
                        or file.lower() == "dockerfile"
                    ):
                        try:
                            with open(
                                path_obj, "r", encoding="utf-8", errors="ignore"
                            ) as f:
                                content = f.read()

                            # Calculate relative path for reporting
                            rel_path = str(path_obj.relative_to(target_abs)).replace(
                                "\\", "/"
                            )
                            findings.extend(self.scan_file(rel_path, content))
                        except Exception:
                            continue
        except Exception:
            logger.error("IaC Scanner: Critical error during directory traversal.")

        return findings

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        """Processes an individual file for IaC vulnerabilities."""
        path_obj = Path(file_path)
        tech_type = self._detect_tech_type(path_obj, content)
        tech_key = tech_type if tech_type != "unknown" else "generic"
        findings = self._analyze_content(content, file_path, tech_key)
        if tech_type == "kubernetes":
            findings.extend(self._check_k8s_absence(content, file_path))
        return findings

    def _detect_tech_type(self, file_path: Path, content: str) -> str:
        """
        Identifies the technology stack of the file.
        Fix for Issue 9: Validates Kubernetes content before assignment.
        """
        suffix = file_path.suffix.lower()
        name = file_path.name.lower()

        if name == "dockerfile" or suffix == ".dockerfile":
            return "dockerfile"

        if suffix in [".tf", ".tfvars"]:
            return "terraform"

        if suffix in [".yaml", ".yml"]:
            # Issue 9 Fix: Verify if YAML is actually a Kubernetes manifest
            is_k8s = re.search(r"^\s*apiVersion:", content, re.MULTILINE) and re.search(
                r"^\s*kind:", content, re.MULTILINE
            )
            if is_k8s:
                return "kubernetes"
            return "unknown"

        return "unknown"

    def _analyze_content(
        self, content: str, file_path: str, tech: str
    ) -> List[Finding]:
        """Matches specific security patterns against the file content."""
        findings = []
        lines = content.splitlines()

        # Default patterns for generic/unknown configurations
        default_patterns = [
            (r"0\.0\.0\.0/0", "HIGH", "IAC_GENERAL_OPEN_NETWORK"),
            (r"(?i)admin" + r"_password", "CRITICAL", "IAC_GENERIC_PASSWORD"),
        ]

        patterns = self.iac_patterns.get(tech, default_patterns)

        for line_num, line in enumerate(lines, 1):
            line_s = line.strip()
            # Skip empty lines, comments, and boilerplate
            if not line_s or line_s.startswith(("#", "//", "import", "from")):
                continue

            for item in patterns:
                pattern, severity, rule_id = item[0], item[1], item[2]
                description = (
                    item[3]
                    if len(item) > 3
                    else f"Security risk in {tech} configuration: {rule_id}"
                )
                if re.search(pattern, line_s, re.IGNORECASE):
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            file_path=file_path,
                            line=line_num,
                            description=description,
                            severity=severity,
                            detector="IacScanner",
                        )
                    )
        return findings

    def _check_k8s_absence(self, content: str, file_path: str) -> List[Finding]:
        """
        Detects missing security fields in Kubernetes manifests.
        Absence checks cannot be done with line-by-line regex.
        """
        findings = []

        # resource limits — отсутствие блока resources: в containers
        if "containers:" in content and "resources:" not in content:
            findings.append(
                Finding(
                    rule_id="K8S_NO_RESOURCE_LIMITS",
                    file_path=file_path,
                    line=1,
                    description=(
                        "No resource limits defined for containers. "
                        "Missing CPU/memory limits allow noisy-neighbour DoS attacks."
                    ),
                    severity="MEDIUM",
                    detector="IacScanner",
                )
            )

        # readOnlyRootFilesystem отсутствует (не выставлено явно)
        if "containers:" in content and "readOnlyRootFilesystem:" not in content:
            findings.append(
                Finding(
                    rule_id="K8S_MISSING_READONLY_FS",
                    file_path=file_path,
                    line=1,
                    description=(
                        "readOnlyRootFilesystem is not set. "
                        "Set to true to limit blast radius of a compromised container."
                    ),
                    severity="LOW",
                    detector="IacScanner",
                )
            )

        # runAsNonRoot отсутствует
        if "containers:" in content and "runAsNonRoot:" not in content:
            findings.append(
                Finding(
                    rule_id="K8S_MISSING_RUN_AS_NON_ROOT",
                    file_path=file_path,
                    line=1,
                    description=(
                        "runAsNonRoot is not set. "
                        "Explicitly set runAsNonRoot: true to prevent root container execution."
                    ),
                    severity="MEDIUM",
                    detector="IacScanner",
                )
            )

        return findings
