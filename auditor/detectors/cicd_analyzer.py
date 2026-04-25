"""
CI/CD Configuration Analyzer.
Identifies overly permissive permissions, secrets in environment, and script injections.
"""

import os
import re
import yaml
import logging
from pathlib import Path
from typing import List, Dict, Any, Iterable, Optional

from auditor.detectors.plugin_base import DetectorPlugin, PluginMetadata
from auditor.core.engine import Finding

logger = logging.getLogger(__name__)

# Security threshold to prevent DoS via large YAML files (YAML bombs)
MAX_CICD_FILE_SIZE = 500 * 1024


class CicdAnalyzer(DetectorPlugin):
    """
    Analyzes CI/CD configuration files (GitHub Actions, GitLab CI, Jenkins)
    for security vulnerabilities and misconfigurations.
    """

    def __init__(self):
        super().__init__()
        # Untrusted contexts that can lead to script injection in shell steps
        self.dangerous_contexts = [
            r"github\.event\.pull_request\.title",
            r"github\.event\.pull_request\.body",
            r"github\.event\.issue\.title",
            r"github\.event\.issue\.body",
            r"github\.event\.comment\.body",
            r"github\.event\.review\.body",
            r"github\.actor",
            r"github\.head_ref",
        ]
        # Secret patterns for detecting hardcoded credentials
        self.secret_patterns = [
            re.compile(r"gh[pousr]_[A-Za-z0-9_]{10,}"),
            re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"),
            re.compile(r"gldt-[A-Za-z0-9\-_]{20,}"),
            re.compile(r"AKIA[0-9A-Z]{16}"),
            re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
            re.compile(
                r"(?i)(password|secret|token|api_key)\s*=\s*(?P<q>['\"])[A-Za-z0-9_\-]{8,256}(?P=q)"
            ),
        ]

    @property
    def metadata(self) -> PluginMetadata:
        """Returns plugin metadata for the orchestration engine."""
        return PluginMetadata(
            name="cicd_analyzer",
            version="1.4.0",
            vendor="DataWizual Lab - Auditor Core",
            description="Security analyzer for CI/CD configurations with exclusion support.",
        )

    def scan(
        self,
        project_path: str,
        files: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> List[Finding]:
        """
        Walks through the project to find and analyze CI/CD configuration files.
        """
        findings = []
        try:
            target_abs = Path(project_path).resolve()
        except Exception:
            return []

        for root, dirs, files in os.walk(target_abs):
            # Apply directory exclusions on the fly
            if exclude:
                dirs[:] = [
                    d
                    for d in dirs
                    if not any(
                        d == ex or str(Path(root) / d).endswith(ex) for ex in exclude
                    )
                ]

            for file in files:
                full_path = Path(root) / file

                # Check file size before processing to prevent DoS
                MEDIA_EXTENSIONS = {
                    ".jpg",
                    ".jpeg",
                    ".png",
                    ".gif",
                    ".bmp",
                    ".svg",
                    ".ico",
                    ".mp4",
                    ".mov",
                    ".avi",
                    ".mkv",
                    ".webm",
                    ".mp3",
                    ".wav",
                    ".ogg",
                    ".pdf",
                    ".zip",
                    ".tar",
                    ".gz",
                    ".whl",
                    ".exe",
                    ".bin",
                }
                if full_path.suffix.lower() in MEDIA_EXTENSIONS:
                    continue

                try:
                    if full_path.stat().st_size > MAX_CICD_FILE_SIZE:
                        logger.warning(
                            f"CI/CD: Skipping {file} (File exceeds size limit)."
                        )
                        continue
                except OSError:
                    continue

                # Identify CI/CD configuration files
                path_str = str(full_path).replace("\\", "/")
                if (
                    ".github/workflows" in path_str
                    or ".github/actions" in path_str
                    or file == ".gitlab-ci.yml"
                    or ".circleci/config" in path_str
                    or file in ("azure-pipelines.yml", "azure-pipelines.yaml")
                    or file == "bitbucket-pipelines.yml"
                    or "Jenkinsfile" in file
                ):
                    try:
                        with open(
                            full_path, "r", encoding="utf-8", errors="ignore"
                        ) as f:
                            content = f.read()

                        # Get path relative to target for clean reporting
                        rel_path = os.path.relpath(full_path, target_abs)
                        findings.extend(self.scan_file(rel_path, content))
                    except Exception as e:
                        logger.error(f"CI/CD: Error reading {file}: {e}")

        return findings

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        """
        Analyzes the content of a single CI/CD file based on its detected type.
        """
        if not content or len(content) > MAX_CICD_FILE_SIZE:
            return []

        findings = []
        try:
            file_type = self._detect_file_type(file_path)

            if file_type == "github_actions":
                findings.extend(self._analyze_github_actions(content, file_path))
            elif file_type == "gitlab_ci":
                findings.extend(self._analyze_gitlab_ci(content, file_path))
            else:
                findings.extend(self._analyze_generic_cicd(content, file_path))
        except Exception as e:
            logger.error(f"CI/CD Analyzer error in {file_path}: {e}")

        return findings

    def _detect_file_type(self, file_path: str) -> str:
        p = file_path.lower().replace("\\", "/")
        if ".github/workflows" in p or ".github/actions" in p:
            return "github_actions"
        if ".gitlab-ci" in p:
            return "gitlab_ci"
        if ".circleci" in p:
            return "circleci"
        if "azure-pipelines" in p:
            return "azure_devops"
        if "bitbucket-pipelines" in p:
            return "bitbucket"
        return "generic"

    def _analyze_github_actions(self, content: str, file_path: str) -> List[Finding]:
        """Specific logic for GitHub Actions YAML analysis."""
        findings = []
        try:
            data = yaml.safe_load(content)
            if not isinstance(data, dict):
                return findings

            # 1. Dangerous Triggers
            on_event = str(data.get("on", {}))
            if "pull_request_target" in on_event:
                findings.append(
                    self._create_finding(
                        "HIGH",
                        "Workflow uses 'pull_request_target'. Risk of PR-based environment hijacking.",
                        file_path,
                        "GHA_PULL_REQUEST_TARGET",
                    )
                )

            # 2. Permissive Permissions
            permissions = data.get("permissions", {})
            if permissions == "write-all" or (
                isinstance(permissions, dict)
                and any(v == "write" for v in permissions.values())
            ):
                findings.append(
                    self._create_finding(
                        "HIGH",
                        "Workflow has excessive write permissions. Principle of least privilege violation.",
                        file_path,
                        "GHA_EXCESSIVE_PERMISSIONS",
                    )
                )

            # 3. Actions Integrity (SHA Pinning)
            findings.extend(
                self._check_env_block(
                    data.get("env", {}), content, file_path, "workflow-level"
                )
            )

            workflow_env = data.get("env", {})
            if isinstance(workflow_env, dict):
                for debug_var in ("ACTIONS_RUNNER_DEBUG", "ACTIONS_STEP_DEBUG"):
                    if str(workflow_env.get(debug_var, "")).lower() == "true":
                        findings.append(
                            self._create_finding(
                                "MEDIUM",
                                f"{debug_var}=true at workflow level may expose secrets in job logs.",
                                file_path,
                                "GHA_DEBUG_LOGGING",
                                line=self._find_line(content, debug_var),
                            )
                        )

            jobs = data.get("jobs", {})
            if isinstance(jobs, dict):
                for job_name, job in jobs.items():
                    if not isinstance(job, dict):
                        continue

                    # Job-level env:
                    findings.extend(
                        self._check_env_block(
                            job.get("env", {}), content, file_path, f"job '{job_name}'"
                        )
                    )

                    for step in job.get("steps", []) or []:
                        if not isinstance(step, dict):
                            continue

                        # Step-level env:
                        findings.extend(
                            self._check_env_block(
                                step.get("env", {}),
                                content,
                                file_path,
                                f"step '{step.get('name', 'unnamed')}'",
                            )
                        )

                        action = step.get("uses")
                        if (
                            action
                            and isinstance(action, str)
                            and not (
                                action.startswith("./")
                                or action.startswith("docker://")
                            )
                        ):
                            if "@" in action:
                                _, version = action.split("@", 1)
                                if not re.match(r"^[0-9a-f]{40}$", version):
                                    findings.append(
                                        self._create_finding(
                                            "MEDIUM",
                                            f"Unpinned action '{action}'. Use a full SHA hash to prevent supply chain attacks.",
                                            file_path,
                                            "GHA_UNPINNED_ACTION",
                                        )
                                    )
                            else:
                                findings.append(
                                    self._create_finding(
                                        "HIGH",
                                        f"Action '{action}' is missing a version pin.",
                                        file_path,
                                        "GHA_NO_VERSION_PIN",
                                    )
                                )

                        with_block = step.get("with", {})
                        if isinstance(with_block, dict):
                            for param_key, param_val in with_block.items():
                                if not isinstance(param_val, str):
                                    continue
                                match = re.search(
                                    r"{{\s*("
                                    + "|".join(self.dangerous_contexts)
                                    + r")\s*}}",
                                    param_val,
                                )
                                if match:
                                    findings.append(
                                        self._create_finding(
                                            "HIGH",
                                            f"Untrusted context '{match.group(1)}' passed via with: "
                                            f"param '{param_key}' to action '{step.get('uses', 'unknown')}'. "
                                            f"The action may forward this value into a shell command.",
                                            file_path,
                                            "GHA_WITH_INJECTION",
                                            line=self._find_line(content, param_key),
                                        )
                                    )

                        # 4. Script Injection Detection
                        run_cmd = step.get("run", "")
                        if run_cmd and isinstance(run_cmd, str):
                            matched_contexts = [
                                ctx
                                for ctx in self.dangerous_contexts
                                if re.search(r"{{\s*" + ctx + r"\s*}}", run_cmd)
                            ]
                            if matched_contexts:
                                line = self._find_line(
                                    content,
                                    matched_contexts[0]
                                    .replace(r"\.", ".")
                                    .split(r"\[")[0],
                                )
                                findings.append(
                                    self._create_finding(
                                        "CRITICAL",
                                        f"Script Injection: untrusted context(s) used directly in shell run: — "
                                        f"{', '.join(matched_contexts)}. "
                                        f"Assign to an env var and sanitise before use.",
                                        file_path,
                                        "GHA_SCRIPT_INJECTION",
                                        line=line,
                                    )
                                )

                            # workflow_dispatch / inputs.* direct use
                            if re.search(
                                r"{{\s*(?:github\.event\.inputs|inputs)\.[A-Za-z0-9_\-]+\s*}}",
                                run_cmd,
                            ):
                                findings.append(
                                    self._create_finding(
                                        "HIGH",
                                        "workflow_dispatch or reusable workflow input used directly in run: step. "
                                        "User-controlled inputs can contain shell metacharacters.",
                                        file_path,
                                        "GHA_DISPATCH_INJECTION",
                                        line=self._find_line(content, "run:"),
                                    )
                                )

                        if step.get("continue-on-error") is True:
                            step_name_lower = step.get("name", "").lower()
                            security_keywords = (
                                "scan",
                                "trivy",
                                "snyk",
                                "bandit",
                                "semgrep",
                                "audit",
                                "security",
                                "lint",
                                "sast",
                                "vuln",
                            )
                            if any(kw in step_name_lower for kw in security_keywords):
                                findings.append(
                                    self._create_finding(
                                        "MEDIUM",
                                        f"Step '{step.get('name')}' has continue-on-error:true. "
                                        f"Security scan failures will not block the pipeline.",
                                        file_path,
                                        "GHA_SECURITY_STEP_SKIPPABLE",
                                        line=self._find_line(
                                            content, "continue-on-error"
                                        ),
                                    )
                                )
        except Exception as e:
            logger.warning(f"CI/CD: GitHub Actions parse error in {file_path}: {e}")
        return findings

    def _analyze_gitlab_ci(self, content: str, file_path: str) -> List[Finding]:
        """Specific logic for GitLab CI analysis."""
        findings = []
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict):
                variables = data.get("variables", {})
                if isinstance(variables, dict):
                    for k, v in variables.items():
                        # Removed len(v) > 32 check - pattern matching is sufficient
                        if isinstance(v, str):
                            for pat in self.secret_patterns:
                                if pat.search(v):
                                    findings.append(
                                        self._create_finding(
                                            "CRITICAL",
                                            f"Potential secret hardcoded in GitLab CI variable '{k}'. "
                                            f"Use GitLab CI/CD masked variables instead.",
                                            file_path,
                                            "GL_SECRET_IN_VARS",
                                            line=self._find_line(content, k),
                                        )
                                    )
                                    break
        except Exception:
            pass
        return findings

    def _analyze_generic_cicd(self, content: str, file_path: str) -> List[Finding]:
        """Fallback analysis for Jenkinsfiles and other CI scripts."""
        findings = []
        patterns = [
            (
                r'password\s*[:=]\s*["\'][^"\']{4,}["\']',
                "CRITICAL",
                "CICD_HARDCODED_SECRET",
            ),
            (r"sudo\s+", "MEDIUM", "CICD_SUDO_USAGE"),
        ]
        for pattern, sev, rid in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(
                    self._create_finding(
                        sev, f"Pipeline Security Risk: {rid}", file_path, rid
                    )
                )
        return findings

    def _create_finding(
        self,
        severity: str,
        description: str,
        file_path: str,
        rule_id: str,
        line: int = 1,
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            severity=severity.upper(),
            file_path=file_path.replace("\\", "/"),
            line=line,
            description=description,
            detector="cicd_analyzer",
        )

    def _check_env_block(
        self, env: object, content: str, file_path: str, scope: str
    ) -> List[Finding]:
        """Checks any env: dict for untrusted context injection."""
        findings = []
        if not isinstance(env, dict):
            return findings
        for key, value in env.items():
            if not isinstance(value, str):
                continue
            match = re.search(
                r"{{\s*(" + "|".join(self.dangerous_contexts) + r")\s*}}", value
            )
            if match:
                line = self._find_line(content, key)
                findings.append(
                    self._create_finding(
                        "HIGH",
                        f"ENV_INJECT_GHA: Untrusted context '{match.group(1)}' injected "
                        f"into env var '{key}' at {scope}. "
                        f"If used in a subsequent run: step this becomes a script injection vector.",
                        file_path,
                        "GHA_ENV_CONTEXT_INJECTION",
                        line=line,
                    )
                )
        return findings

    def _find_line(self, content: str, key: str) -> int:
        """Regex pre-pass: returns 1-based line of first occurrence of key."""
        for i, line in enumerate(content.splitlines(), 1):
            if re.search(re.escape(key), line):
                return i
        return 1

    def _analyze_circleci(self, content: str, file_path: str) -> List[Finding]:
        findings = []
        try:
            data = yaml.safe_load(content)
            if not isinstance(data, dict):
                return findings

            # Hardcoded env vars in job environment blocks
            for job_name, job in (data.get("jobs", {}) or {}).items():
                if not isinstance(job, dict):
                    continue
                env = job.get("environment", {})
                if isinstance(env, dict):
                    for k, v in env.items():
                        if not isinstance(v, str):
                            continue
                        for pat in self.secret_patterns:
                            if pat.search(v):
                                findings.append(
                                    self._create_finding(
                                        "CRITICAL",
                                        f"Potential secret hardcoded in CircleCI job "
                                        f"'{job_name}' environment var '{k}'.",
                                        file_path,
                                        "CIRCLECI_HARDCODED_SECRET",
                                        line=self._find_line(content, k),
                                    )
                                )
                                break

            # Privileged mode
            if re.search(r"privileged:\s*true", content):
                findings.append(
                    self._create_finding(
                        "HIGH",
                        "CircleCI job runs in privileged Docker mode.",
                        file_path,
                        "CIRCLECI_PRIVILEGED",
                        line=self._find_line(content, "privileged: true"),
                    )
                )
        except Exception:
            pass
        return findings

    def _analyze_azure_devops(self, content: str, file_path: str) -> List[Finding]:
        findings = []
        try:
            data = yaml.safe_load(content)
            if not isinstance(data, dict):
                return findings

            # Hardcoded variables
            variables = data.get("variables", [])
            var_items = variables if isinstance(variables, list) else []
            for item in var_items:
                if isinstance(item, dict):
                    val = str(item.get("value", ""))
                    name = item.get("name", "")
                    for pat in self.secret_patterns:
                        if pat.search(val):
                            findings.append(
                                self._create_finding(
                                    "CRITICAL",
                                    f"Potential secret hardcoded in Azure DevOps variable '{name}'. "
                                    f"Use Azure Key Vault or secret variable groups instead.",
                                    file_path,
                                    "ADO_HARDCODED_SECRET",
                                    line=self._find_line(content, name),
                                )
                            )
                            break

            # Script injection via $() or inline expressions
            for line_no, line in enumerate(content.splitlines(), 1):
                if re.search(r"\$\(Build\.SourceBranchName\)", line):
                    findings.append(
                        self._create_finding(
                            "HIGH",
                            "Azure DevOps: Build.SourceBranchName used in script — "
                            "branch names are attacker-controlled in fork PRs.",
                            file_path,
                            "ADO_BRANCH_INJECTION",
                            line=line_no,
                        )
                    )
        except Exception:
            pass
        return findings

    def _analyze_bitbucket(self, content: str, file_path: str) -> List[Finding]:
        findings = []
        try:
            data = yaml.safe_load(content)
            if not isinstance(data, dict):
                return findings

            # Check for privileged Docker steps
            def _walk_steps(obj: object) -> None:
                if isinstance(obj, dict):
                    if obj.get("privileged") is True:
                        findings.append(
                            self._create_finding(
                                "HIGH",
                                "Bitbucket Pipelines step runs in privileged Docker mode. "
                                "This grants host-level capabilities to the container.",
                                file_path,
                                "BB_PRIVILEGED_STEP",
                                line=self._find_line(content, "privileged: true"),
                            )
                        )
                    for v in obj.values():
                        _walk_steps(v)
                elif isinstance(obj, list):
                    for item in obj:
                        _walk_steps(item)

            _walk_steps(data)

            # Hardcoded credentials in script lines
            for line_no, line in enumerate(content.splitlines(), 1):
                for pat in self.secret_patterns:
                    if pat.search(line):
                        findings.append(
                            self._create_finding(
                                "CRITICAL",
                                "Potential hardcoded secret found in Bitbucket Pipelines script.",
                                file_path,
                                "BB_HARDCODED_SECRET",
                                line=line_no,
                            )
                        )
                        break
        except Exception:
            pass
        return findings
