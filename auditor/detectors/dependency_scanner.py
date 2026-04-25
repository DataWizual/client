"""
Dependency Scanner - Auditor Core Professional.
Offline Software Composition Analysis (SCA) engine with Zero Call-Home policy.
"""

import json
import re
import os
import logging
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from auditor.detectors.plugin_base import DetectorPlugin, PluginMetadata
from auditor.core.engine import Finding

logger = logging.getLogger(__name__)


class DependencyScanner(DetectorPlugin):
    """
    Identifies vulnerable dependencies in Python, Node.js, and Ruby projects.
    Uses a local JSON database to ensure maximum privacy and offline capability.
    """

    def __init__(self):
        super().__init__()
        # Path to the local vulnerability database
        self.db_path = (
            Path(__file__).resolve().parent.parent
            / "resources"
            / "vulnerability_db.json"
        )
        self.vulnerabilities = self._load_db()

    def _load_db(self) -> Dict:
        """Loads the local vulnerability definitions from JSON."""
        if self.db_path.exists():
            try:
                with open(self.db_path, "r") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"SCA: Failed to load vulnerability database: {e}")

        # Fallback to internal list if DB is missing or corrupted
        logger.error(
            "SCA: Vulnerability database not found or corrupted. "
            "Dependency scanning will be skipped to avoid false positives."
        )
        return {"pypi": [], "npm": []}

    @property
    def metadata(self) -> PluginMetadata:
        """Returns plugin metadata for the orchestration engine."""
        return PluginMetadata(
            name="DependencyScanner",
            version="1.3.0",
            vendor="DataWizual Lab - Auditor Core",
            description="Offline SCA scanner with local database and path exclusion support.",
        )

    def scan(
        self,
        project_path: str,
        files: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> List[Finding]:
        """
        Scans project directory for manifests and analyzes their dependencies.
        Respects directory exclusions (e.g., venv, node_modules).
        """
        findings = []
        manifests = {
            "requirements.txt",
            "requirements-dev.txt",
            "requirements-test.txt",
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "Pipfile",
            "Pipfile.lock",
            "Gemfile",
            "Gemfile.lock",
            "go.sum",
            "poetry.lock",
        }

        try:
            target_abs = Path(project_path).resolve()
        except Exception:
            return []

        for root, dirs, files in os.walk(target_abs):
            # RCA Item: Efficiency - Prune excluded directories immediately
            if exclude:
                dirs[:] = [d for d in dirs if d not in exclude]

            for file in files:
                if file in manifests:
                    file_path = Path(root) / file
                    try:
                        # Normalize path for reporting
                        rel_path = os.path.relpath(file_path, target_abs).replace(
                            "\\", "/"
                        )

                        with open(
                            file_path, "r", encoding="utf-8", errors="ignore"
                        ) as f:
                            content = f.read()

                        if file in (
                            "requirements.txt",
                            "requirements-dev.txt",
                            "requirements-test.txt",
                        ):
                            findings.extend(
                                list(self._scan_requirements_txt(content, rel_path))
                            )
                        elif file in ("package.json", "package-lock.json"):
                            findings.extend(
                                list(self._scan_package_json(content, rel_path))
                            )
                        elif file == "yarn.lock":
                            findings.extend(
                                list(self._scan_yarn_lock(content, rel_path))
                            )
                        elif file in ("Pipfile", "Pipfile.lock"):
                            findings.extend(list(self._scan_pipfile(content, rel_path)))
                        elif file in ("Gemfile", "Gemfile.lock"):
                            findings.extend(list(self._scan_gemfile(content, rel_path)))
                        elif file == "go.sum":
                            findings.extend(list(self._scan_go_sum(content, rel_path)))
                        elif file == "poetry.lock":
                            findings.extend(
                                list(self._scan_poetry_lock(content, rel_path))
                            )

                    except Exception as e:
                        logger.error(f"SCA: Failed to process {file}: {e}")

        return findings

    def _get_vulns(self, package: str, ecosystem: str) -> List[Dict]:
        """
        Returns list of vulnerability records matching the package name.
        Supports both legacy flat list format and new versioned record format.
        """
        ecosystem_db = self.vulnerabilities.get(ecosystem, [])
        results = []
        for entry in ecosystem_db:
            # Legacy format: flat string list
            if isinstance(entry, str):
                if entry.lower() == package.lower():
                    results.append(
                        {
                            "name": package,
                            "vuln_id": "UNKNOWN",
                            "affected": None,
                            "cvss": 7.5,
                            "description": f"Known vulnerable package: '{package}'",
                        }
                    )
            # New format: versioned record
            elif isinstance(entry, dict):
                if entry.get("name", "").lower() == package.lower():
                    results.append(entry)
        return results

    def _is_version_affected(
        self, installed_version: str, affected_range: Optional[str]
    ) -> bool:
        """
        Checks if installed_version falls within the affected version range.
        Range format: "<2.28.2", ">=1.0,<2.0", "==1.2.3"
        Falls back to True (conservative) if version cannot be parsed.
        """
        if not affected_range or not installed_version:
            return True  # conservative: no version info = assume vulnerable
        # Strip leading operators for wildcard/unpinned versions
        if installed_version in ("*", "", "latest"):
            return True
        try:
            from packaging.version import Version
            from packaging.specifiers import SpecifierSet

            spec = SpecifierSet(affected_range)
            # Strip common prefixes from lockfile versions: ^1.2, ~1.2, >=1.2
            clean = (
                re.sub(r"^[\^~>=<!\s]+", "", installed_version).split(",")[0].strip()
            )
            return Version(clean) in spec
        except Exception:
            return True  # conservative fallback

    def _scan_requirements_txt(self, content: str, file_path: str) -> Iterable[Finding]:
        pattern = r"^([a-zA-Z0-9_\-\[\]]+)([=<>!~]+[a-zA-Z0-9\.\-\*]+)?.*$"
        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(pattern, line)
            if match:
                package = match.group(1).lower()
                version = match.group(2).lstrip("=<>!~") if match.group(2) else ""
                for vuln in self._get_vulns(package, "pypi"):
                    if self._is_version_affected(version, vuln.get("affected")):
                        yield Finding(
                            rule_id="DEP_VULN_PYPI",
                            severity="HIGH",
                            file_path=file_path,
                            line=line_num,
                            description=(
                                f"{vuln.get('vuln_id', 'VULN')}: Vulnerable PyPI package "
                                f"'{package}=={version}' — {vuln.get('description', '')} "
                                f"Affected: {vuln.get('affected', 'unknown range')}."
                            ),
                            cvss_score=float(vuln.get("cvss", 7.5)),
                            detector="DependencyScanner",
                        )

    def _scan_package_json(self, content: str, file_path: str) -> Iterable[Finding]:
        try:
            data = json.loads(content)
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for package, version in deps.items():
                for vuln in self._get_vulns(package, "npm"):
                    if self._is_version_affected(version, vuln.get("affected")):
                        yield Finding(
                            rule_id="DEP_VULN_NPM",
                            severity="HIGH",
                            file_path=file_path,
                            line=1,
                            description=(
                                f"{vuln.get('vuln_id', 'VULN')}: Vulnerable NPM package "
                                f"'{package}@{version}' — {vuln.get('description', '')} "
                                f"Affected: {vuln.get('affected', 'unknown range')}."
                            ),
                            cvss_score=float(vuln.get("cvss", 7.5)),
                            detector="DependencyScanner",
                        )
        except json.JSONDecodeError:
            pass

    def _scan_pipfile(self, content: str, file_path: str) -> Iterable[Finding]:
        """Checks Pipfile for insecure versioning practices."""
        if re.search(r'=\s*["\'][*]["\']', content):
            yield Finding(
                rule_id="DEP_WILDCARD_VERSION",
                severity="MEDIUM",
                file_path=file_path,
                line=1,
                description="Wildcard versioning '*' detected in Pipfile. This allows unverified package updates.",
                cvss_score=4.0,
                detector="DependencyScanner",
            )

    def _scan_gemfile(self, content: str, file_path: str) -> Iterable[Finding]:
        """Analyzes Ruby Gemfiles for insecure source definitions."""
        if "http://" in content:
            yield Finding(
                rule_id="DEP_INSECURE_SOURCE",
                severity="MEDIUM",
                file_path=file_path,
                line=1,
                description="Insecure HTTP source detected in Gemfile. Use HTTPS to prevent MITM attacks.",
                cvss_score=5.0,
                detector="DependencyScanner",
            )

    def _scan_yarn_lock(self, content: str, file_path: str) -> Iterable[Finding]:
        """Parses yarn.lock for vulnerable NPM packages."""
        # yarn.lock format: "package@version:\n  version \"x.y.z\""
        current_package = None
        for line_num, line in enumerate(content.splitlines(), 1):
            pkg_match = re.match(r'^"?([a-zA-Z0-9_\-@/\.]+)@', line)
            if pkg_match:
                current_package = pkg_match.group(1).lstrip("@").split("/")[-1]
            ver_match = re.match(r'\s+version\s+"([^"]+)"', line)
            if ver_match and current_package:
                version = ver_match.group(1)
                for vuln in self._get_vulns(current_package, "npm"):
                    if self._is_version_affected(version, vuln.get("affected")):
                        yield Finding(
                            rule_id="DEP_VULN_NPM",
                            severity="HIGH",
                            file_path=file_path,
                            line=line_num,
                            description=(
                                f"{vuln.get('vuln_id', 'VULN')}: Vulnerable NPM package "
                                f"'{current_package}@{version}' in yarn.lock. "
                                f"Affected: {vuln.get('affected', 'unknown range')}."
                            ),
                            cvss_score=float(vuln.get("cvss", 7.5)),
                            detector="DependencyScanner",
                        )

    def _scan_go_sum(self, content: str, file_path: str) -> Iterable[Finding]:
        """Parses go.sum for vulnerable Go modules."""
        for line_num, line in enumerate(content.splitlines(), 1):
            # go.sum format: module version hash
            parts = line.strip().split()
            if len(parts) >= 2:
                module = parts[0]
                version = parts[1].lstrip("v").split("/")[0]
                package = module.split("/")[-1]
                for vuln in self._get_vulns(package, "go"):
                    if self._is_version_affected(version, vuln.get("affected")):
                        yield Finding(
                            rule_id="DEP_VULN_GO",
                            severity="HIGH",
                            file_path=file_path,
                            line=line_num,
                            description=(
                                f"{vuln.get('vuln_id', 'VULN')}: Vulnerable Go module "
                                f"'{module}@v{version}'. "
                                f"Affected: {vuln.get('affected', 'unknown range')}."
                            ),
                            cvss_score=float(vuln.get("cvss", 7.5)),
                            detector="DependencyScanner",
                        )

    def _scan_poetry_lock(self, content: str, file_path: str) -> Iterable[Finding]:
        """Parses poetry.lock for vulnerable PyPI packages."""
        current_package = None
        current_version = None
        for line_num, line in enumerate(content.splitlines(), 1):
            name_match = re.match(r'^name\s*=\s*"([^"]+)"', line)
            if name_match:
                current_package = name_match.group(1).lower()
            ver_match = re.match(r'^version\s*=\s*"([^"]+)"', line)
            if ver_match:
                current_version = ver_match.group(1)
            if current_package and current_version:
                for vuln in self._get_vulns(current_package, "pypi"):
                    if self._is_version_affected(current_version, vuln.get("affected")):
                        yield Finding(
                            rule_id="DEP_VULN_PYPI",
                            severity="HIGH",
                            file_path=file_path,
                            line=line_num,
                            description=(
                                f"{vuln.get('vuln_id', 'VULN')}: Vulnerable PyPI package "
                                f"'{current_package}=={current_version}' in poetry.lock. "
                                f"Affected: {vuln.get('affected', 'unknown range')}."
                            ),
                            cvss_score=float(vuln.get("cvss", 7.5)),
                            detector="DependencyScanner",
                        )
                current_package = None
                current_version = None

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        """Individual file scanning is handled via the bulk directory scan method."""
        return []
