"""
Semgrep Detector - Auditor Core Professional.
Enterprise-ready Semgrep wrapper with memory-safe streaming and dynamic timeout management.
"""

import subprocess
import json
import logging
import shutil
import os
import tempfile
from typing import Iterable, List, Optional
from pathlib import Path

from auditor.detectors.plugin_base import DetectorPlugin, PluginMetadata
from auditor.core.engine import Finding

logger = logging.getLogger(__name__)

# Hard-excluded directories — never passed to OS argument list
HARD_EXCLUDE_DIRS = {
    "venv",
    ".venv",
    "env",
    "node_modules",
    ".git",
    "__pycache__",
    "dist",
    "build",
    "site-packages",
    ".tox",
    ".eggs",
    "testdata",
    "fixtures",
    "mocks",
    "reports",
}


class SemgrepDetector(DetectorPlugin):
    """
    Orchestrates Semgrep analysis using both default and proprietary logic rules.
    Optimized for memory efficiency by using temporary file streaming for large reports.
    """

    def __init__(self):
        super().__init__()
        self.name = "Semgrep"
        self.semgrep_bin = shutil.which("semgrep")
        rules_dir = Path(__file__).resolve().parent.parent / "rules"
        self.rules_path = rules_dir / "semgrep_rules.yaml"

        self.use_registry_fallback = not self.rules_path.exists()

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="SemgrepDetector",
            version="1.4.0",
            vendor="DataWizual Lab - Auditor Core",
            description="Enterprise-ready Semgrep wrapper with memory-safe streaming and dynamic path resolution.",
        )

    def _calculate_dynamic_timeout(self, project_path: Path) -> int:
        try:
            file_count = sum([len(files) for r, d, files in os.walk(project_path)])
            return max(300, min(60 + (file_count * 2), 1800))
        except Exception:
            return 600

    def _build_exclude_args(
        self, project_path: Path, exclude: Optional[List[str]]
    ) -> List[str]:
        """
        Build --exclude arguments using hard-excluded directory names.
        Semgrep accepts directory names directly — no need for absolute paths.
        Total capped at 20 patterns to stay within OS limits.
        """
        excluded = set()

        # Hard excludes — directory names only, semgrep handles matching
        for dirname in HARD_EXCLUDE_DIRS:
            excluded.add(dirname)

        # Config excludes — strip glob syntax, keep clean names
        if exclude:
            for pattern in exclude:
                clean = pattern.rstrip("/*").lstrip("**/").strip()
                if clean and len(clean) < 255:
                    excluded.add(clean)

        args = []
        for item in sorted(excluded)[:20]:
            args.extend(["--exclude", item])
        return args

    def scan(
        self,
        project_path: str,
        files: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> List[Finding]:

        findings = []

        if not self.semgrep_bin:
            logger.warning("Semgrep: Binary not found. Skipping.")
            return []

        try:
            target_abs = Path(project_path).resolve()
        except Exception:
            return []

        timeout = self._calculate_dynamic_timeout(target_abs)

        config_args = []
        if self.rules_path.exists():
            config_args.extend(["--config", str(self.rules_path)])
        elif self.use_registry_fallback:
            logger.warning(
                "Semgrep: No local rules found. "
                "Falling back to 'p/owasp-top-ten' (requires network)."
            )
            config_args.extend(["--config", "p/owasp-top-ten"])

        with tempfile.NamedTemporaryFile(
            mode="w+", suffix=".json", delete=True
        ) as tmp_report:

            cmd = (
                [self.semgrep_bin, "scan"]
                + config_args
                + ["--json", "--quiet", "--output", tmp_report.name, "--jobs", "2"]
            )

            cmd.extend(self._build_exclude_args(target_abs, exclude))
            cmd.append(str(target_abs))

            try:
                subprocess.run(cmd, timeout=timeout, shell=False)

                tmp_report.seek(0)
                content = tmp_report.read()
                if not content:
                    return []

                data = json.loads(content)

                severity_map = {
                    "ERROR": "CRITICAL",
                    "HIGH": "HIGH",
                    "WARNING": "HIGH",
                    "MEDIUM": "MEDIUM",
                    "INFO": "INFO",
                    "LOW": "LOW",
                }

                for match in data.get("results", []):
                    extra = match.get("extra", {})
                    raw_sev = extra.get("severity", "WARNING").upper()

                    # Extract variable name from Semgrep metavars if present.
                    # Semgrep captures like $VAR, $INPUT, $SINK are stored in
                    # extra.metavars — used by ReachabilityHeuristic / TaintEngine.
                    metavars = extra.get("metavars", {})
                    variable = None
                    for key in ("$VAR", "$INPUT", "$SINK", "$X", "$VALUE"):
                        if key in metavars:
                            variable = metavars[key].get("abstract_content", "")
                            break

                    meta = {}
                    if variable:
                        meta["variable"] = variable

                    findings.append(
                        Finding(
                            rule_id=str(match.get("check_id")),
                            severity=severity_map.get(raw_sev, "LOW"),
                            file_path=match.get("path", ""),
                            line=int(match.get("start", {}).get("line", 0)),
                            column=int(match.get("start", {}).get("col", 0)),
                            description=str(
                                extra.get("message", "No description provided.")
                            ),
                            cvss_score=0.0,
                            detector="SemgrepDetector",
                            meta=meta,
                        )
                    )

            except Exception as e:
                logger.error(f"Semgrep failure: {e}")

        return findings

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        return []
