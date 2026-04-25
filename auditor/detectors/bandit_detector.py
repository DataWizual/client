import subprocess
import json
import logging
import os
from typing import List, Optional, Iterable
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
    "*.egg-info",
    "testdata",
    "fixtures",
    "mocks",
    "reports",
}


class BanditDetector(DetectorPlugin):
    """
    Enterprise Bandit Wrapper.
    Hardened against RCE and DoS. Optimized for high-speed Python source code analysis.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="bandit_detector",
            version="1.7.5",
            vendor="DataWizual Lab - Auditor Core",
            description="Security linter for Python source code using Bandit.",
        )

    def __init__(self):
        super().__init__()
        self.timeout = 600

    def _build_exclude_paths(
        self, project_path: str, exclude: Optional[List[str]]
    ) -> List[str]:
        """
        Build a compact list of absolute exclude paths.
        Hard excludes are resolved to real paths under project_path.
        Config excludes are added only if they resolve to existing directories.
        Total list is capped at 20 to stay well within OS argument limits.
        """
        safe_path = Path(project_path).resolve()
        excluded = set()

        # Hard excludes — resolve to absolute paths under project root
        import fnmatch as _fnmatch

        for dirname in HARD_EXCLUDE_DIRS:
            if any(c in dirname for c in ("*", "?", "[")):
                # glob pattern — expand under project root
                for match in safe_path.glob(dirname):
                    if match.exists():
                        excluded.add(str(match))
            else:
                candidate = safe_path / dirname
                if candidate.exists():
                    excluded.add(str(candidate))

        # Config excludes — clean pattern and resolve
        if exclude:
            for pattern in exclude:
                clean = pattern.rstrip("/*").lstrip("**/")
                candidate = safe_path / clean
                if candidate.exists():
                    excluded.add(str(candidate))

        result = sorted(excluded)[:20]
        return result

    def scan(
        self,
        project_path: str,
        files: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> List[Finding]:
        findings = []

        try:
            safe_path = str(Path(project_path).resolve())
        except Exception:
            logger.error("Bandit: Critical error during project path resolution.")
            return []

        cmd = ["bandit", "-r", safe_path, "-f", "json", "-q", "--aggregate", "file"]

        exclude_paths = self._build_exclude_paths(project_path, exclude)
        if exclude_paths:
            cmd.extend(["-x", ",".join(exclude_paths)])

        try:
            process = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout, check=False
            )

            if not process.stdout.strip():
                return []

            data = json.loads(process.stdout)

            for issue in data.get("results", []):
                raw_path = issue.get("filename", "")
                try:
                    abs_path = Path(raw_path).resolve()
                    rel_path = str(abs_path.relative_to(Path(safe_path).resolve()))
                except ValueError:
                    rel_path = raw_path.replace(safe_path, "").lstrip("/\\")

                findings.append(
                    Finding(
                        rule_id=f"BANDIT_{issue.get('test_id')}",
                        severity=issue.get("issue_severity", "LOW").upper(),
                        file_path=rel_path.replace("\\", "/"),
                        line=issue.get("line_number", 0),
                        description=issue.get("issue_text", ""),
                        detector="BanditDetector",
                        meta={
                            "code": issue.get("code", "").strip(),
                            # test_id is used by ReachabilityHeuristic to classify
                            # dangerous sinks (B602, B608, etc.) vs low-signal hits
                            "test_id": issue.get("test_id", ""),
                        },
                    )
                )

        except subprocess.TimeoutExpired:
            logger.error(f"Bandit: Analysis timed out after {self.timeout}s.")
        except json.JSONDecodeError:
            logger.error(
                "Bandit: Failed to parse JSON output. Check Bandit installation."
            )
        except Exception as e:
            logger.error(f"Bandit: Internal execution error: {e}")

        return findings

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        logger.debug(
            "BanditDetector: scan_file is not supported; use scan() with project_path."
        )
        return []
