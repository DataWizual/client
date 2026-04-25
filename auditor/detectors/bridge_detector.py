"""
Bridge Detector - Auditor Web3 Suite.
Specialized logic engine for Cross-Chain Bridge security analysis.
"""

import subprocess
import json
import os
import logging
import shutil
from typing import List, Optional
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


class BridgeDetector(DetectorPlugin):
    """
    Connects Auditor Core to specialized 'bridge_logic.yaml' rules.
    Designed to detect complex logical flaws in cross-chain protocols
    using static analysis with ReDoS protection.
    """

    def __init__(self):
        super().__init__()
        self.name = "BridgeDetector"

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="BridgeDetector",
            version="1.1.2",
            vendor="DataWizual Lab - Auditor Core",
            description="Specialized logic scanner for Web3 Bridges with ReDoS and DoS protection.",
        )

    def _build_exclude_args(
        self, project_path: Path, exclude: Optional[List[str]]
    ) -> List[str]:
        """
        Build --exclude arguments using hard-excluded directory names.
        Semgrep accepts directory names directly — no need for absolute paths.
        Total capped at 20 patterns to stay within OS limits.
        """
        excluded = set()

        for dirname in HARD_EXCLUDE_DIRS:
            excluded.add(dirname)

        if exclude:
            for pattern in exclude:
                # Убираем glob-префиксы как подстроку, затем валидируем
                clean = (
                    pattern.strip().lstrip("/").replace("../", "").replace("..\\", "")
                )
                # Разрешаем только простые имена директорий или однуровневые пути
                # без компонентов обхода директорий
                if (
                    clean
                    and len(clean) < 128
                    and ".." not in clean
                    and not os.path.isabs(clean)
                ):
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

        semgrep_bin = shutil.which("semgrep")
        if not semgrep_bin:
            logger.warning(
                "BridgeDetector: Semgrep binary not found in PATH. Skipping logic audit."
            )
            return []

        plugin_root = Path(__file__).resolve().parent.parent
        rules_path = plugin_root / "rules" / "bridge_logic.yaml"

        if not rules_path.exists():
            logger.warning(f"BridgeDetector: Custom ruleset '{rules_path}' missing.")
            return []

        try:
            target_abs = Path(project_path).resolve()

            cmd = [
                semgrep_bin,
                "scan",
                "--config",
                str(rules_path),
                "--json",
                "--quiet",
                "--timeout",
                "25",
                "--timeout-threshold",
                "3",
                "--jobs",
                "2",
            ]

            cmd.extend(self._build_exclude_args(target_abs, exclude))
            cmd.append(str(target_abs))

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=600,
                encoding="utf-8",
                errors="ignore",
            )

            if not result.stdout or not result.stdout.strip():
                return []

            if result.returncode not in (0, 1) and result.stderr:
                logger.debug(f"Semgrep stderr diagnostics: {result.stderr[:2000]}")

            data = json.loads(result.stdout)

            for res in data.get("results", []):
                raw_path = res.get("path", "")

                try:
                    clean_path = os.path.relpath(raw_path, str(target_abs))
                except ValueError:
                    clean_path = raw_path

                raw_sev = res.get("extra", {}).get("severity", "HIGH").upper()
                severity_map = {
                    "ERROR": "CRITICAL",
                    "WARNING": "HIGH",
                    "INFO": "MEDIUM",
                }
                mapped_sev = severity_map.get(raw_sev, "HIGH")

                findings.append(
                    Finding(
                        rule_id=f"BRIDGE_{str(res['check_id'].split('.')[-1]).upper()}",
                        severity=mapped_sev,
                        file_path=clean_path.replace("\\", "/"),
                        line=int(res["start"].get("line", 0)),
                        description=str(
                            res["extra"].get(
                                "message",
                                "Potential cross-chain bridge logic violation detected.",
                            )
                        ).strip(),
                        cvss_score=7.0,
                        detector="BridgeDetector",
                        meta={"code_snippet": res["extra"].get("lines", "")},
                    )
                )

        except subprocess.TimeoutExpired:
            logger.error(
                "BridgeDetector: Global scan timeout reached. Check for complex regex in bridge_logic.yaml."
            )
        except json.JSONDecodeError:
            logger.error("BridgeDetector: Failed to parse Semgrep JSON output.")
        except Exception as e:
            logger.error(f"BridgeDetector: Internal execution failure: {e}")

        return findings

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        return []
