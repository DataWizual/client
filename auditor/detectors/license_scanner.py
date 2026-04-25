import os
import logging
from typing import Iterable, List, Optional, Dict
from pathlib import Path

from auditor.detectors.plugin_base import DetectorPlugin, PluginMetadata
from auditor.core.engine import Finding

logger = logging.getLogger(__name__)


class LicenseScanner(DetectorPlugin):
    """
    Legal compliance checker for restrictive OSS licenses.
    Hardened against Symlink attacks and Information Disclosure.
    """

    @property
    def metadata(self) -> PluginMetadata:
        """Required plugin metadata for the Auditor core system."""
        return PluginMetadata(
            name="LicenseScanner",
            version="1.2.1",
            vendor="DataWizual Lab - Auditor Core",
            description="Secure legal compliance checker with path sanitization and symlink protection.",
        )

    def scan(
        self,
        project_path: str,
        files: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> List[Finding]:
        """
        Scans for license files and identifies restrictive legal markers.
        RCA Fix: Implements path validation and symlink protection.
        """
        # RCA Fix: Base path validation
        try:
            target_abs = Path(project_path).resolve()
        except Exception:
            logger.error("License Audit: Invalid target path provided.")
            return []

        if not target_abs.exists():
            logger.error("License Audit: Target directory not found on filesystem.")
            return []

        logger.info("Compliance: Starting legal license audit.")
        findings = []

        restricted_patterns = {
            "GPL": "Reciprocal license detected (GPL). May require source code disclosure.",
            "AGPL": "Network-reciprocal license (AGPL). High risk for SaaS delivery models.",
            "SSPL": "Server Side Public License detected. Commercial usage restrictions apply.",
            "MPL": "Weak copyleft license (MPL). Requires separate file maintenance.",
            "EUPL": "EU Public Licence (EUPL). Copyleft with jurisdiction-specific terms; legal review required.",
            "CDDL": "Common Development and Distribution License (CDDL). File-level copyleft; incompatible with GPL.",
            "OSL": "Open Software License (OSL). Strong copyleft with patent retaliation clause.",
            "LGPL": "Lesser GPL detected (LGPL). Dynamic linking permitted; static linking requires disclosure.",
        }

        # SPDX identifiers map → rule_id suffix (used for package.json scanning)
        SPDX_RESTRICTED = {
            "GPL-2.0",
            "GPL-3.0",
            "GPL-2.0-only",
            "GPL-3.0-only",
            "GPL-2.0-or-later",
            "GPL-3.0-or-later",
            "AGPL-3.0",
            "AGPL-3.0-only",
            "AGPL-3.0-or-later",
            "LGPL-2.0",
            "LGPL-2.1",
            "LGPL-3.0",
            "MPL-2.0",
            "EUPL-1.1",
            "EUPL-1.2",
            "CDDL-1.0",
            "OSL-3.0",
            "SSPL-1.0",
        }

        target_filenames = {
            "LICENSE",
            "COPYING",
            "LICENSE.TXT",
            "LICENSE.MD",
            "COPYRIGHT",
        }

        # Security constant: Prevent DoS via massive license files
        MAX_LICENSE_SIZE = 1 * 1024 * 1024  # 1MB

        for root, dirs, files in os.walk(target_abs):
            if exclude:
                # RCA Fix: Reliable directory filtering via Path logic
                dirs[:] = [d for d in dirs if d not in exclude]

            for file in files:
                if file.upper() in target_filenames:
                    file_path_obj = Path(root) / file

                    # RCA Fix: Symlink Attack Protection (verify file is not a link)
                    if file_path_obj.is_symlink():
                        logger.debug(f"License Audit: Skipping symlink entry: {file}")
                        continue

                    try:
                        # RCA Fix: Size check before file operation
                        if file_path_obj.stat().st_size > MAX_LICENSE_SIZE:
                            continue

                        with open(
                            file_path_obj, "r", encoding="utf-8", errors="ignore"
                        ) as f:
                            # Read initial chunk for marker identification (100KB)
                            content = f.read(102400).upper()

                            # Secure relative path construction
                            rel_file_path = str(
                                file_path_obj.relative_to(target_abs)
                            ).replace("\\", "/")

                            # Build line index once for all pattern searches
                            lines_upper = content.splitlines()
                            reported = set()
                            for lit, desc in restricted_patterns.items():
                                if lit not in content:
                                    continue
                                if lit in reported:
                                    continue
                                # Find first line containing the marker
                                hit_line = 1
                                for idx, ln in enumerate(lines_upper, start=1):
                                    if lit in ln:
                                        hit_line = idx
                                        break
                                reported.add(lit)
                                findings.append(
                                    Finding(
                                        rule_id=f"LICENSE_RISK_{lit}",
                                        severity="MEDIUM",
                                        file_path=rel_file_path,
                                        line=hit_line,
                                        description=desc,
                                        cvss_score=0.0,
                                        detector="LicenseScanner",
                                    )
                                )

                    except Exception:
                        # RCA Fix: Safe logging without path leakage
                        logger.error(
                            "License Scanner: Security exception during file processing."
                        )

        findings.extend(self._scan_package_json_spdx(target_abs, SPDX_RESTRICTED))

        return findings

    def _scan_package_json_spdx(
        self, target_abs: Path, spdx_restricted: set
    ) -> List[Finding]:
        """
        Reads 'license' field from package.json files and flags
        SPDX identifiers that match restricted licenses.
        Handles both string and {type: ...} object forms.
        """
        import json

        findings = []
        for pkg_path in target_abs.rglob("package.json"):
            # Skip node_modules
            try:
                pkg_path.relative_to(target_abs / "node_modules")
                continue
            except ValueError:
                pass

            if pkg_path.is_symlink():
                continue
            try:
                if pkg_path.stat().st_size > 512 * 1024:
                    continue
                raw = pkg_path.read_text(encoding="utf-8", errors="ignore")
                data = json.loads(raw)
            except Exception:
                logger.debug("LicenseScanner: Could not parse %s", pkg_path.name)
                continue

            license_val = data.get("license") or data.get("licence")
            if not license_val:
                continue

            # Normalise: can be string or {"type": "MIT"} object
            if isinstance(license_val, dict):
                license_val = license_val.get("type", "")
            if not isinstance(license_val, str):
                continue

            spdx_id = license_val.strip()
            if spdx_id not in spdx_restricted:
                continue

            rel = str(pkg_path.relative_to(target_abs)).replace("\\", "/")
            # Find exact line number of "license" key in raw JSON text
            hit_line = 1
            for idx, ln in enumerate(raw.splitlines(), start=1):
                if '"license"' in ln.lower() or '"licence"' in ln.lower():
                    hit_line = idx
                    break

            # Map SPDX id to a rule suffix: GPL-3.0-only → GPL
            rule_suffix = spdx_id.replace("-", "_").replace(".", "_")
            desc = (
                f"Restricted SPDX license declared in package.json: {spdx_id}. "
                f"Verify compatibility with commercial distribution terms."
            )
            findings.append(
                Finding(
                    rule_id=f"LICENSE_RISK_SPDX_{rule_suffix}",
                    severity="MEDIUM",
                    file_path=rel,
                    line=hit_line,
                    description=desc,
                    cvss_score=0.0,
                    detector="LicenseScanner",
                )
            )

        return findings

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        """Bulk directory scanning is the preferred method for this detector."""
        return []
