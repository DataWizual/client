"""
Auditor Runner - lightweight Auditor Core pipeline for use inside Sentinel.

Replaces orchestrator.py in the Sentinel context:
- No CLI, no DB, no HTML report
- Scan only -> AI -> JSON report -> exit code
- Called from sentinel/bridge.py
"""

import os
import re
import uuid
import math
import logging
import inspect
import importlib
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class AuditorRunner:
    """
    Embedded Auditor Core engine for Sentinel.
    Runs the full analysis pipeline and returns the path to the JSON report.
    """

    def __init__(self, config: Dict[str, Any], license_key: str):
        self.config = config
        self.license_key = license_key
        self.ai_config = config.get("ai", {"enabled": False})

        # Import Auditor Core components
        from auditor.security.guard import AuditorGuard
        from auditor.core.intake import FileIntake
        from auditor.core.engine import AuditProcessor
        from auditor.core.policy import PolicyEngine
        from auditor.core.baseline import BaselineEngine
        from auditor.security.validation_engine import ValidationEngine
        from auditor.security.posture_engine import PostureScorer

        self.guard = AuditorGuard()
        self.intake = FileIntake(config)
        self.processor = AuditProcessor(config)
        self.policy = PolicyEngine(config)
        self.baseline = BaselineEngine(
            config.get("scanner", {}).get("baseline_file", "baseline.json")
        )
        self.validator = ValidationEngine()
        self.scorer = PostureScorer()
        self.tools = []
        self._load_detectors()

    def _load_detectors(self):
        from auditor.detectors.plugin_base import DetectorPlugin
        detector_path = Path(__file__).parent / "detectors"
        enabled = self.config.get("detectors", {})

        for file in detector_path.glob("*.py"):
            name = file.stem
            if name in ("__init__", "plugin_base") or "ai_" in name:
                continue
            if not enabled.get(name, True):
                continue
            try:
                module = importlib.import_module(f"auditor.detectors.{name}")
                for _, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, DetectorPlugin) and obj is not DetectorPlugin:
                        self.tools.append(obj())
                        logger.debug(f"Loaded detector: {obj.__name__}")
            except Exception as e:
                logger.error(f"Failed to load detector {name}: {e}")

    def _filter_findings_for_ai(self, findings):
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        max_ai = self.ai_config.get("max_findings_per_scan", 20)
        min_sev = self.ai_config.get("min_severity_for_ai", "LOW")
        threshold = severity_order.get(min_sev, 1)
        filtered = [
            f for f in findings
            if severity_order.get(f.meta.get("detector_severity", f.severity), 0) >= threshold
        ]
        return filtered[:max_ai]

    def run(self, target_path: str) -> Optional[str]:
        """
        Runs the full analysis pipeline.

        Args:
            target_path: Path to the project to scan (current directory on git commit)

        Returns:
            Path to the generated JSON report or None on error
        """
        if self.license_key != "TRIAL" and not self.guard.verify_license(self.license_key, self.guard.get_machine_id()):
            logger.error("🛑 AuditorRunner: License verification failed.")
            return None

        # Disable AI in trial mode
        if self.license_key == "TRIAL":
            self.ai_config = {**self.ai_config, "enabled": False}

        target = Path(target_path).absolute()
        self.config["project_root"] = str(target)
        allowed_files = self.intake.collect(str(target))

        # ── STAGE 1: Scanning ──────────────────────────────────────────────────
        all_paths = {
            str(p.relative_to(target)).replace("\\", "/")
            for p in target.rglob("*") if p.is_file()
        }
        allowed_rel = {
            str(p.relative_to(target)).replace("\\", "/")
            for p in allowed_files
        }
        dynamic_excludes = list(all_paths - allowed_rel)

        for tool in self.tools:
            try:
                findings = tool.scan(
                    str(target),
                    files=allowed_files,
                    exclude=self.intake.exclude_patterns + dynamic_excludes,
                )
                for fnd in findings or []:
                    if fnd.file_path in [".", "", None]:
                        fnd.file_path = str(target)
                    fnd = fnd.model_copy(
                        update={"file_path": fnd.file_path.replace("\\", "/")}
                    )
                    if not self.baseline.is_baselined(fnd):
                        self.processor.add_finding(fnd)
            except Exception as e:
                logger.error(f"Detector {tool.__class__.__name__} failed: {e}")

        all_findings_raw = self.processor.get_all_findings()
        all_findings = [self.validator.validate(f) for f in all_findings_raw]

        # Deduplication
        severity_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        deduped = {}
        for fnd in all_findings:
            key = f"{fnd.file_path}:{fnd.line}:{getattr(fnd, 'cwe', 'UNKNOWN')}"
            if key not in deduped:
                deduped[key] = fnd
            else:
                existing = deduped[key]
                if severity_map.get(fnd.severity.upper(), 0) > severity_map.get(existing.severity.upper(), 0):
                    deduped[key] = existing.model_copy(update={"severity": fnd.severity})
        all_findings = list(deduped.values())

        # ── STAGE 2: WSPM weighting ────────────────────────────────────────────
        from auditor.security.taint_engine import analyze_risk_reachability
        for i, fnd in enumerate(all_findings):
            var_match = re.search(r"\{(\w+)\}", fnd.description)
            var_name = var_match.group(1) if var_match else None
            res = analyze_risk_reachability(fnd.file_path, fnd.line, var_name, str(target))
            fnd.meta["taint_result"] = res
            weighted = self.scorer.calculate_weighted_score(fnd)
            original_sev = fnd.severity
            s = "LOW"
            if weighted >= 8.5: s = "CRITICAL"
            elif weighted >= 7.0: s = "HIGH"
            elif weighted >= 4.0: s = "MEDIUM"
            all_findings[i] = fnd.model_copy(
                update={"cvss_score": weighted, "severity": s,
                        "meta": {**fnd.meta, "detector_severity": original_sev}}
            )

        # ── STAGE 3: AI Advisory ───────────────────────────────────────────────
        ai_recommendations_dict = {}
        if self.ai_config.get("enabled", False):
            try:
                from auditor.ai.factory import AIAdvisorFactory
                self.ai_config["project_root"] = str(target)
                advisor = AIAdvisorFactory.create(self.ai_config, global_config=self.config)
                if advisor:
                    ai_input = self._filter_findings_for_ai(all_findings)
                    raw = advisor.generate_recommendations(ai_input)
                    if isinstance(raw, list):
                        for item in raw:
                            if not isinstance(item, dict): continue
                            if item.get("type") == "static_advisory": continue
                            f_id = item.get("finding_id") or item.get("id")
                            if not f_id: continue
                            verdict = item.get("verdict") or "UNKNOWN"
                            if verdict == "UNKNOWN":
                                m = re.search(
                                    r"VERDICT:\s*(SUPPORTED|NOT_SUPPORTED)",
                                    item.get("advice", "")
                                )
                                if m: verdict = m.group(1)
                            ai_recommendations_dict[str(f_id)] = {
                                "finding_id": str(f_id),
                                "verdict": verdict,
                                "reasoning": item.get("reasoning", item.get("advice", "")),
                                "confidence": item.get("confidence", 0),
                                "exploit_chain": item.get("exploit_chain", {}),
                            }
            except Exception as e:
                logger.warning(f"AI Advisory failed: {e}")

        # ── STAGE 4: JSON report ───────────────────────────────────────────────
        decision = self.policy.evaluate(all_findings)
        output_dir = self.config.get("reporting", {}).get("output_dir", "reports")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        proj_name = target.name or "sentinel_scan"

        try:
            from auditor.reporters.json_reporter import JSONReporter
            reporter = JSONReporter()
            reporter.generate(
                all_findings,
                decision,
                output_dir,
                proj_name,
                ai_recommendations=ai_recommendations_dict or None,
            )
            # Locate the newly created report file
            reports = sorted(Path(output_dir).glob(f"report_{proj_name}*.json"), reverse=True)
            if reports:
                logger.info(f"✅ AuditorRunner: Report saved → {reports[0]}")
                return str(reports[0])
        except Exception as e:
            logger.error(f"JSON report generation failed: {e}")

        return None

    def has_critical_findings(self, report_path: str) -> bool:
        """
        Quick check: whether the report contains SUPPORTED HIGH/CRITICAL findings.
        Used for exit code in pre-commit hook.
        """
        import json
        try:
            with open(report_path, "r") as f:
                data = json.load(f)
            for finding in data.get("findings", []):
                ai = finding.get("ai_advisory", {})
                if ai.get("verdict") == "SUPPORTED":
                    sev = finding.get("severity", "")
                    if sev in ("CRITICAL", "HIGH"):
                        return True
        except Exception as e:
            logger.error(f"has_critical_findings failed: {e}")
        return False