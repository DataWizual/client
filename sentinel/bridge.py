"""
Auditor Bridge — связующий модуль между Auditor Core и Sentinel Engine.

Два режима работы:
1. Passive  — читает уже существующий JSON отчёт (быстро, для CI)
2. Active   — сам запускает AuditorRunner, генерирует отчёт, читает результат

Структура JSON отчёта от JSONReporter:
{
    "findings": [
        {
            "id": "...",
            "severity": "HIGH",
            "ai_advisory": {          ← ai_recommendations вшиты внутрь finding
                "verdict": "SUPPORTED",
                "reasoning": "...",
                "confidence": 85
            },
            ...
        }
    ]
}
"""

import os
import json
import glob
import logging
from pathlib import Path
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


class AuditorBridge:
    """
    Мост между Auditor Core и Sentinel.
    Sentinel не анализирует — он только исполняет решение Auditor.
    """

    SEVERITY_MAP = {
        "CRITICAL": "BLOCK",
        "HIGH":     "BLOCK",
        "MEDIUM":   "WARN",
        "LOW":      "WARN",
        "INFO":     "INFO",
    }

    def __init__(self, report_path: Optional[str] = None, auto_run: bool = False,
                 auditor_config: Optional[dict] = None, license_key: Optional[str] = None):
        """
        Args:
            report_path:    Явный путь к JSON отчёту. Если None — ищет последний.
            auto_run:       Если True и отчёт не найден — запускает AuditorRunner.
            auditor_config: Конфиг для AuditorRunner (нужен если auto_run=True).
            license_key:    Лицензионный ключ для AuditorRunner.
        """
        self.auto_run = auto_run
        self.auditor_config = auditor_config or {}
        self.license_key = license_key or os.getenv("AUDITOR_LICENSE_KEY", "")
        self.report_path = report_path or self._find_latest_report()

    def _find_latest_report(self) -> Optional[str]:
        """Ищет последний JSON отчёт Auditor Core."""
        search_patterns = [
            "reports/report_*.json",
            "auditor/reports/report_*.json",
        ]
        for pattern in search_patterns:
            matches = sorted(glob.glob(pattern), reverse=True)
            if matches:
                logger.info(f"🔗 Bridge: Found Auditor report: {matches[0]}")
                return matches[0]
        return None

    def is_available(self) -> bool:
        """Проверяет доступность отчёта."""
        return bool(self.report_path and os.path.exists(self.report_path))

    def ensure_report(self, target_path: str = ".") -> bool:
        """
        Гарантирует наличие актуального отчёта.
        Если auto_run=True и отчёта нет — запускает AuditorRunner.
        """
        if self.is_available():
            return True

        if not self.auto_run:
            logger.debug("Bridge: No report found, auto_run disabled.")
            return False

        logger.info("🔗 Bridge: No report found. Running Auditor Core...")
        try:
            from auditor.runner import AuditorRunner
            runner = AuditorRunner(self.auditor_config, self.license_key)
            report = runner.run(target_path)
            if report:
                self.report_path = report
                return True
        except Exception as e:
            logger.error(f"Bridge: AuditorRunner failed: {e}")

        return False

    def load_violations(self) -> List[Dict]:
        """
        Загружает SUPPORTED findings из отчёта и конвертирует в Sentinel violations.

        JSONReporter хранит AI данные внутри каждого finding в поле ai_advisory:
        finding["ai_advisory"]["verdict"] == "SUPPORTED"
        """
        if not self.is_available():
            logger.debug("Bridge: Report not available.")
            return []

        try:
            with open(self.report_path, "r", encoding="utf-8") as f:
                report = json.load(f)
        except Exception as e:
            logger.error(f"Bridge: Failed to read report: {e}")
            return []

        violations = []
        findings = report.get("findings", [])

        for finding in findings:
            # AI данные вшиты внутрь finding в поле ai_advisory
            ai_data = finding.get("ai_advisory", {})
            verdict = ai_data.get("verdict", "")

            # Берём только AI-верифицированные реальные угрозы
            if verdict != "SUPPORTED":
                continue

            severity_raw = finding.get("severity", "MEDIUM").upper()
            sentinel_sev = self.SEVERITY_MAP.get(severity_raw, "WARN")

            file_path = finding.get("file_path", "unknown")
            line = finding.get("line", 0)
            description = finding.get("description", "No description")
            rule_id = finding.get("rule_id", "AUDITOR")
            reasoning = ai_data.get("reasoning", ai_data.get("advice", ""))
            confidence = ai_data.get("confidence", 0)

            violations.append({
                "rule_id":       f"AUDITOR-{rule_id}",
                "location":      f"{file_path}:{line}",
                "message":       f"[{sentinel_sev}] AUDITOR-{rule_id}: {description}",
                "severity":      sentinel_sev,
                "cvss_score":    float(finding.get("cvss", 7.5)),
                "cwe":           finding.get("cwe", "CWE-Generic"),
                "compliance":    "ISO 27001 A.14.2.1 / SOC 2 CC8.1",
                "is_overridden": False,
                "justification": None,
                "remediation":   reasoning or "Remediate per Auditor Core recommendation.",
                "ai_insight":    (
                    f"Auditor Core: SUPPORTED "
                    f"(confidence: {confidence}%). {reasoning}"
                ),
                "_source":       "auditor_bridge",
                "_verdict":      verdict,
            })

        logger.info(
            f"🔗 Bridge: {len(violations)} SUPPORTED findings loaded "
            f"from {Path(self.report_path).name}"
        )
        return violations