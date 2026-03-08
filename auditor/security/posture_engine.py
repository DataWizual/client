import math
import logging

logger = logging.getLogger(__name__)


class PostureScorer:
    """
    NOTE: Core SPI logic is duplicated from auditor/core/policy.py (PolicyEngine).
    This class should be refactored to delegate to PolicyEngine.
    """

    def __init__(self):
        self.thresholds = [
            (90, "A", "Resilient"),
            (70, "B", "Guarded"),
            (40, "C", "Elevated Risk"),
            (0, "D", "Critical Exposure"),
        ]
        self._base_k = 80.0
        self._scale_factor = 15.0
        self._rule_cap = 30.0

        self._detector_trust = {
            "GitleaksDetector": 0.6,
            "SastScanner": 1.0,
            "DependencyCheck": 0.9,
        }

    def calculate_weighted_score(self, finding) -> float:
        detector = getattr(finding, "scanner_id", "Generic")
        base_score = min(float(getattr(finding, "cvss_score", 5.0)), 8.5)
        meta = getattr(finding, "meta", {}) or {}

        ctx_label = meta.get("context_label", "CORE").upper()
        context_map = {
            "TEST": 0.05,
            "DEMO": 0.2,  # FIX: aligned with policy.py (was 0.1)
            "VENDOR": 0.4,
            "CORE": 1.0,
            "PRODUCTION": 1.0,
        }
        context_mod = context_map.get(ctx_label, 0.7)

        reachability = meta.get("taint_result", "UNKNOWN").upper()
        reach_map = {
            "STATIC_SAFE": 0.1,
            "EXPLOITABLE": 1.5,
            "TRACED": 1.0,
            "UNKNOWN": 0.6,
        }
        reach_mod = reach_map.get(reachability, 0.6)

        trust = self._detector_trust.get(detector, 0.8)
        merged = meta.get("merged_detectors", [])
        # FIX: single detector gets 0.8, consensus raises toward 1.0
        conf_mod = 0.8 + 0.2 * (1 - math.exp(-len(merged))) if merged else 0.8

        return round(base_score * context_mod * reach_mod * trust * conf_mod, 2)

    def evaluate_project_health(self, all_findings) -> dict:
        if not all_findings:
            return {"spi": 100.0, "grade": "A", "label": "Perfect"}

        exposure_by_rule = {}
        for f in all_findings:
            score = self.calculate_weighted_score(f)
            rid = getattr(f, "rule_id", "generic-rule")
            exposure_by_rule.setdefault(rid, []).append(score)

        total_exposure = 0.0
        for rid, scores in exposure_by_rule.items():
            scores.sort(reverse=True)
            weighted_rule_sum = sum(s / (i + 1) for i, s in enumerate(scores[:5]))
            total_exposure += min(weighted_rule_sum, self._rule_cap)

        n = len(all_findings)
        dynamic_k = self._base_k + math.log2(n + 1) * self._scale_factor
        spi = round(100 * math.exp(-total_exposure / dynamic_k), 1)

        # FIX: explicit fallback, no reliance on pre-loop default
        grade, label = "F", "Unknown"
        for limit, g, l in self.thresholds:
            if spi >= limit:
                grade, label = g, l
                break

        return {
            "spi": spi,
            "grade": grade,
            "label": label,
            "exposure": round(total_exposure, 2),
            "k_eff": round(dynamic_k, 2),
        }
