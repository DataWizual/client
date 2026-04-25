"""
Baseline Logic Engine - Auditor Core Professional.
Implements 'Most Specific Rule Wins' logic with weighted priority.
"""

import fnmatch
import logging
from typing import List, Optional
from pathlib import PurePosixPath

# Maintaining strict imports for internal compatibility
from auditor.core.engine import Finding
from auditor.database.models import BaselineRule

logger = logging.getLogger(__name__)


class BaselineMatcher:
    """
    Advanced matching engine for filtering security findings based on database rules.
    Priority scoring ensures precise rules override generic ones:
    - Rule ID + Exact Path: 150
    - Rule ID only: 100
    - Path Glob only: 20-50
    """

    def __init__(self, rules: List[BaselineRule]):
        # Store active rules sorted by specificity weight (highest priority first)
        self._rules = sorted(
            [r for r in rules if r.is_active],
            key=self._calculate_specificity,
            reverse=True,
        )

    def filter_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Processes findings through the database-backed baseline.
        Supports IGNORE (Suppression) and DOWNGRADE (Risk adjustment) actions.
        """
        if not self._rules:
            logger.debug("Baseline Matcher: No active rules found. Skipping filtering.")
            return findings

        original_count = len(findings)
        filtered_findings = []

        for finding in findings:
            matched_rule = self._find_match(finding)

            if matched_rule:
                action = matched_rule.action.upper()

                # Logic: Complete suppression of the finding
                if action in ["IGNORE", "SUPPRESS"]:
                    logger.info(
                        f"Baseline: Suppressing {finding.rule_id} at {finding.file_path} "
                        f"(Matched Rule ID: {matched_rule.id})"
                    )
                    continue

                # Logic: Downgrade severity to INFO (Enterprise risk management feature)
                if action == "DOWNGRADE":
                    original_severity = finding.severity
                    # Use target_severity from rule if set, default to INFO
                    target_sev = (
                        getattr(matched_rule, "target_severity", None) or "INFO"
                    )
                    finding = finding.model_copy(
                        update={
                            "severity": target_sev,
                            "description": f"[POLICY-DOWNGRADE] {finding.description}",
                            "meta": {
                                **finding.meta,
                                "original_severity": original_severity,
                            },
                        }
                    )

            filtered_findings.append(finding)

        if original_count != len(filtered_findings):
            logger.info(
                f"Baseline: Filtered out {original_count - len(filtered_findings)} findings."
            )

        return filtered_findings

    def _find_match(self, finding: Finding) -> Optional[BaselineRule]:
        """Iterates through prioritized rules and returns the first matching object."""
        for rule in self._rules:
            if self._matches(rule, finding):
                return rule
        return None

    def _matches(self, rule: BaselineRule, finding: Finding) -> bool:
        """
        Performs a logical check to see if a baseline rule applies to a specific finding.
        """
        # 1. Match Rule ID (if specified)
        if rule.rule_id and rule.rule_id.strip() and rule.rule_id != finding.rule_id:
            return False

        # 2. Match Path via Glob pattern (supporting complex masks like **/tests/*.py)
        if rule.path_glob:
            # Normalize paths for cross-platform matching (Posix standard)
            target_path = str(finding.file_path).replace("\\", "/")
            pattern = rule.path_glob.replace("\\", "/")

            try:
                # Use PurePosixPath for robust semantic matching
                if not PurePosixPath(target_path).match(pattern):
                    # Fallback to fnmatch for complex globbing support
                    if not fnmatch.fnmatch(target_path, pattern):
                        return False
            except Exception as e:
                logger.error(f"Baseline Matcher: Pattern matching error: {e}")
                return False

        return True

    def _calculate_specificity(self, rule: BaselineRule) -> int:
        """
        Weighted priority system. Ensures precise matches take precedence over broad ones.
        RCA Item: Implementing stable deterministic filtering.
        """
        score = 0
        # Rule ID matches are highly specific
        if rule.rule_id:
            score += 100

        # Path matches vary based on globbing complexity
        if rule.path_glob:
            # Exact paths (no wildcards) are more specific than global patterns
            score += 50 if "*" not in rule.path_glob else 20

        return score
