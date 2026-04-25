"""
Core Logic Unit Tests - Auditor Suite.
Covers Finding validation, deduplication, and Policy thresholds based on context.
"""

import pytest
from auditor.core.engine import Finding, AuditProcessor
from auditor.core.policy import PolicyEngine, DecisionAction


# 1. VALIDATION & NORMALIZATION TESTS
def test_finding_validation_and_normalization():
    f = Finding(
        rule_id="test-01",
        file_path="src/main.py",
        line=10,
        description="Test finding",
        severity="crit",
    )
    assert f.severity == "CRITICAL"


# 2. DEDUPLICATION & STATISTICAL INTEGRITY
def test_processor_stats_and_dedup():
    config = {"scanner": {"max_findings": 100}}
    processor = AuditProcessor(config)

    finding_data = {
        "rule_id": "secret-key",
        "file_path": "config.env",
        "line": 1,
        "description": "API Key exposed",
        "severity": "HIGH",
    }

    processor.add_finding(finding_data)
    processor.add_finding(finding_data)
    processor.add_finding(finding_data)

    assert len(processor.findings) == 1
    total_issues = sum(processor.summary.values())
    assert total_issues == 1


# 3. LIMITS & ACCURATE SUMMARY
def test_max_findings_limit_and_summary():
    config = {"scanner": {"max_findings": 1}}
    processor = AuditProcessor(config)

    processor.add_finding(
        {
            "rule_id": "r1",
            "file_path": "f1",
            "line": 1,
            "description": "d",
            "severity": "CRITICAL",
        }
    )
    processor.add_finding(
        {
            "rule_id": "r2",
            "file_path": "f2",
            "line": 2,
            "description": "d",
            "severity": "CRITICAL",
        }
    )

    assert len(processor.findings) == 1
    assert processor.summary["CRITICAL"] == 2


# 4. POLICY ENGINE THRESHOLDS (CORE FAIL)
def test_policy_engine_thresholds():
    engine = PolicyEngine({})

    f = Finding(
        rule_id="C1",
        file_path="P1",
        line=1,
        description="D",
        severity="HIGH",
        meta={"context_label": "CORE"},
    )

    class MockResult:
        def __init__(self, findings):
            self.findings = findings

    decision = engine.evaluate(MockResult([f]))
    assert decision.action == DecisionAction.FAIL


# 5. POLICY ENGINE WARN (TEST CONTEXT)
def test_policy_engine_polymorphic_summary():
    engine = PolicyEngine({})

    f = Finding(
        rule_id="T1",
        file_path="tests/fixture.py",
        line=1,
        description="Test Issue",
        severity="HIGH",
        meta={"context_label": "TEST"},
    )

    class MockResult:
        def __init__(self, findings):
            self.findings = findings

    decision = engine.evaluate(MockResult([f]))

    assert decision.action == DecisionAction.PASS


def test_baseline_suppression_logic():
    from auditor.core.baseline import BaselineEngine

    engine = BaselineEngine("baseline.json")

    rule_id, file_path, line = "R1", "F1", 1
    f1 = Finding(
        rule_id=rule_id,
        file_path=file_path,
        line=line,
        description="D",
        severity="HIGH",
    )

    fp = engine._generate_fingerprint(rule_id, file_path, line)
    engine.known_fingerprints.add(fp)

    assert engine.is_baselined(f1) is True
