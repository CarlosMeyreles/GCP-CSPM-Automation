"""
test_classifier.py — pure-function tests for classifier.py.

Classifier has no I/O, no mocks needed. Fast, deterministic, exhaustive.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner import Finding
from classifier import classify, SEVERITY_ORDER


def test_empty_list_returns_zero_counts():
    """Empty input must produce a well-formed result with zero counts."""
    result = classify([])
    assert result["total_count"] == 0
    assert all(info["count"] == 0 for info in result["by_severity"].values())
    assert result["by_category"] == {}


def test_single_finding_counted_correctly():
    f = Finding(
        finding_id="x",
        resource_name="r",
        category="PUBLIC_IAM_BINDING",
        severity="CRITICAL",
    )
    result = classify([f])
    assert result["total_count"] == 1
    assert result["by_severity"]["CRITICAL"]["count"] == 1
    assert result["by_severity"]["HIGH"]["count"] == 0
    assert result["by_category"]["PUBLIC_IAM_BINDING"]["count"] == 1


def test_multiple_findings_grouped_correctly():
    findings = [
        Finding(finding_id="1", resource_name="a", category="PUBLIC_BUCKET_ACCESS", severity="HIGH"),
        Finding(finding_id="2", resource_name="b", category="PUBLIC_BUCKET_ACCESS", severity="HIGH"),
        Finding(finding_id="3", resource_name="c", category="PUBLIC_IAM_BINDING", severity="CRITICAL"),
    ]
    result = classify(findings)
    assert result["total_count"] == 3
    assert result["by_severity"]["CRITICAL"]["count"] == 1
    assert result["by_severity"]["HIGH"]["count"] == 2
    assert result["by_category"]["PUBLIC_BUCKET_ACCESS"]["count"] == 2
    assert result["by_category"]["PUBLIC_IAM_BINDING"]["count"] == 1


def test_severity_order_is_critical_first():
    """Iteration order of by_severity must be CRITICAL, HIGH, MEDIUM, LOW."""
    result = classify([])
    severity_keys = list(result["by_severity"].keys())
    assert severity_keys[0] == "CRITICAL"
    assert severity_keys == SEVERITY_ORDER


def test_unknown_severity_bucketed_dynamically():
    """A finding with a weird severity must still be bucketed, not dropped."""
    f = Finding(finding_id="x", resource_name="r", category="X", severity="UNKNOWN_SEVERITY")
    result = classify([f])
    assert "UNKNOWN_SEVERITY" in result["by_severity"]
    assert result["by_severity"]["UNKNOWN_SEVERITY"]["count"] == 1
