"""
classifier.py — Triage findings by severity and category.

Design:
    - PURE FUNCTION: list of Finding in, dict out, zero side effects.
    - Zero network calls, zero file I/O, zero mutations beyond return value.
    - Fully unit-testable without mocks (see tests/test_classifier.py in Step 19).

Why separate from scanner and remediator:
    - Scanner's job: find things.
    - Classifier's job: organize things.
    - Remediator's job: fix things.
    Changing triage policy = classifier change only, scanner and remediator stable.

Output shape:
    {
        "total_count": 7,
        "by_severity": {
            "CRITICAL": {"count": 2, "findings": [Finding, Finding]},
            "HIGH": {"count": 5, "findings": [Finding, ..., Finding]},
            "MEDIUM": {"count": 0, "findings": []},
            "LOW": {"count": 0, "findings": []},
        },
        "by_category": {
            "PUBLIC_IAM_BINDING": {"count": 2, "findings": [...]},
            "PUBLIC_BUCKET_ACCESS": {"count": 5, "findings": [...]},
        },
    }
"""

import logging
from collections import OrderedDict
from typing import List, Dict, Any

from scanner import Finding   # Reuses the Finding dataclass from scanner.py

logger = logging.getLogger(__name__)

# Severity ordering for presentation (highest first).
# Using OrderedDict means reports always display CRITICAL before HIGH, etc.,
# without needing an explicit sort call downstream.
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def classify(findings: List[Finding]) -> Dict[str, Any]:
    """
    Group a flat list of findings into severity buckets and category buckets.

    Args:
        findings: list of Finding dataclass instances from scanner.py.

    Returns:
        dict with 'total_count', 'by_severity', and 'by_category' keys.
        Empty severities and categories are included with count=0 so the
        reporter can render consistent output.
    """
    # Initialize ordered severity buckets so iteration order is deterministic.
    by_severity: Dict[str, Dict[str, Any]] = OrderedDict()
    for sev in SEVERITY_ORDER:
        by_severity[sev] = {"count": 0, "findings": []}

    # Category buckets build dynamically — unknown categories still get bucketed.
    by_category: Dict[str, Dict[str, Any]] = {}

    for finding in findings:
        # --- Group by severity ---
        sev = finding.severity.upper() if finding.severity else "LOW"
        if sev not in by_severity:
            # Unknown severity (e.g. a scanner added a new tier) — bucket it anyway.
            by_severity[sev] = {"count": 0, "findings": []}
        by_severity[sev]["count"] += 1
        by_severity[sev]["findings"].append(finding)

        # --- Group by category ---
        cat = finding.category
        if cat not in by_category:
            by_category[cat] = {"count": 0, "findings": []}
        by_category[cat]["count"] += 1
        by_category[cat]["findings"].append(finding)

    result = {
        "total_count": len(findings),
        "by_severity": by_severity,
        "by_category": by_category,
    }

    logger.info(
        "Classified %d findings: %s",
        result["total_count"],
        {sev: info["count"] for sev, info in by_severity.items() if info["count"] > 0},
    )

    return result
