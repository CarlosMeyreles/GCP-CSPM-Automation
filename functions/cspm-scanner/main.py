"""
main.py — CSPM scanner Cloud Function entry point.

Follows Google's canonical Cloud Functions Gen 2 HTTP pattern:
  - No import functions_framework at module scope (buildpack handles wrapping)
  - Handler takes (request) and returns a tuple (body, status, headers)
  - entry_point in Terraform points at the function name
"""

import json
import logging
import os
import uuid
from datetime import datetime, timezone

from scanner import scan
from classifier import classify
from remediator import fix_public_buckets, fix_iam_bindings
from reporter import report

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

PROJECT_ID     = os.environ.get("GCP_PROJECT_ID", "")
BQ_DATASET     = os.environ.get("BQ_DATASET", "cspm_results")
REPORTS_BUCKET = os.environ.get("REPORTS_BUCKET", "")
DRY_RUN        = os.environ.get("DRY_RUN", "true").lower() == "true"


def cspm_scan(request):
    """
    Cloud Functions Gen 2 HTTP entry point.
    The Google Python buildpack auto-wraps this when entry_point='cspm_scan'.
    No decorator needed when running inside Cloud Functions.
    """
    scan_id = str(uuid.uuid4())
    scan_timestamp = datetime.now(timezone.utc)

    logger.info(
        "CSPM scan starting. scan_id=%s project=%s dry_run=%s",
        scan_id, PROJECT_ID, DRY_RUN,
    )

    if not PROJECT_ID:
        return (json.dumps({"error": "GCP_PROJECT_ID not configured", "scan_id": scan_id}), 500, {"Content-Type": "application/json"})
    if not REPORTS_BUCKET:
        return (json.dumps({"error": "REPORTS_BUCKET not configured", "scan_id": scan_id}), 500, {"Content-Type": "application/json"})

    try:
        findings = scan(PROJECT_ID)
        logger.info("Scan complete. scan_id=%s findings=%d", scan_id, len(findings))

        classified = classify(findings)

        remediations = []
        remediations.extend(fix_public_buckets(PROJECT_ID, findings, dry_run=DRY_RUN))
        remediations.extend(fix_iam_bindings(PROJECT_ID, findings, dry_run=DRY_RUN))
        logger.info("Remediate complete. scan_id=%s attempted=%d dry_run=%s", scan_id, len(remediations), DRY_RUN)

        report_result = report(
            scan_id=scan_id,
            scan_timestamp=scan_timestamp,
            project_id=PROJECT_ID,
            reports_bucket=REPORTS_BUCKET,
            bq_dataset=BQ_DATASET,
            findings=findings,
            classified=classified,
            remediations=remediations,
        )

        return (
            json.dumps({
                "status": "ok",
                "scan_id": scan_id,
                "project_id": PROJECT_ID,
                "dry_run": DRY_RUN,
                "summary": {
                    "total_findings": classified["total_count"],
                    "by_severity": {sev: info["count"] for sev, info in classified["by_severity"].items() if info["count"] > 0},
                    "remediations_attempted": len(remediations),
                    "remediations_successful": sum(1 for r in remediations if r.success),
                },
                "report_output": report_result,
            }, default=str),
            200,
            {"Content-Type": "application/json"},
        )

    except Exception as e:
        logger.exception("CSPM scan FAILED. scan_id=%s", scan_id)
        return (
            json.dumps({"status": "error", "scan_id": scan_id, "error": str(e)}),
            500,
            {"Content-Type": "application/json"},
        )
