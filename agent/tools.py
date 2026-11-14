"""
tools.py - tools for the CSPM posture advisor agent.

Three READ-ONLY tools and one DRAFT-ONLY tool. None can change any resource:
the agent's service account has no permission to, and draft_fix returns text only.

The model sees only each function's name, signature and docstring.
Rules: validate every argument, parameterize every query, never raise to the model.
"""
import json
import os
import re
from pathlib import Path

ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
_CIS_FILE = Path(__file__).parent / "cis_reference.json"
_RESOURCE_RE = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")
_FINDING_ID_RE = re.compile(r"^[A-Za-z0-9-]{8,64}$")
_CIS_ID_RE = re.compile(r"^\d{1,2}\.\d{1,2}$")
_BUCKET_RE = re.compile(r"(?:buckets/|googleapis\.com/)([a-z0-9][a-z0-9._-]{1,220})$")


def _error(message: str) -> dict:
    return {"status": "error", "message": message}


def _settings():
    return os.environ.get("GCP_PROJECT_ID"), os.environ.get("BQ_DATASET")


def query_findings(severity: str, client=None) -> dict:
    """Look up CSPM findings from the most recent scan, filtered by severity.

    Use this when the user asks what misconfigurations or findings exist, how many
    CRITICAL or HIGH issues there are, or which resources are affected. Read-only.

    Args:
        severity: One of CRITICAL, HIGH, MEDIUM or LOW (any letter case).

    Returns:
        A dict with status "ok", a count, and a list of findings (finding_id,
        resource_name, finding_category, severity, state, remediated), at most 50.
        On bad input or a lookup failure: status "error" with a short message.
    """
    severity = (severity or "").strip().upper()
    if severity not in ALLOWED_SEVERITIES:
        return _error(f"severity must be one of {sorted(ALLOWED_SEVERITIES)}")

    project, dataset = _settings()
    if not project or not dataset:
        return _error("GCP_PROJECT_ID and BQ_DATASET must be set")

    try:
        from google.cloud import bigquery

        client = client or bigquery.Client(project=project)
        table = f"`{project}.{dataset}.scan_history`"
        sql = f"""
            SELECT finding_id, resource_name, finding_category, severity, state, remediated
            FROM {table}
            WHERE scan_id = (SELECT scan_id FROM {table} ORDER BY timestamp DESC LIMIT 1)
              AND severity = @severity
            LIMIT 50
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[bigquery.ScalarQueryParameter("severity", "STRING", severity)]
        )
        rows = [dict(row) for row in client.query(sql, job_config=job_config).result()]
        return {"status": "ok", "count": len(rows), "findings": rows}
    except Exception as exc:  # never raise to the model
        return _error(f"lookup failed: {type(exc).__name__}")


def get_remediation_history(resource: str, client=None) -> dict:
    """Show what the remediator did, or would have done, to one resource.

    Use this for questions like "what happened to bucket X?" or "was Y ever fixed?".
    Records with dry_run true mean nothing was changed. Read-only.

    Args:
        resource: A bucket name such as my-bucket, or a full resource name.

    Returns:
        A dict with status "ok", a count, and up to 20 records, newest first
        (timestamp, action_type, dry_run, success, before_state, after_state,
        error_message). On bad input or a lookup failure: status "error".
    """
    resource = (resource or "").strip()
    if not _RESOURCE_RE.match(resource):
        return _error("resource must be 1-200 characters: letters, digits, '.', '_', '-', '/'")

    project, dataset = _settings()
    if not project or not dataset:
        return _error("GCP_PROJECT_ID and BQ_DATASET must be set")

    try:
        from google.cloud import bigquery

        client = client or bigquery.Client(project=project)
        sql = f"""
            SELECT timestamp, action_type, dry_run, success, before_state, after_state, error_message
            FROM `{project}.{dataset}.remediation_log`
            WHERE resource_name IN (
                @resource,
                CONCAT('//storage.googleapis.com/projects/_/buckets/', @resource),
                CONCAT('//storage.googleapis.com/', @resource)
            )
            ORDER BY timestamp DESC
            LIMIT 20
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[bigquery.ScalarQueryParameter("resource", "STRING", resource)]
        )
        records = []
        for row in client.query(sql, job_config=job_config).result():
            record = dict(row)
            record["timestamp"] = str(record["timestamp"])  # datetime is not JSON-safe
            records.append(record)
        return {"status": "ok", "count": len(records), "records": records}
    except Exception as exc:
        return _error(f"lookup failed: {type(exc).__name__}")


def explain_control(cis_id: str) -> dict:
    """Explain a CIS Google Cloud Foundation Benchmark control from the local reference file.

    Use this when the user asks what a CIS control means or how this project addresses it.
    Only a few controls are included. Read-only, no network access.

    Args:
        cis_id: A control number such as "5.1".

    Returns:
        A dict with status "ok" and the control's title, level, why it matters, how this
        project addresses it, and the benchmark version. Unknown ids return status "error"
        listing the available ids.
    """
    cis_id = (cis_id or "").strip()
    if not _CIS_ID_RE.match(cis_id):
        return _error("cis_id must look like '5.1'")
    try:
        data = json.loads(_CIS_FILE.read_text())
        controls = data["controls"]
    except (OSError, ValueError, KeyError):
        return _error("CIS reference file could not be read")
    entry = controls.get(cis_id)
    if entry is None:
        return _error(f"control {cis_id} is not in the local reference. Available: {sorted(controls)}")
    return {"status": "ok", "cis_id": cis_id, "benchmark_version": data.get("benchmark_version"), **entry}


def draft_fix(finding_id: str, client=None) -> dict:
    """Draft a SUGGESTED fix for one finding, as text for a human to review.

    Use this when the user asks how to fix a finding. This tool only returns text. It
    cannot run anything, and nothing it returns has been applied.

    Args:
        finding_id: The finding_id from query_findings.

    Returns:
        A dict with status "ok", draft_only true, the category, the resource, a
        suggested_change (gcloud and Terraform text) and a warning. Unknown findings or
        categories return status "error".
    """
    finding_id = (finding_id or "").strip()
    if not _FINDING_ID_RE.match(finding_id):
        return _error("finding_id must be 8-64 characters: letters, digits, '-'")

    project, dataset = _settings()
    if not project or not dataset:
        return _error("GCP_PROJECT_ID and BQ_DATASET must be set")

    try:
        from google.cloud import bigquery

        client = client or bigquery.Client(project=project)
        sql = f"""
            SELECT finding_id, resource_name, finding_category, severity
            FROM `{project}.{dataset}.scan_history`
            WHERE finding_id = @finding_id
            ORDER BY timestamp DESC
            LIMIT 1
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[bigquery.ScalarQueryParameter("finding_id", "STRING", finding_id)]
        )
        rows = [dict(row) for row in client.query(sql, job_config=job_config).result()]
    except Exception as exc:
        return _error(f"lookup failed: {type(exc).__name__}")

    if not rows:
        return _error("finding not found")

    finding = rows[0]
    match = _BUCKET_RE.search(finding.get("resource_name") or "")
    if not match:
        return _error("draft_fix currently supports bucket findings only")
    bucket = match.group(1)
    category = finding.get("finding_category")

    if category == "PUBLIC_BUCKET_ACCESS":
        text = (
            f"Option 1 (gcloud, one-off):\n"
            f"  gcloud storage buckets update gs://{bucket} --public-access-prevention\n\n"
            f"Option 2 (Terraform, preferred if the bucket is managed as code):\n"
            f'  resource "google_storage_bucket" "<name>" {{\n'
            f'    public_access_prevention = "enforced"\n'
            f"  }}\n\n"
            f"Check first: confirm nothing legitimately needs this bucket to be public."
        )
    elif category == "PUBLIC_IAM_BINDING":
        text = (
            f"Review first:\n"
            f"  gcloud storage buckets get-iam-policy gs://{bucket}\n\n"
            f"Then remove the public member (replace ROLE with the role shown, for example "
            f"roles/storage.objectViewer):\n"
            f"  gcloud storage buckets remove-iam-policy-binding gs://{bucket} "
            f"--member=allUsers --role=ROLE\n"
            f"  (repeat with --member=allAuthenticatedUsers if it is present)\n\n"
            f"Terraform: delete the google_storage_bucket_iam_member or _binding resource "
            f"that grants allUsers."
        )
    else:
        return _error(f"no draft template for category {category}")

    return {
        "status": "ok",
        "draft_only": True,
        "finding_id": finding_id,
        "category": category,
        "resource": finding.get("resource_name"),
        "suggested_change": text,
        "warning": "Draft for human review. Nothing was executed and this agent has no "
                   "permission to execute it.",
    }
