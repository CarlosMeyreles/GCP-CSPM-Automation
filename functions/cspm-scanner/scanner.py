"""
scanner.py — Fallback-path CSPM scanner using Cloud Asset Inventory + Cloud Storage APIs.

Why fallback and not SCC:
    In Step 1d we confirmed Security Command Center returns 404 on personal
    GCP accounts without an organization. The fallback uses two always-free
    APIs that produce findings equivalent to what SCC Standard would report.

Design:
    - Emits `Finding` dataclasses matching SCC's shape (abstraction layer).
    - Downstream (classifier, remediator, reporter) doesn't know which scanner ran.
    - Deterministic finding_id via UUID5 so repeat findings dedup in BigQuery.
    - Severity assigned via SEVERITY_MAP dict (policy, not logic).

Two rule categories implemented:
    1. PUBLIC_IAM_BINDING — any binding granting allUsers or allAuthenticatedUsers
    2. PUBLIC_BUCKET_ACCESS — any bucket with publicAccessPrevention != enforced
"""

import logging
import uuid
from dataclasses import dataclass, field
from typing import List

from google.cloud import asset_v1
from google.cloud import storage

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# POLICY: finding category → severity mapping.
# Changing severities is a policy decision, not a code change.
# In production this would come from a YAML config or a database.
# -----------------------------------------------------------------------------
SEVERITY_MAP = {
    "PUBLIC_IAM_BINDING": "CRITICAL",     # Public IAM grants = immediate pager
    "PUBLIC_BUCKET_ACCESS": "HIGH",       # Could be made public = business-day fix
}

# Namespace UUID for deterministic finding_id generation.
# Keeping a constant namespace means the same (resource + category) always
# produces the same finding_id across runs.
FINDING_ID_NAMESPACE = uuid.UUID("12345678-1234-5678-1234-567812345678")

# Members that indicate public access when granted any role.
PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


# =============================================================================
# FINDING dataclass — the pipeline's canonical finding shape
# -----------------------------------------------------------------------------
# Matches SCC's finding fields so downstream code is scanner-agnostic.
# =============================================================================
@dataclass
class Finding:
    """A single security finding. Immutable once created."""

    finding_id: str          # Deterministic UUID5 (resource + category)
    resource_name: str       # Full GCP resource name (e.g. //storage.googleapis.com/.../buckets/foo)
    category: str            # PUBLIC_IAM_BINDING | PUBLIC_BUCKET_ACCESS
    severity: str            # LOW | MEDIUM | HIGH | CRITICAL
    state: str = "ACTIVE"    # ACTIVE | REMEDIATED | SUPPRESSED
    details: dict = field(default_factory=dict)  # Rule-specific context


def _make_finding_id(resource_name: str, category: str) -> str:
    """Deterministic UUID5 — same resource+category always gets same ID."""
    return str(uuid.uuid5(FINDING_ID_NAMESPACE, f"{resource_name}|{category}"))


# =============================================================================
# RULE 1: Public IAM bindings via Cloud Asset Inventory
# -----------------------------------------------------------------------------
# CAI's searchAllIamPolicies finds every IAM policy in the project.
# We filter for ones where any binding's `members` list contains allUsers
# or allAuthenticatedUsers.
# =============================================================================
def _scan_public_iam_bindings(project_id: str) -> List[Finding]:
    """Returns findings for all IAM bindings granting allUsers / allAuthenticatedUsers."""
    client = asset_v1.AssetServiceClient()
    scope = f"projects/{project_id}"
    findings = []

    try:
        # Query CAI for IAM policies with public members.
        # The query string is CAI's filter DSL — this one matches policies
        # mentioning either public principal.
        results = client.search_all_iam_policies(
            request={
                "scope": scope,
                "query": "policy:(allUsers OR allAuthenticatedUsers)",
                "page_size": 100,
            }
        )

        for result in results:
            # Each result is a resource with its IAM policy attached.
            # We extract the bindings that specifically grant to public members.
            for binding in result.policy.bindings:
                public_members = [m for m in binding.members if m in PUBLIC_MEMBERS]
                if not public_members:
                    continue

                findings.append(Finding(
                    finding_id=_make_finding_id(result.resource, "PUBLIC_IAM_BINDING"),
                    resource_name=result.resource,
                    category="PUBLIC_IAM_BINDING",
                    severity=SEVERITY_MAP["PUBLIC_IAM_BINDING"],
                    details={
                        "role": binding.role,
                        "public_members": public_members,
                    },
                ))

    except Exception as e:
        # Never let the scanner crash — log and return what we have.
        # A partial scan is more useful than no scan.
        logger.exception("Error scanning IAM bindings: %s", e)

    logger.info("Found %d public IAM binding finding(s)", len(findings))
    return findings


# =============================================================================
# RULE 2: Buckets without public-access-prevention enforced
# -----------------------------------------------------------------------------
# Cloud Storage API lists all buckets; we check each one's PAP setting.
# A bucket with PAP="inherited" is a bucket that COULD be made public by
# changing one setting — enterprise policy says lock it to "enforced."
# =============================================================================
def _scan_public_bucket_access(project_id: str) -> List[Finding]:
    """Returns findings for buckets with publicAccessPrevention != enforced."""
    client = storage.Client(project=project_id)
    findings = []

    try:
        for bucket in client.list_buckets():
            # iam_configuration.public_access_prevention is 'enforced' or 'inherited'.
            # 'inherited' means it uses org-level default, which may not be enforced.
            pap = bucket.iam_configuration.public_access_prevention
            if pap == "enforced":
                continue  # This bucket is correctly locked down.

            # Build the full resource name in CAI/SCC canonical form.
            resource_name = f"//storage.googleapis.com/projects/_/buckets/{bucket.name}"

            findings.append(Finding(
                finding_id=_make_finding_id(resource_name, "PUBLIC_BUCKET_ACCESS"),
                resource_name=resource_name,
                category="PUBLIC_BUCKET_ACCESS",
                severity=SEVERITY_MAP["PUBLIC_BUCKET_ACCESS"],
                details={
                    "bucket_name": bucket.name,
                    "current_pap": pap or "inherited",
                    "required_pap": "enforced",
                },
            ))

    except Exception as e:
        logger.exception("Error scanning bucket PAP: %s", e)

    logger.info("Found %d public bucket access finding(s)", len(findings))
    return findings


# =============================================================================
# PUBLIC ENTRY POINT — called by main.py
# =============================================================================
def scan(project_id: str) -> List[Finding]:
    """
    Run all scanner rules against the project.
    Returns a flat list of Finding objects.
    """
    logger.info("Starting CSPM scan on project: %s", project_id)

    all_findings = []
    all_findings.extend(_scan_public_iam_bindings(project_id))
    all_findings.extend(_scan_public_bucket_access(project_id))

    logger.info("Scan complete. Total findings: %d", len(all_findings))
    return all_findings
