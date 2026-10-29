"""
remediator.py — Safe, auditable remediation of CSPM findings.

Enterprise safety guards (ALL enabled by default):
    1. dry_run=True — never mutates unless explicitly set False
    2. ALLOWED_RESOURCE_PATTERNS — allowlist of what remediator may touch
    3. Idempotency — won't "fix" something already fixed
    4. Per-finding try/except — one failure doesn't crash the scan
    5. Captures before/after state — full audit trail for compliance
    6. Structured logging with finding_id context — Cloud Logging-filterable
    7. Returns typed RemediationAction records — downstream type-safe
    8. API client reuse per invocation — no connection pool exhaustion

Interview talking point:
    This is the only module that mutates production state. Every design
    decision here is about limiting blast radius if the code has a bug.
    Compare to scanner.py and classifier.py which are read-only / pure.
"""

import logging
import re
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional

from google.cloud import storage
from google.cloud import resourcemanager_v3
from google.api_core import exceptions as google_exceptions

from scanner import Finding

logger = logging.getLogger(__name__)

# =============================================================================
# SAFETY GUARD #2 — ALLOWLIST of resource name patterns we may remediate.
# -----------------------------------------------------------------------------
# A bug in finding parsing could pass us a resource name we weren't scoped to
# touch. The allowlist ensures the remediator can only ever mutate resources
# matching these patterns, regardless of what the scanner emits.
#
# In production this would come from a config file or Secret Manager so ops
# can tune without a redeploy. For this project, hardcoded is defensible.
# =============================================================================
ALLOWED_RESOURCE_PATTERNS = [
    # Any bucket in our project (scanner emits these for public-bucket findings)
    re.compile(r"^//storage\.googleapis\.com/projects/_/buckets/[a-z0-9][a-z0-9._-]*$"),
    # Any project-level IAM policy in our project
    re.compile(r"^//cloudresourcemanager\.googleapis\.com/projects/[a-z0-9][a-z0-9-]*$"),
]

# Public members we remove when found in IAM bindings.
PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


# =============================================================================
# RemediationAction — typed return record for every attempted remediation.
# -----------------------------------------------------------------------------
# The reporter.py and BigQuery remediation_log table both consume this shape.
# Dataclass means downstream code gets type hints + autocomplete.
# =============================================================================
@dataclass
class RemediationAction:
    """One remediation attempt's full record. Written to BigQuery audit log."""

    finding_id: str                     # Links back to the Finding
    resource_name: str                  # Resource that was targeted
    action_type: str                    # FIX_PUBLIC_BUCKET | FIX_IAM_BINDING
    dry_run: bool                       # Was this a dry-run?
    success: bool                       # Did the action complete?
    before_state: Optional[str] = None  # JSON string of pre-change state
    after_state: Optional[str] = None   # JSON string of post-change state (None if dry_run)
    error_message: Optional[str] = None # Populated only on failure
    details: Dict[str, Any] = field(default_factory=dict)  # Rule-specific extras

    def to_dict(self) -> Dict[str, Any]:
        """For BigQuery insert_rows_json and reporter JSON output."""
        return asdict(self)


# =============================================================================
# SAFETY GUARD #2 helper — is this resource name on our allowlist?
# =============================================================================
def _is_allowed(resource_name: str) -> bool:
    """True iff resource_name matches at least one ALLOWED_RESOURCE_PATTERNS entry."""
    return any(pattern.match(resource_name) for pattern in ALLOWED_RESOURCE_PATTERNS)


# =============================================================================
# RULE 1: Fix public buckets (publicAccessPrevention != enforced → enforced)
# =============================================================================
def fix_public_buckets(
    project_id: str,
    findings: List[Finding],
    dry_run: bool = True,  # SAFETY GUARD #1: default dry-run
) -> List[RemediationAction]:
    """
    For every PUBLIC_BUCKET_ACCESS finding, set the bucket's
    publicAccessPrevention to 'enforced'.

    Args:
        project_id: GCP project ID (for API client scoping).
        findings: Full findings list from scanner.py (we filter internally).
        dry_run: When True (default), log intended actions but don't mutate.

    Returns:
        List of RemediationAction records — one per finding considered.
    """
    # SAFETY GUARD #8: single client per invocation, not per finding.
    client = storage.Client(project=project_id)
    actions: List[RemediationAction] = []

    # Filter to only findings this remediator handles.
    bucket_findings = [f for f in findings if f.category == "PUBLIC_BUCKET_ACCESS"]
    logger.info(
        "fix_public_buckets: processing %d finding(s), dry_run=%s",
        len(bucket_findings), dry_run,
    )

    for finding in bucket_findings:
        # SAFETY GUARD #4: per-finding try/except isolates failures.
        try:
            # SAFETY GUARD #2: allowlist check.
            if not _is_allowed(finding.resource_name):
                logger.warning(
                    "SKIP: resource not on allowlist. finding_id=%s resource=%s",
                    finding.finding_id, finding.resource_name,
                )
                actions.append(RemediationAction(
                    finding_id=finding.finding_id,
                    resource_name=finding.resource_name,
                    action_type="FIX_PUBLIC_BUCKET",
                    dry_run=dry_run,
                    success=False,
                    error_message="Resource not on remediator allowlist",
                ))
                continue

            # Extract bucket name from the resource URI.
            # Format: //storage.googleapis.com/projects/_/buckets/<name>
            bucket_name = finding.resource_name.rsplit("/", 1)[-1]
            bucket = client.get_bucket(bucket_name)

            # SAFETY GUARD #5: capture before state for audit.
            before_pap = bucket.iam_configuration.public_access_prevention or "inherited"
            before_state = f'{{"public_access_prevention": "{before_pap}"}}'

            # SAFETY GUARD #3: idempotency — don't "fix" already-fixed resources.
            if before_pap == "enforced":
                logger.info(
                    "SKIP: already enforced. finding_id=%s bucket=%s",
                    finding.finding_id, bucket_name,
                )
                actions.append(RemediationAction(
                    finding_id=finding.finding_id,
                    resource_name=finding.resource_name,
                    action_type="FIX_PUBLIC_BUCKET",
                    dry_run=dry_run,
                    success=True,
                    before_state=before_state,
                    after_state=before_state,
                    details={"skipped_reason": "already_enforced"},
                ))
                continue

            # SAFETY GUARD #1 enforcement: only mutate if dry_run=False.
            if dry_run:
                logger.info(
                    "DRY-RUN: would set public_access_prevention=enforced. "
                    "finding_id=%s bucket=%s",
                    finding.finding_id, bucket_name,
                )
                actions.append(RemediationAction(
                    finding_id=finding.finding_id,
                    resource_name=finding.resource_name,
                    action_type="FIX_PUBLIC_BUCKET",
                    dry_run=True,
                    success=True,
                    before_state=before_state,
                    after_state=None,  # No mutation = no after state
                    details={"would_set_pap_to": "enforced"},
                ))
                continue

            # Real mutation path (dry_run=False).
            bucket.iam_configuration.public_access_prevention = "enforced"
            bucket.patch()

            after_state = '{"public_access_prevention": "enforced"}'
            logger.info(
                "REMEDIATED: set public_access_prevention=enforced. "
                "finding_id=%s bucket=%s",
                finding.finding_id, bucket_name,
            )
            actions.append(RemediationAction(
                finding_id=finding.finding_id,
                resource_name=finding.resource_name,
                action_type="FIX_PUBLIC_BUCKET",
                dry_run=False,
                success=True,
                before_state=before_state,
                after_state=after_state,
            ))

        # SAFETY GUARD #6: exception taxonomy — handle each type correctly.
        except google_exceptions.PermissionDenied as e:
            logger.error(
                "PERMISSION DENIED on bucket remediation. finding_id=%s error=%s",
                finding.finding_id, e,
            )
            actions.append(_failed_action(finding, "FIX_PUBLIC_BUCKET", dry_run, str(e)))
        except google_exceptions.NotFound as e:
            # Resource was deleted between scan and remediation. Not a failure.
            logger.info(
                "Resource vanished mid-scan (likely deleted). finding_id=%s",
                finding.finding_id,
            )
            actions.append(_failed_action(finding, "FIX_PUBLIC_BUCKET", dry_run,
                                          f"Resource not found: {e}"))
        except Exception as e:
            logger.exception(
                "Unexpected error on bucket remediation. finding_id=%s",
                finding.finding_id,
            )
            actions.append(_failed_action(finding, "FIX_PUBLIC_BUCKET", dry_run, str(e)))

    return actions


# =============================================================================
# RULE 2: Fix public IAM bindings (remove allUsers / allAuthenticatedUsers)
# =============================================================================
def fix_iam_bindings(
    project_id: str,
    findings: List[Finding],
    dry_run: bool = True,  # SAFETY GUARD #1: default dry-run
) -> List[RemediationAction]:
    """
    For every PUBLIC_IAM_BINDING finding on the project IAM policy, remove
    allUsers and allAuthenticatedUsers members from each binding.

    Note: this remediator only handles PROJECT-LEVEL IAM bindings. Bucket-level
    IAM would need a separate code path using the Storage API's getIamPolicy.
    """
    client = resourcemanager_v3.ProjectsClient()
    actions: List[RemediationAction] = []

    iam_findings = [f for f in findings if f.category == "PUBLIC_IAM_BINDING"]
    logger.info(
        "fix_iam_bindings: processing %d finding(s), dry_run=%s",
        len(iam_findings), dry_run,
    )

    # Project-level IAM policy is fetched ONCE and mutated in-memory, then
    # written back ONCE. This avoids race conditions from fetching + writing
    # per-finding if there are multiple PUBLIC_IAM_BINDING findings.
    project_resource = f"projects/{project_id}"
    needs_policy_write = False
    before_state_snapshot: Optional[str] = None

    try:
        policy = client.get_iam_policy(request={"resource": project_resource})
    except Exception as e:
        logger.exception("Could not fetch project IAM policy: %s", e)
        return [_failed_action(f, "FIX_IAM_BINDING", dry_run, str(e)) for f in iam_findings]

    # Snapshot before state for audit.
    before_state_snapshot = _policy_to_json(policy)

    for finding in iam_findings:
        try:
            if not _is_allowed(finding.resource_name):
                logger.warning(
                    "SKIP: resource not on allowlist. finding_id=%s resource=%s",
                    finding.finding_id, finding.resource_name,
                )
                actions.append(RemediationAction(
                    finding_id=finding.finding_id,
                    resource_name=finding.resource_name,
                    action_type="FIX_IAM_BINDING",
                    dry_run=dry_run,
                    success=False,
                    error_message="Resource not on remediator allowlist",
                ))
                continue

            # Which role on this finding has public members?
            public_role = finding.details.get("role", "<unknown>")

            # Scan all bindings; remove public members from any binding whose
            # role matches the finding (or just remove them wholesale).
            removed_members_this_finding = []
            for binding in policy.bindings:
                public_in_binding = [m for m in binding.members if m in PUBLIC_MEMBERS]
                if not public_in_binding:
                    continue

                if dry_run:
                    removed_members_this_finding.extend(
                        [{"role": binding.role, "member": m} for m in public_in_binding]
                    )
                    continue

                # Real mutation path.
                for m in public_in_binding:
                    binding.members.remove(m)
                    removed_members_this_finding.append({"role": binding.role, "member": m})
                needs_policy_write = True

            if not removed_members_this_finding:
                # Nothing to do — likely already remediated.
                actions.append(RemediationAction(
                    finding_id=finding.finding_id,
                    resource_name=finding.resource_name,
                    action_type="FIX_IAM_BINDING",
                    dry_run=dry_run,
                    success=True,
                    before_state=before_state_snapshot,
                    after_state=before_state_snapshot,
                    details={"skipped_reason": "no_public_members_found"},
                ))
                continue

            logger.info(
                "%s: would remove %d public member(s). finding_id=%s role=%s",
                "DRY-RUN" if dry_run else "REMEDIATED",
                len(removed_members_this_finding),
                finding.finding_id,
                public_role,
            )

            actions.append(RemediationAction(
                finding_id=finding.finding_id,
                resource_name=finding.resource_name,
                action_type="FIX_IAM_BINDING",
                dry_run=dry_run,
                success=True,
                before_state=before_state_snapshot,
                after_state=None if dry_run else _policy_to_json(policy),
                details={"removed_members": removed_members_this_finding},
            ))

        except Exception as e:
            logger.exception(
                "Unexpected error on IAM remediation. finding_id=%s",
                finding.finding_id,
            )
            actions.append(_failed_action(finding, "FIX_IAM_BINDING", dry_run, str(e)))

    # Write policy back ONCE if any mutations occurred (not per finding).
    if needs_policy_write and not dry_run:
        try:
            client.set_iam_policy(request={
                "resource": project_resource,
                "policy": policy,
            })
            logger.info("Project IAM policy updated with %d public member(s) removed",
                        sum(len(a.details.get("removed_members", [])) for a in actions))
        except Exception as e:
            logger.exception("Policy write-back failed: %s", e)
            # Mark all actions in this batch as failed since the write didn't persist.
            for a in actions:
                if a.success and not a.dry_run:
                    a.success = False
                    a.error_message = f"Policy write failed: {e}"

    return actions


# =============================================================================
# Internal helpers.
# =============================================================================
def _failed_action(
    finding: Finding,
    action_type: str,
    dry_run: bool,
    error_message: str,
) -> RemediationAction:
    """Build a failed RemediationAction record from a finding + error."""
    return RemediationAction(
        finding_id=finding.finding_id,
        resource_name=finding.resource_name,
        action_type=action_type,
        dry_run=dry_run,
        success=False,
        error_message=error_message,
    )


def _policy_to_json(policy) -> str:
    """Minimal JSON serialization of an IAM policy for audit records."""
    import json
    return json.dumps({
        "bindings": [
            {"role": b.role, "members": list(b.members)}
            for b in policy.bindings
        ],
    })
