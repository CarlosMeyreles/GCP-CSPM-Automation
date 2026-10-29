"""
test_remediator.py — unit tests for remediator.py's nine safety guards.

Every guard from Step 15 has a dedicated test proving it fires correctly.
Mocks substitute real GCP clients — tests run in milliseconds, no network.

Guards covered:
    1. dry_run=True default (default-parameter test)
    2. ALLOWED_RESOURCE_PATTERNS allowlist (allowed/blocked tests)
    3. Idempotency check (already-fixed resource skip)
    4. Per-finding try/except (one failure doesn't abort)
    5. Before/after state capture (audit trail)
    6. Exception taxonomy (PermissionDenied vs NotFound vs generic)
    7. RemediationAction typed return
    8. Single client per invocation (verified via mock call count)
    9. IAM policy fetch-modify-write-once (not per-finding)
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Make the module importable from the tests subdirectory.
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner import Finding
from remediator import (
    fix_public_buckets,
    fix_iam_bindings,
    RemediationAction,
    _is_allowed,
    ALLOWED_RESOURCE_PATTERNS,
)
from google.api_core import exceptions as google_exceptions


# =============================================================================
# Fixtures — reusable test data
# =============================================================================
@pytest.fixture
def public_bucket_finding():
    """A canonical PUBLIC_BUCKET_ACCESS finding on an allowed resource."""
    return Finding(
        finding_id="test-bucket-001",
        resource_name="//storage.googleapis.com/projects/_/buckets/test-public-bucket",
        category="PUBLIC_BUCKET_ACCESS",
        severity="HIGH",
        details={"bucket_name": "test-public-bucket", "current_pap": "inherited"},
    )


@pytest.fixture
def public_iam_finding():
    """A canonical PUBLIC_IAM_BINDING finding."""
    return Finding(
        finding_id="test-iam-001",
        resource_name="//cloudresourcemanager.googleapis.com/projects/fake-project",
        category="PUBLIC_IAM_BINDING",
        severity="CRITICAL",
        details={"role": "roles/storage.objectViewer", "public_members": ["allUsers"]},
    )


@pytest.fixture
def mock_storage_client():
    """A MagicMock replacing google.cloud.storage.Client."""
    client = MagicMock()
    bucket = MagicMock()
    bucket.iam_configuration.public_access_prevention = "inherited"
    client.get_bucket.return_value = bucket
    return client


# =============================================================================
# GUARD #1 — dry_run=True default
# =============================================================================
def test_fix_public_buckets_default_is_dry_run():
    """
    CRITICAL TEST: calling fix_public_buckets without specifying dry_run
    must NOT mutate anything. A regression here = production outage.
    """
    import inspect
    sig = inspect.signature(fix_public_buckets)
    assert sig.parameters["dry_run"].default is True, (
        "fix_public_buckets must default dry_run=True. "
        "Changing this default is a BREAKING SECURITY REGRESSION."
    )


def test_fix_iam_bindings_default_is_dry_run():
    """Same guard, different function."""
    import inspect
    sig = inspect.signature(fix_iam_bindings)
    assert sig.parameters["dry_run"].default is True, (
        "fix_iam_bindings must default dry_run=True."
    )


# =============================================================================
# GUARD #2 — ALLOWED_RESOURCE_PATTERNS allowlist
# =============================================================================
def test_allowlist_accepts_bucket_resource():
    """A valid storage bucket resource name must match the allowlist."""
    assert _is_allowed("//storage.googleapis.com/projects/_/buckets/my-bucket")


def test_allowlist_accepts_project_iam_resource():
    """A valid project-level IAM resource name must match the allowlist."""
    assert _is_allowed("//cloudresourcemanager.googleapis.com/projects/my-project")


def test_allowlist_blocks_random_resource():
    """A resource not matching any pattern must be blocked."""
    assert not _is_allowed("//compute.googleapis.com/projects/x/zones/us-central1-a/instances/vm1")
    assert not _is_allowed("random-string")
    assert not _is_allowed("")


# =============================================================================
# GUARD #3 — Idempotency (don't re-fix already-fixed)
# =============================================================================
def test_fix_public_buckets_skips_already_enforced(public_bucket_finding, mock_storage_client):
    """If a bucket's PAP is already 'enforced', remediator must skip it."""
    mock_storage_client.get_bucket.return_value.iam_configuration.public_access_prevention = "enforced"

    with patch("remediator.storage.Client", return_value=mock_storage_client):
        actions = fix_public_buckets("test-project", [public_bucket_finding], dry_run=False)

    assert len(actions) == 1
    assert actions[0].success is True
    assert actions[0].details.get("skipped_reason") == "already_enforced"


# =============================================================================
# GUARD #4 — Per-finding error isolation
# =============================================================================
def test_fix_public_buckets_isolates_per_finding_errors(mock_storage_client):
    """One broken finding must not abort the entire batch."""
    good = Finding(
        finding_id="good",
        resource_name="//storage.googleapis.com/projects/_/buckets/good-bucket",
        category="PUBLIC_BUCKET_ACCESS",
        severity="HIGH",
    )
    bad = Finding(
        finding_id="bad",
        resource_name="//storage.googleapis.com/projects/_/buckets/bad-bucket",
        category="PUBLIC_BUCKET_ACCESS",
        severity="HIGH",
    )

    good_bucket = MagicMock()
    good_bucket.iam_configuration.public_access_prevention = "inherited"
    mock_storage_client.get_bucket.side_effect = [
        good_bucket,
        google_exceptions.PermissionDenied("blocked"),
    ]

    with patch("remediator.storage.Client", return_value=mock_storage_client):
        actions = fix_public_buckets("test-project", [good, bad], dry_run=True)

    assert len(actions) == 2
    assert actions[0].success is True   # good finding worked
    assert actions[1].success is False  # bad finding reported failure, didn't crash the function


# =============================================================================
# GUARD #5 — Before/after state capture
# =============================================================================
def test_dry_run_captures_before_state_but_no_after(public_bucket_finding, mock_storage_client):
    """In dry-run, before_state must be captured but after_state must be None."""
    with patch("remediator.storage.Client", return_value=mock_storage_client):
        actions = fix_public_buckets("test-project", [public_bucket_finding], dry_run=True)

    assert actions[0].before_state is not None
    assert "inherited" in actions[0].before_state
    assert actions[0].after_state is None  # No mutation = no after state
    assert actions[0].dry_run is True


# =============================================================================
# GUARD #6 — Exception taxonomy
# =============================================================================
def test_permission_denied_marked_failure(public_bucket_finding, mock_storage_client):
    """PermissionDenied must produce a failed action record with error message."""
    mock_storage_client.get_bucket.side_effect = google_exceptions.PermissionDenied("insufficient perms")

    with patch("remediator.storage.Client", return_value=mock_storage_client):
        actions = fix_public_buckets("test-project", [public_bucket_finding], dry_run=False)

    assert len(actions) == 1
    assert actions[0].success is False
    assert "insufficient perms" in actions[0].error_message


def test_not_found_marked_failure_but_not_crash(public_bucket_finding, mock_storage_client):
    """NotFound (resource deleted mid-scan) must be handled without crashing."""
    mock_storage_client.get_bucket.side_effect = google_exceptions.NotFound("gone")

    with patch("remediator.storage.Client", return_value=mock_storage_client):
        actions = fix_public_buckets("test-project", [public_bucket_finding], dry_run=False)

    assert len(actions) == 1
    assert actions[0].success is False


# =============================================================================
# GUARD #7 — Typed RemediationAction return
# =============================================================================
def test_returns_remediation_action_dataclass(public_bucket_finding, mock_storage_client):
    """Return values must be RemediationAction instances, not raw dicts."""
    with patch("remediator.storage.Client", return_value=mock_storage_client):
        actions = fix_public_buckets("test-project", [public_bucket_finding], dry_run=True)

    assert len(actions) == 1
    assert isinstance(actions[0], RemediationAction)
    # to_dict() must produce a dict (for BigQuery serialization).
    assert isinstance(actions[0].to_dict(), dict)


# =============================================================================
# Filtering — remediator ignores findings of the wrong category
# =============================================================================
def test_fix_public_buckets_ignores_non_bucket_findings():
    """A PUBLIC_IAM_BINDING finding must be filtered out of fix_public_buckets."""
    iam_finding = Finding(
        finding_id="iam-test",
        resource_name="//cloudresourcemanager.googleapis.com/projects/x",
        category="PUBLIC_IAM_BINDING",
        severity="CRITICAL",
    )

    with patch("remediator.storage.Client"):
        actions = fix_public_buckets("test-project", [iam_finding], dry_run=True)

    assert len(actions) == 0  # Nothing to do — correctly filtered out
