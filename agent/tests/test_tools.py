import json
from datetime import datetime, timezone

import pytest

from agent import tools
from agent.tests.fakes import FakeBQ


# ---------- query_findings ----------
def test_query_findings_rejects_unknown_severity():
    assert tools.query_findings("EXTREME", client=FakeBQ())["status"] == "error"


def test_query_findings_normalizes_case_and_parameterizes():
    bq = FakeBQ(rows=[{"finding_id": "abc-12345", "severity": "HIGH"}])
    result = tools.query_findings(" high ", client=bq)
    assert result == {"status": "ok", "count": 1,
                      "findings": [{"finding_id": "abc-12345", "severity": "HIGH"}]}
    sql, config = bq.calls[0]
    assert "@severity" in sql
    assert "HIGH" not in sql  # the value travels as a parameter, never inside the SQL text
    assert config.query_parameters[0].value == "HIGH"


def test_query_findings_needs_environment(monkeypatch):
    monkeypatch.delenv("GCP_PROJECT_ID")
    assert tools.query_findings("HIGH", client=FakeBQ())["status"] == "error"


def test_lookup_failure_returns_error_dict_without_details():
    bq = FakeBQ(error=RuntimeError("secret internal detail"))
    result = tools.query_findings("HIGH", client=bq)
    assert result == {"status": "error", "message": "lookup failed: RuntimeError"}


# ---------- get_remediation_history ----------
@pytest.mark.parametrize("bad", ["", "x'; DROP TABLE t; --", "a b", "a" * 201])
def test_history_rejects_bad_resource(bad):
    assert tools.get_remediation_history(bad, client=FakeBQ())["status"] == "error"


def test_history_converts_timestamps_to_strings():
    row = {"timestamp": datetime(2026, 11, 6, tzinfo=timezone.utc), "action_type": "FIX_PUBLIC_BUCKET",
           "dry_run": False, "success": True, "before_state": None, "after_state": None,
           "error_message": None}
    result = tools.get_remediation_history("my-bucket", client=FakeBQ(rows=[row]))
    assert result["status"] == "ok" and result["count"] == 1
    assert isinstance(result["records"][0]["timestamp"], str)
    json.dumps(result)  # must be JSON-safe for the model


# ---------- explain_control ----------
def test_explain_known_control():
    result = tools.explain_control("5.1")
    assert result["status"] == "ok"
    assert "Cloud Storage" in result["title"]
    assert result["benchmark_version"]


def test_explain_unknown_control_lists_available():
    result = tools.explain_control("9.9")
    assert result["status"] == "error" and "5.1" in result["message"]


@pytest.mark.parametrize("bad", ["", "5.1; ls", "abc", "../etc"])
def test_explain_rejects_bad_format(bad):
    assert tools.explain_control(bad)["status"] == "error"


# ---------- draft_fix (text only) ----------
def _finding(resource, category):
    return FakeBQ(rows=[{"finding_id": "f1234567", "resource_name": resource,
                         "finding_category": category, "severity": "HIGH"}])


def test_draft_fix_public_access_prevention_is_text_only():
    bq = _finding("//storage.googleapis.com/projects/_/buckets/my-bucket", "PUBLIC_BUCKET_ACCESS")
    result = tools.draft_fix("f1234567", client=bq)
    assert result["status"] == "ok" and result["draft_only"] is True
    assert "gs://my-bucket" in result["suggested_change"]
    assert "--public-access-prevention" in result["suggested_change"]
    assert "Nothing was executed" in result["warning"]


def test_draft_fix_iam_binding():
    bq = _finding("//storage.googleapis.com/my-bucket", "PUBLIC_IAM_BINDING")
    result = tools.draft_fix("f1234567", client=bq)
    assert result["status"] == "ok"
    assert "remove-iam-policy-binding gs://my-bucket" in result["suggested_change"]


def test_draft_fix_unknown_finding():
    result = tools.draft_fix("f1234567", client=FakeBQ(rows=[]))
    assert result == {"status": "error", "message": "finding not found"}


def test_draft_fix_unsupported_category():
    bq = _finding("//storage.googleapis.com/my-bucket", "SOMETHING_ELSE")
    assert "no draft template" in tools.draft_fix("f1234567", client=bq)["message"]


def test_draft_fix_non_bucket_resource():
    bq = _finding("//compute.googleapis.com/projects/p/zones/z/instances/vm", "PUBLIC_BUCKET_ACCESS")
    assert tools.draft_fix("f1234567", client=bq)["status"] == "error"


def test_draft_fix_rejects_bad_id():
    assert tools.draft_fix("x; drop table", client=FakeBQ())["status"] == "error"
