import json

from agent import guard
from agent.tests.fakes import FakeBQ

GOOD = {"answer": "ok", "cited_finding_ids": [], "actions_executed": "none"}


# ---------- question check ----------
def test_question_empty_rejected():
    assert guard.check_question("   ")[0] is False


def test_question_too_long_rejected():
    assert guard.check_question("x" * 501)[0] is False


def test_question_is_stripped():
    assert guard.check_question("  hi  ") == (True, "hi")


# ---------- tool-call cap ----------
def test_tool_call_cap():
    state = {}
    results = [guard.allow_tool_call(state, limit=3) for _ in range(5)]
    assert results == [True, True, True, False, False]


# ---------- answer schema ----------
def test_parse_valid_answer():
    ok, data = guard.parse_answer(json.dumps(GOOD))
    assert ok and data == GOOD


def test_parse_accepts_markdown_fences():
    ok, data = guard.parse_answer("```json\n" + json.dumps(GOOD) + "\n```")
    assert ok and data == GOOD


def test_parse_rejects_non_json():
    assert guard.parse_answer("I fixed it!")[0] is False
    assert guard.parse_answer("")[0] is False
    assert guard.parse_answer(None)[0] is False


def test_parse_rejects_claimed_action():
    assert guard.parse_answer(json.dumps({**GOOD, "actions_executed": "fixed bucket"}))[0] is False


def test_parse_rejects_extra_keys():
    assert guard.parse_answer(json.dumps({**GOOD, "extra": 1}))[0] is False


def test_parse_rejects_bad_finding_id():
    assert guard.parse_answer(json.dumps({**GOOD, "cited_finding_ids": ["x"]}))[0] is False


def test_parse_rejects_missing_field():
    bad = {k: v for k, v in GOOD.items() if k != "answer"}
    assert guard.parse_answer(json.dumps(bad))[0] is False


# ---------- audit ----------
def test_audit_row_fields():
    calls = [{"name": "query_findings", "args": {"severity": "HIGH"}}]
    row = guard.build_audit_row("id-1", "q", calls, "resp", "model-x", True)
    assert row["interaction_id"] == "id-1"
    assert row["schema_validation_passed"] is True
    assert json.loads(row["tool_calls"])[0]["name"] == "query_findings"


def test_audit_row_truncates_long_text():
    row = guard.build_audit_row("i", "q" * 1000, [], "r" * 20000, "m", False)
    assert len(row["user_question"]) == 500
    assert len(row["agent_response"]) == 8000
    assert row["schema_validation_passed"] is False


def test_write_audit_success():
    bq = FakeBQ()
    assert guard.write_audit({"a": 1}, client=bq) is True
    assert bq.audit[0][0] == "test-proj.test_ds.agent_audit_log"


def test_write_audit_reports_insert_errors():
    assert guard.write_audit({"a": 1}, client=FakeBQ(insert_errors=[{"index": 0}])) is False


def test_write_audit_never_raises(monkeypatch):
    monkeypatch.delenv("GCP_PROJECT_ID")
    assert guard.write_audit({"a": 1}, client=FakeBQ()) is False
