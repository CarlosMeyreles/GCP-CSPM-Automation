"""
guard.py - safety logic for the posture advisor agent.

No ADK imports here, so everything is unit-testable in CI without a model.
"""
import json
import os
import re
from datetime import datetime, timezone

import jsonschema

MAX_QUESTION_CHARS = 500
MAX_TOOL_CALLS = 6

ANSWER_SCHEMA = {
    "type": "object",
    "properties": {
        "answer": {"type": "string", "minLength": 1, "maxLength": 4000},
        "cited_finding_ids": {
            "type": "array",
            "items": {"type": "string", "pattern": "^[A-Za-z0-9-]{8,64}$"},
            "maxItems": 50,
        },
        "actions_executed": {"type": "string", "enum": ["none"]},
    },
    "required": ["answer", "cited_finding_ids", "actions_executed"],
    "additionalProperties": False,
}


def check_question(question):
    """Return (ok, cleaned_question_or_reason)."""
    q = (question or "").strip()
    if not q:
        return False, "question is empty"
    if len(q) > MAX_QUESTION_CHARS:
        return False, f"question is longer than {MAX_QUESTION_CHARS} characters"
    return True, q


def allow_tool_call(state, limit=MAX_TOOL_CALLS):
    """Count this call in the session state. False once the cap is passed."""
    count = (state.get("tool_calls") or 0) + 1
    state["tool_calls"] = count
    return count <= limit


def parse_answer(raw):
    """Validate the model's final text. Return (ok, data_or_reason)."""
    text = (raw or "").strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    try:
        data = json.loads(text)
    except ValueError:
        return False, "answer is not valid JSON"
    try:
        jsonschema.validate(data, ANSWER_SCHEMA)
    except jsonschema.ValidationError as exc:
        return False, f"answer failed schema: {exc.validator}"
    return True, data


def build_audit_row(interaction_id, question, tool_calls, response, model_name, schema_ok):
    return {
        "interaction_id": interaction_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_question": question[:MAX_QUESTION_CHARS],
        "tool_calls": json.dumps(tool_calls)[:8000],
        "agent_response": (response or "")[:8000],
        "model_name": model_name,
        "schema_validation_passed": bool(schema_ok),
    }


def write_audit(row, client=None):
    """Append one row to agent_audit_log. Return True on success, never raise."""
    try:
        from google.cloud import bigquery

        project = os.environ["GCP_PROJECT_ID"]
        dataset = os.environ["BQ_DATASET"]
        client = client or bigquery.Client(project=project)
        errors = client.insert_rows_json(f"{project}.{dataset}.agent_audit_log", [row])
        return not errors
    except Exception:
        return False
