"""
Run the posture advisor as the cspm-agent service account (no key files).

Usage: python3 scripts/run_agent_as_sa.py "your question"
Needs roles/iam.serviceAccountTokenCreator on the agent SA for the operator.
"""
import json
import os
import subprocess
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import urllib.request

import google.auth
import google.oauth2.credentials

PROJECT = os.environ.get("GCP_PROJECT_ID", "cspm-automation-cm")
AGENT_SA = os.environ.get("AGENT_SA", f"cspm-agent@{PROJECT}.iam.gserviceaccount.com")
os.environ.setdefault("GCP_PROJECT_ID", PROJECT)
os.environ.setdefault("BQ_DATASET", "cspm_results")


def main():
    if len(sys.argv) < 2:
        sys.exit('usage: python3 scripts/run_agent_as_sa.py "your question"')

    token = subprocess.check_output(
        ["gcloud", "auth", "print-access-token", f"--impersonate-service-account={AGENT_SA}"],
        text=True,
    ).strip()
    info = json.load(urllib.request.urlopen(f"https://oauth2.googleapis.com/tokeninfo?access_token={token}"))
    print(f"Running as: {info.get('email')}\n")

    creds = google.oauth2.credentials.Credentials(token)
    google.auth.default = lambda *a, **k: (creds, PROJECT)

    from agent import agent as advisor

    result = advisor.ask(sys.argv[1])
    print("Tool calls :", [c["name"] + str(c["args"]) for c in result["tool_calls"]])
    print("Answer     :", result["answer"])
    print("Cited IDs  :", result.get("cited_finding_ids"))
    print("Schema check:", "PASSED" if result["schema_ok"] else "FAILED")
    print("Audit row  :", "written" if result.get("audited") else "NOT written")


if __name__ == "__main__":
    main()
