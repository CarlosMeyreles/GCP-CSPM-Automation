"""
run_local_as_sa.py - run the cspm_scan handler locally AS the scanner service account.

How it works:
  1. gcloud mints a short-lived (about 1 hour) access token for the service account
     via impersonation. No key file is ever created.
  2. We point google.auth.default at that token so every Google client library in
     this process (Asset, Storage, BigQuery) acts as the service account.
  3. We call the real HTTP handler through functions-framework's test client.

Requires roles/iam.serviceAccountTokenCreator on the service account.
"""
import json
import os
import subprocess
import sys
import urllib.request

import google.auth
from google.oauth2.credentials import Credentials

SA = os.environ["SCANNER_SA"]
PROJECT = os.environ["GCP_PROJECT_ID"]

token = subprocess.check_output(
    ["gcloud", "auth", "print-access-token", f"--impersonate-service-account={SA}"],
    text=True,
).strip()

# Prove who we are: ask Google who owns this token.
with urllib.request.urlopen(
    f"https://oauth2.googleapis.com/tokeninfo?access_token={token}"
) as r:
    print("Running as:", json.load(r).get("email"))

creds = Credentials(token)
google.auth.default = lambda *args, **kwargs: (creds, PROJECT)

SRC_DIR = os.path.join("functions", "cspm-scanner")
sys.path.insert(0, SRC_DIR)

from functions_framework import create_app  # noqa: E402

app = create_app(target="cspm_scan", source=os.path.join(SRC_DIR, "main.py"))
resp = app.test_client().post("/", json={"test": "local-as-sa"})

print("HTTP status:", resp.status_code)
body = resp.get_data(as_text=True)
try:
    print(json.dumps(json.loads(body), indent=2))
except ValueError:
    print(body)
