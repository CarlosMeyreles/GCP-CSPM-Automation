#!/usr/bin/env bash
# =============================================================================
# teardown.sh - Decommission the CSPM Automation project
# -----------------------------------------------------------------------------
# Order matters:
#   1. Empty the buckets Terraform manages (destroy fails on non-empty buckets)
#      but NEVER touch the Terraform state bucket yet. Emptying it first would
#      delete the state and leave every resource orphaned and still billing.
#   2. terraform destroy (primary path, uses the intact state)
#   3. Delete resources Terraform does not own: the demo bucket, the buckets
#      Cloud Functions creates on its own, and its Artifact Registry repo
#   4. Delete the state bucket LAST, and only if destroy succeeded and the
#      state is empty
#
# Usage:
#   ./teardown.sh                # Scoped teardown
#   ./teardown.sh --nuke-project # Deletes the entire GCP project
#
# Prerequisites:
#   PROJECT_ID and BILLING_ACCOUNT_ID must be exported.
# =============================================================================

set -u  # error on unset variables; intentionally NOT set -e so the script
        # continues past "resource not found" errors.

: "${PROJECT_ID:?PROJECT_ID is not set. Run: export PROJECT_ID=cspm-automation-cm}"
: "${BILLING_ACCOUNT_ID:?BILLING_ACCOUNT_ID is not set. Run: export BILLING_ACCOUNT_ID=XXXXXX-XXXXXX-XXXXXX}"

REGION="${REGION:-us-central1}"
STATE_BUCKET="cspm-tfstate-${PROJECT_ID}"
DEMO_BUCKET="cspm-demo-public-${PROJECT_ID}"
PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format="value(projectNumber)" 2>/dev/null || true)"

echo "============================================================"
echo " CSPM Automation Teardown"
echo "   Project:  $PROJECT_ID"
echo "   Billing:  $BILLING_ACCOUNT_ID"
echo "   Region:   $REGION"
echo "============================================================"

# -----------------------------------------------------------------------------
# NUCLEAR OPTION - delete the entire project and exit
# -----------------------------------------------------------------------------
if [[ "${1:-}" == "--nuke-project" ]]; then
  echo ""
  echo ">>> NUCLEAR TEARDOWN: deleting entire project $PROJECT_ID"
  echo ">>> The project will be queued for deletion. You have 30 days to"
  echo ">>> recover it via 'gcloud projects undelete $PROJECT_ID'."
  echo ""
  read -r -p "Type the project ID to confirm: " CONFIRM
  if [[ "$CONFIRM" != "$PROJECT_ID" ]]; then
    echo "Confirmation did not match. Aborting."
    exit 1
  fi
  gcloud projects delete "$PROJECT_ID" --quiet
  echo ""
  echo "Project deletion requested. See manual checklist below."
  exit 0
fi

# -----------------------------------------------------------------------------
# SCOPED TEARDOWN
# -----------------------------------------------------------------------------

echo ""
echo ">>> [1/8] Emptying Terraform-managed cspm-* buckets (state bucket is skipped)..."
for B in $(gcloud storage buckets list --project="$PROJECT_ID" --format="value(name)" 2>/dev/null \
           | grep '^cspm-' | grep -v "^${STATE_BUCKET}$"); do
  echo "    - gs://${B}"
  gcloud storage rm --recursive --all-versions "gs://${B}/**" --quiet 2>/dev/null || true
done

echo ""
echo ">>> [2/8] Running 'terraform destroy' (state is still intact)..."
DESTROY_RC=1
REMAINING=999
if [[ -d ~/cspm-automation/terraform ]]; then
  cd ~/cspm-automation/terraform || exit 1
  terraform destroy -auto-approve
  DESTROY_RC=$?
  REMAINING="$(terraform state list 2>/dev/null | wc -l)"
  cd - >/dev/null
  echo "    destroy exit code: ${DESTROY_RC}, resources left in state: ${REMAINING}"
else
  echo "    terraform/ directory not found - skipping."
fi

echo ""
echo ">>> [3/8] Deleting buckets Terraform does not own..."
BUCKETS_TO_DELETE=("$DEMO_BUCKET")
if [[ -n "$PROJECT_NUMBER" ]]; then
  BUCKETS_TO_DELETE+=("gcf-v2-sources-${PROJECT_NUMBER}-${REGION}")
  BUCKETS_TO_DELETE+=("gcf-v2-uploads-${PROJECT_NUMBER}.${REGION}.cloudfunctions.appspot.com")
fi
for B in "${BUCKETS_TO_DELETE[@]}"; do
  echo "    - gs://${B}"
  if gcloud storage buckets describe "gs://${B}" >/dev/null 2>&1; then
    gcloud storage rm --recursive --all-versions "gs://${B}" --quiet 2>/dev/null || true
  else
    echo "      (not found, fine)"
  fi
done

echo ""
echo ">>> [4/8] Deleting the Cloud Functions build-artifact repository (if present)..."
gcloud artifacts repositories delete gcf-artifacts --location="$REGION" \
  --project="$PROJECT_ID" --quiet 2>/dev/null || echo "    (not found, fine)"

echo ""
echo ">>> [5/8] Deleting the Terraform state bucket (last, only if destroy fully succeeded)..."
if [[ "$DESTROY_RC" -eq 0 && "$REMAINING" -eq 0 ]]; then
  gcloud storage rm --recursive --all-versions "gs://${STATE_BUCKET}" --quiet 2>/dev/null || true
  echo "    State bucket removed."
else
  echo "    WARNING: destroy did not finish cleanly. State bucket KEPT so you can"
  echo "    re-run: cd ~/cspm-automation/terraform && terraform destroy"
fi

echo ""
echo ">>> [6/8] Deleting Secret Manager secret and custom role (if still present)..."
gcloud secrets delete gemini-api-key --project="$PROJECT_ID" --quiet 2>/dev/null || true
gcloud iam roles delete cspmScannerRole --project="$PROJECT_ID" --quiet 2>/dev/null || true

echo ""
echo ">>> [7/8] Deleting budget alert 'cspm-automation-5usd-budget'..."
BUDGET_NAME=$(gcloud billing budgets list \
  --billing-account="$BILLING_ACCOUNT_ID" \
  --filter="displayName:cspm-automation-5usd-budget" \
  --format="value(name)" 2>/dev/null || true)
if [[ -n "$BUDGET_NAME" ]]; then
  gcloud billing budgets delete "$BUDGET_NAME" --quiet 2>/dev/null || true
  echo "    Budget deleted."
else
  echo "    No matching budget found."
fi

echo ""
echo ">>> [8/8] Confirming Security Command Center is NOT on a paid tier..."
SCC_STATE=$(gcloud services list --enabled --project="$PROJECT_ID" \
  --filter="name:securitycenter.googleapis.com" \
  --format="value(config.name)" 2>/dev/null || echo "none")
if [[ "$SCC_STATE" == "securitycenter.googleapis.com" ]]; then
  echo "    SCC API still enabled. On personal accounts this is Standard tier (free)."
  echo "    If you ever see 'SCC Premium' anywhere, disable it immediately."
else
  echo "    SCC API not enabled. Clean."
fi

echo ""
echo "============================================================"
echo " Scoped teardown complete."
echo "============================================================"
echo ""
echo " Manual verification checklist (do each one):"
echo ""
echo "  [ ] Console > BigQuery: 'cspm_results' dataset is gone (including agent_audit_log)."
echo "  [ ] Console > Cloud Functions: 'cspm-scanner' is gone."
echo "  [ ] Console > Cloud Scheduler: 'daily-cspm-scan' is gone."
echo "  [ ] Console > Cloud Storage: no 'cspm-*' or 'gcf-v2-*' buckets remain."
echo "  [ ] Console > Artifact Registry: 'gcf-artifacts' is gone."
echo "  [ ] Console > IAM & Admin > Service Accounts: 'cspm-scanner' AND 'cspm-agent' are gone."
echo "  [ ] Console > IAM & Admin > Roles: 'cspmScannerRole' shows DISABLED (gone fully after 7 days)."
echo "  [ ] Console > VPC Network: no 'cspm-*' networks remain."
echo "  [ ] Console > Secret Manager: 'gemini-api-key' is gone."
echo "  [ ] Console > Billing > Budgets: 'cspm-automation-5usd-budget' is gone."
echo ""
echo " Not handled by this script (do these by hand):"
echo "  [ ] Google AI Studio (aistudio.google.com/apikey): delete the Gemini API key and"
echo "      the AI Studio project created for it."
echo "  [ ] GitHub: revoke leftover personal access tokens and the GitHub CLI authorization"
echo "      (Settings > Developer settings / Applications), then run: gh auth logout"
echo ""
echo " [ ] 48 HOURS FROM NOW:"
echo "     Console > Billing > Reports: confirm \$0.00 is accruing for"
echo "     project '$PROJECT_ID'. GCP billing lags ~24h, so 48h is the safe recheck window."
echo ""
echo " If any resource above is NOT clean, re-run this script, or run:"
echo "     ./teardown.sh --nuke-project"
echo " to delete the entire project in one shot."
echo ""
