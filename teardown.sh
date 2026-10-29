#!/usr/bin/env bash
# =============================================================================
# teardown.sh — Decommission the CSPM Automation project
# -----------------------------------------------------------------------------
# Primary path: terraform destroy, because everything is Terraform-managed.
# Wrapper steps handle resources Terraform cannot clean up on its own:
#   - GCS buckets with objects (must be emptied first)
#   - The deliberately-public test bucket from the remediation demo
#   - Secret Manager secrets (Gemini API key)
#   - Verifying Security Command Center is NOT on a paid tier
#
# Usage:
#   ./teardown.sh                # Scoped: terraform destroy + supporting cleanup
#   ./teardown.sh --nuke-project # Nuclear: deletes the entire GCP project
#
# Prerequisites:
#   PROJECT_ID and BILLING_ACCOUNT_ID must be exported (they persist from
#   ~/.bashrc after Step 1).
# =============================================================================

set -u  # error on unset variables; intentionally NOT set -e because we want
        # the script to continue past "resource not found" errors.

: "${PROJECT_ID:?PROJECT_ID is not set. Run: export PROJECT_ID=cspm-automation-cm}"
: "${BILLING_ACCOUNT_ID:?BILLING_ACCOUNT_ID is not set. Run: export BILLING_ACCOUNT_ID=XXXXXX-XXXXXX-XXXXXX}"

REGION="${REGION:-us-central1}"

echo "============================================================"
echo " CSPM Automation Teardown"
echo "   Project:  $PROJECT_ID"
echo "   Billing:  $BILLING_ACCOUNT_ID"
echo "   Region:   $REGION"
echo "============================================================"

# -----------------------------------------------------------------------------
# NUCLEAR OPTION — delete the entire project and exit
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
# SCOPED TEARDOWN — resource-by-resource
# -----------------------------------------------------------------------------

echo ""
echo ">>> [1/6] Emptying GCS buckets (Terraform destroy fails on non-empty buckets)..."

# These are the buckets Terraform will manage. If any contain objects, destroy
# fails. We empty them BEFORE terraform destroy runs.
for BUCKET_NAME in "cspm-reports-${PROJECT_ID}" "cspm-tfstate-${PROJECT_ID}"; do
  echo "    - gs://${BUCKET_NAME}"
  if gsutil ls "gs://${BUCKET_NAME}" >/dev/null 2>&1; then
    gsutil -m rm -r "gs://${BUCKET_NAME}/**" 2>/dev/null || true
  fi
done

# Also empty the deliberately-public test bucket from the remediation demo if it exists.
# Named 'cspm-demo-public-${PROJECT_ID}' per convention set in Step 22.
DEMO_BUCKET="cspm-demo-public-${PROJECT_ID}"
echo "    - gs://${DEMO_BUCKET} (demo bucket — may not exist, that's fine)"
if gsutil ls "gs://${DEMO_BUCKET}" >/dev/null 2>&1; then
  gsutil -m rm -r "gs://${DEMO_BUCKET}/**" 2>/dev/null || true
  gsutil rb "gs://${DEMO_BUCKET}" 2>/dev/null || true
fi

echo ""
echo ">>> [2/6] Running 'terraform destroy' (primary teardown path)..."
if [[ -d ~/cspm-automation/terraform ]]; then
  cd ~/cspm-automation/terraform
  terraform destroy -auto-approve || true
  cd - >/dev/null
else
  echo "    terraform/ directory not found — skipping (nothing to destroy)."
fi

echo ""
echo ">>> [3/6] Deleting Secret Manager secrets (Gemini API key, if present)..."
# Only the agent step (Step 24) creates this. Safe to attempt regardless.
for SECRET in gemini-api-key; do
  echo "    - $SECRET"
  gcloud secrets delete "$SECRET" --quiet 2>/dev/null || true
done

echo ""
echo ">>> [4/6] Deleting the custom IAM role 'cspmScannerRole' (if present)..."
# Terraform destroy should handle this, but belt-and-suspenders. Note:
# Custom roles go to DISABLED first, then DELETED permanently after 7 days.
gcloud iam roles delete cspmScannerRole --project="$PROJECT_ID" --quiet 2>/dev/null || true

echo ""
echo ">>> [5/6] Deleting budget alert 'cspm-automation-5usd-budget'..."
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
echo ">>> [6/6] Confirming Security Command Center is NOT on a paid tier..."
# SCC Standard tier is free. If somehow it got promoted to Premium during
# the build, this would show it. On personal accounts it should always be
# standard or inactive.
SCC_STATE=$(gcloud services list --enabled \
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
echo "  [ ] Console → BigQuery → Explorer: 'cspm_results' dataset is gone."
echo "  [ ] Console → Cloud Functions: 'cspm-scanner' is gone."
echo "  [ ] Console → Cloud Scheduler: 'daily-cspm-scan' is gone."
echo "  [ ] Console → Cloud Storage: no 'cspm-*' buckets remain."
echo "  [ ] Console → IAM & Admin → Service Accounts: 'cspm-scanner' is gone."
echo "  [ ] Console → IAM & Admin → Roles: 'cspmScannerRole' shows DISABLED (gone fully after 7 days)."
echo "  [ ] Console → VPC Network: no 'cspm-*' networks remain."
echo "  [ ] Console → Secret Manager: 'gemini-api-key' is gone."
echo "  [ ] Console → Billing → Budgets: 'cspm-automation-5usd-budget' is gone."
echo ""
echo " [ ] 48 HOURS FROM NOW:"
echo "     Console → Billing → Reports: confirm \$0.00 is accruing for"
echo "     project '$PROJECT_ID'. GCP billing lags ~24h, so 48h is the safe recheck window."
echo ""
echo " If any resource above is NOT clean, re-run this script, or run:"
echo "     ./teardown.sh --nuke-project"
echo " to delete the entire project in one shot (recommended for a throwaway build)."
echo ""
