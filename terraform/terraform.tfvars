# =============================================================================
# terraform.tfvars — Values for THIS deployment
# -----------------------------------------------------------------------------
# In production this file is gitignored and values come from CI/CD or a vault.
# For this learning project it's committed to show reproducibility.
# NEVER put secrets here (API keys, passwords). Those live in Secret Manager.
# =============================================================================

project_id         = "cspm-automation-cm"
region             = "us-central1"
zone               = "us-central1-a"
environment        = "dev"
owner              = "carlos"
scheduler_cron     = "0 6 * * *"
scheduler_timezone = "America/New_York"
remediator_dry_run = true
