# =============================================================================
# versions.tf — Terraform CLI and provider version pinning
# -----------------------------------------------------------------------------
# Why pin versions:
#   - Reproducibility: `terraform apply` on another machine (or CI) uses the
#     same provider behavior, not whatever is latest.
#   - Security: supply-chain control — unexpected provider releases could
#     introduce breaking schema changes or, in rare cases, compromised binaries.
#   - The lock file (.terraform.lock.hcl) checksum-locks the exact binary.
# =============================================================================

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.40"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.40"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }

  backend "gcs" {
    bucket = "cspm-tfstate-cspm-automation-cm"
    prefix = "cspm-automation/state"
  }
}
