# =============================================================================
# variables.tf — Input variable declarations
# -----------------------------------------------------------------------------
# Every variable declared with explicit type and description. No defaults on
# variables that identify the deployment target (project_id) — forces caller
# to be explicit so we never deploy to the wrong project by accident.
# =============================================================================

variable "project_id" {
  description = "GCP project ID where all CSPM resources will be created."
  type        = string
  # No default — caller MUST supply this via tfvars or -var flag.
}

variable "region" {
  description = "Default GCP region for regional resources."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "Default GCP zone for zonal resources (subnet only, functions are regional)."
  type        = string
  default     = "us-central1-a"
}

variable "environment" {
  description = "Deployment environment, propagated as a label on every resource for billing attribution and ops filtering."
  type        = string
  default     = "dev"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "owner" {
  description = "Owner label applied to every resource for accountability."
  type        = string
  default     = "carlos"
}

variable "scheduler_cron" {
  description = "Cron expression for daily CSPM scan. Default: 06:00 UTC every day."
  type        = string
  default     = "0 6 * * *"
}

variable "scheduler_timezone" {
  description = "Timezone for the cron schedule."
  type        = string
  default     = "America/New_York"
}

variable "remediator_dry_run" {
  description = "Safety flag: when true, remediator logs intended actions but does NOT mutate resources. Default true for safe-by-default posture."
  type        = bool
  default     = true
}
