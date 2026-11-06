# =============================================================================
# main.tf — Provider configuration + common data sources
# -----------------------------------------------------------------------------
# This file will grow as we add VPC, service account, BigQuery, Storage,
# Cloud Function, and Scheduler resources. For now: provider config only.
# =============================================================================

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone

  # Default labels applied to every resource that supports them.
  # Powerful for billing attribution and ops filtering at scale.
  default_labels = {
    environment = var.environment
    owner       = var.owner
    project     = "cspm"
    managed_by  = "terraform"
  }
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

# -----------------------------------------------------------------------------
# Data source: look up the project number for IAM bindings on managed SAs
# (e.g., the Pub/Sub managed SA format requires project NUMBER, not ID).
# -----------------------------------------------------------------------------
data "google_project" "current" {}

# =============================================================================
# API ENABLEMENT — codify what gcloud enabled in Step 2
# -----------------------------------------------------------------------------
# For each API, if it's already enabled, Terraform imports it into state.
# `disable_on_destroy = false` prevents `terraform destroy` from disabling the
# API (which would break any other projects sharing the billing account) and
# avoids a 24-hour cooldown re-enabling it.
# =============================================================================

locals {
  required_apis = [
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "compute.googleapis.com",
    "bigquery.googleapis.com",
    "storage.googleapis.com",
    "cloudfunctions.googleapis.com",
    "cloudbuild.googleapis.com",
    "run.googleapis.com",
    "eventarc.googleapis.com",
    "artifactregistry.googleapis.com",
    "cloudscheduler.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudasset.googleapis.com",
    "securitycenter.googleapis.com",
  ]
}

resource "google_project_service" "enabled" {
  for_each = toset(local.required_apis)
  project  = var.project_id
  service  = each.value

  disable_on_destroy         = false
  disable_dependent_services = false
}

# =============================================================================
# VPC + PRIVATE SUBNET — isolated network for the CSPM scanner
# -----------------------------------------------------------------------------
# Custom VPC (NOT the default) because:
#   - Default VPC has permissive pre-created firewall rules we don't want
#   - Custom VPC starts with zero firewall rules → default-deny posture
#   - Explicit subnet = explicit IP range we can audit and firewall against
#
# Private Google Access = true means the subnet's resources (which have no
# public IPs) can STILL reach Google APIs via Google's private backbone.
# This gives us internet-free access to BigQuery, Cloud Storage, SCC, etc.
# No Cloud NAT needed, no external IPs needed, no egress cost.
# =============================================================================

resource "google_compute_network" "cspm_vpc" {
  name                    = "cspm-vpc"
  description             = "Private VPC for the CSPM scanner. No public ingress permitted."
  auto_create_subnetworks = false      # false = custom subnet mode; true = auto-provision subnets in every region (wasteful)
  routing_mode            = "REGIONAL" # REGIONAL = routes stay in-region; GLOBAL = cross-region (more complex, we don't need it)

  depends_on = [google_project_service.enabled]
}

resource "google_compute_subnetwork" "cspm_subnet" {
  name          = "cspm-subnet"
  description   = "Subnet for CSPM scanner resources. Private Google Access enabled."
  network       = google_compute_network.cspm_vpc.id
  region        = var.region
  ip_cidr_range = "10.10.0.0/24" # /24 = 256 IPs. Plenty for a scanner that uses 0-5.

  # CRITICAL: lets no-public-IP resources reach Google APIs via private backbone.
  private_ip_google_access = true

  # VPC Flow Logs ON for auditability. Sampling 50% + 10 min aggregation
  # keeps logging cost minimal while still giving us connection records.
  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# =============================================================================
# FIREWALL: default-deny posture via a single DENY-ALL ingress rule
# -----------------------------------------------------------------------------
# GCP VPCs are "default-deny-ingress" by API default, but this explicit rule
# makes the posture visible and auditable. If someone later adds an allow rule
# with lower priority, our deny rule takes precedence by having priority=65534
# (one less than the default implicit deny at 65535).
# =============================================================================

resource "google_compute_firewall" "deny_all_ingress" {
  name        = "cspm-deny-all-ingress"
  description = "Explicit default-deny for all inbound traffic. Add specific allow rules above this priority."
  network     = google_compute_network.cspm_vpc.name

  direction = "INGRESS"
  priority  = 65534 # Lower number = higher priority. 65534 is the lowest-but-visible slot.

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"] # Deny from everywhere.

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# =============================================================================
# CUSTOM IAM ROLE — least-privilege permissions for the CSPM scanner
# -----------------------------------------------------------------------------
# Predefined roles (storage.admin, bigquery.dataEditor) are too broad for our
# scanner. This custom role contains ONLY the 17 permissions the scanner needs.
# Blast radius of compromised credentials is bounded by this list, not by the
# superset implied by a predefined role.
#
# Lifecycle note: custom roles go to DISABLED for 7 days on destroy, then
# permanently delete. Re-applying within 7 days needs a role_id with a suffix
# or waiting out the window.
# =============================================================================

resource "google_project_iam_custom_role" "cspm_scanner" {
  role_id     = "cspmScannerRole"
  title       = "CSPM Scanner (least-privilege)"
  description = "Least-privilege role for the CSPM scanner Cloud Function. 17 permissions covering read for findings and write for remediation."
  stage       = "GA"
  project     = var.project_id

  permissions = [
    # --- Cloud Asset Inventory (fallback scanner data source) ---
    "cloudasset.assets.searchAllIamPolicies",
    "cloudasset.assets.searchAllResources",

    # --- Project-level IAM read + remediation ---
    "resourcemanager.projects.getIamPolicy",
    "resourcemanager.projects.setIamPolicy",

    # --- Cloud Storage read, list, remediation ---
    "storage.buckets.get",
    "storage.buckets.list",
    "storage.buckets.update",
    "storage.buckets.getIamPolicy",
    "storage.buckets.setIamPolicy",

    # --- Report upload to cspm-reports bucket ---
    "storage.objects.create",
    "storage.objects.get",
    "storage.objects.list",

    # --- BigQuery scan_history writes ---
    "bigquery.datasets.get",
    "bigquery.tables.get",
    "bigquery.tables.updateData",

    # --- Structured logging ---
    "logging.logEntries.create",
  ]

  depends_on = [google_project_service.enabled]
}

# =============================================================================
# SERVICE ACCOUNT — the identity the Cloud Function runs as
# -----------------------------------------------------------------------------
# No downloaded keys. The Cloud Function picks up this SA via its runtime
# service_account_email attribute (set in Step 10). Keys are the #1 GCP
# credential leak vector; we never create them.
# =============================================================================

resource "google_service_account" "cspm_scanner" {
  account_id   = "cspm-scanner"
  display_name = "CSPM Scanner"
  description  = "Service account for the CSPM scanner Cloud Function. Least-privilege via custom role cspmScannerRole."

  depends_on = [google_project_service.enabled]
}

# =============================================================================
# IAM BINDING — grant the custom role to the service account
# -----------------------------------------------------------------------------
# Using google_project_iam_member (additive) over google_project_iam_binding
# (authoritative). The additive form adds one principal; the authoritative
# form replaces the entire role's membership list. Additive is the safer
# default — a bug in Terraform can't accidentally wipe other principals.
# =============================================================================

resource "google_project_iam_member" "cspm_scanner_custom_role" {
  project = var.project_id
  role    = google_project_iam_custom_role.cspm_scanner.id
  member  = "serviceAccount:${google_service_account.cspm_scanner.email}"
}


# =============================================================================
# BIGQUERY DATASET — holds scan_history, remediation_log, and agent_audit_log
# -----------------------------------------------------------------------------
# US multi-region: cheaper than regional for small datasets, same free-tier
# benefits, no cross-region egress for us-central1 Cloud Functions.
#
# delete_contents_on_destroy = true: for learning projects, lets `terraform
# destroy` drop tables inside. For production you'd set this to false so
# destroy fails loudly if tables are populated.
# =============================================================================

resource "google_bigquery_dataset" "cspm_results" {
  #checkov:skip=CKV_GCP_81:Google-managed encryption at rest is on by default. CMEK needs a Cloud KMS key with recurring cost and key lifecycle overhead. Enterprise would use CMEK per data classification.
  dataset_id    = "cspm_results"
  friendly_name = "CSPM Scan + Remediation Results"
  description   = "Tables holding scanner output, remediation audit trail, and AI agent interaction log."
  location      = "US"

  delete_contents_on_destroy = true

  depends_on = [google_project_service.enabled]
}

# =============================================================================
# TABLE 1: scan_history — every finding seen on every scan
# -----------------------------------------------------------------------------
# Partitioned by `timestamp` so recent-window queries scan only recent partitions.
# One row per finding per scan. If the same finding appears in two scans, we
# get two rows — the primary key (scan_id, finding_id) differentiates them.
# =============================================================================

resource "google_bigquery_table" "scan_history" {
  #checkov:skip=CKV_GCP_80:Google-managed encryption at rest is on by default. CMEK needs a Cloud KMS key with recurring cost and key lifecycle overhead. Enterprise would use CMEK per data classification.
  #checkov:skip=CKV_GCP_121:Lab project must be fully removable with terraform destroy and teardown.sh. Enterprise would enable deletion_protection on production tables.
  dataset_id          = google_bigquery_dataset.cspm_results.dataset_id
  table_id            = "scan_history"
  deletion_protection = false # Allow terraform destroy to drop this table

  description = "One row per finding per scan run. Full audit trail of what the scanner saw."

  schema = jsonencode([
    {
      name        = "scan_id"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Unique UUID for this scan run. Groups all findings produced by a single scanner invocation."
    },
    {
      name        = "timestamp"
      type        = "TIMESTAMP"
      mode        = "REQUIRED"
      description = "When the scan started, UTC. Partition key."
    },
    {
      name        = "finding_id"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Unique identifier for this finding. Deterministic hash of (resource_name + category) so repeat findings dedup within a scan."
    },
    {
      name        = "resource_name"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Full GCP resource name, e.g. //storage.googleapis.com/projects/_/buckets/foo"
    },
    {
      name        = "finding_category"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Rule category: PUBLIC_BUCKET | PUBLIC_IAM_BINDING | etc."
    },
    {
      name        = "severity"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "LOW | MEDIUM | HIGH | CRITICAL"
    },
    {
      name        = "state"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "ACTIVE | REMEDIATED | SUPPRESSED"
    },
    {
      name        = "remediated"
      type        = "BOOLEAN"
      mode        = "REQUIRED"
      description = "True if the remediator took action on this finding during this scan."
    },
    {
      name        = "remediation_action"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Human-readable description of the action taken (null if remediated=false or dry_run=true)."
    }
  ])

  time_partitioning {
    type  = "DAY"
    field = "timestamp"
  }
}

# =============================================================================
# TABLE 2: remediation_log — detailed before/after state of every change
# -----------------------------------------------------------------------------
# Separate from scan_history because: (1) remediation events are rarer than
# findings, (2) we want before/after state preserved for compliance (which
# scan_history doesn't capture), (3) different retention policies may apply.
# =============================================================================

resource "google_bigquery_table" "remediation_log" {
  #checkov:skip=CKV_GCP_80:Google-managed encryption at rest is on by default. CMEK needs a Cloud KMS key with recurring cost and key lifecycle overhead. Enterprise would use CMEK per data classification.
  #checkov:skip=CKV_GCP_121:Lab project must be fully removable with terraform destroy and teardown.sh. Enterprise would enable deletion_protection on production tables.
  dataset_id          = google_bigquery_dataset.cspm_results.dataset_id
  table_id            = "remediation_log"
  deletion_protection = false

  description = "One row per remediation action attempted. Captures before/after state for compliance evidence."

  schema = jsonencode([
    {
      name        = "remediation_id"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Unique UUID for this remediation action."
    },
    {
      name        = "timestamp"
      type        = "TIMESTAMP"
      mode        = "REQUIRED"
      description = "When the remediation was attempted, UTC. Partition key."
    },
    {
      name        = "scan_id"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Links back to the scan_history row that triggered this remediation."
    },
    {
      name        = "finding_id"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "The finding that triggered this remediation."
    },
    {
      name        = "resource_name"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Resource that was modified."
    },
    {
      name        = "action_type"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "FIX_IAM_BINDING | FIX_PUBLIC_BUCKET | etc."
    },
    {
      name        = "dry_run"
      type        = "BOOLEAN"
      mode        = "REQUIRED"
      description = "True if this was a dry-run (no actual change made). Default posture for scanner is dry_run=true."
    },
    {
      name        = "before_state"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "JSON string of resource state BEFORE remediation."
    },
    {
      name        = "after_state"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "JSON string of resource state AFTER remediation (null if dry_run=true)."
    },
    {
      name        = "success"
      type        = "BOOLEAN"
      mode        = "REQUIRED"
      description = "True if the action completed successfully (or would have, for dry-runs)."
    },
    {
      name        = "error_message"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Error details if success=false."
    }
  ])

  time_partitioning {
    type  = "DAY"
    field = "timestamp"
  }
}

# =============================================================================
# TABLE 3: agent_audit_log — every AI agent interaction (Step 24)
# -----------------------------------------------------------------------------
# Core governance table for the Posture Advisor Agent. Every question, every
# tool call the agent made, every answer. If the agent ever gets accused of
# making a bad call, this table is the forensic record.
# =============================================================================

resource "google_bigquery_table" "agent_audit_log" {
  #checkov:skip=CKV_GCP_80:Google-managed encryption at rest is on by default. CMEK needs a Cloud KMS key with recurring cost and key lifecycle overhead. Enterprise would use CMEK per data classification.
  #checkov:skip=CKV_GCP_121:Lab project must be fully removable with terraform destroy and teardown.sh. Enterprise would enable deletion_protection on production tables.
  dataset_id          = google_bigquery_dataset.cspm_results.dataset_id
  table_id            = "agent_audit_log"
  deletion_protection = false

  description = "Full interaction log for the Posture Advisor AI agent. Every question, tool call, and response for governance evidence."

  schema = jsonencode([
    {
      name        = "interaction_id"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Unique UUID for this user interaction."
    },
    {
      name        = "timestamp"
      type        = "TIMESTAMP"
      mode        = "REQUIRED"
      description = "When the agent received the question, UTC. Partition key."
    },
    {
      name        = "user_question"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "The verbatim question the user asked."
    },
    {
      name        = "tool_calls"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "JSON array of tool names and args the agent invoked. Null if agent answered without tools."
    },
    {
      name        = "agent_response"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "The verbatim text the agent returned to the user."
    },
    {
      name        = "model_name"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "e.g. gemini-1.5-flash. Captured so we know which model version produced the answer."
    },
    {
      name        = "schema_validation_passed"
      type        = "BOOLEAN"
      mode        = "REQUIRED"
      description = "True if agent_response passed JSON schema validation (safety check)."
    }
  ])

  time_partitioning {
    type  = "DAY"
    field = "timestamp"
  }
}

# =============================================================================
# GCS REPORTS BUCKET — stores scanner JSON and CSV output
# -----------------------------------------------------------------------------
# Four security guards baked in at creation:
#   1. uniform_bucket_level_access = true (blocks legacy ACL grants)
#   2. public_access_prevention = enforced (nothing here can ever go public)
#   3. versioning = enabled (deleted objects are recoverable)
#   4. labels for billing attribution and ops filtering
#
# Soft delete policy is Google's default 7 days — extra recovery buffer.
#
# NOT created in Terraform: the Terraform state bucket (bootstrapped manually
# in Step 4, chicken-and-egg) and the demo public bucket (Step 22, created
# manually with gsutil for the remediation showcase).
# =============================================================================

resource "google_storage_bucket" "cspm_reports" {
  #checkov:skip=CKV_GCP_62:Access logging needs a second log bucket. Admin Activity audit logs are on by default. Enterprise would route logs to a central log sink project.
  name          = "cspm-reports-${var.project_id}"
  location      = "US" # Multi-region for durability + cheap storage
  storage_class = "STANDARD"
  force_destroy = true # Learning project; set false in prod

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  # Lifecycle: delete non-current versions older than 30 days to control cost.
  # Current objects are kept indefinitely.
  lifecycle_rule {
    condition {
      age        = 30
      with_state = "ARCHIVED" # ARCHIVED = non-current versions
    }
    action {
      type = "Delete"
    }
  }

  labels = {
    purpose    = "cspm-reports"
    data_class = "internal" # Not customer data, but not public
  }

  depends_on = [google_project_service.enabled]
}

# =============================================================================
# BUCKET-LEVEL IAM — grant the scanner SA write access to the reports bucket
# -----------------------------------------------------------------------------
# More surgical than the project-level storage.objects.create permission in
# the custom role. If the custom role were ever accidentally granted to another
# SA, that SA still couldn't write here without this bucket-level binding.
# Defense in depth at the IAM layer.
# =============================================================================

resource "google_storage_bucket_iam_member" "cspm_scanner_reports_writer" {
  bucket = google_storage_bucket.cspm_reports.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.cspm_scanner.email}"
}

# =============================================================================
# ARCHIVE_FILE — zip the function source for Terraform to upload
# -----------------------------------------------------------------------------
# archive_file is a Terraform-native data source. It zips a local directory
# into memory at plan time, then the zip is written to disk during apply.
# No gcloud, no gsutil, no shell scripts — fully declarative.
#
# `output_path` is where the zip lands on the local filesystem; Terraform's
# archive provider manages this transparently.
# =============================================================================

data "archive_file" "cspm_scanner_source" {
  type        = "zip"
  source_dir  = "${path.module}/../functions/cspm-scanner"
  output_path = "${path.module}/.terraform-cspm-scanner-source.zip"
}

# =============================================================================
# UPLOAD THE ZIP TO GCS — Cloud Functions reads source from a bucket
# -----------------------------------------------------------------------------
# We re-use the reports bucket with a `function-source/` prefix. In production
# I'd use a dedicated bucket for function source to separate code artifacts
# from runtime data. The name includes the source's MD5 hash so any source
# change produces a new object — Terraform detects the change and redeploys
# the function automatically.
# =============================================================================

resource "google_storage_bucket_object" "cspm_scanner_source" {
  name   = "function-source/cspm-scanner-${data.archive_file.cspm_scanner_source.output_md5}.zip"
  bucket = google_storage_bucket.cspm_reports.name
  source = data.archive_file.cspm_scanner_source.output_path
}

# =============================================================================
# CLOUD FUNCTION (Gen 2) — the scanner itself
# -----------------------------------------------------------------------------
# Gen 2 = Cloud Run under the hood with Eventarc trigger plumbing.
# Nine deliberate choices:
#   1. service_account_email = cspm-scanner SA (least-privilege, not default)
#   2. ingress_settings = ALLOW_INTERNAL_ONLY (no public internet access)
#   3. max_instance_count = 3 (cost blast-radius cap)
#   4. available_memory = 256Mi (minimum useful; scanner is I/O-bound not CPU)
#   5. timeout_seconds = 540 (9 min; well under Gen 2 max of 60 min)
#   6. no all_traffic_on_latest_revision allUsers invoker
#   7. environment_variables for config (never secrets)
#   8. source zip hashed into object name so changes trigger redeploy
#   9. labels for ops filtering
# =============================================================================

resource "google_cloudfunctions2_function" "cspm_scanner" {
  name        = "cspm-scanner"
  location    = var.region
  description = "CSPM scanner function. Called by Cloud Scheduler via OIDC-authenticated HTTP."

  build_config {
    runtime     = "python311"
    entry_point = "cspm_scan"

    source {
      storage_source {
        bucket = google_storage_bucket.cspm_reports.name
        object = google_storage_bucket_object.cspm_scanner_source.name
      }
    }
  }

  service_config {
    max_instance_count             = 3
    min_instance_count             = 0
    available_memory               = "512Mi"
    available_cpu                  = "1"
    timeout_seconds                = 540
    ingress_settings               = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision = true

    service_account_email = google_service_account.cspm_scanner.email

    environment_variables = {
      GCP_PROJECT_ID = var.project_id
      BQ_DATASET     = google_bigquery_dataset.cspm_results.dataset_id
      REPORTS_BUCKET = google_storage_bucket.cspm_reports.name
      DRY_RUN        = tostring(var.remediator_dry_run)
    }
  }

  depends_on = [
    google_project_service.enabled,
    google_project_iam_member.cspm_scanner_custom_role,
  ]
}

# =============================================================================
# IAM: let the scanner SA invoke the Cloud Run service (Gen 2 function)
# -----------------------------------------------------------------------------
# Gen 2 Cloud Functions ARE Cloud Run services under the hood. Scheduler's
# OIDC token asserts the cspm-scanner SA identity; the invoker IAM grant
# tells Cloud Run "this identity may invoke this service."
# =============================================================================

resource "google_cloud_run_service_iam_member" "cspm_scanner_invoker" {
  project  = var.project_id
  location = google_cloudfunctions2_function.cspm_scanner.location
  service  = google_cloudfunctions2_function.cspm_scanner.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.cspm_scanner.email}"
}

# =============================================================================
# IAM: belt-and-suspenders Gen 1-compatible invoker role
# -----------------------------------------------------------------------------
# Gen 2 should only need roles/run.invoker, but GCP's docs sometimes recommend
# both for cross-generation compatibility. Grants cost nothing to add.
# =============================================================================

resource "google_cloudfunctions2_function_iam_member" "cspm_scanner_invoker" {
  project        = var.project_id
  location       = google_cloudfunctions2_function.cspm_scanner.location
  cloud_function = google_cloudfunctions2_function.cspm_scanner.name
  role           = "roles/cloudfunctions.invoker"
  member         = "serviceAccount:${google_service_account.cspm_scanner.email}"
}

# =============================================================================
# CLOUD SCHEDULER JOB — daily CSPM scan trigger
# -----------------------------------------------------------------------------
# Three deliberate choices:
#   1. OIDC auth (not public, not static tokens) — Scheduler proves identity
#      cryptographically with a short-lived Google-signed token
#   2. Target URI is the function's internal Cloud Run URL — invocation stays
#      inside Google's network, never touches the public internet
#   3. Retry config caps attempts so a broken function doesn't retry forever
#      and burn through free-tier invocations
# =============================================================================

resource "google_cloud_scheduler_job" "daily_cspm_scan" {
  name        = "daily-cspm-scan"
  description = "Runs the CSPM scanner every day at 06:00 America/New_York."
  schedule    = var.scheduler_cron
  time_zone   = var.scheduler_timezone
  region      = var.region

  # Cap the retry escalation so a buggy function can't retry forever.
  retry_config {
    retry_count          = 1
    max_retry_duration   = "300s"
    min_backoff_duration = "30s"
    max_backoff_duration = "300s"
  }

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.cspm_scanner.service_config[0].uri

    # OIDC token: Google signs a JWT asserting the service_account_email's
    # identity. Scheduler attaches it as a bearer token on every call.
    # The function's Cloud Run runtime verifies the signature + IAM policy.
    oidc_token {
      service_account_email = google_service_account.cspm_scanner.email
      # audience is auto-set to the function URI if omitted — explicit for clarity.
      audience = google_cloudfunctions2_function.cspm_scanner.service_config[0].uri
    }

    headers = {
      "Content-Type" = "application/json"
    }

    body = base64encode(jsonencode({
      source  = "cloud-scheduler"
      trigger = "daily-scan"
    }))
  }

  depends_on = [
    google_cloud_run_service_iam_member.cspm_scanner_invoker,
    google_cloudfunctions2_function_iam_member.cspm_scanner_invoker,
  ]
}
