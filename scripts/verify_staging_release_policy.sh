#!/usr/bin/env bash
# Read-only policy gate for the local-to-OCI staging release boundary.
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
failures=0

fail() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
}

require_dockerignore_line() {
  line=$1
  # Windows checkouts may retain CRLF in this text-only contract file.
  if ! tr -d '\r' < "$repo_root/.dockerignore" | grep -Fqx -- "$line"; then
    fail ".dockerignore is missing: $line"
  fi
}

require_absence() {
  pattern=$1
  path=$2
  if grep -F -n -- "$pattern" "$repo_root/$path" >/dev/null; then
    fail "$path contains a retired API-only deployment setting: $pattern"
  fi
}

require_match() {
  pattern=$1
  path=$2
  if ! grep -F -q -- "$pattern" "$repo_root/$path"; then
    fail "$path is missing the API-only deployment contract: $pattern"
  fi
}

for ignored_path in \
  '.local/' \
  'backups/' \
  'media/' \
  'protected_media/' \
  'private_media/' \
  'output/' \
  'tmp/' \
  'staticfiles/' \
  'static_collected/' \
  'docs/' \
  'infra/' \
  'scripts/' \
  'tests/' \
  '**/tests/' \
  'compose*.yaml' \
  'deploy/*' \
  '!deploy/compass-secret-env.sh' \
  '*.pem' \
  '*.key' \
  '*.p12' \
  '*.pfx' \
  '*.crt' \
  '*.csr' \
  '*.tfstate' \
  '*.tfstate.*' \
  '.env*'; do
  require_dockerignore_line "$ignored_path"
done

for required_path in \
  Containerfile \
  compose.staging.yaml \
  deploy/bootstrap_vault_podman_secrets.sh \
  deploy/compass-secret-env.sh \
  deploy/nginx/compass.conf \
  deploy/staging.env.example \
  deploy/vault-secret-map.example \
  static/images/ucn_cnsc_logo.png; do
  [ -f "$repo_root/$required_path" ] || fail "Required file is missing: $required_path"
done

if git -C "$repo_root" check-ignore -q -- deploy/compass-secret-env.sh; then
  fail "The runtime secret wrapper is ignored by Git."
fi
if git -C "$repo_root" check-ignore -q -- static/images/ucn_cnsc_logo.png; then
  fail "The new UCN/CNSC logo is ignored by Git."
fi

tracked_local_only=0
while IFS= read -r -d '' tracked_path; do
  case "$tracked_path" in
    .local/*|backups/*|media/*|protected_media/*|private_media/*|output/*|tmp/*|staticfiles/*|static_collected/*)
      tracked_local_only=$((tracked_local_only + 1))
      ;;
  esac
done < <(git -C "$repo_root" ls-files -z)

if [ "$tracked_local_only" -ne 0 ]; then
  echo "NOTICE: $tracked_local_only pre-existing local/review artifact(s) remain tracked but are excluded from staging." >&2
fi

if grep -Eq '^[[:space:]]*build:' "$repo_root/compose.staging.yaml"; then
  fail "compose.staging.yaml must use an image, not a local build."
fi
if grep -Eiq '^[[:space:]]{2}(minio|mailpit):' "$repo_root/compose.staging.yaml"; then
  fail "compose.staging.yaml contains a local-only MinIO/Mailpit service."
fi
if ! grep -Fq 'archive --format=tar' "$repo_root/scripts/oci/build_staging_image.sh"; then
  fail "The image build script does not use a committed Git archive."
fi
if ! grep -Fq 'status --porcelain --untracked-files=all' "$repo_root/scripts/oci/build_staging_image.sh"; then
  fail "The image build script lacks the dirty-worktree guard."
fi
if ! grep -Fq 'archive --format=tar' "$repo_root/scripts/oci/package_staging_release.sh"; then
  fail "The release package script does not use an explicit Git allowlist."
fi
if ! grep -Fq 'scp' "$repo_root/scripts/oci/push_staging_release.sh" || \
   ! grep -Fq -- '--execute' "$repo_root/scripts/oci/push_staging_release.sh"; then
  fail "The staging transfer script lacks explicit scp execution gating."
fi

# The service is API-only. Keep the root URL contract explicit so a retired
# server-rendered route cannot silently return through a staging release.
if ! grep -Fq 'path("api/v1/", api_v1.urls)' "$repo_root/config/urls.py"; then
  fail "config/urls.py does not expose the canonical API root."
fi
if grep -E -n 'include\(|TemplateView|render\(' "$repo_root/config/urls.py" >/dev/null; then
  fail "config/urls.py contains a server-rendered/MVT root route."
fi

# These controls are Governance-owned. Deployment files must not become a
# second policy source after the API cutover.
for policy_setting in \
  'ECOUNSELING_JOIN_WINDOW_BEFORE_MINUTES' \
  'ECOUNSELING_JOIN_WINDOW_AFTER_MINUTES' \
  'ECOUNSELING_DAILY_MEETING_TOKEN_TTL_SECONDS' \
  'ECOUNSELING_RECORDING_ENABLED' \
  'ECOUNSELING_RECORDING_WORKER_ENABLED' \
  'ECOUNSELING_RECORDING_AUDIO_VIDEO_ENABLED' \
  'ECOUNSELING_RECORDING_TRANSCRIPTION_ENABLED' \
  'ECOUNSELING_RECORDING_TRANSCRIPTION_WORKER_ENABLED' \
  'ECOUNSELING_RECORDING_MAX_FILE_SIZE_BYTES' \
  'ECOUNSELING_RECORDING_TRANSCRIPTION_MAX_FILE_SIZE_BYTES'; do
  require_absence "$policy_setting" compose.staging.yaml
  require_absence "$policy_setting" deploy/staging.env.example
  require_absence "$policy_setting" .env.example
  if [ -f "$repo_root/.env" ]; then
    require_absence "$policy_setting" .env
  fi
done

# Operational controls are deployment-owned. Keep the same contract in the
# staging image, the checked-in environment template, and the canonical local
# environment template so a setting cannot silently disappear during rollout.
for deployment_setting in \
  'MAINTENANCE_ENFORCEMENT_ENABLED' \
  'DOCUMENT_PDF_RENDERER_ENABLED' \
  'DOCUMENT_PDF_RENDERER_TIMEOUT_MS' \
  'ACCOUNT_SECURITY_CAPTCHA_TIMEOUT_SECONDS' \
  'EMAIL_TIMEOUT' \
  'NOTIFICATION_WORKER_ENABLED' \
  'NOTIFICATION_WORKER_INTERVAL_SECONDS' \
  'NOTIFICATION_WORKER_BATCH_SIZE' \
  'NOTIFICATION_WORKER_LOCK_TIMEOUT_SECONDS' \
  'BACKUP_WORKER_POLL_INTERVAL_SECONDS' \
  'REPORT_SYNC_MAX_OUTPUT_BYTES' \
  'REPORT_SYNC_MAX_WORK_UNITS' \
  'REPORT_ASYNC_AFTER_WORK_UNITS' \
  'REPORT_RUN_TIMEOUT_SECONDS' \
  'REPORT_EXPORT_MAX_OUTPUT_BYTES' \
  'PROTECTED_STORAGE_MAX_FILE_SIZE_BYTES'; do
  require_match "$deployment_setting" compose.staging.yaml
  require_match "$deployment_setting" deploy/staging.env.example
  require_match "$deployment_setting" .env.example
done

for retired_setting in \
  'ECOUNSELING_JOIN_DENIAL_RATE_LIMIT_COUNT' \
  'ECOUNSELING_JOIN_DENIAL_RATE_LIMIT_WINDOW_SECONDS' \
  'COMPASS_APPLICATION_BASE_URL' \
  'COMPASS_ACTIVE_INSTITUTION_NAME' \
  'COMPASS_ACTIVE_OFFICE_NAME' \
  'student-activation-token-secret'; do
  require_absence "$retired_setting" compose.staging.yaml
  require_absence "$retired_setting" deploy/staging.env.example
  require_absence "$retired_setting" .env.example
  if [ -f "$repo_root/.env" ]; then
    require_absence "$retired_setting" .env
  fi
done

require_match 'ALLOWED_HOSTS: "${ALLOWED_HOSTS:-staging-api.compass-gco.com}' compose.staging.yaml
require_match 'COMPASS_API_BASE_URL: ${COMPASS_API_BASE_URL:-https://staging-api.compass-gco.com}' compose.staging.yaml
require_match 'CORS_ALLOWED_ORIGINS=https://staging.compass-gco.com' deploy/staging.env.example
require_match 'COMPASS_API_BASE_URL=https://staging-api.compass-gco.com' deploy/staging.env.example
require_match 'COMPASS_CLIENT_BASE_URL=https://staging.compass-gco.com' deploy/staging.env.example

if [ "$failures" -ne 0 ]; then
  echo "Staging release policy failed with $failures issue(s)." >&2
  exit 78
fi

echo "Staging release policy passed."
echo "Local runtime data is excluded; release packaging remains committed-release only."
