#!/usr/bin/env bash
# Retrieve approved OCI Vault secret versions and create root-owned external
# Podman secrets. This script never prints secret values and refuses to replace
# an existing Podman secret.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this bootstrap as root so the secrets belong to the rootful Podman store." >&2
  exit 77
fi

oci_profile=${OCI_PROFILE:-COMPASS}
oci_region=${OCI_REGION:-ap-singapore-1}
oci_auth=${OCI_AUTH:-api_key}
secret_prefix=${COMPASS_SECRET_PREFIX:-compass-staging}
secret_map=${COMPASS_VAULT_SECRET_MAP_FILE:-/etc/compass/vault-secret-map}
skip_existing=${COMPASS_SECRET_BOOTSTRAP_SKIP_EXISTING:-False}

if [ ! -r "$secret_map" ]; then
  echo "Vault secret map is unavailable: $secret_map" >&2
  exit 78
fi
command -v oci >/dev/null 2>&1 || { echo "OCI CLI is required." >&2; exit 127; }
command -v podman >/dev/null 2>&1 || { echo "Podman is required." >&2; exit 127; }
command -v python3 >/dev/null 2>&1 || { echo "Python 3 is required to decode the OCI response." >&2; exit 127; }
command -v base64 >/dev/null 2>&1 || { echo "base64 is required." >&2; exit 127; }

tmp_root=$(mktemp -d /run/compass-secret-bootstrap.XXXXXX)
cleanup() {
  chmod -R go-rwx "$tmp_root" 2>/dev/null || true
  rm -rf "$tmp_root"
}
trap cleanup EXIT HUP INT TERM
chmod 700 "$tmp_root"

podman_secret_name() {
  logical_name=$1
  printf '%s-%s' "$secret_prefix" "$logical_name" \
    | tr '[:upper:]_' '[:lower:]-'
}

flag_enabled() {
  normalized=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  case "$normalized" in
    1|true|yes) return 0 ;;
    *) return 1 ;;
  esac
}

decode_bundle_content() {
  python3 -c '
import base64
import json
import sys

payload = json.load(sys.stdin)
data = payload.get("data") or {}
content = (
    data.get("secretBundleContent", {}).get("content")
    or data.get("secret-bundle-content", {}).get("content")
)
if not content:
    raise SystemExit("OCI secret bundle did not contain secret content")
sys.stdout.buffer.write(base64.b64decode(content))
'
}

allowed_targets=' POSTGRES_PASSWORD SECRET_KEY AUDIT_HASH_SECRET ACCOUNT_SECURITY_HASH_SECRET ACCOUNT_ACTIVATION_TOKEN_SECRET DATABASE_URL PROTECTED_STORAGE_S3_ACCESS_KEY PROTECTED_STORAGE_S3_SECRET_KEY BACKUP_STORAGE_S3_ACCESS_KEY BACKUP_STORAGE_S3_SECRET_KEY FIELD_ENCRYPTION_KEY ACCOUNT_SECURITY_TURNSTILE_SECRET EMAIL_HOST_PASSWORD ECOUNSELING_DAILY_API_KEY ECOUNSELING_DAILY_WEBHOOK_SECRET ECOUNSELING_ROOM_SALT '
seen_targets=" "

while IFS='=' read -r target secret_ocid _extra; do
  target=$(printf '%s' "$target" | tr -d '[:space:]')
  secret_ocid=$(printf '%s' "$secret_ocid" | tr -d '[:space:]')
  [ -z "$target" ] && continue
  case "$target" in \#*) continue ;; esac
  case "$allowed_targets" in *" $target "*) ;; *) echo "Unsupported secret target: $target" >&2; exit 78 ;; esac
  case "$secret_ocid" in
    ocid1.vaultsecret.oc1.*) ;;
    *) echo "Invalid OCI Vault secret OCID for $target." >&2; exit 78 ;;
  esac
  case "$seen_targets" in *" $target "*) echo "Duplicate secret target: $target" >&2; exit 78 ;; esac
  seen_targets="$seen_targets$target "

  podman_name=$(podman_secret_name "$target")
  if podman secret inspect "$podman_name" >/dev/null 2>&1; then
    if flag_enabled "$skip_existing"; then
      echo "Keeping existing root-owned Podman secret: $podman_name"
      continue
    fi
    echo "Refusing to replace existing Podman secret: $podman_name" >&2
    exit 78
  fi

  secret_file="$tmp_root/$target"
  oci --profile "$oci_profile" --region "$oci_region" --auth "$oci_auth" \
    secrets secret-bundle get --secret-id "$secret_ocid" --stage CURRENT --output json \
    | decode_bundle_content > "$secret_file"
  chmod 600 "$secret_file"
  if ! grep -q '[^[:space:]]' "$secret_file"; then
    echo "OCI secret is empty: $target" >&2
    exit 78
  fi
  podman secret create "$podman_name" "$secret_file" >/dev/null
  echo "Created root-owned Podman secret: $podman_name"
done < "$secret_map"

for required_target in POSTGRES_PASSWORD SECRET_KEY AUDIT_HASH_SECRET ACCOUNT_SECURITY_HASH_SECRET \
  ACCOUNT_ACTIVATION_TOKEN_SECRET DATABASE_URL PROTECTED_STORAGE_S3_ACCESS_KEY \
  PROTECTED_STORAGE_S3_SECRET_KEY BACKUP_STORAGE_S3_ACCESS_KEY \
  BACKUP_STORAGE_S3_SECRET_KEY FIELD_ENCRYPTION_KEY ACCOUNT_SECURITY_TURNSTILE_SECRET \
  EMAIL_HOST_PASSWORD ECOUNSELING_DAILY_API_KEY ECOUNSELING_DAILY_WEBHOOK_SECRET \
  ECOUNSELING_ROOM_SALT; do
  case "$seen_targets" in
    *" $required_target "*) ;;
    *) echo "Vault secret map is missing: $required_target" >&2; exit 78 ;;
  esac
done
