#!/usr/bin/env bash
# Portable local-staging bootstrap and lifecycle wrapper for macOS and Linux.
# Windows uses the equivalent scripts/windows/local-staging.ps1 entry point.

set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
env_path="$repo_root/deploy/local-staging.env"
env_example_path="$repo_root/deploy/local-staging.env.example"
compose_file="$repo_root/compose.local-staging.yaml"
project_name="compass-local-staging"

compose_command=()

usage() {
    cat <<'EOF'
Usage:
  scripts/unix/local-staging.sh bootstrap [options]
  scripts/unix/local-staging.sh up
  scripts/unix/local-staging.sh down
  scripts/unix/local-staging.sh status
  scripts/unix/local-staging.sh health-only
  scripts/unix/local-staging.sh activate
  scripts/unix/local-staging.sh seed
  scripts/unix/local-staging.sh readiness [--system-identity VALUE]

Bootstrap options:
  --configure-daily
  --daily-domain VALUE
  --daily-webhook-id VALUE
  --daily-webhook-url VALUE

The script prefers native podman-compose because the stack uses external
Podman secrets. If only `podman compose` is available, it selects the native
podman-compose provider through PODMAN_COMPOSE_PROVIDER.
EOF
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

select_compose_command() {
    if command -v podman-compose >/dev/null 2>&1; then
        compose_command=(podman-compose)
        return
    fi

    # Podman's compose shim otherwise prefers the Docker Compose provider on
    # some installations. That provider cannot consume these external Podman
    # secrets, so force the native provider when using the shim.
    export PODMAN_COMPOSE_PROVIDER=podman-compose
    compose_command=(podman compose)
}

run_compose() {
    "${compose_command[@]}" \
        --project-name "$project_name" \
        --env-file "$env_path" \
        -f "$compose_file" \
        "$@"
}

random_hex() {
    openssl rand -hex "$1" | tr -d '\r\n'
}

random_base64() {
    openssl rand -base64 "$1" | tr -d '\r\n'
}

random_fernet_key() {
    random_base64 32 | tr '+/' '-_'
}

assert_single_line() {
    local name=$1
    local value=$2
    case "$value" in
        *$'\n'*|*$'\r'*) die "$name contains an invalid line break." ;;
    esac
}

secret_exists() {
    local name=$1
    local existing=$2
    printf '%s\n' "$existing" | grep -Fqx -- "$name"
}

create_secret() {
    local name=$1
    local value=$2
    local existing=$3

    if secret_exists "$name" "$existing"; then
        return 0
    fi
    [[ -n "$value" ]] || die "Refusing to create an empty Podman secret: $name"
    printf '%s' "$value" | podman secret create "$name" - >/dev/null
}

set_env_entry() {
    local name=$1
    local value=$2
    local tmp

    [[ "$name" =~ ^[A-Z][A-Z0-9_]*$ ]] || die "Invalid environment setting name."
    assert_single_line "$name" "$value"
    tmp=$(mktemp "${env_path}.tmp.XXXXXX")
    awk -v key="$name" -v replacement="$name=$value" '
        index($0, key "=") == 1 { print replacement; found = 1; next }
        { print }
        END { if (!found) print replacement }
    ' "$env_path" > "$tmp"
    mv "$tmp" "$env_path"
}

read_hidden() {
    local prompt=$1
    local value
    read -r -s -p "$prompt" value
    printf '\n' >&2
    printf '%s' "$value"
}

validate_daily_options() {
    [[ "$daily_domain" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || \
        die "DailyDomain must be a canonical host without a scheme, path, or port."
    [[ "$daily_domain" != *..* ]] || \
        die "DailyDomain must not contain consecutive dots."

    if [[ -n "$daily_webhook_id" ]]; then
        [[ "$daily_webhook_id" =~ ^[A-Za-z0-9-]{1,128}$ ]] || \
            die "DailyWebhookId contains invalid characters."
    fi

    if [[ -n "$daily_webhook_url" ]]; then
        case "$daily_webhook_url" in
            https://?*) ;;
            *) die "DailyWebhookUrl must be an absolute HTTPS URL." ;;
        esac
    fi
}

bootstrap() {
    require_command openssl

    [[ ! -e "$env_path" ]] || \
        die "deploy/local-staging.env already exists; refusing to overwrite it."

    local existing
    existing=$(podman secret ls --format '{{.Name}}') || \
        die "Unable to inspect the local Podman secret store."
    if printf '%s\n' "$existing" | grep -q '^compass-local-staging-'; then
        die "Local staging secrets already exist; refusing to rotate credentials implicitly. Restore deploy/local-staging.env or remove the isolated stack explicitly."
    fi

    cp "$env_example_path" "$env_path"
    chmod 600 "$env_path"
    local stamp
    stamp=$(date +%Y%m%d%H%M%S)
    set_env_entry COMPASS_RELEASE_VERSION "local-staging-$stamp"
    set_env_entry COMPASS_BUILD_ID "local-staging-$stamp"

    local daily_api_key="disabled-local-staging-$(random_hex 16)"
    local daily_webhook_secret
    daily_webhook_secret=$(random_base64 32)

    if [[ "$configure_daily" == 1 ]]; then
        daily_api_key=$(read_hidden "Daily API key: ")
        [[ -n "$daily_api_key" ]] || die "Daily API key cannot be empty."
        validate_daily_options

        local provided_webhook_secret
        provided_webhook_secret=$(read_hidden "Daily webhook HMAC secret (leave blank to generate a base64 rehearsal secret): ")
        if [[ -n "$provided_webhook_secret" ]]; then
            local decoded_file decoded_bytes
            decoded_file=$(mktemp)
            if ! printf '%s' "$provided_webhook_secret" | openssl base64 -d -A > "$decoded_file" 2>/dev/null; then
                rm -f "$decoded_file"
                die "Daily webhook HMAC secret must be valid base64."
            fi
            decoded_bytes=$(wc -c < "$decoded_file" | tr -d '[:space:]')
            rm -f "$decoded_file"
            [[ "$decoded_bytes" -ge 32 ]] || \
                die "Daily webhook HMAC secret must decode to at least 32 bytes."
            daily_webhook_secret=$provided_webhook_secret
        fi
    fi

    local postgres_password protected_access_key protected_secret_key
    local backup_access_key backup_secret_key
    postgres_password=$(random_hex 24)
    protected_access_key="compasslocal$(random_hex 8)"
    protected_secret_key=$(random_hex 24)
    backup_access_key="compassbackup$(random_hex 8)"
    backup_secret_key=$(random_hex 24)

    create_secret compass-local-staging-postgres-password "$postgres_password" "$existing"
    create_secret compass-local-staging-secret-key "$(random_hex 48)" "$existing"
    create_secret compass-local-staging-audit-hash-secret "$(random_hex 48)" "$existing"
    create_secret compass-local-staging-account-security-hash-secret "$(random_hex 48)" "$existing"
    create_secret compass-local-staging-account-activation-token-secret "$(random_hex 48)" "$existing"
    create_secret compass-local-staging-database-url \
        "postgresql://compass:$postgres_password@db:5432/compass_local_staging" "$existing"
    create_secret compass-local-staging-protected-storage-s3-access-key "$protected_access_key" "$existing"
    create_secret compass-local-staging-protected-storage-s3-secret-key "$protected_secret_key" "$existing"
    create_secret compass-local-staging-backup-storage-s3-access-key "$backup_access_key" "$existing"
    create_secret compass-local-staging-backup-storage-s3-secret-key "$backup_secret_key" "$existing"
    create_secret compass-local-staging-field-encryption-key "$(random_fernet_key)" "$existing"
    create_secret compass-local-staging-account-security-turnstile-secret \
        "1x0000000000000000000000000000000AA" "$existing"
    create_secret compass-local-staging-email-host-password "$(random_hex 24)" "$existing"
    create_secret compass-local-staging-ecounseling-daily-api-key "$daily_api_key" "$existing"
    create_secret compass-local-staging-ecounseling-daily-webhook-secret "$daily_webhook_secret" "$existing"
    create_secret compass-local-staging-ecounseling-room-salt "$(random_hex 48)" "$existing"

    if [[ "$configure_daily" == 1 ]]; then
        set_env_entry COMPASS_LOCAL_STAGING_DAILY_ENABLED True
        set_env_entry ECOUNSELING_DAILY_DOMAIN "$daily_domain"
        set_env_entry ECOUNSELING_DAILY_WEBHOOK_ID "$daily_webhook_id"
        set_env_entry ECOUNSELING_DAILY_WEBHOOK_URL "$daily_webhook_url"
        if [[ -n "$daily_webhook_id" && -n "$daily_webhook_url" ]]; then
            set_env_entry ECOUNSELING_PROVIDER DAILY
        else
            set_env_entry ECOUNSELING_PROVIDER disabled
            printf '%s\n' "WARNING: Daily credentials were imported, but the provider remains disabled until a matching public HTTPS webhook URL and webhook id are configured." >&2
        fi
    fi

    printf '%s\n' "Local staging configuration created. Secret values were written only to the local Podman secret store."
}

require_env() {
    [[ -f "$env_path" ]] || \
        die "Run scripts/unix/local-staging.sh bootstrap first."
}

action=${1:-status}
shift || true
configure_daily=0
daily_domain="demo-compass.daily.co"
daily_webhook_id=""
daily_webhook_url=""
system_identity=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --configure-daily)
            configure_daily=1
            shift
            ;;
        --daily-domain)
            [[ $# -ge 2 ]] || die "--daily-domain requires a value."
            daily_domain=$2
            shift 2
            ;;
        --daily-domain=*)
            daily_domain=${1#*=}
            shift
            ;;
        --daily-webhook-id)
            [[ $# -ge 2 ]] || die "--daily-webhook-id requires a value."
            daily_webhook_id=$2
            shift 2
            ;;
        --daily-webhook-id=*)
            daily_webhook_id=${1#*=}
            shift
            ;;
        --daily-webhook-url)
            [[ $# -ge 2 ]] || die "--daily-webhook-url requires a value."
            daily_webhook_url=$2
            shift 2
            ;;
        --daily-webhook-url=*)
            daily_webhook_url=${1#*=}
            shift
            ;;
        --system-identity)
            [[ $# -ge 2 ]] || die "--system-identity requires a value."
            system_identity=$2
            shift 2
            ;;
        --system-identity=*)
            system_identity=${1#*=}
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "Unknown option: $1"
            ;;
    esac
done

require_command podman
select_compose_command

if [[ "$action" == bootstrap ]]; then
    bootstrap
    exit 0
fi

if [[ "$action" == -h || "$action" == --help ]]; then
    usage
    exit 0
fi

require_env

case "$action" in
    up)
        run_compose up -d --build
        ;;
    down)
        run_compose down
        ;;
    status)
        run_compose ps
        ;;
    health-only)
        set_env_entry COMPASS_ACCESS_MODE health_only
        run_compose up -d
        ;;
    activate)
        set_env_entry COMPASS_ACCESS_MODE active
        run_compose up -d
        ;;
    seed)
        run_compose exec -T web /usr/local/bin/compass-secret-env python manage.py seed_operating_demo
        ;;
    readiness)
        readiness_args=(
            exec -T web /usr/local/bin/compass-secret-env python manage.py verify_health
            --strict --probe-external --format json
        )
        if [[ -n "$system_identity" ]]; then
            readiness_args+=(--system-identity "$system_identity")
        fi
        run_compose "${readiness_args[@]}"
        ;;
    *)
        usage >&2
        die "Unknown action: $action"
        ;;
esac
