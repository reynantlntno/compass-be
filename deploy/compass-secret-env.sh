#!/bin/sh
# Read only the explicitly declared runtime secrets. Values never go to
# stdout/stderr; the wrapper replaces itself with the requested application
# process after exporting them.
set -eu

secret_dir=${COMPASS_SECRET_ENV_DIR:-/run/secrets}
secret_prefix=${COMPASS_SECRET_PREFIX:-}
include_turnstile_secret=${COMPASS_SECRET_ENV_INCLUDE_TURNSTILE_SECRET:-False}
include_email_secret=${COMPASS_SECRET_ENV_INCLUDE_EMAIL_SECRET:-False}
include_ecounseling_secret=${COMPASS_SECRET_ENV_INCLUDE_ECOUNSELING_SECRET:-False}

secret_mount_name() {
    logical_name=$1
    if [ -n "$secret_prefix" ]; then
        printf '%s-%s' "$secret_prefix" "$logical_name" \
            | tr '[:upper:]_' '[:lower:]-'
    else
        printf '%s' "$logical_name"
    fi
}

read_required_secret() {
    name=$1
    path="$secret_dir/$(secret_mount_name "$name")"
    if [ ! -r "$path" ] || [ ! -f "$path" ]; then
        echo "COMPASS secret mount is unavailable: $name" >&2
        exit 78
    fi
    value=$(cat "$path")
    case "$value" in
        *[![:space:]]*) ;;
        *)
            echo "COMPASS secret mount is empty: $name" >&2
            exit 78
            ;;
    esac
    case "$value" in
        [[:space:]]*|*[[:space:]])
            echo "COMPASS secret mount has surrounding whitespace: $name" >&2
            exit 78
            ;;
    esac
    case "$value" in
        *[![:print:]]*)
            echo "COMPASS secret mount contains non-printable data: $name" >&2
            exit 78
            ;;
    esac
    export "$name=$value"
}

read_required_secret SECRET_KEY
read_required_secret AUDIT_HASH_SECRET
read_required_secret ACCOUNT_SECURITY_HASH_SECRET
read_required_secret ACCOUNT_ACTIVATION_TOKEN_SECRET
read_required_secret DATABASE_URL
read_required_secret PROTECTED_STORAGE_S3_ACCESS_KEY
read_required_secret PROTECTED_STORAGE_S3_SECRET_KEY
read_required_secret BACKUP_STORAGE_S3_ACCESS_KEY
read_required_secret BACKUP_STORAGE_S3_SECRET_KEY
read_required_secret FIELD_ENCRYPTION_KEY

assert_distinct_secret() {
    left_name=$1
    left_value=$2
    right_name=$3
    right_value=$4
    if [ "$left_value" = "$right_value" ]; then
        echo "COMPASS secrets must be distinct: $left_name and $right_name" >&2
        exit 78
    fi
}

assert_distinct_secret SECRET_KEY "$SECRET_KEY" AUDIT_HASH_SECRET "$AUDIT_HASH_SECRET"
assert_distinct_secret SECRET_KEY "$SECRET_KEY" ACCOUNT_SECURITY_HASH_SECRET "$ACCOUNT_SECURITY_HASH_SECRET"
assert_distinct_secret SECRET_KEY "$SECRET_KEY" ACCOUNT_ACTIVATION_TOKEN_SECRET "$ACCOUNT_ACTIVATION_TOKEN_SECRET"
assert_distinct_secret AUDIT_HASH_SECRET "$AUDIT_HASH_SECRET" ACCOUNT_SECURITY_HASH_SECRET "$ACCOUNT_SECURITY_HASH_SECRET"
assert_distinct_secret AUDIT_HASH_SECRET "$AUDIT_HASH_SECRET" ACCOUNT_ACTIVATION_TOKEN_SECRET "$ACCOUNT_ACTIVATION_TOKEN_SECRET"
assert_distinct_secret ACCOUNT_SECURITY_HASH_SECRET "$ACCOUNT_SECURITY_HASH_SECRET" ACCOUNT_ACTIVATION_TOKEN_SECRET "$ACCOUNT_ACTIVATION_TOKEN_SECRET"

secret_flag_enabled() {
    normalized=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
    case "$normalized" in
        1|true|yes) return 0 ;;
        *) return 1 ;;
    esac
}

if secret_flag_enabled "$include_turnstile_secret"; then
    read_required_secret ACCOUNT_SECURITY_TURNSTILE_SECRET
fi
if secret_flag_enabled "$include_email_secret"; then
    read_required_secret EMAIL_HOST_PASSWORD
fi
if secret_flag_enabled "$include_ecounseling_secret"; then
    read_required_secret ECOUNSELING_DAILY_API_KEY
    read_required_secret ECOUNSELING_DAILY_WEBHOOK_SECRET
    read_required_secret ECOUNSELING_ROOM_SALT
    assert_distinct_secret SECRET_KEY "$SECRET_KEY" ECOUNSELING_ROOM_SALT "$ECOUNSELING_ROOM_SALT"
    assert_distinct_secret AUDIT_HASH_SECRET "$AUDIT_HASH_SECRET" ECOUNSELING_ROOM_SALT "$ECOUNSELING_ROOM_SALT"
    assert_distinct_secret ACCOUNT_SECURITY_HASH_SECRET "$ACCOUNT_SECURITY_HASH_SECRET" ECOUNSELING_ROOM_SALT "$ECOUNSELING_ROOM_SALT"
    assert_distinct_secret ACCOUNT_ACTIVATION_TOKEN_SECRET "$ACCOUNT_ACTIVATION_TOKEN_SECRET" ECOUNSELING_ROOM_SALT "$ECOUNSELING_ROOM_SALT"
fi

if [ "$#" -eq 0 ]; then
    echo "COMPASS secret wrapper requires an application command." >&2
    exit 64
fi

exec "$@"
