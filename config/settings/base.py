# Project: COMPASS
# File: config/settings/base.py
# Module: config
# Purpose: Shared Django settings for all environments
# Domain boundary and service policy.
# Notes: Environment-specific values are parsed via django-environ.
#   AUTH_USER_MODEL must be set here before any migration.

import json
import os
from datetime import datetime, timedelta, timezone as datetime_timezone
from pathlib import Path

import environ
from django.core.exceptions import ImproperlyConfigured

from .environment import validate_origins
from config.runtime_settings import read_environment_setting

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------
# BASE_DIR is the project root (where manage.py lives)
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# --------------------------------------------------------------------------
# Environment
# --------------------------------------------------------------------------
env = environ.Env(
    DEBUG=(bool, False),
    ALLOWED_HOSTS=(list, []),
)
# Read .env file if it exists (development convenience)
environ.Env.read_env(os.path.join(BASE_DIR, ".env"), overwrite=False)


def strict_env_bool(name, *, default=None, required=False):
    """Read a canonical boolean without exposing its raw value on failure."""
    raw_value = os.environ.get(name)
    if raw_value is None:
        if required:
            raise ImproperlyConfigured(f"{name} must be explicitly configured.")
        return default
    normalized = raw_value.strip().lower()
    if normalized in {"true", "1", "yes", "on"}:
        return True
    if normalized in {"false", "0", "no", "off"}:
        return False
    raise ImproperlyConfigured(f"{name} must be a canonical boolean.")


def runtime_env(name):
    """Read an environment-owned runtime control from the canonical inventory."""

    try:
        return read_environment_setting(name)
    except ValueError as exc:
        raise ImproperlyConfigured(str(exc)) from exc


# --------------------------------------------------------------------------
# Core
# --------------------------------------------------------------------------
SECRET_KEY = env("SECRET_KEY")
DEBUG = env("DEBUG")
ALLOWED_HOSTS = env("ALLOWED_HOSTS")
COMPASS_ENVIRONMENT = env("COMPASS_ENVIRONMENT", default="development")
# These values are supplied by the immutable deployment artifact for staging
# and production.  They are intentionally non-secret and safe to include in
# IT-only readiness output and redacted application-error metadata.
COMPASS_RELEASE_VERSION = env("COMPASS_RELEASE_VERSION", default="")
COMPASS_BUILD_ID = env("COMPASS_BUILD_ID", default="")

# SECURITY/PRIVACY: AUDIT_HASH_SECRET is used as the HMAC salt for IP and User-Agent hashing.
# It should be set separately in production so SECRET_KEY rotation does not break audit hash comparability.
AUDIT_HASH_SECRET = env("AUDIT_HASH_SECRET", default=SECRET_KEY)
ACCOUNT_SECURITY_HASH_SECRET = env("ACCOUNT_SECURITY_HASH_SECRET", default=AUDIT_HASH_SECRET)

# --------------------------------------------------------------------------
# Custom User Model — MUST be set before first migration
# --------------------------------------------------------------------------
AUTH_USER_MODEL = "accounts.User"

# --------------------------------------------------------------------------
# Installed Apps
# --------------------------------------------------------------------------
DJANGO_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.staticfiles",
]

THIRD_PARTY_APPS = [
    "ninja",
    "corsheaders",
]

COMPASS_APPS = [
    "apps.common.apps.CommonConfig",
    "apps.orchestration",
    "apps.governance",
    "apps.security",
    "apps.privacy",
    "apps.accounts",
    "apps.organizations",
    "apps.audit",
    "apps.system",
    "apps.profiles",
    "apps.access_control",
    "apps.imports",
    "apps.student_activation",
    "apps.inventory",
    "apps.appointments",
    "apps.counseling",
    "apps.referrals",
    "apps.call_slips",
    "apps.documents",
    "apps.good_moral",
    "apps.workflow",
    "apps.notifications",
    "apps.content",
    "apps.account_security",
    "apps.form_collection",
    "apps.feedback",
    "apps.exit_interviews",
    "apps.graduate_tracer",
    "apps.reports",
    "apps.support_needs",
    "apps.assessments",

    "apps.backups",
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + COMPASS_APPS

# --------------------------------------------------------------------------
# Middleware
# --------------------------------------------------------------------------
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "apps.common.cache.middleware.CacheRequestScopeMiddleware",
    "apps.common.api.middleware.ApiBoundaryMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "apps.system.middleware.CompassAccessModeMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "apps.system.middleware.MaintenanceModeMiddleware",
    "apps.system.middleware.ApplicationErrorCaptureMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

# --------------------------------------------------------------------------
# URLs
# --------------------------------------------------------------------------
ROOT_URLCONF = "config.urls"
CSRF_TRUSTED_ORIGINS = validate_origins(
    env.list("CSRF_TRUSTED_ORIGINS", default=[]),
    name="CSRF_TRUSTED_ORIGINS",
)
CORS_ALLOWED_ORIGINS = validate_origins(
    env.list("CORS_ALLOWED_ORIGINS", default=[]),
    name="CORS_ALLOWED_ORIGINS",
)
# Browser authentication is same-origin through the Next.js BFF.  Do not
# enable credentialed cross-origin requests even if an old deployment
# environment still contains the legacy setting.
CORS_ALLOW_CREDENTIALS = False
CORS_URLS_REGEX = r"^/api/.*$"

# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------
# API token and assurance lifetimes are governed by target-scoped Governance
# records rather than deployment environment variables.

# --------------------------------------------------------------------------
# Templates
# --------------------------------------------------------------------------
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            # Templates are retained only for backend email/notification/PDF
            # rendering. No page context processors are needed by the API.
            "context_processors": [],
        },
    },
]

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {
        "redact_recovery_query": {
            "()": "apps.system.logging_filters.RecoveryQueryRedactionFilter",
        },
    },
    "formatters": {
        "django_server_safe": {
            "()": "django.utils.log.ServerFormatter",
            "format": "[{server_time}] {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "filters": ["redact_recovery_query"],
        },
        "django_server_console": {
            "class": "logging.StreamHandler",
            "filters": ["redact_recovery_query"],
            "formatter": "django_server_safe",
        },
    },
    "loggers": {
        "django": {"handlers": ["console"], "level": "INFO"},
        "django.server": {"handlers": ["django_server_console"], "level": "INFO", "propagate": False},
    },
}

# --------------------------------------------------------------------------
# WSGI / ASGI
# --------------------------------------------------------------------------
WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

# --------------------------------------------------------------------------
# Database — default parsed from DATABASE_URL
# --------------------------------------------------------------------------
DATABASES = {
    "default": env.db("DATABASE_URL", default="sqlite:///db.sqlite3"),
}

# Abuse counters use a shared Redis-compatible backend in deployment.  Local
# settings deliberately override this with an explicit LocMemCache adapter.
CACHE_URL = env("CACHE_URL", default="locmem://compass-default")
if str(CACHE_URL).startswith(("redis://", "rediss://")):
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": CACHE_URL,
        }
    }
else:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": str(CACHE_URL or "compass-default"),
        }
    }

# --------------------------------------------------------------------------
# Password Validation
# --------------------------------------------------------------------------
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# --------------------------------------------------------------------------
# Internationalization
# --------------------------------------------------------------------------
LANGUAGE_CODE = "en-us"
TIME_ZONE = "Asia/Manila"
USE_I18N = True
USE_TZ = True

# --------------------------------------------------------------------------
# Static Files
# --------------------------------------------------------------------------
STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"

# --------------------------------------------------------------------------
# Media Files
# --------------------------------------------------------------------------
MEDIA_URL = "media/"
MEDIA_ROOT = BASE_DIR / "media"

# --------------------------------------------------------------------------
# Default Primary Key
# --------------------------------------------------------------------------
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Appointment scheduling controls are governed by the Policy Center.

# --------------------------------------------------------------------------
# Secure E-Counseling / Daily.co Defaults
# --------------------------------------------------------------------------
ECOUNSELING_PROVIDER = env("ECOUNSELING_PROVIDER", default="DAILY")
ECOUNSELING_PROVIDER_MODE = env("ECOUNSELING_PROVIDER_MODE", default="DAILY_CLOUD")
ECOUNSELING_DAILY_API_KEY = env("ECOUNSELING_DAILY_API_KEY", default="")
ECOUNSELING_DAILY_DOMAIN = env("ECOUNSELING_DAILY_DOMAIN", default="")
ECOUNSELING_DAILY_WEBHOOK_SECRET = env("ECOUNSELING_DAILY_WEBHOOK_SECRET", default="")
ECOUNSELING_DAILY_WEBHOOK_ID = env("ECOUNSELING_DAILY_WEBHOOK_ID", default="")
ECOUNSELING_DAILY_WEBHOOK_URL = env("ECOUNSELING_DAILY_WEBHOOK_URL", default="")

ECOUNSELING_ROOM_PREFIX = env("ECOUNSELING_ROOM_PREFIX", default="compass-ecs")
ECOUNSELING_ROOM_SALT = env("ECOUNSELING_ROOM_SALT", default=SECRET_KEY)
# Join windows, denial limits, meeting-token TTL, and recording controls are
# governed by target-scoped Policy Center records.
ECOUNSELING_REQUIRE_PROVIDER_AUTH_IN_PRODUCTION = env.bool(
    "ECOUNSELING_REQUIRE_PROVIDER_AUTH_IN_PRODUCTION",
    default=True,
)
ECOUNSELING_UNSAFE_PROVIDER_MODE_ACKNOWLEDGED = env.bool(
    "ECOUNSELING_UNSAFE_PROVIDER_MODE_ACKNOWLEDGED",
    default=False,
)
# --------------------------------------------------------------------------
# Account Activation
# --------------------------------------------------------------------------
# validity duration for activation tokens (defaulting to 3 days)
# Activation invitation validity is governed by the central account-security
# policy; deployment settings do not override it.
# secret key for student and staff activation token HMACs (fallback allowed only in dev/test)
ACCOUNT_ACTIVATION_TOKEN_SECRET = env(
    "ACCOUNT_ACTIVATION_TOKEN_SECRET", default=SECRET_KEY
)

# --------------------------------------------------------------------------
# Security & Private Storage Foundation
# --------------------------------------------------------------------------
# Assessment attachment limits and allowlists are governed by a typed
# target-free Policy Center record.  The code-owned validator still bounds
# the values so a policy cannot broaden the approved formats.

# Root directory for local private storage (dev/test fallback only)
# DO NOT put inside MEDIA_ROOT to prevent public exposure via MEDIA_URL.
PROTECTED_STORAGE_LOCAL_ROOT = env(
    "PROTECTED_STORAGE_LOCAL_ROOT", default=str(BASE_DIR / "protected_media")
)

# Active storage backend: 'local' (test/dev) or 's3' (production/MinIO)
PROTECTED_STORAGE_BACKEND = env("PROTECTED_STORAGE_BACKEND", default="local")

# MinIO/S3 compatible credentials (safe placeholders)
PROTECTED_STORAGE_S3_ENDPOINT_URL = env("PROTECTED_STORAGE_S3_ENDPOINT_URL", default="")
PROTECTED_STORAGE_S3_ACCESS_KEY = env("PROTECTED_STORAGE_S3_ACCESS_KEY", default="")
PROTECTED_STORAGE_S3_SECRET_KEY = env("PROTECTED_STORAGE_S3_SECRET_KEY", default="")
PROTECTED_STORAGE_S3_BUCKET_NAME = env("PROTECTED_STORAGE_S3_BUCKET_NAME", default="compass-private")
PROTECTED_STORAGE_S3_USE_SSL = env.bool("PROTECTED_STORAGE_S3_USE_SSL", default=True)
PROTECTED_STORAGE_S3_REGION_NAME = env("PROTECTED_STORAGE_S3_REGION_NAME", default="us-east-1")
PROTECTED_STORAGE_S3_ADDRESSING_STYLE = env(
    "PROTECTED_STORAGE_S3_ADDRESSING_STYLE", default="path"
)

# PDF renderer enablement and timeout are deployment-owned technical controls.
# The Chromium executable path remains deployment-owned infrastructure config.
DOCUMENT_PDF_RENDERER_ENABLED = runtime_env("DOCUMENT_PDF_RENDERER_ENABLED")
DOCUMENT_PDF_RENDERER_TIMEOUT_MS = runtime_env("DOCUMENT_PDF_RENDERER_TIMEOUT_MS")
DOCUMENT_PDF_CHROMIUM_EXECUTABLE_PATH = env("DOCUMENT_PDF_CHROMIUM_EXECUTABLE_PATH", default="")

# Key Source Settings
# 'env' or 'podman_secret'. OCI Vault remains an infrastructure bootstrap
# source that materializes Podman secrets; it is not an application provider.
KEY_SOURCE_PROVIDER = env("KEY_SOURCE_PROVIDER", default="env")
# Directory where Podman secrets are mounted
KEY_SOURCE_PODMAN_SECRETS_DIR = env(
    "KEY_SOURCE_PODMAN_SECRETS_DIR", default=str(BASE_DIR / "secrets")
)
# Versioned encrypted-field foundation. Metadata rows choose their source
# provider and reference; KEY_SOURCE_PROVIDER is the single deployment-level
# provider policy used by settings and operational key loading.
# Numeric field-encryption limits are immutable source-owned safety controls.
# Only the checkpoint directory remains deployment-specific.
FIELD_ENCRYPTION_CHECKPOINT_DIR = env(
    "FIELD_ENCRYPTION_CHECKPOINT_DIR", default="/tmp/compass-field-encryption-checkpoints"
)

# Release 1 inventory-encryption compatibility is disabled unless a deployment
# explicitly enables it and supplies a validator-approved absolute UTC cutoff.
INVENTORY_ENCRYPTION_COMPATIBILITY_ENABLED = strict_env_bool(
    "INVENTORY_ENCRYPTION_COMPATIBILITY_ENABLED", default=False
)
INVENTORY_ENCRYPTION_COMPATIBILITY_DEADLINE = env(
    "INVENTORY_ENCRYPTION_COMPATIBILITY_DEADLINE", default=None
)

# Release 1 counseling-encryption compatibility is disabled unless a deployment
# explicitly enables it and supplies a validator-approved absolute UTC cutoff.
COUNSELING_ENCRYPTION_COMPATIBILITY_ENABLED = strict_env_bool(
    "COUNSELING_ENCRYPTION_COMPATIBILITY_ENABLED", default=False
)
COUNSELING_ENCRYPTION_COMPATIBILITY_DEADLINE = env(
    "COUNSELING_ENCRYPTION_COMPATIBILITY_DEADLINE", default=None
)

# Release 1 referral-encryption compatibility is disabled unless a deployment
# explicitly enables it and supplies a validator-approved absolute UTC cutoff.
REFERRALS_ENCRYPTION_COMPATIBILITY_ENABLED = strict_env_bool(
    "REFERRALS_ENCRYPTION_COMPATIBILITY_ENABLED", default=False
)
REFERRALS_ENCRYPTION_COMPATIBILITY_DEADLINE = env(
    "REFERRALS_ENCRYPTION_COMPATIBILITY_DEADLINE", default=None
)

CALL_SLIPS_ENCRYPTION_COMPATIBILITY_ENABLED = strict_env_bool(
    "CALL_SLIPS_ENCRYPTION_COMPATIBILITY_ENABLED", default=False
)
CALL_SLIPS_ENCRYPTION_COMPATIBILITY_DEADLINE = env(
    "CALL_SLIPS_ENCRYPTION_COMPATIBILITY_DEADLINE", default=None
)

# --------------------------------------------------------------------------
# Account Security & Profile Settings Foundation
# --------------------------------------------------------------------------
# OTP, recovery, activation, and trusted-device durations are governed by
# target-scoped Policy Center records.
ACCOUNT_SECURITY_CAPTCHA_ADAPTER = env(
    "ACCOUNT_SECURITY_CAPTCHA_ADAPTER",
    default="apps.account_security.captcha.CloudflareTurnstileAdapter",
)
ACCOUNT_SECURITY_CAPTCHA_PROVIDER = env("ACCOUNT_SECURITY_CAPTCHA_PROVIDER", default="turnstile")
ACCOUNT_SECURITY_TURNSTILE_SITE_KEY = env("ACCOUNT_SECURITY_TURNSTILE_SITE_KEY", default="")
ACCOUNT_SECURITY_TURNSTILE_SECRET = env("ACCOUNT_SECURITY_TURNSTILE_SECRET", default="")
ACCOUNT_SECURITY_TURNSTILE_HOSTNAMES = env.list("ACCOUNT_SECURITY_TURNSTILE_HOSTNAMES", default=[])
ACCOUNT_SECURITY_CACHE_ALIAS = env("ACCOUNT_SECURITY_CACHE_ALIAS", default="default")
ABUSE_CONTROL_CACHE_ALIAS = env("ABUSE_CONTROL_CACHE_ALIAS", default=ACCOUNT_SECURITY_CACHE_ALIAS)
TRUSTED_PROXY_HOPS = env.int("TRUSTED_PROXY_HOPS", default=0)
# Coarse-network classification boundary. Only these explicit campus/private
# ranges are ever labeled ``campus_network``; a campus is never inferred from
# an arbitrary address. Values must be IP networks (CIDR). Raw IPs and
# User-Agents are never persisted — only this configured classification plus
# the HMAC hashes are stored.
CAMPUS_NETWORK_CIDRS = env.list("CAMPUS_NETWORK_CIDRS", default=[])
CSP_ENABLED = env.bool("CSP_ENABLED", default=False)
CSP_SCRIPT_SRC = env.list("CSP_SCRIPT_SRC", default=[])
CSP_FRAME_SRC = env.list("CSP_FRAME_SRC", default=[])
# Internal 2FA enforcement is a target-scoped Governance policy.  Keep
# deployment secrets and adapter configuration here, but do not let an
# environment variable become a second policy source.
COMPASS_API_BASE_URL = env("COMPASS_API_BASE_URL", default="")
COMPASS_CLIENT_BASE_URL = env("COMPASS_CLIENT_BASE_URL", default="")
COMPASS_ACCESS_MODE = env("COMPASS_ACCESS_MODE", default="active").strip().lower()
COMPASS_ONBOARDING_CATALOG_VERSION = env("COMPASS_ONBOARDING_CATALOG_VERSION", default="")
COMPASS_ONBOARDING_ALLOW_DEMO_CATALOG = env.bool("COMPASS_ONBOARDING_ALLOW_DEMO_CATALOG", default=False)
# Student-import upload limits are governed by Governance records.
COMPASS_EMAIL_REPLY_TO = env("COMPASS_EMAIL_REPLY_TO", default="")
COMPASS_EMAIL_VERIFIED_SENDER_DOMAIN = env("COMPASS_EMAIL_VERIFIED_SENDER_DOMAIN", default="")

# --------------------------------------------------------------------------
# Deployment-owned runtime controls
# --------------------------------------------------------------------------
# These are intentionally not read from PolicyRecord.  Their values are
# injected into every process that may consume them and take effect on restart.
MAINTENANCE_ENFORCEMENT_ENABLED = runtime_env("MAINTENANCE_ENFORCEMENT_ENABLED")
ACCOUNT_SECURITY_CAPTCHA_TIMEOUT_SECONDS = runtime_env(
    "ACCOUNT_SECURITY_CAPTCHA_TIMEOUT_SECONDS"
)
EMAIL_TIMEOUT = runtime_env("EMAIL_TIMEOUT")
NOTIFICATION_WORKER_ENABLED = runtime_env("NOTIFICATION_WORKER_ENABLED")
NOTIFICATION_WORKER_INTERVAL_SECONDS = runtime_env("NOTIFICATION_WORKER_INTERVAL_SECONDS")
NOTIFICATION_WORKER_BATCH_SIZE = runtime_env("NOTIFICATION_WORKER_BATCH_SIZE")
NOTIFICATION_WORKER_LOCK_TIMEOUT_SECONDS = runtime_env(
    "NOTIFICATION_WORKER_LOCK_TIMEOUT_SECONDS"
)
BACKUP_WORKER_POLL_INTERVAL_SECONDS = runtime_env("BACKUP_WORKER_POLL_INTERVAL_SECONDS")
REPORT_SYNC_MAX_OUTPUT_BYTES = runtime_env("REPORT_SYNC_MAX_OUTPUT_BYTES")
REPORT_SYNC_MAX_WORK_UNITS = runtime_env("REPORT_SYNC_MAX_WORK_UNITS")
REPORT_ASYNC_AFTER_WORK_UNITS = runtime_env("REPORT_ASYNC_AFTER_WORK_UNITS")
REPORT_RUN_TIMEOUT_SECONDS = runtime_env("REPORT_RUN_TIMEOUT_SECONDS")
REPORT_EXPORT_MAX_OUTPUT_BYTES = runtime_env("REPORT_EXPORT_MAX_OUTPUT_BYTES")
PROTECTED_STORAGE_MAX_FILE_SIZE_BYTES = runtime_env("PROTECTED_STORAGE_MAX_FILE_SIZE_BYTES")
# Backup & Restore Operations Settings
BACKUP_STORAGE_BACKEND = env("BACKUP_STORAGE_BACKEND", default="metadata_only")
BACKUP_STORAGE_S3_ENDPOINT_URL = env("BACKUP_STORAGE_S3_ENDPOINT_URL", default="")
BACKUP_STORAGE_S3_BUCKET = env("BACKUP_STORAGE_S3_BUCKET", default="compass-backups")
BACKUP_STORAGE_S3_ACCESS_KEY = env("BACKUP_STORAGE_S3_ACCESS_KEY", default="")
BACKUP_STORAGE_S3_SECRET_KEY = env("BACKUP_STORAGE_S3_SECRET_KEY", default="")
BACKUP_STORAGE_S3_USE_SSL = env.bool("BACKUP_STORAGE_S3_USE_SSL", default=True)
BACKUP_STORAGE_S3_REGION_NAME = env("BACKUP_STORAGE_S3_REGION_NAME", default="us-east-1")
BACKUP_STORAGE_S3_ADDRESSING_STYLE = env("BACKUP_STORAGE_S3_ADDRESSING_STYLE", default="path")
BACKUP_LOCAL_DEMO_ROOT = env("BACKUP_LOCAL_DEMO_ROOT", default="backups")
BACKUP_RESTORE_EXECUTION_MODE = env("BACKUP_RESTORE_EXECUTION_MODE", default="dry_run_only")
BACKUP_WORKER_ENABLED = env.bool("BACKUP_WORKER_ENABLED", default=False)
BACKUP_ARCHIVE_MAX_BYTES = env.int(
    "BACKUP_ARCHIVE_MAX_BYTES", default=4 * 1024 * 1024 * 1024
)
BACKUP_LEGACY_FERNET_MAX_BYTES = env.int(
    "BACKUP_LEGACY_FERNET_MAX_BYTES", default=64 * 1024 * 1024
)
# Backup retention is governed by Policy Center records.

# An active maintenance window is only a notice in development until an
# environment deliberately opts in.  Non-local deployment configuration must
# set this explicitly so that an accidental active row cannot block a release.
