"""Isolated production-like settings for the local COMPASS rehearsal stack.

This module deliberately does not import ``config.settings.staging``.  OCI
staging keeps its own fail-closed contract, while this target permits only the
loopback services declared by ``compose.local-staging.yaml``.
"""

from urllib.parse import urlparse

from django.core.exceptions import ImproperlyConfigured

from .base import *  # noqa: F401,F403
from .base import env
from .environment import (
    require_database_url,
    require_https_origins,
    require_https_url,
    require_redis_url,
    require_secret,
    require_value,
    validate_allowed_hosts,
    validate_origins,
)


DEBUG = False
ALLOWED_HOSTS = validate_allowed_hosts(env.list("ALLOWED_HOSTS"))
# Keep deployment-grade checks active, but identify this isolated target with
# a separate immutable flag and settings module.
COMPASS_ENVIRONMENT = "staging"
COMPASS_LOCAL_STAGING = True
if not env.bool("COMPASS_LOCAL_STAGING_ACKNOWLEDGED", default=False):
    raise ImproperlyConfigured(
        "Local staging requires COMPASS_LOCAL_STAGING_ACKNOWLEDGED=True."
    )

COMPASS_ACCESS_MODE = env("COMPASS_ACCESS_MODE", default="health_only").strip().lower()
if COMPASS_ACCESS_MODE not in {"health_only", "active"}:
    raise ImproperlyConfigured("COMPASS_ACCESS_MODE must be health_only or active.")

COMPASS_RELEASE_VERSION = require_value("COMPASS_RELEASE_VERSION", reject_placeholders=True)
COMPASS_BUILD_ID = require_value("COMPASS_BUILD_ID", reject_placeholders=True)
if not COMPASS_RELEASE_VERSION.startswith("local-staging-"):
    raise ImproperlyConfigured(
        "Local staging releases must use a local-staging-* release identity."
    )

SECRET_KEY = require_secret("SECRET_KEY", minimum_length=32)
AUDIT_HASH_SECRET = require_secret(
    "AUDIT_HASH_SECRET", distinct_from=(SECRET_KEY,), minimum_length=32
)
ACCOUNT_SECURITY_HASH_SECRET = require_secret(
    "ACCOUNT_SECURITY_HASH_SECRET",
    distinct_from=(SECRET_KEY, AUDIT_HASH_SECRET),
    minimum_length=32,
)
ACCOUNT_ACTIVATION_TOKEN_SECRET = require_secret(
    "ACCOUNT_ACTIVATION_TOKEN_SECRET",
    distinct_from=(SECRET_KEY, AUDIT_HASH_SECRET, ACCOUNT_SECURITY_HASH_SECRET),
    minimum_length=32,
)
FIELD_ENCRYPTION_KEY = require_secret("FIELD_ENCRYPTION_KEY", minimum_length=32)

DATABASE_URL = require_database_url()
DATABASES = {"default": env.db("DATABASE_URL")}
CACHE_URL = require_redis_url()
TRUSTED_PROXY_HOPS = env.int("TRUSTED_PROXY_HOPS", default=1)
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": CACHE_URL,
    }
}

CSRF_TRUSTED_ORIGINS = require_https_origins()
CORS_ALLOWED_ORIGINS = validate_origins(
    env.list("CORS_ALLOWED_ORIGINS", default=[]),
    name="CORS_ALLOWED_ORIGINS",
    require_https=True,
)
if CORS_ALLOW_CREDENTIALS and not CORS_ALLOWED_ORIGINS:
    raise ImproperlyConfigured(
        "CORS_ALLOW_CREDENTIALS requires at least one CORS_ALLOWED_ORIGINS entry."
    )
COMPASS_API_BASE_URL = require_https_url("COMPASS_API_BASE_URL")
COMPASS_CLIENT_BASE_URL = require_https_url("COMPASS_CLIENT_BASE_URL")

KEY_SOURCE_PROVIDER = env("KEY_SOURCE_PROVIDER", default="podman_secret").strip().lower()
if KEY_SOURCE_PROVIDER != "podman_secret":
    raise ImproperlyConfigured("Local staging key sources must use podman_secret.")
KEY_SOURCE_PODMAN_SECRETS_DIR = require_value("KEY_SOURCE_PODMAN_SECRETS_DIR")


def _require_local_object_store(name: str) -> str:
    value = require_value(name, reject_placeholders=True)
    parsed = urlparse(value)
    try:
        port = parsed.port
    except ValueError:
        raise ImproperlyConfigured(f"{name} must target the isolated local MinIO service.") from None
    if (
        parsed.scheme != "http"
        or parsed.hostname != "minio"
        or port != 9000
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ImproperlyConfigured(f"{name} must target the isolated local MinIO service.")
    return "http://minio:9000"


PROTECTED_STORAGE_BACKEND = env("PROTECTED_STORAGE_BACKEND", default="s3").strip().lower()
if PROTECTED_STORAGE_BACKEND != "s3":
    raise ImproperlyConfigured("Local staging protected storage must use s3.")
PROTECTED_STORAGE_S3_ENDPOINT_URL = _require_local_object_store(
    "PROTECTED_STORAGE_S3_ENDPOINT_URL"
)
for _setting_name in (
    "PROTECTED_STORAGE_S3_ACCESS_KEY",
    "PROTECTED_STORAGE_S3_SECRET_KEY",
    "PROTECTED_STORAGE_S3_BUCKET_NAME",
):
    require_value(_setting_name, reject_placeholders=True)
if PROTECTED_STORAGE_S3_USE_SSL:  # noqa: F405
    raise ImproperlyConfigured("Local staging MinIO must use its internal HTTP endpoint.")

BACKUP_STORAGE_BACKEND = env("BACKUP_STORAGE_BACKEND", default="s3_compatible").strip().lower()
if BACKUP_STORAGE_BACKEND != "s3_compatible":
    raise ImproperlyConfigured("Local staging backups must use s3_compatible storage.")
BACKUP_STORAGE_S3_ENDPOINT_URL = _require_local_object_store(
    "BACKUP_STORAGE_S3_ENDPOINT_URL"
)
for _setting_name in (
    "BACKUP_STORAGE_S3_BUCKET",
    "BACKUP_STORAGE_S3_ACCESS_KEY",
    "BACKUP_STORAGE_S3_SECRET_KEY",
):
    require_value(_setting_name, reject_placeholders=True)
if BACKUP_STORAGE_S3_USE_SSL:  # noqa: F405
    raise ImproperlyConfigured("Local staging MinIO must use its internal HTTP endpoint.")

# Browser-facing traffic keeps the staging HTTPS posture. TLS is terminated by
# the local-only Caddy service before requests reach Gunicorn.
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True

# Mail is always captured by this stack's Mailpit instance. This invariant is
# enforced even in health_only mode so local staging cannot send real mail.
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = env("EMAIL_HOST", default="")
EMAIL_PORT = env.int("EMAIL_PORT", default=1025)
EMAIL_USE_TLS = env.bool("EMAIL_USE_TLS", default=False)
EMAIL_USE_SSL = env.bool("EMAIL_USE_SSL", default=False)
EMAIL_HOST_USER = env("EMAIL_HOST_USER", default="")
EMAIL_HOST_PASSWORD = env("EMAIL_HOST_PASSWORD", default="")
DEFAULT_FROM_EMAIL = env("DEFAULT_FROM_EMAIL", default="")
COMPASS_EMAIL_REPLY_TO = env("COMPASS_EMAIL_REPLY_TO", default="")
COMPASS_EMAIL_VERIFIED_SENDER_DOMAIN = env(
    "COMPASS_EMAIL_VERIFIED_SENDER_DOMAIN", default=""
)
if not (
    EMAIL_HOST == "mailpit"
    and EMAIL_PORT == 1025
    and not EMAIL_USE_TLS
    and not EMAIL_USE_SSL
    and not EMAIL_HOST_USER
    and DEFAULT_FROM_EMAIL.endswith("@local.invalid")
    and COMPASS_EMAIL_REPLY_TO.endswith("@local.invalid")
    and COMPASS_EMAIL_VERIFIED_SENDER_DOMAIN == "local.invalid"
):
    raise ImproperlyConfigured(
        "Local staging email must use the isolated Mailpit local.invalid contract."
    )


def _normalize_daily_host(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    candidate = raw if "://" in raw else f"https://{raw}"
    parsed = urlparse(candidate)
    try:
        port = parsed.port
    except ValueError:
        raise ImproperlyConfigured(
            "ECOUNSELING_DAILY_DOMAIN must be a canonical HTTPS host."
        ) from None
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or port is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ImproperlyConfigured(
            "ECOUNSELING_DAILY_DOMAIN must be a canonical HTTPS host."
        )
    return parsed.hostname.rstrip(".").lower()


ECOUNSELING_DAILY_DOMAIN = _normalize_daily_host(ECOUNSELING_DAILY_DOMAIN)  # noqa: F405
if ECOUNSELING_DAILY_WEBHOOK_URL:  # noqa: F405
    ECOUNSELING_DAILY_WEBHOOK_URL = require_https_url("ECOUNSELING_DAILY_WEBHOOK_URL")
if str(ECOUNSELING_PROVIDER).strip().lower() not in {"none", "disabled", "off"}:  # noqa: F405
    ECOUNSELING_DAILY_API_KEY = require_secret("ECOUNSELING_DAILY_API_KEY")
    if not ECOUNSELING_DAILY_DOMAIN:
        raise ImproperlyConfigured("ECOUNSELING_DAILY_DOMAIN must be configured.")
    ECOUNSELING_ROOM_SALT = require_secret(
        "ECOUNSELING_ROOM_SALT",
        distinct_from=(
            SECRET_KEY,
            AUDIT_HASH_SECRET,
            ACCOUNT_SECURITY_HASH_SECRET,
            ACCOUNT_ACTIVATION_TOKEN_SECRET,
        ),
        minimum_length=32,
    )
