# Project: COMPASS
# File: config/settings/staging.py
# Module: config
# Purpose: Staging settings — near-production configuration with explicit
# provider activation controlled by the deployment environment.
# Notes: The OCI staging database is blank; demo fixtures are never implicit.

from .base import *  # noqa: F401, F403
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
from django.core.exceptions import ImproperlyConfigured

# --------------------------------------------------------------------------
# Debug
# --------------------------------------------------------------------------
DEBUG = False
ALLOWED_HOSTS = validate_allowed_hosts(env.list("ALLOWED_HOSTS"))
COMPASS_ENVIRONMENT = "staging"
COMPASS_ACCESS_MODE = env("COMPASS_ACCESS_MODE", default="health_only").strip().lower()
if COMPASS_ACCESS_MODE not in {"health_only", "active"}:
    raise ImproperlyConfigured("COMPASS_ACCESS_MODE must be health_only or active.")

COMPASS_RELEASE_VERSION = require_value("COMPASS_RELEASE_VERSION", reject_placeholders=True)
COMPASS_BUILD_ID = require_value("COMPASS_BUILD_ID", reject_placeholders=True)
SECRET_KEY = require_secret("SECRET_KEY", minimum_length=32)
AUDIT_HASH_SECRET = require_secret(
    "AUDIT_HASH_SECRET",
    distinct_from=(SECRET_KEY,),
    minimum_length=32,
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
    raise ImproperlyConfigured("Staging key sources must use podman_secret.")
KEY_SOURCE_PODMAN_SECRETS_DIR = require_value("KEY_SOURCE_PODMAN_SECRETS_DIR")

PROTECTED_STORAGE_BACKEND = env("PROTECTED_STORAGE_BACKEND", default="s3").strip().lower()
if PROTECTED_STORAGE_BACKEND != "s3":
    raise ImproperlyConfigured("Staging protected storage must use s3.")
for _setting_name in (
    "PROTECTED_STORAGE_S3_ENDPOINT_URL",
    "PROTECTED_STORAGE_S3_ACCESS_KEY",
    "PROTECTED_STORAGE_S3_SECRET_KEY",
    "PROTECTED_STORAGE_S3_BUCKET_NAME",
):
    require_value(_setting_name, reject_placeholders=True)
if not PROTECTED_STORAGE_S3_USE_SSL:  # noqa: F405
    raise ImproperlyConfigured("Staging protected storage must use TLS.")

BACKUP_STORAGE_BACKEND = env("BACKUP_STORAGE_BACKEND", default="s3_compatible").strip().lower()
if BACKUP_STORAGE_BACKEND != "s3_compatible":
    raise ImproperlyConfigured("Staging backups must use s3_compatible storage.")
for _setting_name in (
    "BACKUP_STORAGE_S3_ENDPOINT_URL",
    "BACKUP_STORAGE_S3_BUCKET",
    "BACKUP_STORAGE_S3_ACCESS_KEY",
    "BACKUP_STORAGE_S3_SECRET_KEY",
):
    require_value(_setting_name, reject_placeholders=True)
if not BACKUP_STORAGE_S3_USE_SSL:  # noqa: F405
    raise ImproperlyConfigured("Staging backup storage must use TLS.")

# --------------------------------------------------------------------------
# Security
# --------------------------------------------------------------------------
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True

# Notification provider settings are explicit in staging; credentials are
# injected by the approved secret/configuration manager.
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = env("EMAIL_HOST", default="")
EMAIL_PORT = env.int("EMAIL_PORT", default=587)
EMAIL_USE_TLS = env.bool("EMAIL_USE_TLS", default=True)
EMAIL_USE_SSL = env.bool("EMAIL_USE_SSL", default=False)
EMAIL_HOST_USER = env("EMAIL_HOST_USER", default="")
EMAIL_HOST_PASSWORD = env("EMAIL_HOST_PASSWORD", default="")
DEFAULT_FROM_EMAIL = env("DEFAULT_FROM_EMAIL", default="")
COMPASS_EMAIL_REPLY_TO = env("COMPASS_EMAIL_REPLY_TO", default="")
COMPASS_EMAIL_VERIFIED_SENDER_DOMAIN = env("COMPASS_EMAIL_VERIFIED_SENDER_DOMAIN", default="")

if COMPASS_ACCESS_MODE == "active":
    require_value("EMAIL_HOST", reject_placeholders=True)
    require_value("EMAIL_HOST_USER", reject_placeholders=True)
    require_secret("EMAIL_HOST_PASSWORD")
    require_value("DEFAULT_FROM_EMAIL", reject_placeholders=True)
    require_value("COMPASS_EMAIL_REPLY_TO", reject_placeholders=True)
    require_value(
        "COMPASS_EMAIL_VERIFIED_SENDER_DOMAIN", reject_placeholders=True
    )
    if EMAIL_USE_TLS == EMAIL_USE_SSL:
        raise ImproperlyConfigured("Exactly one SMTP TLS mode must be enabled.")

if str(ECOUNSELING_PROVIDER).strip().lower() not in {"none", "disabled", "off"}:
    ECOUNSELING_DAILY_API_KEY = require_secret("ECOUNSELING_DAILY_API_KEY")
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
