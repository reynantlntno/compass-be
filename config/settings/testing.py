# Project: COMPASS
# File: config/settings/testing.py
# Module: config
# Purpose: Testing-specific settings — fast password hashing, in-memory email
# Notes: SQLite is allowed only for initial foundation smoke tests.
#   PostgreSQL remains the default container test target for real workflow features.

from .base import *  # noqa: F401, F403
from .base import env

# --------------------------------------------------------------------------
# Debug — off for testing to catch template/context errors
# --------------------------------------------------------------------------
DEBUG = False
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "testserver"]
COMPASS_ENVIRONMENT = "testing"
ACCOUNT_SECURITY_CAPTCHA_ADAPTER = "apps.account_security.captcha.FakeCaptchaAdapter"
ACCOUNT_SECURITY_CAPTCHA_PROVIDER = "fake"
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "compass-testing-abuse-cache",
    }
}

# --------------------------------------------------------------------------
# Secret Key — fixed for deterministic test runs
# --------------------------------------------------------------------------
SECRET_KEY = "compass-testing-secret-key-not-for-production"

# --------------------------------------------------------------------------
# Database — PostgreSQL in containers, SQLite fallback for host-only foundation tests
# --------------------------------------------------------------------------
DATABASES = {
    "default": env.db(
        "DATABASE_URL",
        default="sqlite:///" + str(BASE_DIR / "db.sqlite3"),  # noqa: F405
    ),
}

# --------------------------------------------------------------------------
# Password Hashing — fast hasher for test speed
# --------------------------------------------------------------------------
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.MD5PasswordHasher",
]

# --------------------------------------------------------------------------
# Email — in-memory backend for testing
# --------------------------------------------------------------------------
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"

# --------------------------------------------------------------------------
# Inventory — current academic year is resolved from the active
# organizations.AcademicTerm. Tests create an active term through the domain
# lifecycle or directly as fixture data.
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# Security & Private Storage Test Settings
# --------------------------------------------------------------------------
PROTECTED_STORAGE_BACKEND = "local"
PROTECTED_STORAGE_LOCAL_ROOT = str(BASE_DIR / "test_protected_media")
KEY_SOURCE_PROVIDER = "env"
