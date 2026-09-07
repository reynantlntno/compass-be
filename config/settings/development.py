# Project: COMPASS
# File: config/settings/development.py
# Module: config
# Purpose: Development-specific settings — DEBUG=True, console email, relaxed hosts
# Notes: This is the default DJANGO_SETTINGS_MODULE.

from .base import *  # noqa: F401, F403
from .base import env

# --------------------------------------------------------------------------
# Debug
# --------------------------------------------------------------------------
DEBUG = True
ALLOWED_HOSTS = env("ALLOWED_HOSTS", default=["*"])
ACCOUNT_SECURITY_CAPTCHA_ADAPTER = "apps.account_security.captcha.FakeCaptchaAdapter"
ACCOUNT_SECURITY_CAPTCHA_PROVIDER = "fake"
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "compass-development-abuse-cache",
    }
}

# --------------------------------------------------------------------------
# Email — SMTP via Mailpit for development
# --------------------------------------------------------------------------
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = env("EMAIL_HOST", default="mailpit")
EMAIL_PORT = env.int("EMAIL_PORT", default=1025)
EMAIL_USE_TLS = False
EMAIL_USE_SSL = False
EMAIL_HOST_USER = ""
EMAIL_HOST_PASSWORD = ""
DEFAULT_FROM_EMAIL = env("DEFAULT_FROM_EMAIL", default="noreply@compass.edu.ph")
COMPASS_EMAIL_REPLY_TO = env("COMPASS_EMAIL_REPLY_TO", default="support@compass.edu.ph")
COMPASS_API_BASE_URL = env("COMPASS_API_BASE_URL", default="http://localhost:8000")
COMPASS_CLIENT_BASE_URL = env("COMPASS_CLIENT_BASE_URL", default="http://localhost:3000")
COMPASS_ONBOARDING_ALLOW_DEMO_CATALOG = env.bool("COMPASS_ONBOARDING_ALLOW_DEMO_CATALOG", default=True)

# --------------------------------------------------------------------------
# Database — use DATABASE_URL from .env, or SQLite for quick host-only testing
# --------------------------------------------------------------------------
# PostgreSQL is the default container target. SQLite is allowed only for
# initial foundation smoke tests when containers are unavailable.
DATABASES = {
    "default": env.db(
        "DATABASE_URL",
        default="sqlite:///" + str(BASE_DIR / "db.sqlite3"),  # noqa: F405
    ),
}

# PDF renderer enablement is governed by the local Policy Center seed.
