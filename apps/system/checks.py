# Project: COMPASS
# File: apps/system/checks.py
# Module: apps.system
# Purpose: System settings validations and deployment posture checks
# Domain boundary and service policy.
# Notes:
#   - NO database reads or writes.
#   - NO secret values or settings values in check messages.
#   - Only setting names and reason codes should be reported.

import os
import importlib.util
import re
import sys
from urllib.parse import urlparse
from django.conf import settings
from django.core.checks import Error, Warning, register, Tags
from django.core.cache import caches

def _abuse_control_configuration_errors(environment: str):
    """Fail closed for deployment CAPTCHA/cache/policy posture."""
    if environment not in {"staging", "production"}:
        return []
    errors = []
    access_mode = str(getattr(settings, "COMPASS_ACCESS_MODE", "active") or "active").strip().lower()
    adapter_path = str(getattr(settings, "ACCOUNT_SECURITY_CAPTCHA_ADAPTER", "") or "").strip()
    fake_path = "apps.account_security.captcha.FakeCaptchaAdapter"
    if not adapter_path or adapter_path == fake_path:
        errors.append(Error("A real CAPTCHA adapter is required in deployment.", id="system.E080"))
    else:
        try:
            from apps.account_security.captcha import BaseCaptchaAdapter, FakeCaptchaAdapter
            from django.utils.module_loading import import_string

            adapter_class = import_string(adapter_path)
            if not issubclass(adapter_class, BaseCaptchaAdapter) or issubclass(adapter_class, FakeCaptchaAdapter):
                errors.append(Error("Configured CAPTCHA adapter is invalid for deployment.", id="system.E081"))
        except (ImportError, AttributeError, TypeError, ValueError):
            errors.append(Error("Configured CAPTCHA adapter could not be loaded.", id="system.E081"))
    if access_mode == "active":
        if not getattr(settings, "ACCOUNT_SECURITY_TURNSTILE_SITE_KEY", ""):
            errors.append(Error("Turnstile site key is required in deployment.", id="system.E082"))
        if not getattr(settings, "ACCOUNT_SECURITY_TURNSTILE_SECRET", ""):
            errors.append(Error("Turnstile secret is required in deployment.", id="system.E083"))
        if not getattr(settings, "ACCOUNT_SECURITY_TURNSTILE_HOSTNAMES", ()):
            errors.append(Error("Turnstile hostname allowlist is required in deployment.", id="system.E084"))
    # The timeout is a governed technical policy, not a deployment setting.
    # Keep this check database-free: the Policy Center validator owns the
    # bounded value and the CAPTCHA adapter reads the effective record.
    from config.runtime_settings import RUNTIME_SETTING_RULES

    if RUNTIME_SETTING_RULES.get("ACCOUNT_SECURITY_CAPTCHA_TIMEOUT_SECONDS") != ("int", 1, 15):
        errors.append(Error("CAPTCHA timeout safety bounds are not registered.", id="system.E085"))
    if int(getattr(settings, "TRUSTED_PROXY_HOPS", 0) or 0) != 1:
        errors.append(Error("Deployment must explicitly configure exactly one trusted proxy hop.", id="system.E089"))
    cache_config = getattr(settings, "CACHES", {}).get("default", {})
    backend = str(cache_config.get("BACKEND", "")).lower()
    location = str(cache_config.get("LOCATION", "") or "")
    if "redis" not in backend or not location.startswith(("redis://", "rediss://")):
        errors.append(Error("Distributed Redis cache is required for abuse controls in deployment.", id="system.E086"))
    if getattr(settings, "CSP_ENABLED", False):
        required_origin = "https://challenges.cloudflare.com"
        script_sources = set(getattr(settings, "CSP_SCRIPT_SRC", ()) or ())
        frame_sources = set(getattr(settings, "CSP_FRAME_SRC", ()) or ())
        if required_origin not in script_sources or required_origin not in frame_sources:
            errors.append(Error("Turnstile CSP requires challenges.cloudflare.com in script and frame sources.", id="system.E090"))
    try:
        from apps.account_security.abuse_controls import AbuseAction, POLICIES

        expected = {str(action) for action in AbuseAction}
        if set(POLICIES) != expected:
            errors.append(Error("Code-owned abuse policy catalog is missing an action.", id="system.E087"))
        for action in expected:
            try:
                policy = POLICIES[action]
                if policy.window_seconds <= 0 or policy.challenge_threshold <= 0 or policy.hard_limit <= 0:
                    raise ValueError
                if policy.challenge_threshold > policy.hard_limit:
                    errors.append(Error(f"Abuse policy {action} challenge threshold exceeds hard limit.", id="system.E088"))
                if policy.ip_challenge_threshold > policy.ip_hard_limit:
                    errors.append(Error(f"Abuse policy {action} IP challenge threshold exceeds hard limit.", id="system.E088"))
            except (TypeError, ValueError, KeyError):
                errors.append(Error(f"Abuse policy {action} is invalid.", id="system.E087"))
    except (ImportError, AttributeError, TypeError):
        errors.append(Error("Required abuse policies could not be loaded.", id="system.E087"))

    # A deployment must prove the configured cache can be reached without
    # creating a probe key or changing application state.  A cache failure is
    # a readiness failure; request-time abuse controls still use DB fallback.
    try:
        caches["default"].get("compass:abuse:readiness-probe:v1")
    except Exception:
        errors.append(Error("Configured abuse-control cache failed its read-only probe.", id="system.E091"))
    return errors


def _s3_client_dependency_available() -> bool:
    def available(module_name):
        try:
            return importlib.util.find_spec(module_name) is not None
        except (ImportError, ValueError):
            # Some test integrations install a lightweight module stub without
            # a ModuleSpec. Presence in sys.modules still means the adapter
            # dependency boundary is available for that process.
            return module_name in sys.modules

    try:
        return available("boto3") and available("botocore")
    except Exception:
        return False


def _playwright_dependency_available() -> bool:
    try:
        return importlib.util.find_spec("playwright") is not None
    except (ImportError, ValueError):
        return False


def _chromium_executable_path_error() -> bool:
    executable_path = str(getattr(settings, "DOCUMENT_PDF_CHROMIUM_EXECUTABLE_PATH", "") or "").strip()
    if not executable_path:
        return False
    return (
        "\x00" in executable_path
        or not os.path.isabs(executable_path)
        or not os.path.isfile(executable_path)
        or not os.access(executable_path, os.X_OK)
    )


def _playwright_chromium_probe_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright
        launch_options = {"headless": True}
        executable_path = str(getattr(settings, "DOCUMENT_PDF_CHROMIUM_EXECUTABLE_PATH", "") or "").strip()
        if executable_path:
            launch_options["executable_path"] = executable_path
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(**launch_options)
            browser.close()
        return True
    except Exception:
        return False


def _setting_missing(setting_name: str) -> bool:
    return not bool(getattr(settings, setting_name, ""))


def _endpoint_has_safe_shape(setting_name: str) -> bool:
    endpoint = str(getattr(settings, setting_name, "") or "")
    parsed = urlparse(endpoint)
    return (
        parsed.scheme in {"http", "https"}
        and bool(parsed.netloc)
        and not parsed.username
        and not parsed.password
    )


_RELEASE_IDENTITY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$")


def _release_identity_is_placeholder(value) -> bool:
    """Reject deployment labels that cannot identify a releasable artifact."""

    normalized = str(value or "").strip().lower()
    return normalized in {
        "",
        "unknown",
        "unversioned",
        "development",
        "dev",
        "local",
        "none",
        "null",
        "tbd",
        "placeholder",
    } or _RELEASE_IDENTITY_PATTERN.fullmatch(normalized) is None


@register(Tags.security)
def check_environment_settings(app_configs, **kwargs):
    errors = []

    # 1. COMPASS_ENVIRONMENT check
    env_name = getattr(settings, "COMPASS_ENVIRONMENT", None)
    valid_envs = {"development", "testing", "staging", "production"}
    if not env_name or env_name not in valid_envs:
        errors.append(
            Error(
                "COMPASS_ENVIRONMENT is not set or set to an invalid value.",
                hint="Set COMPASS_ENVIRONMENT to one of: development, testing, staging, production.",
                id="system.E001",
            )
        )
        return errors

    is_prod = (env_name == "production")
    is_deployment = env_name in {"staging", "production"}
    errors.extend(_abuse_control_configuration_errors(env_name))

    access_mode = str(getattr(settings, "COMPASS_ACCESS_MODE", "") or "").strip().lower()
    if access_mode not in {"health_only", "active"}:
        errors.append(
            Error(
                "COMPASS_ACCESS_MODE is invalid.",
                hint="Set COMPASS_ACCESS_MODE to health_only or active.",
                id="system.E095",
            )
        )

    # Release identity is deliberately checked for every deployment-like
    # environment.  A Django check failure is safer and more useful to an
    # operator than silently emitting readiness evidence with no artifact
    # identity.
    if is_deployment:
        if _release_identity_is_placeholder(
            getattr(settings, "COMPASS_RELEASE_VERSION", "")
        ):
            errors.append(
                Error(
                    "COMPASS_RELEASE_VERSION is missing, invalid, or a placeholder in a deployment environment.",
                    hint="Inject an immutable release version from the deployment artifact.",
                    id="system.E030",
                )
            )
        if _release_identity_is_placeholder(
            getattr(settings, "COMPASS_BUILD_ID", "")
        ):
            errors.append(
                Error(
                    "COMPASS_BUILD_ID is missing, invalid, or a placeholder in a deployment environment.",
                    hint="Inject an immutable build or commit identifier from the deployment artifact.",
                    id="system.E031",
                )
            )

    # 2. DEBUG check in production
    if is_prod and getattr(settings, "DEBUG", False):
        errors.append(
            Error(
                "DEBUG must be False in production environment.",
                hint="Configure DEBUG=False in production.",
                id="system.E002",
            )
        )

    # 3. ALLOWED_HOSTS check in production
    if is_prod:
        allowed_hosts = getattr(settings, "ALLOWED_HOSTS", [])
        if not allowed_hosts:
            errors.append(
                Error(
                    "ALLOWED_HOSTS is empty in production.",
                    hint="Configure a non-empty list of allowed hosts in production.",
                    id="system.E003",
                )
            )
        elif "*" in allowed_hosts:
            errors.append(
                Error(
                    "ALLOWED_HOSTS contains a wildcard '*' in production.",
                    hint="Configure specific hosts/domains for ALLOWED_HOSTS in production.",
                    id="system.E004",
                )
            )

    # 4. HTTPS & secure cookie posture in staging/production
    if env_name in {"production", "staging"}:
        if not getattr(settings, "CSRF_COOKIE_SECURE", False):
            if is_prod:
                errors.append(
                    Error(
                        "CSRF_COOKIE_SECURE must be True in production.",
                        hint="Configure CSRF_COOKIE_SECURE=True.",
                        id="system.E005",
                    )
                )
            else:
                errors.append(
                    Warning(
                        "CSRF_COOKIE_SECURE is False in staging.",
                        hint="Consider CSRF_COOKIE_SECURE=True in staging for parity.",
                        id="system.W001",
                    )
                )

        if not getattr(settings, "SESSION_COOKIE_SECURE", False):
            if is_prod:
                errors.append(
                    Error(
                        "SESSION_COOKIE_SECURE must be True in production.",
                        hint="Configure SESSION_COOKIE_SECURE=True.",
                        id="system.E006",
                    )
                )
            else:
                errors.append(
                    Warning(
                        "SESSION_COOKIE_SECURE is False in staging.",
                        hint="Consider SESSION_COOKIE_SECURE=True in staging for parity.",
                        id="system.W002",
                    )
                )

    if is_prod:
        if not getattr(settings, "SECURE_SSL_REDIRECT", False):
            errors.append(
                Error(
                    "SECURE_SSL_REDIRECT must be True in production.",
                    hint="Configure SECURE_SSL_REDIRECT=True.",
                    id="system.E007",
                )
            )

        if not getattr(settings, "SECURE_HSTS_SECONDS", 0):
            errors.append(
                Warning(
                    "SECURE_HSTS_SECONDS is not set or is 0 in production.",
                    hint="Configure SECURE_HSTS_SECONDS in production to enforce HSTS.",
                    id="system.W003",
                )
            )

    # 5. AUDIT_HASH_SECRET check
    if is_prod:
        audit_secret = getattr(settings, "AUDIT_HASH_SECRET", None)
        secret_key = getattr(settings, "SECRET_KEY", None)
        if not audit_secret:
            errors.append(
                Error(
                    "AUDIT_HASH_SECRET is missing.",
                    hint="Configure a distinct AUDIT_HASH_SECRET in production.",
                    id="system.E008",
                )
            )
        elif audit_secret == secret_key:
            errors.append(
                Error(
                    "AUDIT_HASH_SECRET must not fall back to SECRET_KEY in production.",
                    hint="Configure a distinct high-entropy value for AUDIT_HASH_SECRET.",
                    id="system.E009",
                )
            )

    # 6. ACCOUNT_SECURITY_HASH_SECRET check
    if is_prod:
        account_sec_secret = getattr(settings, "ACCOUNT_SECURITY_HASH_SECRET", None)
        secret_key = getattr(settings, "SECRET_KEY", None)
        if not account_sec_secret:
            errors.append(
                Error(
                    "ACCOUNT_SECURITY_HASH_SECRET is missing.",
                    hint="Configure a distinct ACCOUNT_SECURITY_HASH_SECRET in production.",
                    id="system.E010",
                )
            )
        elif account_sec_secret == secret_key:
            errors.append(
                Error(
                    "ACCOUNT_SECURITY_HASH_SECRET must not fall back to SECRET_KEY in production.",
                    hint="Configure a distinct high-entropy value for ACCOUNT_SECURITY_HASH_SECRET.",
                    id="system.E011",
                )
            )

    # 7. ACCOUNT_ACTIVATION_TOKEN_SECRET check
    if is_prod:
        activation_secret = getattr(settings, "ACCOUNT_ACTIVATION_TOKEN_SECRET", None)
        secret_key = getattr(settings, "SECRET_KEY", None)
        if not activation_secret:
            errors.append(
                Error(
                    "ACCOUNT_ACTIVATION_TOKEN_SECRET is missing.",
                    hint="Configure a distinct ACCOUNT_ACTIVATION_TOKEN_SECRET in production.",
                    id="system.E012",
                )
            )
        elif activation_secret == secret_key:
            errors.append(
                Error(
                    "ACCOUNT_ACTIVATION_TOKEN_SECRET must not fall back to SECRET_KEY in production.",
                    hint="Configure a distinct high-entropy value for ACCOUNT_ACTIVATION_TOKEN_SECRET.",
                    id="system.E013",
                )
            )

    # 8. Protected storage checks
    storage_backend = str(getattr(settings, "PROTECTED_STORAGE_BACKEND", "local")).lower()
    if is_prod and storage_backend == "local":
        allow_local = getattr(settings, "COMPASS_ALLOW_LOCAL_PROTECTED_STORAGE_IN_PRODUCTION", False)
        if not allow_local:
            errors.append(
                Error(
                    "PROTECTED_STORAGE_BACKEND is configured to local in production without explicit acknowledgment.",
                    hint="Use an S3-compatible backend for production or explicitly acknowledge the local fallback via COMPASS_ALLOW_LOCAL_PROTECTED_STORAGE_IN_PRODUCTION.",
                    id="system.E014",
                )
            )
        else:
            errors.append(
                Warning(
                    "PROTECTED_STORAGE_BACKEND is configured to local in production under acknowledged fallback.",
                    hint="Ensure local storage is secure and backed up; this is not recommended for production hosting.",
                    id="system.W004",
                )
            )
    if storage_backend == "s3":
        required_storage_settings = [
            "PROTECTED_STORAGE_S3_ENDPOINT_URL",
            "PROTECTED_STORAGE_S3_ACCESS_KEY",
            "PROTECTED_STORAGE_S3_SECRET_KEY",
            "PROTECTED_STORAGE_S3_BUCKET_NAME",
        ]
        if any(_setting_missing(setting_name) for setting_name in required_storage_settings):
            errors.append(
                Error(
                    "PROTECTED_STORAGE_BACKEND is configured to s3 with incomplete provider settings.",
                    hint="Configure the required PROTECTED_STORAGE_S3_* setting names before enabling s3 protected storage.",
                    id="system.E020",
                )
            )
        elif not _endpoint_has_safe_shape("PROTECTED_STORAGE_S3_ENDPOINT_URL"):
            errors.append(
                Error(
                    "PROTECTED_STORAGE_S3_ENDPOINT_URL has an unsafe or invalid shape.",
                    hint="Use an http(s) endpoint without embedded credentials.",
                    id="system.E021",
                )
            )
        elif not _s3_client_dependency_available():
            errors.append(
                Error(
                    "PROTECTED_STORAGE_BACKEND is configured to s3 but the S3 client dependency is unavailable.",
                    hint="Install the pinned boto3 and botocore dependencies before enabling s3 protected storage.",
                    id="system.E022",
                )
            )

    backup_storage_backend = str(
        getattr(settings, "BACKUP_STORAGE_BACKEND", "metadata_only") or "metadata_only"
    ).strip().lower()
    if is_deployment and backup_storage_backend == "metadata_only":
        errors.append(
            Error(
                "BACKUP_STORAGE_BACKEND cannot use metadata_only in a deployment environment.",
                hint="Configure an approved S3-compatible backup destination before deployment.",
                id="system.E032",
            )
        )
    if is_deployment and backup_storage_backend == "local_demo":
        errors.append(
            Error(
                "BACKUP_STORAGE_BACKEND cannot use local_demo in a deployment environment.",
                hint="Configure an approved S3-compatible backup destination before deployment.",
                id="system.E033",
            )
        )

    if backup_storage_backend == "s3_compatible":
        required_backup_settings = [
            "BACKUP_STORAGE_S3_ENDPOINT_URL",
            "BACKUP_STORAGE_S3_BUCKET",
            "BACKUP_STORAGE_S3_ACCESS_KEY",
            "BACKUP_STORAGE_S3_SECRET_KEY",
        ]
        if any(_setting_missing(setting_name) for setting_name in required_backup_settings):
            errors.append(
                Error(
                    "BACKUP_STORAGE_BACKEND is configured to s3_compatible with incomplete provider settings.",
                    hint="Configure the required BACKUP_STORAGE_S3_* setting names before selecting the s3_compatible backup target.",
                    id="system.E023",
                )
            )
        elif not _endpoint_has_safe_shape("BACKUP_STORAGE_S3_ENDPOINT_URL"):
            errors.append(
                Error(
                    "BACKUP_STORAGE_S3_ENDPOINT_URL has an unsafe or invalid shape.",
                    hint="Use an http(s) endpoint without embedded credentials.",
                    id="system.E024",
                )
            )
        elif str(getattr(settings, "BACKUP_STORAGE_S3_ADDRESSING_STYLE", "path")).lower() not in {"path", "virtual"}:
            errors.append(
                Error(
                    "BACKUP_STORAGE_S3_ADDRESSING_STYLE has an unsupported value.",
                    hint="Use path or virtual addressing style for S3-compatible backup storage.",
                    id="system.E025",
                )
            )
        elif not _s3_client_dependency_available():
            errors.append(
                Error(
                    "BACKUP_STORAGE_BACKEND is configured to s3_compatible but the S3 client dependency is unavailable.",
                    hint="Install the pinned boto3 and botocore dependencies before enabling S3-compatible backup storage.",
                    id="system.E026",
                )
            )

    # 9. Key source provider check
    key_provider = str(getattr(settings, "KEY_SOURCE_PROVIDER", "env")).lower()
    valid_providers = {"env", "podman_secret"}
    if key_provider not in valid_providers:
        errors.append(
            Error(
                "KEY_SOURCE_PROVIDER is configured to an unknown provider.",
                hint="Configure KEY_SOURCE_PROVIDER to one of: env, podman_secret.",
                id="system.E015",
            )
        )
    elif key_provider == "podman_secret":
        if not getattr(settings, "KEY_SOURCE_PODMAN_SECRETS_DIR", None):
            errors.append(
                Error(
                    "KEY_SOURCE_PROVIDER is set to podman_secret, but KEY_SOURCE_PODMAN_SECRETS_DIR is not configured.",
                    hint="Configure KEY_SOURCE_PODMAN_SECRETS_DIR path.",
                    id="system.E017",
                )
            )

    # 10. SMTP / Email backend consistency check
    email_backend = getattr(settings, "EMAIL_BACKEND", "")
    access_mode = str(getattr(settings, "COMPASS_ACCESS_MODE", "active") or "active").strip().lower()
    if "smtp" in email_backend.lower() and (env_name == "production" or access_mode == "active"):
        if not getattr(settings, "EMAIL_HOST", None):
            errors.append(
                Error(
                    "EMAIL_BACKEND is configured for SMTP, but EMAIL_HOST is not configured.",
                    hint="Configure EMAIL_HOST setting.",
                    id="system.E018",
                )
            )

    # 11. Cache / Redis backend consistency check
    caches = getattr(settings, "CACHES", {})
    for cache_name, cache_config in caches.items():
        backend = cache_config.get("BACKEND", "")
        if "redis" in backend.lower():
            location = cache_config.get("LOCATION", "")
            if not location:
                errors.append(
                    Error(
                        f"Cache '{cache_name}' is configured with a Redis backend, but LOCATION is missing.",
                        hint="Configure LOCATION (e.g. redis://...) in the cache settings.",
                        id="system.E019",
                    )
                )

    return errors


@register(Tags.security)
def check_notification_provider_settings(app_configs, **kwargs):
    """Fail closed for unsafe staging/production notification configuration."""
    environment = str(getattr(settings, "COMPASS_ENVIRONMENT", "development") or "development").lower()
    if environment not in {"staging", "production"}:
        return []
    access_mode = str(getattr(settings, "COMPASS_ACCESS_MODE", "active") or "active").strip().lower()
    local_staging = bool(getattr(settings, "COMPASS_LOCAL_STAGING", False))
    if environment == "staging" and access_mode == "health_only":
        return []
    errors = []
    backend = str(getattr(settings, "EMAIL_BACKEND", "") or "")
    if "smtp" not in backend.lower():
        errors.append(Error("Notification email backend must be SMTP in deployment.", id="system.E060"))
    host = str(getattr(settings, "EMAIL_HOST", "") or "").strip()
    if not host:
        errors.append(Error("EMAIL_HOST is required in deployment.", id="system.E061"))
    port = getattr(settings, "EMAIL_PORT", 0)
    if not isinstance(port, int) or not 1 <= port <= 65535:
        errors.append(Error("EMAIL_PORT is invalid in deployment.", id="system.E062"))
    use_tls = bool(getattr(settings, "EMAIL_USE_TLS", False))
    use_ssl = bool(getattr(settings, "EMAIL_USE_SSL", False))
    if local_staging:
        if host != "mailpit" or use_tls or use_ssl:
            errors.append(
                Error(
                    "Local staging SMTP must use the isolated Mailpit service without transport TLS.",
                    id="system.E063",
                )
            )
    else:
        if use_tls == use_ssl:
            errors.append(Error("Exactly one SMTP TLS mode must be enabled in deployment.", id="system.E063"))
        if not getattr(settings, "EMAIL_HOST_USER", "") or not getattr(settings, "EMAIL_HOST_PASSWORD", ""):
            errors.append(Error("SMTP credentials must be supplied by the deployment secret manager.", id="system.E064"))

    archive_max_bytes = getattr(settings, "BACKUP_ARCHIVE_MAX_BYTES", None)
    legacy_fernet_max_bytes = getattr(settings, "BACKUP_LEGACY_FERNET_MAX_BYTES", None)
    if type(archive_max_bytes) is not int or not 1 <= archive_max_bytes <= 4 * 1024 * 1024 * 1024:
        errors.append(
            Error(
                "BACKUP_ARCHIVE_MAX_BYTES must be a positive value no larger than 4 GiB.",
                id="system.E034",
            )
        )
    if type(legacy_fernet_max_bytes) is not int or not 1 <= legacy_fernet_max_bytes <= 64 * 1024 * 1024:
        errors.append(
            Error(
                "BACKUP_LEGACY_FERNET_MAX_BYTES must be a positive value no larger than 64 MiB.",
                id="system.E035",
            )
        )
    from config.runtime_settings import RUNTIME_SETTING_RULES

    if RUNTIME_SETTING_RULES.get("EMAIL_TIMEOUT") != ("int", 1, 60):
        errors.append(Error("EMAIL_TIMEOUT safety bounds are not registered.", id="system.E065"))
    sender = str(getattr(settings, "DEFAULT_FROM_EMAIL", "") or "")
    reply_to = str(getattr(settings, "COMPASS_EMAIL_REPLY_TO", "") or "")
    sender_domain = str(getattr(settings, "COMPASS_EMAIL_VERIFIED_SENDER_DOMAIN", "") or "").lower().strip()
    for value, name, code in ((sender, "DEFAULT_FROM_EMAIL", "E066"), (reply_to, "COMPASS_EMAIL_REPLY_TO", "E067")):
        if "@" not in value:
            errors.append(Error(f"{name} must be configured.", id=f"system.{code}"))
    if not sender_domain:
        errors.append(Error("COMPASS_EMAIL_VERIFIED_SENDER_DOMAIN must be configured.", id="system.E068"))
    elif sender.lower().rsplit("@", 1)[-1] != sender_domain:
        errors.append(Error("DEFAULT_FROM_EMAIL must match COMPASS_EMAIL_VERIFIED_SENDER_DOMAIN.", id="system.E068"))
    if local_staging and sender_domain != "local.invalid":
        errors.append(
            Error(
                "Local staging email must use the non-routable local.invalid domain.",
                id="system.E068",
            )
        )
    for setting_name, error_code in (("COMPASS_API_BASE_URL", "E069"), ("COMPASS_CLIENT_BASE_URL", "E070")):
        base_url = str(getattr(settings, setting_name, "") or "")
        parsed = urlparse(base_url)
        if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
            errors.append(Error(f"{setting_name} must be a canonical HTTPS URL.", id=f"system.{error_code}"))
    return errors


@register(Tags.security)
def check_django_admin_disabled(app_configs, **kwargs):
    """Keep the removed Django Admin surface out of every environment."""

    def root_admin_route_configured():
        try:
            from django.urls import get_resolver

            for pattern in get_resolver().url_patterns:
                pattern_config = getattr(pattern, "pattern", None)
                route = str(getattr(pattern_config, "_route", "") or "").strip("/")
                if route == "admin":
                    return True
                regex = getattr(getattr(pattern_config, "regex", None), "pattern", "")
                if re.match(r"^\^?admin(?:/|$)", str(regex)):
                    return True
        except Exception:
            return False
        return False

    forbidden = {
        "django.contrib.admin",
    }
    configured_apps = set(getattr(settings, "INSTALLED_APPS", ()))
    configured_middleware = set(getattr(settings, "MIDDLEWARE", ()))
    admin_middleware_configured = any(
        "django.contrib.admin" in middleware for middleware in configured_middleware
    )
    if (
        forbidden.intersection(configured_apps)
        or admin_middleware_configured
        or root_admin_route_configured()
    ):
        return [
            Error(
                "Django Admin is disabled for the API-only service.",
                hint="Remove the Django Admin app, middleware, and /admin/ route.",
                id="system.E096",
            )
        ]
    return []
