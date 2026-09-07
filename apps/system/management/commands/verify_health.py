"""Deployment-like health verification with no operational side effects."""

from django.conf import settings
from django.core import mail
from django.core.management.base import BaseCommand, CommandError

from apps.backups.readiness_services import collect_backup_readiness
from apps.counseling.ecounseling_providers import (
    DailyProvider,
    ProviderConfigurationError,
    ProviderOperationError,
)
from apps.security.readiness_services import collect_encryption_configuration_readiness
from apps.system.health_services import (
    check_application_errors,
    check_audit_configuration,
    check_daily_configuration,
    check_default_cache_read_only,
    check_email_backlog,
    check_email_backend,
    check_notification_provider_readiness,
    check_notification_worker_liveness,
    check_latest_backup,
    check_migration_state,
    check_notification_outbox,
    check_pdf_renderer,
    check_protected_storage,
    check_redis_cache_read_only,
    check_settings_posture,
    check_database,
)
from apps.system.maintenance_services import get_active_maintenance_window
from apps.system.readiness_services import (
    ReadinessCheck,
    build_report,
    check_from_health_status,
    is_deployment_environment,
    render_report,
)
from apps.governance.runtime_config import resolve_runtime_setting


_SECRET_CONFIGURATION_NAMES = frozenset(
    {
        "SECRET_KEY",
        "AUDIT_HASH_SECRET",
        "ACCOUNT_SECURITY_HASH_SECRET",
        "ACCOUNT_ACTIVATION_TOKEN_SECRET",
        "DATABASE_URL",
        "FIELD_ENCRYPTION_KEY",
        "PROTECTED_STORAGE_S3_ACCESS_KEY",
        "PROTECTED_STORAGE_S3_SECRET_KEY",
        "BACKUP_STORAGE_S3_ACCESS_KEY",
        "BACKUP_STORAGE_S3_SECRET_KEY",
        "ACCOUNT_SECURITY_TURNSTILE_SECRET",
        "EMAIL_HOST_PASSWORD",
        "ECOUNSELING_DAILY_API_KEY",
        "ECOUNSELING_DAILY_WEBHOOK_SECRET",
        "ECOUNSELING_ROOM_SALT",
    }
)

_DEPLOYMENT_CONFIGURATION_NAMES = (
    "COMPASS_RELEASE_VERSION",
    "COMPASS_BUILD_ID",
    "COMPASS_API_BASE_URL",
    "COMPASS_CLIENT_BASE_URL",
    "ALLOWED_HOSTS",
    "CSRF_TRUSTED_ORIGINS",
    "CACHE_URL",
    "SECRET_KEY",
    "AUDIT_HASH_SECRET",
    "ACCOUNT_SECURITY_HASH_SECRET",
    "ACCOUNT_ACTIVATION_TOKEN_SECRET",
    "DATABASE_URL",
    "KEY_SOURCE_PROVIDER",
    "KEY_SOURCE_PODMAN_SECRETS_DIR",
    "FIELD_ENCRYPTION_KEY",
    "PROTECTED_STORAGE_BACKEND",
    "PROTECTED_STORAGE_S3_ENDPOINT_URL",
    "PROTECTED_STORAGE_S3_ACCESS_KEY",
    "PROTECTED_STORAGE_S3_SECRET_KEY",
    "PROTECTED_STORAGE_S3_BUCKET_NAME",
    "BACKUP_STORAGE_BACKEND",
    "BACKUP_STORAGE_S3_ENDPOINT_URL",
    "BACKUP_STORAGE_S3_ACCESS_KEY",
    "BACKUP_STORAGE_S3_SECRET_KEY",
    "BACKUP_STORAGE_S3_BUCKET",
    "ACCOUNT_SECURITY_CAPTCHA_ADAPTER",
    "ACCOUNT_SECURITY_TURNSTILE_SITE_KEY",
    "ACCOUNT_SECURITY_TURNSTILE_SECRET",
    "ACCOUNT_SECURITY_TURNSTILE_HOSTNAMES",
    "EMAIL_HOST",
    "EMAIL_HOST_USER",
    "EMAIL_HOST_PASSWORD",
    "DEFAULT_FROM_EMAIL",
    "COMPASS_EMAIL_REPLY_TO",
    "COMPASS_EMAIL_VERIFIED_SENDER_DOMAIN",
    "ECOUNSELING_PROVIDER",
    "ECOUNSELING_DAILY_DOMAIN",
    "ECOUNSELING_DAILY_API_KEY",
    "ECOUNSELING_DAILY_WEBHOOK_ID",
    "ECOUNSELING_DAILY_WEBHOOK_SECRET",
    "ECOUNSELING_DAILY_WEBHOOK_URL",
    "ECOUNSELING_ROOM_SALT",
)


def _safe_configuration_presence() -> list[dict]:
    """Return names and presence only; never serialize configuration values."""

    deployment = is_deployment_environment()
    active = str(getattr(settings, "COMPASS_ACCESS_MODE", "active") or "active").lower() == "active"
    daily_enabled = _daily_enabled()
    secret_source = "podman_secret_wrapper" if deployment else "environment"
    active_only = {
        "ACCOUNT_SECURITY_TURNSTILE_SITE_KEY",
        "ACCOUNT_SECURITY_TURNSTILE_SECRET",
        "ACCOUNT_SECURITY_TURNSTILE_HOSTNAMES",
        "EMAIL_HOST_USER",
        "EMAIL_HOST_PASSWORD",
        "DEFAULT_FROM_EMAIL",
        "COMPASS_EMAIL_REPLY_TO",
        "COMPASS_EMAIL_VERIFIED_SENDER_DOMAIN",
    }
    daily_only = {
        "ECOUNSELING_DAILY_DOMAIN",
        "ECOUNSELING_DAILY_API_KEY",
        "ECOUNSELING_DAILY_WEBHOOK_ID",
        "ECOUNSELING_DAILY_WEBHOOK_SECRET",
        "ECOUNSELING_DAILY_WEBHOOK_URL",
        "ECOUNSELING_ROOM_SALT",
    }
    entries = []
    for name in _DEPLOYMENT_CONFIGURATION_NAMES:
        value = getattr(settings, name, None)
        if isinstance(value, (list, tuple, set, dict)):
            present = bool(value)
        else:
            present = bool(str(value or "").strip())
        classification = "secret" if name in _SECRET_CONFIGURATION_NAMES else "static_configuration"
        required = deployment
        if name in active_only:
            required = deployment and active
        if name in daily_only:
            required = deployment and daily_enabled
        entries.append(
            {
                "name": name,
                "classification": classification,
                "declared_source": secret_source if classification == "secret" else "environment_or_settings",
                "required": bool(required),
                "present": present,
                "validity": (
                    "VALIDATED_BY_SETTINGS"
                    if present
                    else ("MISSING" if required else "NOT_CONFIGURED")
                ),
            }
        )
    return entries


def _email_configuration_check() -> ReadinessCheck:
    health = check_email_backend()
    check = check_from_health_status(health, required=True, evidence_type="configuration")
    backend = str(getattr(settings, "EMAIL_BACKEND", "") or "").lower()
    unsafe_deployment_backend = is_deployment_environment() and any(
        token in backend for token in ("locmem", "console", "filebased")
    )
    if unsafe_deployment_backend:
        return ReadinessCheck(
            name="email_backend",
            status="FAIL",
            required=True,
            reason_code="EMAIL_DEPLOYMENT_BACKEND_UNSAFE",
            message="Staging/production email must not use an in-memory, console, or file backend.",
            evidence_type="configuration",
        )
    return check


def _email_connection_check(*, probe_external: bool) -> ReadinessCheck:
    if not probe_external:
        return ReadinessCheck(
            name="email_connection",
            status="PENDING",
            required=True,
            reason_code="EMAIL_CONNECTION_PROBE_NOT_REQUESTED",
            message="Email connection was not probed; use --probe-external when authorized.",
            evidence_type="read_only_probe",
        )
    connection = None
    try:
        connection = mail.get_connection(fail_silently=False)
        if hasattr(connection, "timeout"):
            connection.timeout = resolve_runtime_setting(
                "technical.delivery_operations",
                "EMAIL_TIMEOUT",
            )
        connection.open()
    except Exception:
        return ReadinessCheck(
            name="email_connection",
            status="FAIL",
            required=True,
            reason_code="EMAIL_CONNECTION_FAILED",
            message="Email backend connection probe failed without sending a message.",
            evidence_type="read_only_probe",
        )
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
    return ReadinessCheck(
        name="email_connection",
        status="PASS",
        required=True,
        reason_code="EMAIL_CONNECTION_OK",
        message="Email backend connection opened and closed without sending a message.",
        evidence_type="read_only_probe",
    )


def _email_external_evidence_check(name, reason_code, message):
    return ReadinessCheck(
        name=name,
        status="PENDING",
        # This command can verify configuration and read-only connectivity,
        # but it cannot manufacture institutional/provider acceptance. Keep
        # these visible without making automated strict readiness impossible.
        required=False,
        reason_code=reason_code,
        message=message,
        evidence_type="external_acceptance",
    )


def _daily_enabled() -> bool:
    provider = str(getattr(settings, "ECOUNSELING_PROVIDER", "") or "").strip().lower()
    return provider not in {"", "none", "disabled", "off"}


def _daily_probe_check(*, probe_external: bool) -> ReadinessCheck:
    if not _daily_enabled():
        return ReadinessCheck(
            name="daily_connectivity",
            status="SKIP",
            required=False,
            reason_code="DAILY_DISABLED",
            message="Daily.co is explicitly disabled for this environment.",
            evidence_type="configuration",
        )
    if not probe_external:
        return ReadinessCheck(
            name="daily_connectivity",
            status="PENDING",
            required=True,
            reason_code="DAILY_PROBE_NOT_REQUESTED",
            message="Daily.co connectivity was not probed; use --probe-external when authorized.",
            evidence_type="read_only_probe",
        )
    try:
        provider = DailyProvider()
        if not provider.api.configured():
            raise ProviderConfigurationError("daily_not_configured")
        webhook_id = str(getattr(settings, "ECOUNSELING_DAILY_WEBHOOK_ID", "") or "").strip()
        if webhook_id:
            provider.api.get_webhook(webhook_id)
        else:
            provider.api.list_webhooks()
    except (ProviderConfigurationError, ProviderOperationError):
        return ReadinessCheck(
            name="daily_connectivity",
            status="FAIL",
            required=True,
            reason_code="DAILY_READ_ONLY_PROBE_FAILED",
            message="Daily.co read-only API probe failed or is not configured.",
            evidence_type="read_only_probe",
        )
    except Exception:
        return ReadinessCheck(
            name="daily_connectivity",
            status="FAIL",
            required=True,
            reason_code="DAILY_READ_ONLY_PROBE_FAILED",
            message="Daily.co read-only API probe failed safely.",
            evidence_type="read_only_probe",
        )
    return ReadinessCheck(
        name="daily_connectivity",
        status="PASS",
        required=True,
        reason_code="DAILY_READ_ONLY_PROBE_OK",
        message="Daily.co responded to a read-only webhook API request.",
        evidence_type="read_only_probe",
    )


def _maintenance_check() -> ReadinessCheck:
    try:
        active = get_active_maintenance_window() is not None
    except Exception:
        return ReadinessCheck(
            name="maintenance_notice_state",
            status="FAIL",
            required=True,
            reason_code="MAINTENANCE_NOTICE_QUERY_FAILED",
            message="Maintenance notice state could not be queried safely.",
            evidence_type="read_only_query",
        )
    return ReadinessCheck(
        name="maintenance_notice_state",
        status="PASS",
        required=True,
        reason_code="MAINTENANCE_NOTICE_ACTIVE" if active else "MAINTENANCE_NOTICE_INACTIVE",
        message=(
            "Maintenance notice state was queried; no global maintenance enforcement was applied."
        ),
        evidence_type="read_only_query",
    )


def _health_checks(*, probe_external: bool, system_identity: str | None) -> list[ReadinessCheck]:
    checks = []
    health_functions = (
        (check_database, True),
        (check_default_cache_read_only, True),
        (
            check_redis_cache_read_only,
            "redis" in str(getattr(settings, "CACHES", {}).get("default", {}).get("BACKEND", "")).lower(),
        ),
        (check_protected_storage, True),
        (check_notification_outbox, True),
        (check_email_backlog, True),
        (check_application_errors, True),
        (check_audit_configuration, True),
        (check_migration_state, True),
        (check_settings_posture, True),
        (check_latest_backup, True),
        (
            check_pdf_renderer,
            bool(
                resolve_runtime_setting(
                    "technical.renderer",
                    "DOCUMENT_PDF_RENDERER_ENABLED",
                )
            ),
        ),
    )
    for health_function, required in health_functions:
        checks.append(
            check_from_health_status(
                health_function(),
                required=required,
                evidence_type="read_only_query",
            )
        )

    checks.append(_email_configuration_check())
    checks.append(check_from_health_status(check_notification_provider_readiness(), required=True, evidence_type="configuration"))
    checks.append(check_from_health_status(check_notification_worker_liveness(), required=True, evidence_type="worker_liveness"))
    checks.append(_email_connection_check(probe_external=probe_external))
    checks.extend([
        _email_external_evidence_check("email_provider_acceptance", "EMAIL_PROVIDER_ACCEPTANCE_PENDING", "Provider acceptance evidence requires a staging send and provider response."),
        _email_external_evidence_check("email_real_inbox", "EMAIL_INBOX_DELIVERY_PENDING", "Real inbox delivery evidence is not produced by local readiness checks."),
        _email_external_evidence_check("email_dns_authentication", "EMAIL_DNS_AUTH_PENDING", "SPF/DKIM/DMARC alignment evidence is supplied by the institution DNS owner."),
        _email_external_evidence_check("email_bounce_feedback", "EMAIL_BOUNCE_FEEDBACK_PENDING", "Signed provider bounce feedback is not configured by the provider-neutral local service."),
    ])

    if _daily_enabled():
        checks.append(
            check_from_health_status(
                check_daily_configuration(),
                required=True,
                evidence_type="configuration",
            )
        )
    else:
        checks.append(
            ReadinessCheck(
                name="daily_configuration",
                status="SKIP",
                required=False,
                reason_code="DAILY_DISABLED",
                message="Daily.co is explicitly disabled for this environment.",
                evidence_type="configuration",
            )
        )
    checks.append(_daily_probe_check(probe_external=probe_external))
    checks.extend(collect_encryption_configuration_readiness())
    checks.extend(
        collect_backup_readiness(
            system_identity=system_identity,
            probe_external=probe_external,
        )
    )
    checks.append(_maintenance_check())
    return checks


class Command(BaseCommand):
    help = "Verify deployment health without sending, writing, creating, or executing operational actions."

    def add_arguments(self, parser):
        parser.add_argument(
            "--system-identity",
            help="Optional existing IT Admin email or numeric user ID for backup authorization evidence.",
        )
        parser.add_argument(
            "--probe-external",
            action="store_true",
            help="Opt in to read-only email, Daily.co, and S3 connectivity probes.",
        )
        parser.add_argument(
            "--strict",
            action="store_true",
            help="Treat required warnings and pending evidence as failures.",
        )
        parser.add_argument(
            "--format",
            choices=("text", "json"),
            default="text",
            help="Output format; JSON contains only safe readiness metadata.",
        )

    def handle(self, *args, **options):
        strict = bool(options["strict"])
        probe_external = bool(options["probe_external"])
        try:
            checks = _health_checks(
                probe_external=probe_external,
                system_identity=options.get("system_identity"),
            )
        except Exception:
            checks = [
                ReadinessCheck(
                    name="health_collection",
                    status="FAIL",
                    required=True,
                    reason_code="HEALTH_COLLECTION_FAILED",
                    message="Health readiness checks failed safely before completion.",
                    evidence_type="read_only_query",
                )
            ]
        report = build_report(
            "verify_health",
            checks,
            strict=strict,
            probe_external=probe_external,
        )
        report["configuration_presence"] = _safe_configuration_presence()
        render_report(report, output_format=options["format"], stdout=self.stdout)
        if not report["passed"]:
            raise CommandError("health_readiness_failed")
