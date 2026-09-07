# Project: COMPASS
# File: apps/system/health_services.py
# Module: apps.system
# Purpose: On-demand system health check services and components validation
# Domain boundary and service policy.
# Notes:
#   - Redacts raw exceptions and stack traces.
#   - Exposes safe message, component key, status, and reason code.
#   - No database writes, no live SMTP send, no sensitive file generation.

import importlib.util
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from urllib.parse import urlparse
from django.conf import settings
from django.db import connection, connections
from django.core.cache import caches
from django.db.migrations.executor import MigrationExecutor
from django.utils import timezone

from apps.system.checks import check_environment_settings
from apps.counseling.recording_policy import recording_availability_projection
from apps.governance.runtime_config import resolve_runtime_setting


@dataclass
class HealthComponentStatus:
    component: str
    label: str
    status: str
    message: str
    reason_code: str
    duration_ms: float
    checked_at: str

    def to_dict(self) -> dict:
        return asdict(self)


def check_database() -> HealthComponentStatus:
    """Safe database connectivity check."""
    start = time.perf_counter()
    checked_at = datetime.utcnow().isoformat()
    try:
        connection.ensure_connection()
        # Perform a minimal query to verify read access
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1;")
            cursor.fetchone()
        status = "ok"
        message = "Database connection is healthy."
        reason_code = "DB_CONN_OK"
    except Exception as exc:
        status = "error"
        message = "Database is unreachable or misconfigured."
        reason_code = "DB_CONN_FAIL"
    duration = round((time.perf_counter() - start) * 1000, 2)
    return HealthComponentStatus(
        component="database",
        label="Database Connectivity",
        status=status,
        message=message,
        reason_code=reason_code,
        duration_ms=duration,
        checked_at=checked_at,
    )


def check_default_cache() -> HealthComponentStatus:
    """Safe cache read/write check."""
    start = time.perf_counter()
    checked_at = datetime.utcnow().isoformat()
    try:
        cache = caches["default"]
        test_key = "health_check_test_key"
        cache.set(test_key, 1, timeout=5)
        val = cache.get(test_key)
        cache.delete(test_key)
        if val == 1:
            status = "ok"
            message = "Default cache is functioning correctly."
            reason_code = "CACHE_OK"
        else:
            status = "error"
            message = "Default cache read/write test mismatch."
            reason_code = "CACHE_MISMATCH"
    except Exception as exc:
        status = "error"
        message = "Default cache connection failed."
        reason_code = "CACHE_CONN_FAIL"
    duration = round((time.perf_counter() - start) * 1000, 2)
    return HealthComponentStatus(
        component="default_cache",
        label="Default Cache Service",
        status=status,
        message=message,
        reason_code=reason_code,
        duration_ms=duration,
        checked_at=checked_at,
    )


def check_default_cache_read_only() -> HealthComponentStatus:
    """Read-only default-cache connectivity check.

    Deployment readiness must not create or delete a cache key.  A cache GET
    is sufficient to force a backend connection while preserving the
    command's non-mutating contract.
    """
    start = time.perf_counter()
    checked_at = datetime.utcnow().isoformat()
    try:
        cache = caches["default"]
        cache.get("compass:deployment-readiness:connectivity")
        status = "ok"
        message = "Default cache read-only connectivity check passed."
        reason_code = "CACHE_READ_ONLY_OK"
    except Exception:
        status = "error"
        message = "Default cache read-only connectivity check failed."
        reason_code = "CACHE_READ_ONLY_FAIL"
    duration = round((time.perf_counter() - start) * 1000, 2)
    return HealthComponentStatus(
        component="default_cache",
        label="Default Cache Service",
        status=status,
        message=message,
        reason_code=reason_code,
        duration_ms=duration,
        checked_at=checked_at,
    )


def check_redis_cache() -> HealthComponentStatus:
    """Safe Redis cache checks if Redis backend is configured."""
    start = time.perf_counter()
    checked_at = datetime.utcnow().isoformat()
    caches_config = getattr(settings, "CACHES", {})
    default_config = caches_config.get("default", {})
    backend = default_config.get("BACKEND", "")
    if "redis" in backend.lower():
        # Redis is active, check using default cache adapter
        try:
            cache = caches["default"]
            test_key = "redis_health_check_test_key"
            cache.set(test_key, 1, timeout=5)
            val = cache.get(test_key)
            cache.delete(test_key)
            if val == 1:
                status = "ok"
                message = "Redis default cache is healthy."
                reason_code = "REDIS_OK"
            else:
                status = "error"
                message = "Redis cache read/write mismatch."
                reason_code = "REDIS_MISMATCH"
        except Exception:
            status = "error"
            message = "Redis cache connection failed."
            reason_code = "REDIS_CONN_FAIL"
    else:
        status = "skipped"
        message = "Redis is not configured as the default cache backend."
        reason_code = "REDIS_NOT_CONFIGURED"
    duration = round((time.perf_counter() - start) * 1000, 2)
    return HealthComponentStatus(
        component="redis",
        label="Redis Cache Backend",
        status=status,
        message=message,
        reason_code=reason_code,
        duration_ms=duration,
        checked_at=checked_at,
    )


def check_redis_cache_read_only() -> HealthComponentStatus:
    """Read-only Redis connectivity check when Redis is configured."""
    start = time.perf_counter()
    checked_at = datetime.utcnow().isoformat()
    caches_config = getattr(settings, "CACHES", {})
    default_config = caches_config.get("default", {})
    backend = default_config.get("BACKEND", "")
    if "redis" not in backend.lower():
        status = "skipped"
        message = "Redis is not configured as the default cache backend."
        reason_code = "REDIS_NOT_CONFIGURED"
    else:
        try:
            caches["default"].get("compass:deployment-readiness:redis-connectivity")
            status = "ok"
            message = "Redis read-only connectivity check passed."
            reason_code = "REDIS_READ_ONLY_OK"
        except Exception:
            status = "error"
            message = "Redis read-only connectivity check failed."
            reason_code = "REDIS_READ_ONLY_FAIL"
    duration = round((time.perf_counter() - start) * 1000, 2)
    return HealthComponentStatus(
        component="redis",
        label="Redis Cache Backend",
        status=status,
        message=message,
        reason_code=reason_code,
        duration_ms=duration,
        checked_at=checked_at,
    )


def check_protected_storage() -> HealthComponentStatus:
    """Safe protected storage configuration check.

    This intentionally does not instantiate storage adapters. The local
    adapter creates its root directory during construction, and health checks
    must remain non-mutating.
    """
    start = time.perf_counter()
    checked_at = datetime.utcnow().isoformat()
    try:
        backend_name = str(getattr(settings, "PROTECTED_STORAGE_BACKEND", "local") or "").lower()
        environment = str(getattr(settings, "COMPASS_ENVIRONMENT", "development") or "").lower()

        if backend_name == "local":
            allow_local_prod = bool(
                getattr(settings, "COMPASS_ALLOW_LOCAL_PROTECTED_STORAGE_IN_PRODUCTION", False)
            )
            if environment == "production" and not allow_local_prod:
                status = "error"
                message = "Protected storage local backend requires explicit production acknowledgement."
                reason_code = "STORAGE_LOCAL_PRODUCTION_UNACKNOWLEDGED"
            else:
                status = "ok"
                message = "Protected storage local backend configuration is declared."
                reason_code = "STORAGE_LOCAL_CONFIGURED"
        elif backend_name == "s3":
            required_settings = [
                "PROTECTED_STORAGE_S3_ENDPOINT_URL",
                "PROTECTED_STORAGE_S3_ACCESS_KEY",
                "PROTECTED_STORAGE_S3_SECRET_KEY",
                "PROTECTED_STORAGE_S3_BUCKET_NAME",
            ]
            missing_settings = [
                setting_name for setting_name in required_settings
                if not getattr(settings, setting_name, "")
            ]
            if missing_settings:
                status = "error"
                message = "S3-compatible protected storage configuration is incomplete."
                reason_code = "STORAGE_S3_CONFIG_MISSING"
            elif not _s3_endpoint_has_safe_shape("PROTECTED_STORAGE_S3_ENDPOINT_URL"):
                status = "error"
                message = "S3-compatible protected storage endpoint configuration is invalid."
                reason_code = "STORAGE_S3_ENDPOINT_INVALID"
            elif not _s3_client_dependency_available():
                status = "error"
                message = "S3-compatible protected storage dependency is unavailable."
                reason_code = "STORAGE_S3_DEPENDENCY_MISSING"
            else:
                status = "ok"
                message = "S3-compatible protected storage configuration and dependency are declared."
                reason_code = "STORAGE_S3_READY"
        else:
            status = "error"
            message = "Protected storage backend setting is not recognized."
            reason_code = "STORAGE_BACKEND_UNKNOWN"
    except Exception:
        status = "error"
        message = "Failed to inspect protected storage configuration."
        reason_code = "STORAGE_CONFIG_CHECK_FAIL"
    duration = round((time.perf_counter() - start) * 1000, 2)
    return HealthComponentStatus(
        component="protected_storage",
        label="Protected Storage Adapter",
        status=status,
        message=message,
        reason_code=reason_code,
        duration_ms=duration,
        checked_at=checked_at,
    )


def _s3_client_dependency_available() -> bool:
    try:
        return (
            importlib.util.find_spec("boto3") is not None
            and importlib.util.find_spec("botocore") is not None
        )
    except (ImportError, ValueError):
        return False


def _s3_endpoint_has_safe_shape(setting_name: str) -> bool:
    endpoint = str(getattr(settings, setting_name, "") or "")
    parsed = urlparse(endpoint)
    return (
        parsed.scheme in {"http", "https"}
        and bool(parsed.netloc)
        and not parsed.username
        and not parsed.password
    )


def check_email_backend() -> HealthComponentStatus:
    """Safe email backend configuration check."""
    start = time.perf_counter()
    checked_at = datetime.utcnow().isoformat()
    try:
        backend_path = getattr(settings, "EMAIL_BACKEND", "")
        if backend_path:
            status = "ok"
            message = "Email backend setting is declared."
            reason_code = "EMAIL_OK"
        else:
            status = "warning"
            message = "No email backend configured."
            reason_code = "EMAIL_NOT_CONFIGURED"
    except Exception:
        status = "error"
        message = "Email backend check encountered an error."
        reason_code = "EMAIL_CHECK_FAIL"
    duration = round((time.perf_counter() - start) * 1000, 2)
    return HealthComponentStatus(
        component="email_backend",
        label="Email Backend Configuration",
        status=status,
        message=message,
        reason_code=reason_code,
        duration_ms=duration,
        checked_at=checked_at,
    )


def check_notification_provider_readiness() -> HealthComponentStatus:
    """Separate configured/provider/inbox/DNS/feedback/worker evidence states."""
    start = time.perf_counter()
    checked_at = datetime.utcnow().isoformat()
    environment = str(getattr(settings, "COMPASS_ENVIRONMENT", "development") or "development")
    local_staging = bool(getattr(settings, "COMPASS_LOCAL_STAGING", False))
    configured = bool(
        getattr(settings, "EMAIL_HOST", "")
        and getattr(settings, "DEFAULT_FROM_EMAIL", "")
        and getattr(settings, "COMPASS_EMAIL_REPLY_TO", "")
        and getattr(settings, "COMPASS_EMAIL_VERIFIED_SENDER_DOMAIN", "")
        and getattr(settings, "COMPASS_CLIENT_BASE_URL", "")
        and (
            local_staging
            or (
                getattr(settings, "EMAIL_HOST_USER", "")
                and getattr(settings, "EMAIL_HOST_PASSWORD", "")
            )
        )
    )
    if not configured:
        status, reason, message = "warning", "NOTIFICATION_CONFIGURATION_PENDING", "Notification configuration is incomplete."
    else:
        status, reason, message = "ok", "NOTIFICATION_CONFIGURATION_DECLARED", "Configuration is declared; provider acceptance, inbox, DNS, bounce, and worker evidence remain separate gates."
    return HealthComponentStatus(
        component="notification_provider_readiness",
        label="Notification Provider Readiness",
        status=status,
        message=message,
        reason_code=reason,
        duration_ms=round((time.perf_counter() - start) * 1000, 2),
        checked_at=checked_at,
    )


def check_notification_worker_liveness() -> HealthComponentStatus:
    start = time.perf_counter()
    checked_at = datetime.utcnow().isoformat()
    enabled = bool(
        resolve_runtime_setting(
            "technical.delivery_operations",
            "NOTIFICATION_WORKER_ENABLED",
        )
    )
    if enabled:
        status, reason, message = "ok", "NOTIFICATION_WORKER_DECLARED", "Supervised notification worker is declared; process health is supplied by Compose."
    else:
        status, reason, message = "warning", "NOTIFICATION_WORKER_NOT_DECLARED", "Notification worker is not declared in this environment."
    return HealthComponentStatus(
        component="notification_worker",
        label="Notification Worker Liveness",
        status=status,
        message=message,
        reason_code=reason,
        duration_ms=round((time.perf_counter() - start) * 1000, 2),
        checked_at=checked_at,
    )


def check_notification_outbox() -> HealthComponentStatus:
    """Safe outbox event queue backlog query check."""
    start = time.perf_counter()
    checked_at = datetime.utcnow().isoformat()
    try:
        from apps.workflow.models import OutboxEvent
        pending = OutboxEvent.objects.filter(status="pending").count()
        processing = OutboxEvent.objects.filter(status="processing").count()
        failed = OutboxEvent.objects.filter(status="failed").count()
        dead = OutboxEvent.objects.filter(status="dead").count()
        status = "ok"
        if failed > 0 or dead > 0:
            status = "warning"
        message = f"Outbox events: {pending} pending, {processing} processing, {failed} failed, {dead} dead."
        reason_code = "OUTBOX_BACKLOG_OK"
    except Exception:
        status = "error"
        message = "Failed to query outbox queue metrics."
        reason_code = "OUTBOX_QUERY_FAIL"
    duration = round((time.perf_counter() - start) * 1000, 2)
    return HealthComponentStatus(
        component="outbox_backlog",
        label="Transactional Outbox Backlog",
        status=status,
        message=message,
        reason_code=reason_code,
        duration_ms=duration,
        checked_at=checked_at,
    )


def check_email_backlog() -> HealthComponentStatus:
    """Safe email delivery backlog query check."""
    start = time.perf_counter()
    checked_at = datetime.utcnow().isoformat()
    try:
        from apps.notifications.models import EmailDelivery
        pending = EmailDelivery.objects.filter(delivery_state="queued").count()
        processing = EmailDelivery.objects.filter(delivery_state="sending").count()
        delayed = EmailDelivery.objects.filter(delivery_state="delayed").count()
        failed = EmailDelivery.objects.filter(delivery_state="failed").count()
        exhausted = EmailDelivery.objects.filter(delivery_state="retry_exhausted").count()
        bounced = EmailDelivery.objects.filter(delivery_state="bounced").count()
        status = "ok"
        if failed > 0 or exhausted > 0 or bounced > 0:
            status = "warning"
        message = f"Email deliveries: {pending} queued, {processing} sending, {delayed} delayed, {failed} failed, {exhausted} retry exhausted, {bounced} bounced."
        reason_code = "EMAIL_BACKLOG_OK"
    except Exception:
        status = "error"
        message = "Failed to query email queue metrics."
        reason_code = "EMAIL_QUERY_FAIL"
    duration = round((time.perf_counter() - start) * 1000, 2)
    return HealthComponentStatus(
        component="email_backlog",
        label="Outgoing Email Queue Backlog",
        status=status,
        message=message,
        reason_code=reason_code,
        duration_ms=duration,
        checked_at=checked_at,
    )


def check_daily_configuration() -> HealthComponentStatus:
    """Safe Daily.co e-counseling posture checks."""
    start = time.perf_counter()
    checked_at = datetime.utcnow().isoformat()
    provider = str(getattr(settings, "ECOUNSELING_PROVIDER", "DAILY") or "").strip().lower()
    if provider in {"none", "disabled", "off"}:
        duration = round((time.perf_counter() - start) * 1000, 2)
        return HealthComponentStatus(
            component="daily",
            label="Daily.co E-Counseling Configuration",
            status="warning",
            message="Daily.co e-counseling is explicitly disabled in this environment.",
            reason_code="DAILY_DISABLED",
            duration_ms=duration,
            checked_at=checked_at,
        )
    projection = recording_availability_projection()
    if projection.blocked:
        daily_join_configured = bool(
            getattr(settings, "ECOUNSELING_DAILY_DOMAIN", "")
            and getattr(settings, "ECOUNSELING_DAILY_API_KEY", "")
        )
        status = "warning"
        message = (
            "Daily.co join configuration is present; recording is disabled by approved policy and deferred."
            if daily_join_configured
            else "Recording is disabled by approved policy and deferred; Daily.co recording readiness is not evaluated."
        )
        duration = round((time.perf_counter() - start) * 1000, 2)
        return HealthComponentStatus(
            component="daily",
            label="Daily.co E-Counseling Configuration",
            status=status,
            message=message,
            reason_code=projection.reason_code,
            duration_ms=duration,
            checked_at=checked_at,
        )
    try:
        from apps.privacy.services import recording_retention_days

        daily_domain = getattr(settings, "ECOUNSELING_DAILY_DOMAIN", "")
        daily_api_key = getattr(settings, "ECOUNSELING_DAILY_API_KEY", "")
        webhook_ready = bool(
            getattr(settings, "ECOUNSELING_DAILY_WEBHOOK_SECRET", "")
            and getattr(settings, "ECOUNSELING_DAILY_WEBHOOK_ID", "")
            and getattr(settings, "ECOUNSELING_DAILY_WEBHOOK_URL", "")
            and resolve_runtime_setting(
                "counseling.ecounseling_controls",
                "ECOUNSELING_RECORDING_WORKER_ENABLED",
            )
            and resolve_runtime_setting(
                "counseling.ecounseling_controls",
                "ECOUNSELING_RECORDING_TRANSCRIPTION_ENABLED",
            )
            and resolve_runtime_setting(
                "counseling.ecounseling_controls",
                "ECOUNSELING_RECORDING_TRANSCRIPTION_WORKER_ENABLED",
            )
            and str(getattr(settings, "PROTECTED_STORAGE_BACKEND", "local")).lower() == "s3"
            and getattr(settings, "PROTECTED_STORAGE_S3_ENDPOINT_URL", "")
            and getattr(settings, "PROTECTED_STORAGE_S3_ACCESS_KEY", "")
            and getattr(settings, "PROTECTED_STORAGE_S3_SECRET_KEY", "")
            and getattr(settings, "PROTECTED_STORAGE_S3_BUCKET_NAME", "")
            and int(
                resolve_runtime_setting(
                    "counseling.ecounseling_controls",
                    "ECOUNSELING_RECORDING_MAX_FILE_SIZE_BYTES",
                )
            )
            > 0
            and int(
                resolve_runtime_setting(
                    "counseling.ecounseling_controls",
                    "ECOUNSELING_RECORDING_TRANSCRIPTION_MAX_FILE_SIZE_BYTES",
                )
            )
            > 0
            and recording_retention_days() > 0
        )
        recording_enabled = bool(
            resolve_runtime_setting(
                "counseling.ecounseling_controls",
                "ECOUNSELING_RECORDING_ENABLED",
            )
        )
        if daily_domain and daily_api_key and (not recording_enabled or webhook_ready):
            status = "ok"
            message = "Daily.co join authentication is configured; recording readiness is fail-closed unless all gates are enabled."
            reason_code = "DAILY_OK" if not recording_enabled or webhook_ready else "DAILY_RECORDING_NOT_READY"
        elif daily_domain and daily_api_key:
            status = "warning"
            message = "Daily.co join authentication is configured, but recording prerequisites are not ready."
            reason_code = "DAILY_RECORDING_NOT_READY"
        elif daily_domain:
            status = "warning"
            message = "Daily.co domain configured, but API key is missing."
            reason_code = "DAILY_PARTIAL_CONFIG"
        else:
            status = "warning"
            message = "Daily.co integration is not configured."
            reason_code = "DAILY_NOT_CONFIGURED"
    except Exception:
        status = "error"
        message = "Failed to parse Daily.co e-counseling settings."
        reason_code = "DAILY_CHECK_FAIL"
    duration = round((time.perf_counter() - start) * 1000, 2)
    return HealthComponentStatus(
        component="daily",
        label="Daily.co E-Counseling Configuration",
        status=status,
        message=message,
        reason_code=reason_code,
        duration_ms=duration,
        checked_at=checked_at,
    )


def check_pdf_renderer() -> HealthComponentStatus:
    """Safe PDF / document rendering check."""
    start = time.perf_counter()
    checked_at = datetime.utcnow().isoformat()
    try:
        from apps.documents.renderers import get_renderer
        # check if pdf support is available
        pdf_avail = False
        try:
            renderer = get_renderer("PLAYWRIGHT_PDF")
            pdf_avail = renderer.is_pdf_available()
        except Exception:
            pass
        if pdf_avail:
            status = "ok"
            message = "Playwright PDF renderer backend is available."
            reason_code = "PDF_AVAILABLE"
        else:
            status = "warning"
            message = "PDF rendering backend is not available. Using HTML-only renderer."
            reason_code = "PDF_UNAVAILABLE"
    except Exception:
        status = "error"
        message = "Failed to verify rendering backend availability."
        reason_code = "PDF_CHECK_FAIL"
    duration = round((time.perf_counter() - start) * 1000, 2)
    return HealthComponentStatus(
        component="pdf_renderer",
        label="Document PDF Renderer",
        status=status,
        message=message,
        reason_code=reason_code,
        duration_ms=duration,
        checked_at=checked_at,
    )


def check_application_errors() -> HealthComponentStatus:
    """Safe ApplicationErrorEvent backlog check."""
    start = time.perf_counter()
    checked_at = datetime.utcnow().isoformat()
    try:
        from apps.system.models import ApplicationErrorEvent
        unresolved_count = ApplicationErrorEvent.objects.filter(is_resolved=False).count()
        status = "ok"
        if unresolved_count > 0:
            status = "warning"
        message = f"Found {unresolved_count} unresolved application error event(s)."
        reason_code = "ERRORS_BACKLOG_OK"
    except Exception:
        status = "error"
        message = "Failed to query application error event backlog."
        reason_code = "ERRORS_QUERY_FAIL"
    duration = round((time.perf_counter() - start) * 1000, 2)
    return HealthComponentStatus(
        component="application_errors",
        label="Application Error Log Backlog",
        status=status,
        message=message,
        reason_code=reason_code,
        duration_ms=duration,
        checked_at=checked_at,
    )


def check_audit_configuration() -> HealthComponentStatus:
    """Safe audit logging HMAC configuration check."""
    start = time.perf_counter()
    checked_at = datetime.utcnow().isoformat()
    try:
        audit_secret = getattr(settings, "AUDIT_HASH_SECRET", "")
        secret_key = getattr(settings, "SECRET_KEY", "")
        if audit_secret and audit_secret != secret_key:
            status = "ok"
            message = "Audit log HMAC configuration is verified."
            reason_code = "AUDIT_OK"
        else:
            status = "warning"
            message = "Audit log signature uses fallback configuration."
            reason_code = "AUDIT_FALLBACK"
    except Exception:
        status = "error"
        message = "Failed to inspect audit settings."
        reason_code = "AUDIT_CHECK_FAIL"
    duration = round((time.perf_counter() - start) * 1000, 2)
    return HealthComponentStatus(
        component="audit",
        label="Audit Log Configuration",
        status=status,
        message=message,
        reason_code=reason_code,
        duration_ms=duration,
        checked_at=checked_at,
    )


def check_migration_state() -> HealthComponentStatus:
    """Safe migration plan check without database writes."""
    start = time.perf_counter()
    checked_at = datetime.utcnow().isoformat()
    try:
        executor = MigrationExecutor(connections["default"])
        plan = executor.migration_plan(executor.loader.graph.leaf_nodes())
        if not plan:
            status = "ok"
            message = "All migrations are applied."
            reason_code = "MIGRATIONS_OK"
        else:
            status = "warning"
            message = f"Found {len(plan)} pending migration(s) to apply."
            reason_code = "MIGRATIONS_PENDING"
    except Exception:
        status = "error"
        message = "Failed to determine migration state."
        reason_code = "MIGRATIONS_CHECK_FAIL"
    duration = round((time.perf_counter() - start) * 1000, 2)
    return HealthComponentStatus(
        component="migrations",
        label="Database Migrations State",
        status=status,
        message=message,
        reason_code=reason_code,
        duration_ms=duration,
        checked_at=checked_at,
    )


def check_settings_posture() -> HealthComponentStatus:
    """Safe environment system checks execution."""
    start = time.perf_counter()
    checked_at = datetime.utcnow().isoformat()
    try:
        system_checks = check_environment_settings(None)
        errors_count = sum(1 for e in system_checks if e.is_serious())
        warnings_count = sum(1 for e in system_checks if not e.is_serious())
        if errors_count > 0:
            status = "error"
            message = f"Settings checks identified {errors_count} error(s) and {warnings_count} warning(s)."
            reason_code = "SETTINGS_ERRORS"
        elif warnings_count > 0:
            status = "warning"
            message = f"Settings checks identified {warnings_count} warning(s)."
            reason_code = "SETTINGS_WARNINGS"
        else:
            status = "ok"
            message = "All environment configuration posture checks passed."
            reason_code = "SETTINGS_OK"
    except Exception:
        status = "error"
        message = "Failed to run settings configuration checks."
        reason_code = "SETTINGS_CHECK_FAIL"
    duration = round((time.perf_counter() - start) * 1000, 2)
    return HealthComponentStatus(
        component="settings_posture",
        label="Environment Config Posture",
        status=status,
        message=message,
        reason_code=reason_code,
        duration_ms=duration,
        checked_at=checked_at,
    )


def check_latest_backup() -> HealthComponentStatus:
    """Safe check of the latest backup posture."""
    start = time.perf_counter()
    checked_at = datetime.utcnow().isoformat()
    try:
        from django.apps import apps
        if not apps.is_installed("apps.backups"):
            status = "skipped"
            message = "Backups app is not installed."
            reason_code = "BACKUP_APP_NOT_INSTALLED"
        else:
            from apps.backups.services import build_latest_backup_health_status
            from apps.backups.models import BackupJob
            if not BackupJob.objects.exists():
                status = "warning"
                message = "No backup jobs recorded in the system metadata."
                reason_code = "NO_BACKUPS_EXIST"
            else:
                stats = build_latest_backup_health_status()
                if stats["verification_status"] != "verified":
                    status = "warning"
                    message = "Latest successful backup is not verified."
                    reason_code = "BACKUP_NOT_VERIFIED"
                elif stats["retention_warning"]:
                    status = "warning"
                    message = "Latest backup is older than the configured retention threshold."
                    reason_code = "BACKUP_RETENTION_WARNING"
                else:
                    status = "ok"
                    message = f"Latest backup verified. DB: {stats['database_backup_coverage']}, Media: {stats['media_backup_coverage']}."
                    reason_code = "BACKUP_POSTURE_HEALTHY"
    except Exception:
        status = "error"
        message = "Failed to query backup health status."
        reason_code = "BACKUP_HEALTH_CHECK_FAIL"

    duration = round((time.perf_counter() - start) * 1000, 2)
    return HealthComponentStatus(
        component="latest_backup",
        label="Latest Backup Posture",
        status=status,
        message=message,
        reason_code=reason_code,
        duration_ms=duration,
        checked_at=checked_at,
    )


def run_all_health_checks() -> list[dict]:
    """Execute all health check checks and return DTO-style results list."""
    checks = [
        check_database,
        check_default_cache,
        check_redis_cache,
        check_protected_storage,
        check_email_backend,
        check_notification_provider_readiness,
        check_notification_worker_liveness,
        check_notification_outbox,
        check_email_backlog,
        check_daily_configuration,
        check_pdf_renderer,
        check_application_errors,
        check_audit_configuration,
        check_migration_state,
        check_settings_posture,
        check_latest_backup,
    ]
    results = []
    for check_fn in checks:
        results.append(check_fn().to_dict())
    return results
