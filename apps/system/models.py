# Project: COMPASS
# File: apps/system/models.py
# Module: apps.system
# Purpose: System operations, health, and feature records
# Domain boundary and service policy.
# Notes: Deployment configuration belongs in Django settings/environment.

from django.db import models
from django.db.models import F, Q
from django.core.exceptions import ValidationError
from django.conf import settings
from django.utils import timezone

from apps.common.models import TimestampedModel
from apps.system.choices import (
    ErrorCategoryChoices,
    ErrorEnvironmentChoices,
    ErrorSeverityChoices,
    MaintenanceStatusChoices,
)

class OperationalCommandRun(TimestampedModel):
    """Safe, immutable-ish history for allowlisted operational commands.

    The record intentionally contains no argv, raw command output, settings
    values, credentials, or workflow/student identifiers.  It is suitable for
    the Release & Operations projection and audit reconciliation.
    """

    command_key = models.CharField("command key", max_length=100)
    mode = models.CharField("mode", max_length=20, default="execute")
    actor_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="operational_command_runs",
    )
    actor_identity = models.CharField("actor or system identity", max_length=120, blank=True)
    environment = models.CharField("environment", max_length=40)
    reason_code = models.CharField("reason code", max_length=100)
    configuration_identifier = models.CharField("configuration identifier", max_length=160, blank=True)
    started_at = models.DateTimeField("started at")
    finished_at = models.DateTimeField("finished at", null=True, blank=True)
    outcome = models.CharField("outcome", max_length=30, default="STARTED")
    outcome_reason_code = models.CharField("outcome reason code", max_length=100, blank=True)
    release_version = models.CharField("release version", max_length=64, blank=True)
    build_id = models.CharField("build identifier", max_length=128, blank=True)
    summary_json = models.JSONField("allowlisted summary", default=dict, blank=True)

    class Meta:
        ordering = ["-started_at", "-pk"]
        indexes = [
            models.Index(fields=["command_key", "started_at"]),
            models.Index(fields=["outcome", "started_at"]),
        ]

    def __str__(self):
        return f"{self.command_key} ({self.outcome})"

    def save(self, *args, **kwargs):
        if self.pk:
            from django.core.exceptions import ValidationError
            raise ValidationError("Operational command history is append-only.")
        return super().save(*args, **kwargs)


# ---------------------------------------------------------------------------
# Application Error Reporting
# ---------------------------------------------------------------------------
# PRIVACY/SECURITY:
#   - Never store raw request bodies, raw POST, raw query strings, raw IP,
#     raw User-Agent, raw exception messages, stack traces (unless gated),
#     tokens, secrets, signed URLs, Daily/JWT,
#     counseling notes, referral reasons, assessment interpretations,
#     support messages, or health/family/financial narratives.
#   - `redacted_stack_trace` is nullable and environment-gated; production
#     capture must store NULL unless explicitly approved.
#   - `metadata_json` is sanitized by apps.system.error_services before save.

class ApplicationErrorEvent(TimestampedModel):
    """Redacted, operational application error event.

    Used to give end users a safe Error ID and to allow IT Admins to review
    safe operational metadata. This is NOT a raw exception/stack-trace store
    and NOT a public error-reporting endpoint.
    """

    error_id = models.CharField(
        "error id",
        max_length=32,
        unique=True,
        help_text="User-safe Error ID, e.g. ERR-2026-000001.",
    )
    trace_id = models.CharField(
        "trace id",
        max_length=100,
        null=True,
        blank=True,
        help_text="Optional correlation/trace identifier.",
    )
    request_id = models.CharField(
        "request id",
        max_length=100,
        null=True,
        blank=True,
        help_text="Optional HTTP request correlation identifier.",
    )

    severity = models.CharField(
        "severity",
        max_length=20,
        choices=ErrorSeverityChoices.choices,
        default=ErrorSeverityChoices.ERROR,
    )
    category = models.CharField(
        "category",
        max_length=40,
        choices=ErrorCategoryChoices.choices,
        default=ErrorCategoryChoices.UNKNOWN,
    )
    environment = models.CharField(
        "environment",
        max_length=20,
        choices=ErrorEnvironmentChoices.choices,
        default=ErrorEnvironmentChoices.PRODUCTION,
    )

    release_version = models.CharField(
        "release version",
        max_length=64,
        null=True,
        blank=True,
        help_text="Optional release/version label from settings/env.",
    )
    build_id = models.CharField(
        "build identifier",
        max_length=128,
        null=True,
        blank=True,
        help_text="Immutable deployment build identifier from release identity.",
    )
    app_label = models.CharField(
        "app label",
        max_length=100,
        null=True,
        blank=True,
        help_text="Django app label where the error originated, if known.",
    )
    route_name = models.CharField(
        "route name",
        max_length=255,
        null=True,
        blank=True,
        help_text="URL route name, if available.",
    )
    view_name = models.CharField(
        "view name",
        max_length=255,
        null=True,
        blank=True,
        help_text="View/module name, if available.",
    )
    http_method = models.CharField(
        "http method",
        max_length=10,
        null=True,
        blank=True,
        help_text="HTTP method, if applicable.",
    )
    path_template = models.CharField(
        "path template",
        max_length=255,
        null=True,
        blank=True,
        help_text="Sanitized, parameterized path template. No raw query strings.",
    )
    status_code = models.IntegerField(
        "status code",
        null=True,
        blank=True,
        help_text="HTTP status code, if applicable.",
    )

    actor_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="application_error_events",
        help_text="Authenticated actor at time of error, if any.",
    )
    actor_role = models.CharField(
        "actor role",
        max_length=50,
        null=True,
        blank=True,
        help_text="Snapshot of the actor's COMPASS role.",
    )
    actor_ip_hash = models.CharField(
        "actor ip hash",
        max_length=64,
        null=True,
        blank=True,
        help_text="HMAC hash of actor IP. Raw IP is never stored.",
    )
    user_agent_hash = models.CharField(
        "user agent hash",
        max_length=64,
        null=True,
        blank=True,
        help_text="HMAC hash of User-Agent. Raw UA is never stored.",
    )

    related_reference_code = models.CharField(
        "related reference code",
        max_length=50,
        null=True,
        blank=True,
        help_text="Safe workflow reference code, e.g. DOC-AY2526-000001.",
    )
    related_object_type = models.CharField(
        "related object type",
        max_length=100,
        null=True,
        blank=True,
        help_text="Safe model label, e.g. counseling.StudentSession.",
    )
    related_object_id = models.CharField(
        "related object id",
        max_length=100,
        null=True,
        blank=True,
        help_text="Safe internal reference only. No sensitive identifiers.",
    )

    exception_class = models.CharField(
        "exception class",
        max_length=255,
        null=True,
        blank=True,
        help_text="Exception class name only. Never raw exception text.",
    )
    safe_message = models.CharField(
        "safe message",
        max_length=255,
        help_text="Generic, bounded, privacy-safe message selected by category.",
    )
    redacted_stack_trace = models.TextField(
        "redacted stack trace",
        null=True,
        blank=True,
        help_text=(
            "Environment-gated. Must be NULL in production unless explicitly "
            "approved. Never shown to normal users."
        ),
    )
    metadata_json = models.JSONField(
        "metadata",
        default=dict,
        help_text="Sanitized safe JSON only. No secrets/private content.",
    )

    is_resolved = models.BooleanField(
        "is resolved",
        default=False,
        help_text="Whether an IT Admin has marked this error resolved.",
    )
    resolved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="resolved_application_error_events",
        help_text="IT Admin who resolved this error.",
    )
    resolved_at = models.DateTimeField(
        "resolved at",
        null=True,
        blank=True,
    )
    resolution_note = models.CharField(
        "resolution note",
        max_length=255,
        blank=True,
        help_text="Bounded, sanitized resolution note. No sensitive content.",
    )

    class Meta:
        verbose_name = "application error event"
        verbose_name_plural = "application error events"
        indexes = [
            models.Index(fields=["error_id"]),
            models.Index(fields=["created_at"]),
            models.Index(fields=["severity"]),
            models.Index(fields=["category"]),
            models.Index(fields=["environment"]),
            models.Index(fields=["is_resolved"]),
            models.Index(fields=["app_label"]),
            models.Index(fields=["related_reference_code"]),
        ]
        ordering = ["-created_at"]

    def __str__(self):
        return self.error_id


class ErrorEventCounter(TimestampedModel):
    """Yearly counter for safe Error ID generation.

    Uses row-level locking for race safety. Lives in apps.system to avoid
    cross-app dependencies. Period key is a calendar year (e.g. '2026').
    """

    period_key = models.CharField(
        "period key",
        max_length=10,
        unique=True,
        help_text="Calendar year, e.g. '2026'.",
    )
    last_sequence = models.PositiveIntegerField(
        "last sequence",
        default=0,
    )

    class Meta:
        verbose_name = "error event counter"
        verbose_name_plural = "error event counters"

    def __str__(self):
        return f"{self.period_key} → {self.last_sequence}"


class MaintenanceWindow(TimestampedModel):
    """Tracks IT Admin-controlled maintenance windows.

    The versioned maintenance middleware enforces an active window only when
    the environment explicitly enables it.  Development can keep notices
    observational while staging and production use the reviewed route matrix.
    """

    status = models.CharField(
        "status",
        max_length=20,
        choices=MaintenanceStatusChoices.choices,
        default=MaintenanceStatusChoices.SCHEDULED,
        db_index=True,
    )
    starts_at = models.DateTimeField("starts at", db_index=True)
    ends_at = models.DateTimeField("ends at", db_index=True)
    safe_public_message = models.TextField(
        "safe public message",
        blank=True,
        help_text="Sanitized public message shown to users during maintenance.",
    )
    internal_reason_code = models.CharField(
        "internal reason code",
        max_length=100,
        blank=True,
        help_text="Sanitized code describing internal reason, e.g. DB_UPGRADE.",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_maintenance_windows",
        help_text="Admin user who scheduled the maintenance.",
    )
    activated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="activated_maintenance_windows",
        help_text="Admin user who activated the maintenance.",
    )
    deactivated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="deactivated_maintenance_windows",
        help_text="Admin user who completed/deactivated the maintenance.",
    )

    class Meta:
        verbose_name = "maintenance window"
        verbose_name_plural = "maintenance windows"
        ordering = ["-starts_at"]
        constraints = [
            models.CheckConstraint(
                condition=Q(ends_at__gt=F("starts_at")),
                name="maintenance_window_ends_after_starts",
            ),
            models.UniqueConstraint(
                condition=Q(status=MaintenanceStatusChoices.ACTIVE),
                fields=("status",),
                name="maintenance_window_one_active",
            ),
        ]

    def clean(self):
        super().clean()
        from apps.system.maintenance_services import (
            clean_internal_reason_code,
            clean_public_maintenance_message,
        )

        self.safe_public_message = clean_public_maintenance_message(self.safe_public_message)
        self.internal_reason_code = clean_internal_reason_code(self.internal_reason_code)
        if self.starts_at and self.ends_at and self.ends_at <= self.starts_at:
            raise ValidationError({"ends_at": "Maintenance ends_at must be after starts_at."})

    @property
    def is_expired(self) -> bool:
        """Whether an active window has reached its derived expiry boundary."""
        return (
            self.status == MaintenanceStatusChoices.ACTIVE
            and timezone.now() >= self.ends_at
        )

    def __str__(self):
        return f"Maintenance: {self.status} ({self.starts_at} - {self.ends_at})"
