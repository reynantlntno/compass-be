# Project: COMPASS
# File: apps/system/maintenance_services.py
# Module: apps.system
# Purpose: Service functions for managing the maintenance mode lifecycle
# Domain boundary and service policy.
# Notes:
#   - Excludes sensitive details from audit records and public metadata.
#   - Only IT Admin actions are allowed (enforced in views and services).

import re
from datetime import timedelta
from math import ceil

from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.system.models import MaintenanceWindow
from apps.system.choices import MaintenanceStatusChoices
from apps.system.policies import can_bypass_maintenance, can_manage_maintenance_mode
from apps.audit.services import audit_log
from apps.common.exceptions import (
    DependencyFailureError,
    NotFoundError,
    PermissionDeniedError as PermissionDenied,
    StaleStateError,
    ValidationError,
)
from apps.system.commands import MaintenanceScheduleCommand, MaintenanceTransitionCommand
from apps.governance.runtime_config import resolve_runtime_setting


DEFAULT_PUBLIC_MAINTENANCE_MESSAGE = (
    "COMPASS has a scheduled maintenance window. Please check official office channels for updates."
)
PUBLIC_MESSAGE_MAX_LENGTH = 240
REASON_CODE_MAX_LENGTH = 64
SAFE_REASON_CODE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{1,63}$")
CONTROL_WHITESPACE_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+")
HTML_TAG_RE = re.compile(r"<[^>]+>")
UNSAFE_PUBLIC_MESSAGE_PATTERNS = [
    re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://", re.IGNORECASE),
    re.compile(r"\bwww\.", re.IGNORECASE),
    re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"(?<!\w)/(?:protected_media|private_media|media|var|etc|home|users|tmp|mnt|srv)\S*", re.IGNORECASE),
    re.compile(r"[A-Za-z]:\\"),
    re.compile(
        r"\b(password|passwd|secret|token|api[_ -]?key|vault|jwt|credential|signed[_ -]?url|"
        r"smtp|s3|minio|bucket|object[_ -]?key|access[_ -]?key|secret[_ -]?key|daily)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(student[_ -]?number|control[_ -]?number|student[_ -]?id|control[_ -]?no)\b", re.IGNORECASE),
    re.compile(r"(?:\d[- ]*){6,}"),
    re.compile(
        r"\b(counseling[_ -]?notes?|referral[_ -]?reasons?|"
        r"assessment[_ -]?interpretations?|support[_ -]?messages?|health[_ -]?narrative|"
        r"family[_ -]?narrative|financial[_ -]?narrative)\b",
        re.IGNORECASE,
    ),
]
UNSAFE_REASON_TERMS = {
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "vault",
    "jwt",
    "credential",
    "student_number",
    "control_number",
    "counseling_notes",
    "referral_reason",
    "assessment_interpretation",
    "support_message",
}

MAINTENANCE_ROUTE_MATRIX_VERSION = "MAINT-001"
MAINTENANCE_ENFORCEMENT_INACTIVE_REASON = "MAINTENANCE_ENFORCEMENT_INACTIVE"
PUBLIC_SCHEDULED_MAINTENANCE_HORIZON = timedelta(days=14)

# This matrix is intentionally route-name based rather than path-pattern
# based. It is reviewed as a small explicit API contract and never derives
# access from a broad URL prefix. Health liveness remains public; future
# API routes must be added here explicitly when their maintenance behavior is
# defined.
MAINTENANCE_PUBLIC_ROUTE_NAMES = frozenset(
    {
        "health-check",
        "system_public_status",
        "api:v1:system_public_status",
        "public_status",
        "compass-api-v1:public_status",
    }
)
MAINTENANCE_IT_BYPASS_ROUTE_NAMES = frozenset()


def _normalize_public_text(value: str) -> str:
    value = CONTROL_WHITESPACE_RE.sub(" ", str(value or ""))
    return " ".join(value.split())


def clean_public_maintenance_message(value: str) -> str:
    """Return a bounded safe public maintenance message or raise safely."""
    normalized = _normalize_public_text(value)
    if not normalized:
        return DEFAULT_PUBLIC_MAINTENANCE_MESSAGE
    if len(normalized) > PUBLIC_MESSAGE_MAX_LENGTH:
        raise ValidationError("Maintenance public message failed safety validation.")
    if HTML_TAG_RE.search(normalized):
        raise ValidationError("Maintenance public message failed safety validation.")
    if any(pattern.search(normalized) for pattern in UNSAFE_PUBLIC_MESSAGE_PATTERNS):
        raise ValidationError("Maintenance public message failed safety validation.")
    return normalized


def clean_internal_reason_code(value: str) -> str:
    """Return a safe short reason code or raise safely."""
    normalized = str(value or "").strip()
    if not normalized:
        return ""
    if len(normalized) > REASON_CODE_MAX_LENGTH or not SAFE_REASON_CODE_RE.fullmatch(normalized):
        raise ValidationError("Maintenance reason code failed safety validation.")
    lowered = normalized.lower()
    if any(term in lowered for term in UNSAFE_REASON_TERMS):
        raise ValidationError("Maintenance reason code failed safety validation.")
    return normalized


def _safe_reason_code_for_audit(value: str) -> str:
    try:
        return clean_internal_reason_code(value)
    except ValidationError:
        return "invalid_reason_code"


def _ensure_maintenance_manager(actor) -> None:
    if not can_manage_maintenance_mode(actor):
        raise PermissionDenied("You are not authorized to manage maintenance windows.")


def _resolved_route_identity(request) -> tuple[str, str]:
    """Read only Django's already-resolved route metadata.

    This deliberately does not inspect path text, query strings, request
    bodies, headers, credentials, or session state.  The returned identities
    are descriptive only while enforcement remains disabled.
    """
    resolver_match = getattr(request, "resolver_match", None)
    if resolver_match is None:
        return "unresolved", "unresolved"

    route_name = (
        getattr(resolver_match, "view_name", None)
        or getattr(resolver_match, "url_name", None)
        or "unresolved"
    )
    callback = getattr(resolver_match, "func", None)
    view_class = getattr(callback, "view_class", None)
    if view_class is not None:
        route_class = _qualified_route_class(view_class)
    elif callback is not None:
        route_class = _qualified_route_class(callback)
    else:
        route_class = "unresolved"
    return str(route_name), route_class


def _qualified_route_class(value) -> str:
    module = getattr(value, "__module__", None)
    qualname = getattr(value, "__qualname__", None)
    if module and qualname:
        return f"{module}.{qualname}"
    return "unresolved"


def evaluate_maintenance_request(request) -> dict:
    """Classify a request against the reviewed maintenance route matrix.

    This service has no side effects.  The middleware is responsible for the
    response and for fail-closed auditing of an IT bypass.  Keeping evaluation
    pure makes the route matrix testable without creating audit records.
    """
    route_name, route_class = _resolved_route_identity(request)
    enabled = bool(
        resolve_runtime_setting(
            "technical.configuration",
            "MAINTENANCE_ENFORCEMENT_ENABLED",
        )
    )
    base = {
        "enabled": enabled,
        "route_class": route_class,
        "route_name": route_name,
        "route_matrix_version": MAINTENANCE_ROUTE_MATRIX_VERSION,
        "window": None,
        "retry_after_seconds": None,
        "response_format": "none",
    }
    if not enabled:
        return {
            **base,
            "action": "PASS",
            "reason_code": MAINTENANCE_ENFORCEMENT_INACTIVE_REASON,
        }

    window = get_active_maintenance_window()
    if window is None:
        return {
            **base,
            "action": "PASS",
            "reason_code": "MAINTENANCE_NO_ACTIVE_WINDOW",
        }

    if route_name in MAINTENANCE_PUBLIC_ROUTE_NAMES:
        return {
            **base,
            "action": "PASS",
            "reason_code": "MAINTENANCE_PUBLIC_ROUTE_ALLOWED",
            "window": window,
        }

    if route_name in MAINTENANCE_IT_BYPASS_ROUTE_NAMES and can_bypass_maintenance(
        getattr(request, "user", None)
    ):
        return {
            **base,
            "action": "BYPASS",
            "reason_code": "MAINTENANCE_IT_BYPASS_ALLOWED",
            "window": window,
        }

    retry_after_seconds = max(
        1,
        ceil((window.ends_at - timezone.now()).total_seconds()),
    )
    return {
        **base,
        "action": "BLOCK",
        "reason_code": "MAINTENANCE_ACTIVE",
        "window": window,
        "retry_after_seconds": retry_after_seconds,
        "response_format": "json",
    }


def audit_maintenance_bypass(request, decision: dict) -> bool:
    """Audit a narrowly approved IT bypass without retaining request content.

    A missing audit record means the caller must not receive the bypass.  Only
    route identity, method, and the immutable window identifier are recorded;
    no path, parameters, headers, or session data are copied into the audit
    event.
    """
    window = decision.get("window")
    if decision.get("action") != "BYPASS" or window is None:
        return False
    entry = audit_log(
        action_type="MAINTENANCE_BYPASS_GRANTED",
        event_category="SYSTEM",
        severity="WARNING",
        target_model="system.MaintenanceWindow",
        target_object_id=str(window.pk),
        actor_user=getattr(request, "user", None),
        source_app="apps.system",
        source_view=decision.get("route_name"),
        metadata={
            "route_name": decision.get("route_name"),
            "request_method": str(getattr(request, "method", "GET") or "GET").upper(),
            "route_matrix_version": MAINTENANCE_ROUTE_MATRIX_VERSION,
        },
    )
    return entry is not None


def get_active_maintenance_window(*, include_expired: bool = False):
    """Retrieve the active maintenance notice visible to the caller.

    Expiry is derived rather than persisted. Consumers receive only a
    currently effective window unless they explicitly request expired rows.
    """
    now = timezone.now()
    active = MaintenanceWindow.objects.filter(
        status=MaintenanceStatusChoices.ACTIVE,
        starts_at__lte=now,
    )
    if not include_expired:
        active = active.filter(ends_at__gt=now)
    return active.order_by("starts_at").first()


def _public_service_status_for_window(window: MaintenanceWindow, status: str) -> dict:
    """Build the deliberately small anonymous status projection."""

    try:
        message = clean_public_maintenance_message(window.safe_public_message)
    except ValidationError as exc:
        # A malformed persisted notice must never cross the anonymous
        # boundary. Treat it as a dependency failure so the caller receives
        # the standard safe 503 envelope.
        raise DependencyFailureError(retry_after=60) from exc
    return {
        "status": status,
        "message": message,
        "starts_at": window.starts_at,
        "ends_at": window.ends_at,
    }


def public_service_status() -> dict:
    """Return the safe maintenance state available to anonymous clients.

    The query intentionally exposes no window identity, governance setting,
    actor, internal reason, or diagnostic metadata. Active maintenance takes
    precedence over an upcoming scheduled window, but only when the existing
    enforcement setting is enabled.
    """

    try:
        now = timezone.now()
        enforcement_enabled = bool(
            resolve_runtime_setting(
                "technical.configuration",
                "MAINTENANCE_ENFORCEMENT_ENABLED",
            )
        )
        if enforcement_enabled:
            active = get_active_maintenance_window()
            if active is not None:
                return _public_service_status_for_window(active, "maintenance_active")

        scheduled = MaintenanceWindow.objects.filter(
            status=MaintenanceStatusChoices.SCHEDULED,
            starts_at__gt=now,
            starts_at__lte=now + PUBLIC_SCHEDULED_MAINTENANCE_HORIZON,
        ).order_by("starts_at", "pk").first()
        if scheduled is not None:
            return _public_service_status_for_window(scheduled, "maintenance_scheduled")

        return {
            "status": "operational",
            "message": None,
            "starts_at": None,
            "ends_at": None,
        }
    except DependencyFailureError:
        raise
    except Exception as exc:
        # Query/configuration failures are intentionally indistinguishable
        # from other temporary dependency failures at the public boundary.
        raise DependencyFailureError(retry_after=60) from exc


def _schedule_maintenance(
    actor, starts_at, ends_at, safe_public_message="", internal_reason_code=""
) -> MaintenanceWindow:
    """Schedule a new maintenance window.

    Validates that:
    - ends_at is after starts_at.
    - starts_at is not in the past.
    """
    _ensure_maintenance_manager(actor)
    now = timezone.now()
    if timezone.is_naive(starts_at) or timezone.is_naive(ends_at):
        raise ValidationError("Maintenance datetimes must include a timezone.")
    if starts_at < now:
        raise ValidationError("Maintenance starts_at cannot be in the past.")
    if ends_at <= starts_at:
        raise ValidationError("Maintenance ends_at must be after starts_at.")
    safe_public_message = clean_public_maintenance_message(safe_public_message)
    internal_reason_code = clean_internal_reason_code(internal_reason_code)

    with transaction.atomic():
        window = MaintenanceWindow.objects.create(
            status=MaintenanceStatusChoices.SCHEDULED,
            starts_at=starts_at,
            ends_at=ends_at,
            safe_public_message=safe_public_message,
            internal_reason_code=internal_reason_code,
            created_by=actor,
        )

        audit_log(
            action_type="MAINTENANCE_SCHEDULED",
            event_category="SYSTEM",
            severity="INFO",
            target_model="system.MaintenanceWindow",
            target_object_id=str(window.id),
            actor_user=actor,
            metadata={
                "action": "schedule",
                "starts_at": starts_at.isoformat(),
                "ends_at": ends_at.isoformat(),
                "reason_code": internal_reason_code,
            },
        )
        return window


def _lock_current_window(window: MaintenanceWindow) -> MaintenanceWindow:
    """Refetch the authoritative row for a lifecycle transition."""
    if not getattr(window, "pk", None):
        raise ValidationError("Maintenance window could not be identified safely.")
    return MaintenanceWindow.objects.select_for_update().get(pk=window.pk)


def _require_aware_datetime(value, *, field_name: str):
    if value is None or not hasattr(value, "utcoffset") or timezone.is_naive(value):
        raise ValidationError(f"Maintenance {field_name} must include a timezone.")
    return value


def _validate_locked_window_timestamps(window: MaintenanceWindow) -> None:
    """Revalidate authoritative timestamps after acquiring the row lock."""
    _require_aware_datetime(window.starts_at, field_name="starts_at")
    _require_aware_datetime(window.ends_at, field_name="ends_at")
    if window.ends_at <= window.starts_at:
        raise ValidationError("Maintenance ends_at must be after starts_at.")


def _activation_integrity_error() -> ValidationError:
    return ValidationError(
        "Another maintenance window became active concurrently. "
        "Complete or cancel it before activating another."
    )


def _activate_maintenance(actor, window: MaintenanceWindow) -> MaintenanceWindow:
    """Transition a current, non-expired scheduled window to active.

    The caller object is intentionally never mutated.  The conditional unique
    database constraint is the final race-safety boundary; its error is
    translated into an operator-facing validation error outside the atomic
    block so the transaction remains usable.
    """
    _ensure_maintenance_manager(actor)

    try:
        with transaction.atomic():
            locked_window = _lock_current_window(window)
            _validate_locked_window_timestamps(locked_window)
            now = timezone.now()
            if locked_window.status != MaintenanceStatusChoices.SCHEDULED:
                raise ValidationError("Only scheduled maintenance windows can be activated.")
            if locked_window.ends_at <= now:
                raise ValidationError(
                    "Expired maintenance windows cannot be activated; complete or cancel them first."
                )
            active_conflict_exists = MaintenanceWindow.objects.select_for_update().filter(
                status=MaintenanceStatusChoices.ACTIVE
            ).exclude(pk=locked_window.pk).exists()
            if active_conflict_exists:
                raise ValidationError(
                    "Complete or cancel the active maintenance window before activating another."
                )

            locked_window.status = MaintenanceStatusChoices.ACTIVE
            locked_window.activated_by = actor
            locked_window.save(update_fields=["status", "activated_by", "updated_at"])

            audit_log(
                action_type="MAINTENANCE_ACTIVATED",
                event_category="SYSTEM",
                severity="WARNING",
                target_model="system.MaintenanceWindow",
                target_object_id=str(locked_window.id),
                actor_user=actor,
                metadata={
                    "action": "activate",
                    "activated_at": now.isoformat(),
                    "reason_code": _safe_reason_code_for_audit(locked_window.internal_reason_code),
                },
            )
            return locked_window
    except IntegrityError as exc:
        # Do not expose backend/index details to an operator or caller.
        raise _activation_integrity_error() from exc


def _extend_maintenance(actor, window: MaintenanceWindow, new_ends_at) -> MaintenanceWindow:
    """Extend the duration of an active maintenance window."""
    _ensure_maintenance_manager(actor)
    _require_aware_datetime(new_ends_at, field_name="ends_at")
    with transaction.atomic():
        locked_window = _lock_current_window(window)
        _validate_locked_window_timestamps(locked_window)
        now = timezone.now()
        if locked_window.status != MaintenanceStatusChoices.ACTIVE:
            raise ValidationError("Only active maintenance windows can be extended.")
        if locked_window.ends_at <= now:
            raise ValidationError(
                "Expired maintenance windows cannot be revived by extension; complete or cancel them first."
            )
        if new_ends_at <= now:
            raise ValidationError("New ends_at must be in the future.")
        if new_ends_at <= locked_window.ends_at:
            raise ValidationError("New ends_at must be later than the current database ends_at.")

        old_ends_at = locked_window.ends_at
        locked_window.ends_at = new_ends_at
        locked_window.save(update_fields=["ends_at", "updated_at"])

        audit_log(
            action_type="MAINTENANCE_EXTENDED",
            event_category="SYSTEM",
            severity="INFO",
            target_model="system.MaintenanceWindow",
            target_object_id=str(locked_window.id),
            actor_user=actor,
            metadata={
                "action": "extend",
                "old_ends_at": old_ends_at.isoformat(),
                "new_ends_at": new_ends_at.isoformat(),
            },
        )
    return locked_window

def _complete_maintenance(actor, window: MaintenanceWindow) -> MaintenanceWindow:
    """Transition an active maintenance window to completed."""
    _ensure_maintenance_manager(actor)
    with transaction.atomic():
        locked_window = _lock_current_window(window)
        _validate_locked_window_timestamps(locked_window)
        if locked_window.status != MaintenanceStatusChoices.ACTIVE:
            raise ValidationError("Only active maintenance windows can be completed.")
        now = timezone.now()
        was_expired = now >= locked_window.ends_at
        locked_window.status = MaintenanceStatusChoices.COMPLETED
        locked_window.deactivated_by = actor
        locked_window.save(update_fields=["status", "deactivated_by", "updated_at"])

        audit_log(
            action_type="MAINTENANCE_COMPLETED",
            event_category="SYSTEM",
            severity="INFO",
            target_model="system.MaintenanceWindow",
            target_object_id=str(locked_window.id),
            actor_user=actor,
            metadata={
                "action": "complete",
                "completed_at": now.isoformat(),
                "was_expired": was_expired,
            },
        )
        return locked_window


def _cancel_maintenance(actor, window: MaintenanceWindow) -> MaintenanceWindow:
    """Cancel a scheduled or active maintenance window."""
    _ensure_maintenance_manager(actor)
    with transaction.atomic():
        locked_window = _lock_current_window(window)
        _validate_locked_window_timestamps(locked_window)
        if locked_window.status not in {
            MaintenanceStatusChoices.SCHEDULED,
            MaintenanceStatusChoices.ACTIVE,
        }:
            raise ValidationError("Only scheduled or active maintenance windows can be cancelled.")
        now = timezone.now()
        old_status = locked_window.status
        was_expired = (
            old_status == MaintenanceStatusChoices.ACTIVE and now >= locked_window.ends_at
        )
        locked_window.status = MaintenanceStatusChoices.CANCELLED
        locked_window.deactivated_by = actor
        locked_window.save(update_fields=["status", "deactivated_by", "updated_at"])

        audit_log(
            action_type="MAINTENANCE_CANCELLED",
            event_category="SYSTEM",
            severity="INFO",
            target_model="system.MaintenanceWindow",
            target_object_id=str(locked_window.id),
            actor_user=actor,
            metadata={
                "action": "cancel",
                "previous_status": old_status,
                "cancelled_at": now.isoformat(),
                "was_expired": was_expired,
            },
        )
        return locked_window


# Stable-ID API command adapters. The legacy model-oriented functions above
# remain internal to this module and are never called by an API router.

def _parse_command_datetime(value: str, field_name: str):
    from django.utils.dateparse import parse_datetime

    parsed = parse_datetime(value)
    if parsed is None:
        raise ValidationError(f"Maintenance {field_name} must be a valid ISO datetime.")
    return parsed


def _locked_window_by_id(window_id: str) -> MaintenanceWindow:
    try:
        return MaintenanceWindow.objects.select_for_update().get(pk=window_id)
    except MaintenanceWindow.DoesNotExist as exc:
        raise NotFoundError() from exc


def _assert_window_expected_updated_at(window: MaintenanceWindow, expected_updated_at: str | None) -> None:
    if not expected_updated_at:
        return
    from django.utils.dateparse import parse_datetime

    expected = parse_datetime(expected_updated_at)
    if expected is None or window.updated_at != expected:
        raise StaleStateError()


@transaction.atomic
def schedule_maintenance_command(actor, command: MaintenanceScheduleCommand) -> MaintenanceWindow:
    return _schedule_maintenance(
        actor,
        _parse_command_datetime(command.starts_at, "starts_at"),
        _parse_command_datetime(command.ends_at, "ends_at"),
        command.public_message,
        command.reason_code,
    )


@transaction.atomic
def activate_maintenance_by_id(actor, command: MaintenanceTransitionCommand) -> MaintenanceWindow:
    window = _locked_window_by_id(command.window_id)
    _assert_window_expected_updated_at(window, command.expected_updated_at)
    return _activate_maintenance(actor, window)


@transaction.atomic
def extend_maintenance_by_id(actor, command: MaintenanceTransitionCommand) -> MaintenanceWindow:
    if not command.ends_at:
        raise ValidationError("ends_at is required when extending maintenance.")
    window = _locked_window_by_id(command.window_id)
    _assert_window_expected_updated_at(window, command.expected_updated_at)
    return _extend_maintenance(actor, window, _parse_command_datetime(command.ends_at, "ends_at"))


@transaction.atomic
def complete_maintenance_by_id(actor, command: MaintenanceTransitionCommand) -> MaintenanceWindow:
    window = _locked_window_by_id(command.window_id)
    _assert_window_expected_updated_at(window, command.expected_updated_at)
    return _complete_maintenance(actor, window)


@transaction.atomic
def cancel_maintenance_by_id(actor, command: MaintenanceTransitionCommand) -> MaintenanceWindow:
    window = _locked_window_by_id(command.window_id)
    _assert_window_expected_updated_at(window, command.expected_updated_at)
    return _cancel_maintenance(actor, window)
