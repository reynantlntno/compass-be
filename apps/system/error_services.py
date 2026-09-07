# Project: COMPASS
# File: apps/system/error_services.py
# Module: apps.system
# Purpose: Application error event capture, sanitization, and Error ID generation
# Domain boundary and service policy.
# Notes:
#   PRIVACY/SECURITY:
#     - Never store raw request bodies, raw POST, raw query strings, raw IP,
#       raw User-Agent, raw exception messages, tokens, secrets, signed URLs,
#       Daily/JWT, counseling notes, referral reasons,
#       assessment interpretations, support messages, or health/family/financial
#       narratives.
#     - Stack traces are not captured or shown in any environment in this
#       diagnostic slice.
#     - Capture failures must not leak raw exception text.

import hashlib
import hmac
import json
import logging
import re
from typing import Any, Dict, Optional

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.system.choices import (
    ErrorCategoryChoices,
    ErrorEnvironmentChoices,
    ErrorSeverityChoices,
)
from apps.system.models import ApplicationErrorEvent, ErrorEventCounter
from apps.account_security.network import get_client_ip_from_headers
from apps.system.readiness_services import release_identity
from apps.common.exceptions import NotFoundError, PermissionDeniedError, StaleStateError
from apps.system.policies import (
    can_reopen_application_error_event,
    can_resolve_application_error_event,
)

logger = logging.getLogger("apps.system.error_services")

# ---------------------------------------------------------------------------
# Sensitive-key denylist for error metadata sanitization
# ---------------------------------------------------------------------------
ERROR_SENSITIVE_KEYS = {
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "encryption_key",
    "otp",
    "jwt",
    "credential",
    "smtp_password",
    "session_key",
    "authorization",
    "auth",
    "cookie",
    "signature",
    "salt",
    "daily",
    "request_body",
    "raw_body",
    "post_data",
    "query_string",
    "counseling_notes",
    "referral_reason",
    "assessment_interpretation",
    "support_message",
    "student_message",
    "triage_notes",
    "case_details",
    "health_narrative",
    "family_narrative",
    "financial_narrative",
    "inventory_answers",
    "student_number",
    "control_number",
    "email",
    "ip_address",
    "user_agent",
    "vault",
    "storage_key",
    "private_url",
    "signed_url",
    "reset_link",
}

# Sensitive substrings to redact in string values (case-insensitive).
ERROR_SENSITIVE_VALUE_KEYWORDS = {
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "encryption_key",
    "otp",
    "jwt",
    "credential",
    "smtp_password",
    "session_key",
    "authorization",
    "auth",
    "cookie",
    "signature",
    "salt",
    "daily",
    "request_body",
    "raw_body",
    "post_data",
    "counseling_notes",
    "counseling notes",
    "counseling note",
    "referral_reason",
    "referral reason",
    "referral reasons",
    "assessment_interpretation",
    "assessment interpretation",
    "support_message",
    "support message",
    "support request",
    "case_details",
    "case details",
    "health_narrative",
    "health narrative",
    "family_narrative",
    "family narrative",
    "financial_narrative",
    "financial narrative",
    "raw inventory answers",
    "student_number",
    "student number",
    "control_number",
    "control number",
    "vault",
    "storage_key",
    "storage key",
    "private_url",
    "private url",
    "signed_url",
    "signed url",
    "reset_link",
    "reset link",
    "csrfmiddlewaretoken",
}

JWT_REGEX = re.compile(r"ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+")
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ERROR_ID_REGEX = re.compile(r"\AERR-[0-9]{4}-[0-9]{6}\Z")
CORRELATION_ID_REGEX = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,99}\Z")

MAX_STRING_LENGTH = 1024
MAX_METADATA_SIZE_BYTES = 65536  # 64KB
MAX_SAFE_TEXT_LENGTH = 255

SAFE_REFERENCE_CODE_REGEX = re.compile(r"^[A-Z][A-Z0-9]{1,15}-[A-Z0-9][A-Z0-9-]{0,48}$")
SAFE_MODEL_LABEL_REGEX = re.compile(r"^[a-z_][a-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*$")
SAFE_INTERNAL_ID_REGEX = re.compile(
    r"^(?:[1-9][0-9]{0,18}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$"
)


def is_safe_error_id(value: Optional[str]) -> bool:
    """Return whether a value is a server-generated, user-safe Error ID."""
    return bool(isinstance(value, str) and ERROR_ID_REGEX.fullmatch(value))


def _safe_correlation_id(value: Optional[str]) -> Optional[str]:
    """Keep only bounded, header-safe correlation identifiers."""
    if value is None:
        return None
    candidate = str(value).strip()
    if not candidate or len(candidate) > 100:
        return None
    if not CORRELATION_ID_REGEX.fullmatch(candidate):
        return None
    return candidate

# Category -> safe generic message mapping.
SAFE_MESSAGES = {
    ErrorCategoryChoices.VALIDATION: "The request could not be processed.",
    ErrorCategoryChoices.PERMISSION: "You are not authorized to perform this action.",
    ErrorCategoryChoices.EXTERNAL_SERVICE: "An external service could not be reached.",
    ErrorCategoryChoices.BACKGROUND_JOB: "A background task could not be completed.",
    ErrorCategoryChoices.DATABASE: "A database error occurred.",
    ErrorCategoryChoices.SECURITY: "A security-related error occurred.",
    ErrorCategoryChoices.UNKNOWN: "An unexpected error occurred.",
}


def _hash_value(value: str) -> Optional[str]:
    """HMAC-SHA256 hash for privacy-sensitive values (IP, User-Agent)."""
    if not value:
        return None
    key = settings.AUDIT_HASH_SECRET.encode("utf-8")
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def _redact_string(value: str) -> str:
    """Redact sensitive substrings within a string value."""
    if not isinstance(value, str):
        return value
    val_lower = value.lower()

    # JWT-like tokens
    if JWT_REGEX.search(value):
        return "[REDACTED]"
    # Email addresses
    if EMAIL_REGEX.search(value):
        return "[REDACTED]"
    # Raw IPv4 addresses
    if IPV4_REGEX.search(value):
        return "[REDACTED]"
    # HTTP URLs with sensitive parameters
    if "http" in val_lower and any(
        param in val_lower
        for param in ["signature", "awsaccesskeyid", "expires", "token", "jwt", "secret", "key"]
    ):
        return "[REDACTED]"
    # Daily links with credentials
    if "daily" in val_lower and any(kw in val_lower for kw in ["jwt", "token", "secret", "room"]):
        return "[REDACTED]"
    # Request body / credential markers
    if any(term in val_lower for term in ["csrfmiddlewaretoken", "password=", 'password"', 'secret"', 'token"']):
        return "[REDACTED]"
    # General sensitive value keywords
    if any(keyword in val_lower for keyword in ERROR_SENSITIVE_VALUE_KEYWORDS):
        return "[REDACTED]"

    if len(value) > MAX_STRING_LENGTH:
        return value[:MAX_STRING_LENGTH] + "...[TRUNCATED]"
    return value


def clean_safe_text(
    value: Optional[str],
    *,
    max_length: int = MAX_SAFE_TEXT_LENGTH,
    redacted_value: str = "[REDACTED]",
) -> str:
    """Return bounded safe text, redacting sensitive content."""
    if not value or not isinstance(value, str):
        return ""
    cleaned = value.strip()[:max_length]
    if not cleaned:
        return ""
    redacted = _redact_string(cleaned)
    if redacted == "[REDACTED]":
        return redacted_value
    return redacted[:max_length]


def _resolve_safe_message(category: str, safe_message: Optional[str]) -> str:
    """Prefer category defaults unless a caller-provided message is safe."""
    fallback = SAFE_MESSAGES.get(category, SAFE_MESSAGES[ErrorCategoryChoices.UNKNOWN])
    if not safe_message:
        return fallback
    cleaned = clean_safe_text(safe_message, redacted_value="")
    if not cleaned or cleaned == "[REDACTED]":
        return fallback
    return cleaned


def _safe_reference_code(value: Optional[str]) -> Optional[str]:
    """Keep only reference-code-like values; reject sensitive or narrative text."""
    if not value:
        return None
    candidate = str(value).strip()[:50]
    if _redact_string(candidate) == "[REDACTED]":
        return None
    if SAFE_REFERENCE_CODE_REGEX.match(candidate):
        return candidate
    return None


def _safe_model_label(value: Optional[str]) -> Optional[str]:
    """Keep only app.Model-style labels."""
    if not value:
        return None
    candidate = str(value).strip()[:100]
    if _redact_string(candidate) == "[REDACTED]":
        return None
    if SAFE_MODEL_LABEL_REGEX.match(candidate):
        return candidate
    return None


def _safe_internal_id(value: Optional[str]) -> Optional[str]:
    """Keep only integer or UUID identifiers."""
    if value is None:
        return None
    candidate = str(value).strip()[:100]
    if _redact_string(candidate) == "[REDACTED]":
        return None
    if SAFE_INTERNAL_ID_REGEX.match(candidate):
        return candidate
    return None


def sanitize_error_metadata(metadata: Any) -> Any:
    """Recursively sanitize error metadata.

    Redacts sensitive keys, sensitive string values, JWTs, emails, raw IPs,
    signed URLs, Daily credentials, and truncates long strings. Non-serializable
    objects fall back to a safe placeholder (never raw str(obj)).
    """
    if isinstance(metadata, dict):
        sanitized = {}
        for k, v in metadata.items():
            k_lower = str(k).lower()
            if any(sensitive in k_lower for sensitive in ERROR_SENSITIVE_KEYS):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_error_metadata(v)
        return sanitized
    if isinstance(metadata, (list, tuple)):
        return [sanitize_error_metadata(item) for item in metadata]
    if isinstance(metadata, str):
        return _redact_string(metadata)
    if isinstance(metadata, (int, float, bool, type(None))):
        return metadata
    # Non-serializable fallback: never leak raw str(obj).
    return "[NON_SERIALIZABLE]"


def _prepare_safe_metadata(metadata: Optional[Dict]) -> Dict:
    """Sanitize and size-bound metadata for storage."""
    if not metadata:
        return {}
    try:
        sanitized = sanitize_error_metadata(metadata)
        json_str = json.dumps(sanitized, default=str)
        if len(json_str.encode("utf-8")) > MAX_METADATA_SIZE_BYTES:
            return {"error": "Metadata exceeded maximum allowed size", "truncated": True}
        return sanitized
    except Exception:
        # Never leak raw exception text.
        return {"error": "Failed to sanitize metadata"}


def redact_exception_metadata(exc: Optional[BaseException]) -> Dict:
    """Build a safe metadata dict from an exception.

    Stores only the exception class name. Never stores raw exception text.
    """
    if exc is None:
        return {}
    return {
        "exception_class": type(exc).__name__,
    }


def _resolve_environment() -> str:
    """Resolve the current environment label from settings."""
    env = getattr(settings, "COMPASS_ENVIRONMENT", None)
    if env:
        return env
    if getattr(settings, "DEBUG", False):
        return ErrorEnvironmentChoices.DEVELOPMENT
    return ErrorEnvironmentChoices.PRODUCTION


def _capture_stack_trace(exc: Optional[BaseException]) -> Optional[str]:
    """Stack traces remain disabled in all environments."""
    return None


def generate_error_id() -> str:
    """Generate a unique, race-safe Error ID in the format ERR-YYYY-000001.

    Uses a transactional yearly counter with row-level locking.
    """
    year = str(timezone.now().year)
    with transaction.atomic():
        counter = (
            ErrorEventCounter.objects
            .select_for_update()
            .filter(period_key=year)
            .first()
        )
        if counter is None:
            try:
                with transaction.atomic():
                    ErrorEventCounter.objects.create(
                        period_key=year,
                        last_sequence=0,
                    )
            except IntegrityError:
                logger.debug(
                    "Concurrent ErrorEventCounter creation for %s.",
                    year,
                )
            counter = (
                ErrorEventCounter.objects
                .select_for_update()
                .get(period_key=year)
            )
        counter.last_sequence += 1
        counter.save(update_fields=["last_sequence", "updated_at"])
        sequence = counter.last_sequence

    return f"ERR-{year}-{sequence:06d}"


def _safe_path_template(request) -> Optional[str]:
    """Return a sanitized path template without raw query strings."""
    if request is None:
        return None
    try:
        resolver_match = getattr(request, "resolver_match", None)
        if resolver_match and getattr(resolver_match, "route", None):
            return resolver_match.route[:255]
        # Do not fall back to the concrete request path: it may contain a
        # token, record reference, student identifier, or other route value.
        # A missing route pattern is safer than retaining that value.
        return None
    except Exception:
        return None


def _safe_actor_snapshot(actor_user) -> Dict:
    """Return a safe actor snapshot (role only). No email/student number."""
    snapshot = {}
    if actor_user and getattr(actor_user, "is_authenticated", False):
        snapshot["actor_role"] = getattr(actor_user, "role", None)
    return snapshot


def capture_application_error_event(
    *,
    category: str = ErrorCategoryChoices.UNKNOWN,
    severity: str = ErrorSeverityChoices.ERROR,
    exception: Optional[BaseException] = None,
    request=None,
    actor_user=None,
    related_reference_code: Optional[str] = None,
    related_object_type: Optional[str] = None,
    related_object_id: Optional[str] = None,
    metadata: Optional[Dict] = None,
    app_label: Optional[str] = None,
    status_code: Optional[int] = None,
    safe_message: Optional[str] = None,
) -> Optional[ApplicationErrorEvent]:
    """Capture an application error event with redacted, safe metadata.

    Never stores raw request bodies, raw POST, raw query strings, raw IP,
    raw User-Agent, raw exception text, or stack traces.
    Returns the created event, or None if capture failed.
    """
    try:
        environment = _resolve_environment()
        safe_meta = _prepare_safe_metadata(metadata or {})
        exc_meta = redact_exception_metadata(exception)
        if exc_meta:
            safe_meta.update(exc_meta)

        actor_snapshot = _safe_actor_snapshot(actor_user)
        actor_role = actor_snapshot.get("actor_role")

        ip_hash = None
        ua_hash = None
        http_method = None
        path_template = None
        route_name = None
        view_name = None
        request_id = None
        trace_id = None

        if request is not None:
            request_meta = getattr(request, "META", {}) or {}
            http_method = (getattr(request, "method", None) or "")[:10] or None
            path_template = _safe_path_template(request)
            resolver_match = getattr(request, "resolver_match", None)
            if resolver_match:
                route_name = (getattr(resolver_match, "url_name", None) or "")[:255] or None
                view_name = (getattr(resolver_match, "view_name", None) or "")[:255] or None
            # Correlation is assigned by the API boundary middleware.  The
            # server-owned request ID is authoritative; only a validated
            # trace ID may be propagated from an inbound header.
            request_id = _safe_correlation_id(
                getattr(request, "_compass_request_id", None)
            )
            trace_id = _safe_correlation_id(
                getattr(request, "_compass_trace_id", None)
            )
            # Hash IP and User-Agent. Never store raw values.
            ip_address = get_client_ip_from_headers(getattr(request, "META", {}) or {}) or None
            if ip_address:
                ip_hash = _hash_value(ip_address)
            user_agent = request_meta.get("HTTP_USER_AGENT")
            if user_agent:
                ua_hash = _hash_value(user_agent)

        message = _resolve_safe_message(category, safe_message)
        deployment_identity = release_identity()

        event = ApplicationErrorEvent.objects.create(
            error_id=generate_error_id(),
            trace_id=trace_id,
            request_id=request_id,
            severity=severity,
            category=category,
            environment=environment,
            release_version=deployment_identity["version"],
            build_id=deployment_identity["build_id"],
            app_label=app_label,
            route_name=route_name,
            view_name=view_name,
            http_method=http_method,
            path_template=path_template,
            status_code=status_code,
            actor_user=actor_user if (actor_user and getattr(actor_user, "is_authenticated", False)) else None,
            actor_role=actor_role,
            actor_ip_hash=ip_hash,
            user_agent_hash=ua_hash,
            related_reference_code=_safe_reference_code(related_reference_code),
            related_object_type=_safe_model_label(related_object_type),
            related_object_id=_safe_internal_id(related_object_id),
            exception_class=type(exception).__name__ if exception else None,
            safe_message=message[:255],
            redacted_stack_trace=_capture_stack_trace(exception),
            metadata_json=safe_meta,
        )
        return event
    except Exception:
        # Never leak raw exception text. Use safe logging.
        logger.warning(
            "application_error_event_capture_failed",
            extra={"reason_code": "capture_exception"},
        )
        return None


def capture_external_service_failure_event(
    *,
    service_name: str,
    exception: Optional[BaseException] = None,
    actor_user=None,
    related_reference_code: Optional[str] = None,
    metadata: Optional[Dict] = None,
    safe_message: Optional[str] = None,
) -> Optional[ApplicationErrorEvent]:
    """Capture an external-service failure with safe metadata only."""
    safe_meta = dict(metadata or {})
    # Never store the service response body or credentials.
    safe_meta["service_name"] = service_name
    return capture_application_error_event(
        category=ErrorCategoryChoices.EXTERNAL_SERVICE,
        severity=ErrorSeverityChoices.ERROR,
        exception=exception,
        actor_user=actor_user,
        related_reference_code=related_reference_code,
        metadata=safe_meta,
        safe_message=safe_message or "An external service could not be reached.",
    )


def capture_background_job_failure_event(
    *,
    job_name: str,
    exception: Optional[BaseException] = None,
    actor_user=None,
    related_reference_code: Optional[str] = None,
    metadata: Optional[Dict] = None,
    safe_message: Optional[str] = None,
) -> Optional[ApplicationErrorEvent]:
    """Capture a background-job failure with safe metadata only."""
    safe_meta = dict(metadata or {})
    safe_meta["job_name"] = job_name
    return capture_application_error_event(
        category=ErrorCategoryChoices.BACKGROUND_JOB,
        severity=ErrorSeverityChoices.ERROR,
        exception=exception,
        actor_user=actor_user,
        related_reference_code=related_reference_code,
        metadata=safe_meta,
        safe_message=safe_message or "A background task could not be completed.",
    )


def _mark_application_error_resolved(
    *,
    actor,
    event: ApplicationErrorEvent,
    resolution_note: str = "",
) -> ApplicationErrorEvent:
    """Mark an error event resolved. IT Admin only (enforced by policy caller)."""
    from apps.audit.services import audit_log

    event.is_resolved = True
    event.resolved_by = actor
    event.resolved_at = timezone.now()
    event.resolution_note = clean_safe_text(
        resolution_note,
        redacted_value="[NOTE REDACTED]",
    )
    event.save(update_fields=[
        "is_resolved",
        "resolved_by",
        "resolved_at",
        "resolution_note",
        "updated_at",
    ])

    audit_log(
        action_type="application_error_resolved",
        event_category="WORKFLOW",
        target_model="system.ApplicationErrorEvent",
        target_object_id=str(event.id),
        actor_user=actor,
        source_app="system",
        reference_code=event.error_id,
        metadata={
            "error_id": event.error_id,
            "resolution_note_length": len(event.resolution_note or ""),
        },
    )
    return event


def _reopen_application_error_event(
    *,
    actor,
    event: ApplicationErrorEvent,
    note: str = "",
) -> ApplicationErrorEvent:
    """Reopen an error event. IT Admin only (enforced by policy caller)."""
    from apps.audit.services import audit_log

    event.is_resolved = False
    event.resolved_by = actor
    event.resolved_at = timezone.now()
    event.resolution_note = clean_safe_text(
        note,
        redacted_value="[NOTE REDACTED]",
    )
    event.save(update_fields=[
        "is_resolved",
        "resolved_by",
        "resolved_at",
        "resolution_note",
        "updated_at",
    ])

    audit_log(
        action_type="application_error_reopened",
        event_category="WORKFLOW",
        target_model="system.ApplicationErrorEvent",
        target_object_id=str(event.id),
        actor_user=actor,
        source_app="system",
        reference_code=event.error_id,
        metadata={
            "error_id": event.error_id,
            "note_length": len(event.resolution_note or ""),
        },
    )
    return event


def _assert_error_expected_updated_at(event, expected_updated_at: str | None) -> None:
    if not expected_updated_at:
        return
    from django.utils.dateparse import parse_datetime

    expected = parse_datetime(expected_updated_at)
    if expected is None or event.updated_at != expected:
        raise StaleStateError()


@transaction.atomic
def resolve_application_error_by_id(*, actor, error_id: str, note: str = "", expected_updated_at: str | None = None):
    if not can_resolve_application_error_event(actor, None):
        raise PermissionDeniedError()
    try:
        event = ApplicationErrorEvent.objects.select_for_update().get(error_id=error_id)
    except ApplicationErrorEvent.DoesNotExist as exc:
        raise NotFoundError() from exc
    _assert_error_expected_updated_at(event, expected_updated_at)
    return _mark_application_error_resolved(actor=actor, event=event, resolution_note=note)


@transaction.atomic
def reopen_application_error_by_id(*, actor, error_id: str, note: str = "", expected_updated_at: str | None = None):
    if not can_reopen_application_error_event(actor, None):
        raise PermissionDeniedError()
    try:
        event = ApplicationErrorEvent.objects.select_for_update().get(error_id=error_id)
    except ApplicationErrorEvent.DoesNotExist as exc:
        raise NotFoundError() from exc
    _assert_error_expected_updated_at(event, expected_updated_at)
    return _reopen_application_error_event(actor=actor, event=event, note=note)


def build_safe_error_context(event: Optional[ApplicationErrorEvent]) -> Dict:
    """Build a privacy-safe context dict for user-facing error pages.

    Only exposes the Error ID and a generic safe message. Never exposes
    stack traces, raw exception text, request bodies, or private content.
    """
    if event is None:
        return {
            "error_id": None,
            "safe_message": SAFE_MESSAGES[ErrorCategoryChoices.UNKNOWN],
        }
    return {
        "error_id": event.error_id,
        "safe_message": event.safe_message,
    }
