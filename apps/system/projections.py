"""Bounded JSON projections for system operations and diagnostics."""

import hashlib
import json
import re

from django.utils import timezone

from apps.system.choices import ErrorCategoryChoices
from apps.system.models import ApplicationErrorEvent
from apps.system.policies import can_view_application_error_event


FINGERPRINT_VERSION = "error-fingerprint-v1"
FINGERPRINT_FIELDS = (
    "category", "exception_class", "app_label", "route_name", "view_name",
    "http_method", "path_template", "status_code",
)
DIAGNOSTIC_CONTEXT_FIELDS = frozenset({
    "service_name", "job_name", "reason_code", "component", "operation",
    "phase", "dependency", "provider_code", "retryable", "status_code",
})
REMEDIATION_CATALOG = {
    ErrorCategoryChoices.VALIDATION: ("CHECK_INPUT_VALIDATION", "Review the request validation path and client contract."),
    ErrorCategoryChoices.PERMISSION: ("REVIEW_AUTHORIZATION", "Review the capability, scope, and action policy for this request."),
    ErrorCategoryChoices.EXTERNAL_SERVICE: ("CHECK_DEPENDENCY", "Check the configured dependency and its current availability."),
    ErrorCategoryChoices.BACKGROUND_JOB: ("CHECK_WORKER", "Check the background worker and retry state."),
    ErrorCategoryChoices.DATABASE: ("CHECK_DATABASE", "Check database health, migrations, and transaction state."),
    ErrorCategoryChoices.SECURITY: ("REVIEW_SECURITY_EVENTS", "Review related security and audit events."),
    ErrorCategoryChoices.UNKNOWN: ("CORRELATE_ERROR_CONTEXT", "Correlate request and trace identifiers with deployment logs."),
}
_SAFE_CODE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}$")


def _safe_code(value, *, fallback: str = "unknown") -> str:
    candidate = str(value or "").strip()
    return candidate[:100] if _SAFE_CODE.fullmatch(candidate) else fallback


def _timestamp(value):
    if value is None:
        return None
    return timezone.localtime(value).isoformat() if timezone.is_aware(value) else value.isoformat()


def _project_context(event: ApplicationErrorEvent) -> dict:
    raw_metadata = event.metadata_json if isinstance(event.metadata_json, dict) else {}
    values = {}
    for field in DIAGNOSTIC_CONTEXT_FIELDS:
        value = raw_metadata.get(field)
        if isinstance(value, str):
            values[field] = value[:255]
        elif type(value) in {int, float, bool}:
            values[field] = value
    return {"state": "available" if values else "not_captured", "values": values}


def _fingerprint(event: ApplicationErrorEvent) -> str:
    payload = json.dumps(
        [FINGERPRINT_VERSION, *[getattr(event, field, None) for field in FINGERPRINT_FIELDS]],
        ensure_ascii=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def project_application_error_event(actor, event: ApplicationErrorEvent | None) -> dict | None:
    if event is None or not can_view_application_error_event(actor, event):
        return None
    code, hint = REMEDIATION_CATALOG.get(event.category, REMEDIATION_CATALOG[ErrorCategoryChoices.UNKNOWN])
    return {
        "error_id": event.error_id,
        "created_at": _timestamp(event.created_at),
        "request_id": event.request_id,
        "trace_id": event.trace_id,
        "severity": event.severity,
        "category": event.category,
        "environment": event.environment,
        "release_version": event.release_version,
        "build_id": event.build_id,
        "app_label": event.app_label,
        "route_name": event.route_name,
        "view_name": event.view_name,
        "http_method": event.http_method,
        "path_template": event.path_template,
        "status_code": event.status_code,
        "exception_class": event.exception_class,
        "safe_message": event.safe_message,
        "fingerprint_version": FINGERPRINT_VERSION,
        "fingerprint": _fingerprint(event),
        "diagnostic_context": _project_context(event),
        "remediation": {"code": code, "hint": hint},
        "is_resolved": bool(event.is_resolved),
        "resolved_at": _timestamp(event.resolved_at),
    }


def maintenance_projection(window) -> dict:
    if window is None:
        return {}
    return {
        "id": str(window.pk),
        "status": _safe_code(window.status),
        "starts_at": _timestamp(window.starts_at),
        "ends_at": _timestamp(window.ends_at),
        "safe_public_message": str(window.safe_public_message or "")[:240],
        "internal_reason_code": _safe_code(window.internal_reason_code, fallback=""),
        "is_expired": bool(window.is_expired),
        "created_at": _timestamp(window.created_at),
        "updated_at": _timestamp(window.updated_at),
    }


def operational_command_run_projection(run) -> dict:
    if run is None:
        return {}
    return {
        "id": str(run.pk),
        "command_key": _safe_code(run.command_key),
        "mode": _safe_code(run.mode),
        "environment": _safe_code(run.environment),
        "reason_code": _safe_code(run.reason_code),
        "configuration_identifier": _safe_code(run.configuration_identifier, fallback="") if run.configuration_identifier else None,
        "started_at": _timestamp(run.started_at),
        "finished_at": _timestamp(run.finished_at),
        "outcome": _safe_code(run.outcome),
        "outcome_reason_code": _safe_code(run.outcome_reason_code, fallback="") if run.outcome_reason_code else None,
        "release_version": _safe_code(run.release_version, fallback="") if run.release_version else None,
        "build_id": _safe_code(run.build_id, fallback="") if run.build_id else None,
    }
