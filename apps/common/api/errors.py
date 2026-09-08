"""One transport adapter for all COMPASS JSON/API errors."""

from __future__ import annotations

import re

from django.core.exceptions import PermissionDenied as DjangoPermissionDenied
from django.core.exceptions import ValidationError as DjangoValidationError
from django.http import Http404, JsonResponse
from ninja.errors import HttpError
from ninja.errors import ValidationError as NinjaValidationError

from apps.common.api.correlation import request_id, trace_id
from apps.common.api.headers import NOINDEX_ROBOTS_TAG
from apps.common.exceptions import (
    CompassError,
    BadRequestError,
    DependencyFailureError,
    ErrorCode,
    InternalError,
    MethodNotAllowedError,
    NotFoundError,
    PayloadTooLargeError,
    PermissionDeniedError,
    RateLimitError,
    UnauthenticatedError,
    ValidationError,
)


STATUS_BY_CODE = {
    ErrorCode.BAD_REQUEST: 400,
    ErrorCode.UNAUTHENTICATED: 401,
    ErrorCode.PERMISSION: 403,
    ErrorCode.ASSURANCE_REQUIRED: 403,
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.METHOD_NOT_ALLOWED: 405,
    ErrorCode.LIFECYCLE_CONFLICT: 409,
    ErrorCode.STALE_STATE: 409,
    ErrorCode.VALIDATION: 422,
    ErrorCode.PAYLOAD_TOO_LARGE: 413,
    ErrorCode.RATE_LIMITED: 429,
    ErrorCode.DEPENDENCY_FAILURE: 503,
    ErrorCode.INTERNAL_ERROR: 500,
}

_FIELD_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9_.-]{0,63}\Z")
_SENSITIVE_WORDS = {
    "password", "token", "otp", "secret", "credential", "authorization",
    "cookie", "email", "phone", "student", "note", "narrative", "ip",
}


def status_for_code(code: ErrorCode | str) -> int:
    try:
        return STATUS_BY_CODE[ErrorCode(code)]
    except (KeyError, ValueError):
        return 500


def _safe_field_errors(field_errors) -> dict[str, list[str]]:
    if not isinstance(field_errors, dict):
        return {}
    result: dict[str, list[str]] = {}
    for raw_field, raw_messages in list(field_errors.items())[:20]:
        field = str(raw_field).strip()
        if not _FIELD_RE.fullmatch(field):
            continue
        if any(word in field.lower() for word in _SENSITIVE_WORDS):
            continue
        values = raw_messages if isinstance(raw_messages, (list, tuple)) else [raw_messages]
        safe_values = []
        for raw_message in values[:3]:
            message = str(raw_message or "").strip()[:160]
            if not message or any(word in message.lower() for word in _SENSITIVE_WORDS):
                message = "Invalid value."
            safe_values.append(message)
        if safe_values:
            result[field] = safe_values
    return result


def _validation_fields(exception) -> dict[str, list[str]]:
    if isinstance(exception, CompassError):
        return _safe_field_errors(getattr(exception, "field_errors", {}))
    if isinstance(exception, DjangoValidationError):
        if hasattr(exception, "message_dict"):
            return _safe_field_errors(exception.message_dict)
        return {}
    if isinstance(exception, NinjaValidationError):
        result: dict[str, list[str]] = {}
        for item in list(getattr(exception, "errors", ()) or ())[:20]:
            if not isinstance(item, dict):
                continue
            location = item.get("loc") or ()
            parts = [str(part) for part in location if str(part) not in {"body", "query", "path", "header"}]
            field = ".".join(parts)[:64]
            if not field:
                continue
            message = str(item.get("msg") or "Invalid value.")[:160]
            result.setdefault(field, []).append(message)
        return _safe_field_errors(result)
    return {}


def _safe_error_id(request) -> str | None:
    value = getattr(request, "_compass_error_id", None)
    return value if isinstance(value, str) and re.fullmatch(r"ERR-[0-9]{4}-[0-9]{6}", value) else None


def _validated_error_id(value) -> str | None:
    return value if isinstance(value, str) and re.fullmatch(r"ERR-[0-9]{4}-[0-9]{6}", value) else None


def _headers(request, status: int, *, retry_after: int | None = None) -> dict[str, str]:
    headers = {
        "Cache-Control": "no-store",
        "Vary": "Accept, X-COMPASS-Auth-Transport",
        "X-Request-ID": request_id(request),
        "X-Robots-Tag": NOINDEX_ROBOTS_TAG,
    }
    accepted_trace_id = trace_id(request)
    if accepted_trace_id:
        headers["X-Trace-ID"] = accepted_trace_id
    if status in {401, 403}:
        headers["Pragma"] = "no-cache"
    if retry_after is not None and status in {429, 503}:
        headers["Retry-After"] = str(max(1, int(retry_after)))
    return headers


def error_payload(request, exception: CompassError, *, status: int | None = None, error_id=None) -> dict:
    code = ErrorCode(getattr(exception, "code", ErrorCode.INTERNAL_ERROR))
    resolved_status = status if status is not None else status_for_code(code)
    payload = {
        "detail": getattr(exception, "public_message", InternalError.public_message),
        "code": code.value,
        "request_id": request_id(request),
        "error_id": _validated_error_id(error_id) if resolved_status >= 500 else None,
        "field_errors": _safe_field_errors(getattr(exception, "field_errors", {})),
    }
    return payload


def render_error_response(request, exception: CompassError, *, status: int | None = None, error_id=None):
    resolved_status = status if status is not None else status_for_code(exception.code)
    return JsonResponse(
        error_payload(request, exception, status=resolved_status, error_id=error_id),
        status=resolved_status,
        headers=_headers(request, resolved_status, retry_after=getattr(exception, "retry_after", None)),
    )


def _from_framework_exception(exception):
    if isinstance(exception, (Http404,)):
        return NotFoundError()
    if isinstance(exception, DjangoPermissionDenied):
        return PermissionDeniedError()
    if isinstance(exception, (DjangoValidationError, NinjaValidationError)):
        return ValidationError(field_errors=_validation_fields(exception))
    if isinstance(exception, HttpError):
        status = int(getattr(exception, "status_code", 500) or 500)
        if status == 400:
            return BadRequestError()
        if status == 401:
            return UnauthenticatedError()
        if status == 403:
            return PermissionDeniedError()
        if status == 404:
            return NotFoundError()
        if status == 409:
            return CompassError(code=ErrorCode.LIFECYCLE_CONFLICT)
        if status == 405:
            return MethodNotAllowedError()
        if status == 413:
            return PayloadTooLargeError()
        if status == 429:
            return RateLimitError(retry_after=60)
        if status == 503:
            return DependencyFailureError(retry_after=60)
        if status >= 500:
            return InternalError()
        return ValidationError()
    return None


def handle_compass_error(request, exception):
    return render_error_response(request, exception)


def handle_framework_error(request, exception):
    mapped = _from_framework_exception(exception) or InternalError()
    status = status_for_code(mapped.code)
    return render_error_response(request, mapped, status=status, error_id=_safe_error_id(request))


def handle_unexpected_error(request, exception):
    error_id = _safe_error_id(request)
    if error_id is None:
        try:
            from apps.system.error_services import capture_application_error_event
            event = capture_application_error_event(
                request=request,
                exception=exception,
                status_code=500,
            )
            error_id = event.error_id if event else None
            if error_id:
                request._compass_error_id = error_id
        except Exception:
            error_id = None
    return render_error_response(request, InternalError(), status=500, error_id=error_id)
