"""HTTP adapter for the existing workflow idempotency records."""

from __future__ import annotations

from dataclasses import dataclass, field

from apps.account_security.network import get_client_ip_from_headers
from apps.common.api.constants import API_MAX_IDEMPOTENCY_KEY_LENGTH
from apps.common.exceptions import LifecycleConflictError, NotFoundError, PermissionDeniedError, ValidationError
from apps.common.request_dedup import normalize_request_key
from apps.workflow.services import (
    IdempotencyActorMismatchError,
    IdempotencyConflictError,
    IdempotencyExpiredError,
    IdempotencyProcessingError,
    record_idempotency_failure,
    record_idempotency_success,
    start_idempotent_action,
)


def _raw_key(request) -> str:
    value = str((getattr(request, "META", {}) or {}).get("HTTP_IDEMPOTENCY_KEY", "") or "")
    try:
        return normalize_request_key(value, max_length=API_MAX_IDEMPOTENCY_KEY_LENGTH)
    except ValidationError as exc:
        raise ValidationError("Idempotency-Key is required and must be bounded.") from exc


def require_idempotency_key(request) -> str:
    return _raw_key(request)


@dataclass(frozen=True, slots=True)
class ApiMutationOutcome:
    value: object
    related_object: object | None = None
    related_object_ids: tuple[str, ...] = ()
    safe_response_path: str = "/"
    metadata: dict = field(default_factory=dict)


def _actor(request):
    auth = getattr(request, "auth", None)
    return getattr(auth, "user", None)


def run_api_mutation(
    request,
    operation_id: str,
    payload: dict,
    operation,
    replay,
    *,
    prepared_operation,
):
    """Run a registered mutation and replay a successful safe projection."""

    if getattr(prepared_operation, "operation_id", None) != operation_id:
        raise ValidationError("The API operation was not prepared for this mutation.")
    raw_key = prepared_operation.idempotency_key
    if not raw_key:
        raise ValidationError("This mutation requires a prepared idempotency key.")
    actor = _actor(request)
    session = getattr(request, "session", None)
    session_key = getattr(session, "session_key", None)
    ip_address = get_client_ip_from_headers(getattr(request, "META", {}) or {})
    user_agent = (getattr(request, "META", {}) or {}).get("HTTP_USER_AGENT")
    try:
        idempotency_key, is_new = start_idempotent_action(
            raw_key=raw_key,
            action_scope=operation_id,
            method=str(getattr(request, "method", "POST")),
            path=str(getattr(request, "path", "/")),
            payload=payload or {},
            actor_user=actor,
            session_key=session_key,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    except (IdempotencyConflictError, IdempotencyProcessingError, IdempotencyExpiredError) as exc:
        raise LifecycleConflictError() from exc
    except IdempotencyActorMismatchError as exc:
        raise PermissionDeniedError() from exc
    except (TypeError, ValueError) as exc:
        raise ValidationError() from exc

    if not is_new:
        if idempotency_key.status == "succeeded":
            value = replay(idempotency_key)
            if value is None:
                raise NotFoundError()
            return value
        if idempotency_key.status == "processing":
            raise LifecycleConflictError()

    try:
        outcome = operation()
        if not isinstance(outcome, ApiMutationOutcome):
            raise TypeError("API mutation operation must return ApiMutationOutcome.")
        metadata = dict(outcome.metadata or {})
        if outcome.related_object_ids:
            metadata["related_object_ids"] = [str(item) for item in outcome.related_object_ids[:100]]
        record_idempotency_success(
            ikey=idempotency_key,
            related_object=outcome.related_object,
            safe_response_path=outcome.safe_response_path,
            actor_user=actor,
            ip_address=ip_address,
            user_agent=user_agent,
            result_metadata=metadata,
        )
        return outcome.value
    except Exception as exc:
        error_code = getattr(getattr(exc, "code", None), "value", None) or "internal_error"
        try:
            record_idempotency_failure(
                idempotency_key,
                error_code=error_code,
                actor_user=actor,
                ip_address=ip_address,
                user_agent=user_agent,
            )
        except Exception:
            pass
        raise
