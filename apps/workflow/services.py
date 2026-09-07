import hmac
import hashlib
import json
import re
from datetime import timedelta
from urllib.parse import parse_qsl, urlsplit
from django.db import models, transaction
from django.db.utils import IntegrityError
from django.utils import timezone
from django.conf import settings
from apps.audit.services import audit_log, SENSITIVE_KEYS, SENSITIVE_VALUE_KEYWORDS, JWT_REGEX
from apps.workflow.models import IdempotencyKey, OutboxEvent
from apps.common.exceptions import LifecycleConflictError, PermissionDeniedError, ValidationError
from apps.common.request_dedup import (
    build_request_fingerprint as build_shared_request_fingerprint,
    hash_request_key,
)


# --------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------
class IdempotencyError(LifecycleConflictError):
    pass

class IdempotencyConflictError(IdempotencyError):
    pass

class IdempotencyProcessingError(IdempotencyError):
    pass

class IdempotencyExpiredError(IdempotencyError):
    pass

class IdempotencyActorMismatchError(PermissionDeniedError):
    pass

class UnsafePayloadError(ValueError):
    pass


class UnsafeResponsePathError(ValueError):
    pass


# --------------------------------------------------------------------------
# Idempotency Helpers & Services
# --------------------------------------------------------------------------
def hash_idempotency_key(key: str) -> str:
    """
    Computes a deterministic SHA256 HMAC of a client key using SECRET_KEY.
    Prevents raw keys from being stored in the database.
    """
    return hash_request_key(key, secret_setting="SECRET_KEY")


def build_idempotency_context_hash(
    action_scope: str,
    actor_user=None,
    session_key: str = None,
    session_key_hash: str = None,
    token_context: str = None,
) -> str:
    """Builds a stable, non-sensitive actor/session context hash for DB uniqueness."""
    actor_id = str(actor_user.pk) if actor_user and getattr(actor_user, "pk", None) else ""
    normalized_session_hash = session_key_hash or (hash_idempotency_key(session_key) if session_key else "")
    token_hash = hash_idempotency_key(token_context) if token_context else ""
    context = {
        "actor_id": actor_id,
        "session_key_hash": normalized_session_hash,
        "token_hash": token_hash,
        "action_scope": action_scope,
    }
    serialized = json.dumps(context, sort_keys=True, separators=(",", ":"))
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        serialized.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_SENSITIVE_QUERY_KEYWORDS = {
    "token", "raw_token", "otp", "password", "secret", "smtp_password",
    "api_key", "key", "signature", "x-amz-signature", "signed_url",
}


def normalize_safe_response_path(path: str | None) -> str | None:
    """Returns a safe local response path or raises UnsafeResponsePathError."""
    if path in (None, ""):
        return None
    if not isinstance(path, str):
        raise UnsafeResponsePathError("Response path must be a string or None")
    if path != path.strip():
        raise UnsafeResponsePathError("Response path must not contain surrounding whitespace")
    if _CONTROL_CHAR_RE.search(path):
        raise UnsafeResponsePathError("Response path must not contain control characters")
    if "\\" in path:
        raise UnsafeResponsePathError("Response path must not contain backslashes")
    if not path.startswith("/"):
        raise UnsafeResponsePathError("Response path must start with /")
    if path.startswith("//"):
        raise UnsafeResponsePathError("Response path must not be protocol-relative")

    split = urlsplit(path)
    if split.scheme or split.netloc:
        raise UnsafeResponsePathError("Response path must be local")
    if "\\" in split.path or split.path.startswith("//"):
        raise UnsafeResponsePathError("Response path must be local")

    for key, _value in parse_qsl(split.query, keep_blank_values=True):
        key_lower = key.lower()
        if any(keyword in key_lower for keyword in _SENSITIVE_QUERY_KEYWORDS):
            raise UnsafeResponsePathError("Response path query contains sensitive key")

    return path


def build_request_fingerprint(
    method: str,
    path: str,
    payload: dict,
    actor_user=None,
    session_key: str = None
) -> str:
    """
    Generates a deterministic request fingerprint hash.
    Excludes volatile fields like CSRF tokens and sensitive fields.
    """
    return build_shared_request_fingerprint(
        method,
        path,
        payload,
        actor_user,
        session_key,
    )


@transaction.atomic
def start_idempotent_action(
    raw_key: str,
    action_scope: str,
    method: str,
    path: str,
    payload: dict,
    actor_user=None,
    session_key: str = None,
    ttl_minutes: int = 60,
    ip_address=None,
    user_agent=None
) -> tuple[IdempotencyKey, bool]:
    """
    Begins or validates an idempotent action in the database.
    Returns (idempotency_key_instance, is_new_execution_started).
    """
    key_hash = hash_idempotency_key(raw_key)
    session_key_hash = hash_idempotency_key(session_key) if session_key else None
    context_hash = build_idempotency_context_hash(
        action_scope=action_scope,
        actor_user=actor_user,
        session_key_hash=session_key_hash,
    )
    fingerprint = build_request_fingerprint(method, path, payload, actor_user, session_key)

    try:
        existing_key = IdempotencyKey.objects.select_for_update().get(
            context_hash=context_hash,
            key_hash=key_hash,
            action_scope=action_scope,
        )
    except IdempotencyKey.DoesNotExist:
        if IdempotencyKey.objects.select_for_update().filter(
            key_hash=key_hash,
            action_scope=action_scope,
        ).exclude(context_hash=context_hash).exists():
            audit_log(
                action_type="IDEMPOTENCY_ACTOR_MISMATCH",
                event_category="SECURITY",
                target_model="workflow.IdempotencyKey",
                target_object_id="",
                actor_user=actor_user,
                ip_address=ip_address,
                user_agent=user_agent,
                source_app="workflow",
                metadata={"action_scope": action_scope}
            )
            raise IdempotencyActorMismatchError("Idempotency key user/session context mismatch")

        expires_at = timezone.now() + timedelta(minutes=ttl_minutes)
        defaults = {
            "actor_user": actor_user,
            "session_key_hash": session_key_hash,
            "request_fingerprint": fingerprint,
            "status": "processing",
            "expires_at": expires_at,
            "metadata_json": {},
        }
        try:
            ikey, created = IdempotencyKey.objects.get_or_create(
                context_hash=context_hash,
                action_scope=action_scope,
                key_hash=key_hash,
                defaults=defaults,
            )
        except IntegrityError:
            ikey = IdempotencyKey.objects.select_for_update().get(
                context_hash=context_hash,
                action_scope=action_scope,
                key_hash=key_hash,
            )
            created = False
        if not created:
            existing_key = IdempotencyKey.objects.select_for_update().get(pk=ikey.pk)
        else:
            audit_log(
                action_type="IDEMPOTENCY_KEY_CREATED",
                event_category="SECURITY",
                target_model="workflow.IdempotencyKey",
                target_object_id=ikey.id,
                actor_user=actor_user,
                ip_address=ip_address,
                user_agent=user_agent,
                source_app="workflow",
                metadata={
                    "action_scope": action_scope,
                    "expires_at": expires_at.isoformat(),
                }
            )
            return ikey, True

    if "existing_key" not in locals():
        existing_key = ikey

    # 1. Actor User mismatch validation
    if (
        existing_key.context_hash != context_hash
        or existing_key.actor_user_id != (actor_user.pk if actor_user else None)
        or existing_key.session_key_hash != session_key_hash
    ):
        audit_log(
            action_type="IDEMPOTENCY_ACTOR_MISMATCH",
            event_category="SECURITY",
            target_model="workflow.IdempotencyKey",
            target_object_id=existing_key.id,
            actor_user=actor_user,
            ip_address=ip_address,
            user_agent=user_agent,
            source_app="workflow",
            metadata={
                "action_scope": action_scope,
                "existing_actor_id": str(existing_key.actor_user.id) if existing_key.actor_user else None,
            }
        )
        raise IdempotencyActorMismatchError("Idempotency key user/session context mismatch")

    # 2. Expiration check
    if existing_key.expires_at < timezone.now() or existing_key.status == "expired":
        if existing_key.status != "expired":
            existing_key.status = "expired"
            existing_key.save(update_fields=["status"])
            audit_log(
                action_type="IDEMPOTENCY_KEY_EXPIRED",
                event_category="SECURITY",
                target_model="workflow.IdempotencyKey",
                target_object_id=existing_key.id,
                actor_user=actor_user,
                ip_address=ip_address,
                user_agent=user_agent,
                source_app="workflow",
                metadata={"action_scope": action_scope}
            )
        raise IdempotencyExpiredError("Idempotency key has expired")

    # 3. Fingerprint mismatch validation (double submit conflict)
    if existing_key.request_fingerprint != fingerprint:
        audit_log(
            action_type="IDEMPOTENCY_CONFLICT",
            event_category="SECURITY",
            target_model="workflow.IdempotencyKey",
            target_object_id=existing_key.id,
            actor_user=actor_user,
            ip_address=ip_address,
            user_agent=user_agent,
            source_app="workflow",
            metadata={"action_scope": action_scope}
        )
        raise IdempotencyConflictError("Idempotency request fingerprint mismatch")

    # 4. Same key + fingerprint + processing state check
    if existing_key.status == "processing":
        existing_key.last_seen_at = timezone.now()
        existing_key.save(update_fields=["last_seen_at"])
        audit_log(
            action_type="IDEMPOTENCY_RETRY_PROCESSING",
            event_category="SECURITY",
            target_model="workflow.IdempotencyKey",
            target_object_id=existing_key.id,
            actor_user=actor_user,
            ip_address=ip_address,
            user_agent=user_agent,
            source_app="workflow",
            metadata={"action_scope": action_scope}
        )
        raise IdempotencyProcessingError("Idempotent action is currently processing")

    # 5. Same key + fingerprint + succeeded state check
    if existing_key.status == "succeeded":
        existing_key.last_seen_at = timezone.now()
        existing_key.save(update_fields=["last_seen_at"])
        audit_log(
            action_type="IDEMPOTENCY_RETRY_RETURNED",
            event_category="SECURITY",
            target_model="workflow.IdempotencyKey",
            target_object_id=existing_key.id,
            actor_user=actor_user,
            ip_address=ip_address,
            user_agent=user_agent,
            source_app="workflow",
            metadata={
                "action_scope": action_scope,
                "safe_response_path": existing_key.safe_response_path
            }
        )
        return existing_key, False

    # 6. Retry in failed status allows re-attempt
    if existing_key.status == "failed":
        existing_key.status = "processing"
        existing_key.last_seen_at = timezone.now()
        existing_key.save(update_fields=["status", "last_seen_at"])
        audit_log(
            action_type="IDEMPOTENCY_KEY_RETRY_RESET",
            event_category="SECURITY",
            target_model="workflow.IdempotencyKey",
            target_object_id=existing_key.id,
            actor_user=actor_user,
            ip_address=ip_address,
            user_agent=user_agent,
            source_app="workflow",
            metadata={"action_scope": action_scope}
        )
        return existing_key, True

    return existing_key, False


@transaction.atomic
def record_idempotency_success(
    ikey: IdempotencyKey,
    related_object,
    safe_response_path: str,
    actor_user=None,
    ip_address=None,
    user_agent=None,
    result_metadata=None,
) -> None:
    """Marks an idempotent key as succeeded, attaching the result target."""
    safe_response_path = normalize_safe_response_path(safe_response_path)
    ikey = IdempotencyKey.objects.select_for_update().get(pk=ikey.pk)
    ikey.status = "succeeded"
    ikey.completed_at = timezone.now()
    ikey.safe_response_path = safe_response_path
    if related_object:
        ikey.related_object_type = related_object.__class__.__name__
        ikey.related_object_id = str(related_object.pk)
    safe_metadata = result_metadata if isinstance(result_metadata, dict) else {}
    safe_metadata = {
        str(key): value
        for key, value in safe_metadata.items()
        if str(key) in {"related_object_ids", "result_kind"}
    }
    if "related_object_ids" in safe_metadata:
        ids = safe_metadata["related_object_ids"]
        if not isinstance(ids, list) or len(ids) > 100 or any(not str(item).strip() for item in ids):
            raise ValueError("Idempotency result metadata is unsafe.")
        safe_metadata["related_object_ids"] = [str(item)[:100] for item in ids]
    ikey.metadata_json = safe_metadata
    ikey.save(update_fields=["status", "completed_at", "safe_response_path", "related_object_type", "related_object_id", "metadata_json"])

    audit_log(
        action_type="IDEMPOTENT_ACTION_SUCCEEDED",
        event_category="SECURITY",
        target_model="workflow.IdempotencyKey",
        target_object_id=ikey.id,
        actor_user=actor_user,
        ip_address=ip_address,
        user_agent=user_agent,
        source_app="workflow",
        metadata={
            "action_scope": ikey.action_scope,
            "related_object_type": ikey.related_object_type,
            "related_object_id": ikey.related_object_id,
        }
    )


@transaction.atomic
def record_idempotency_failure(
    ikey: IdempotencyKey,
    error_code: str,
    actor_user=None,
    ip_address=None,
    user_agent=None
) -> None:
    """Marks an idempotent key as failed, saving the error code."""
    ikey = IdempotencyKey.objects.select_for_update().get(pk=ikey.pk)
    ikey.status = "failed"
    ikey.error_code = error_code
    ikey.save(update_fields=["status", "error_code"])

    audit_log(
        action_type="IDEMPOTENT_ACTION_FAILED",
        event_category="SECURITY",
        target_model="workflow.IdempotencyKey",
        target_object_id=ikey.id,
        actor_user=actor_user,
        ip_address=ip_address,
        user_agent=user_agent,
        source_app="workflow",
        metadata={
            "action_scope": ikey.action_scope,
            "error_code": error_code,
        }
    )


def expire_old_idempotency_keys() -> int:
    """Ticks active/expired keys and transitions expired keys to 'expired'."""
    now = timezone.now()
    expired_keys = IdempotencyKey.objects.filter(
        expires_at__lt=now
    ).exclude(status="expired")

    count = 0
    for ikey in expired_keys:
        ikey.status = "expired"
        ikey.save(update_fields=["status"])
        count += 1
        audit_log(
            action_type="IDEMPOTENCY_KEY_EXPIRED",
            event_category="SECURITY",
            target_model="workflow.IdempotencyKey",
            target_object_id=ikey.id,
            source_app="workflow"
        )
    return count


# --------------------------------------------------------------------------
# Outbox Services & Handler Registry
# --------------------------------------------------------------------------
_handler_registry = {}


def register_outbox_handler(event_type: str, handler_func):
    """Registers an outbox event processor callback."""
    _handler_registry[event_type] = handler_func


def get_outbox_handler(event_type: str):
    """Retrieves an outbox event handler by type."""
    return _handler_registry.get(event_type)


def validate_outbox_payload(event_type: str, payload: dict) -> None:
    """
    Enforces privacy and payload rules on transactional events.
    Rejects narratives, tokens, object storage keys, and raw credentials.
    """
    def _check(val):
        if isinstance(val, dict):
            for k, v in val.items():
                k_lower = str(k).lower()
                # Collection titles are an explicit notification allowlist value.
                # Keep the broad narrative/title guard for every other payload
                # key while permitting the catalogued collection copy field.
                if any(sk in k_lower for sk in SENSITIVE_KEYS) and k_lower != "collection_title":
                    raise UnsafePayloadError(f"Payload contains sensitive metadata key: {k}")
                _check(v)
        elif isinstance(val, (list, tuple)):
            for item in val:
                _check(item)
        elif isinstance(val, str):
            val_lower = val.lower()
            if JWT_REGEX.search(val):
                raise UnsafePayloadError("Payload includes raw JWT signature pattern")
            if any(kw in val_lower for kw in SENSITIVE_VALUE_KEYWORDS):
                raise UnsafePayloadError(f"Payload references forbidden narrative or credentials: {val}")
            if "http" in val_lower and any(kw in val_lower for kw in ["signature", "awsaccesskeyid", "expires", "token"]):
                raise UnsafePayloadError("Payload contains AWS or signed storage credentials")

    _check(payload)


def build_event_key(event_type: str, related_object=None, idempotency_key=None, payload=None) -> str:
    """Builds a unique deterministic event key from stable, non-sensitive inputs."""
    if not event_type:
        raise ValueError("event_type is required to build an event key")

    payload = payload or {}
    related_type = related_object.__class__.__name__ if related_object else ""
    related_id = str(related_object.pk) if related_object else ""
    idempotency_id = str(idempotency_key.id) if idempotency_key else ""
    if not (related_id or idempotency_id or payload):
        raise ValueError("A deterministic event key requires related object, idempotency key, payload, or explicit event_key")

    payload_hash = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    seed = {
        "event_type": event_type,
        "related_object_type": related_type,
        "related_object_id": related_id,
        "idempotency_key_id": idempotency_id,
        "payload_hash": payload_hash,
    }
    seed_hash = hashlib.sha256(
        json.dumps(seed, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    parts = [event_type]
    if related_object:
        parts.append(related_type)
        parts.append(related_id)
    if idempotency_key:
        parts.append(idempotency_id)
    parts.append(seed_hash[:32])
    return ":".join(parts)


@transaction.atomic
def enqueue_outbox_event(
    event_type: str,
    payload: dict,
    related_object=None,
    idempotency_key=None,
    event_key=None
) -> tuple[OutboxEvent, bool]:
    """
    Transactionally registers an event in the outbox queue.
    """
    validate_outbox_payload(event_type, payload)

    if not event_key:
        event_key = build_event_key(event_type, related_object, idempotency_key, payload)

    now = timezone.now()
    event, created = OutboxEvent.objects.get_or_create(
        event_key=event_key,
        defaults={
            "event_type": event_type,
            "payload_json": payload,
            "status": "pending",
            "next_retry_at": now,
            "available_at": now,
            "related_object_type": related_object.__class__.__name__ if related_object else None,
            "related_object_id": str(related_object.pk) if related_object else None,
            "idempotency_key": idempotency_key,
        }
    )

    if not created and (event.event_type != event_type or event.payload_json != payload):
        raise ValueError("Outbox event key already exists for different event data")

    if created:
        audit_log(
            action_type="OUTBOX_EVENT_CREATED",
            event_category="WORKFLOW",
            target_model="workflow.OutboxEvent",
            target_object_id=event.id,
            source_app="workflow",
            metadata={"event_type": event_type, "event_key": event_key}
        )
    return event, created


@transaction.atomic
def retry_outbox_event(event: OutboxEvent, actor_user=None, allow_dead: bool = True) -> OutboxEvent:
    """Queues a failed/dead event for manual retry through lifecycle policy."""
    event = OutboxEvent.objects.select_for_update().get(pk=event.pk)
    allowed_statuses = {"failed"}
    if allow_dead:
        allowed_statuses.add("dead")
    if event.status not in allowed_statuses:
        raise ValueError("Only failed or explicitly allowed dead outbox events can be retried")

    now = timezone.now()
    event.status = "pending"
    event.attempts = 0
    event.next_retry_at = now
    event.available_at = now
    event.locked_by = None
    event.locked_at = None
    event.last_error_code = None
    event.last_error_safe_summary = None
    event.save(update_fields=[
        "status", "attempts", "next_retry_at", "available_at", "locked_by",
        "locked_at", "last_error_code", "last_error_safe_summary",
    ])
    audit_log(
        action_type="OUTBOX_EVENT_MANUAL_RETRY",
        event_category="WORKFLOW",
        target_model="workflow.OutboxEvent",
        target_object_id=event.id,
        actor_user=actor_user,
        source_app="workflow",
        metadata={"event_type": event.event_type}
    )
    return event


@transaction.atomic
def mark_outbox_event_dead(event: OutboxEvent, error_summary: str, actor_user=None) -> OutboxEvent:
    """Marks a retryable outbox event dead through a service boundary."""
    event = OutboxEvent.objects.select_for_update().get(pk=event.pk)
    if event.status in {"sent", "cancelled"}:
        raise ValueError("Sent or cancelled outbox events cannot be marked dead")
    mark_dead(event, error_summary)
    audit_log(
        action_type="OUTBOX_EVENT_MANUAL_DEAD_LETTER",
        event_category="WORKFLOW",
        target_model="workflow.OutboxEvent",
        target_object_id=event.id,
        actor_user=actor_user,
        source_app="workflow",
        metadata={"event_type": event.event_type}
    )
    return event


@transaction.atomic
def claim_outbox_events(worker_id: str, batch_size: int = 20, lock_timeout_seconds: int = 300) -> list[OutboxEvent]:
    """
    Queries and locks pending event records for processing.
    """
    now = timezone.now()
    lock_cutoff = now - timedelta(seconds=lock_timeout_seconds)

    db_engine = settings.DATABASES["default"]["ENGINE"]
    is_sqlite = "sqlite" in db_engine

    if is_sqlite:
        qs = OutboxEvent.objects.select_for_update().filter(
            models.Q(status__in=["pending", "failed"], available_at__lte=now) |
            models.Q(status="processing", locked_at__lte=lock_cutoff)
        ).order_by("available_at")[:batch_size]
    else:
        qs = OutboxEvent.objects.select_for_update(skip_locked=True).filter(
            models.Q(status__in=["pending", "failed"], available_at__lte=now) |
            models.Q(status="processing", locked_at__lte=lock_cutoff)
        ).order_by("available_at")[:batch_size]

    claimed_events = []
    for event in qs:
        event.status = "processing"
        event.locked_by = worker_id
        event.locked_at = now
        event.save(update_fields=["status", "locked_by", "locked_at"])
        claimed_events.append(event)

        audit_log(
            action_type="OUTBOX_EVENT_CLAIMED",
            event_category="WORKFLOW",
            target_model="workflow.OutboxEvent",
            target_object_id=event.id,
            source_app="workflow",
            metadata={
                "event_type": event.event_type,
                "locked_by": worker_id,
            }
        )
    return claimed_events


def schedule_retry(event: OutboxEvent, error_summary: str) -> None:
    """Updates status to failed and schedules exponential backoff retry."""
    event.attempts += 1
    backoff_seconds = min(15 * (2 ** event.attempts), 3600)
    event.status = "failed"
    event.next_retry_at = timezone.now() + timedelta(seconds=backoff_seconds)
    event.last_error_code = "RETRYABLE_ERROR"
    event.last_error_safe_summary = error_summary
    event.locked_by = None
    event.locked_at = None
    event.save(update_fields=["status", "attempts", "next_retry_at", "last_error_code", "last_error_safe_summary", "locked_by", "locked_at"])

    audit_log(
        action_type="OUTBOX_EVENT_RETRY_SCHEDULED",
        event_category="WORKFLOW",
        target_model="workflow.OutboxEvent",
        target_object_id=event.id,
        source_app="workflow",
        metadata={
            "event_type": event.event_type,
            "attempt": event.attempts,
            "next_retry_at": event.next_retry_at.isoformat()
        }
    )


def mark_dead(event: OutboxEvent, error_summary: str) -> None:
    """Poisons execution queue element, routing to dead letters."""
    event.status = "dead"
    event.last_error_code = "MAX_ATTEMPTS_EXCEEDED"
    event.last_error_safe_summary = error_summary
    event.locked_by = None
    event.locked_at = None
    event.save(update_fields=["status", "last_error_code", "last_error_safe_summary", "locked_by", "locked_at"])

    audit_log(
        action_type="OUTBOX_EVENT_DEAD_LETTERED",
        event_category="WORKFLOW",
        target_model="workflow.OutboxEvent",
        target_object_id=event.id,
        severity="WARNING",
        source_app="workflow",
        metadata={
            "event_type": event.event_type,
            "attempts": event.attempts,
            "error": error_summary
        }
    )


def cancel_outbox_event(event: OutboxEvent) -> None:
    """Cancels enqueued outbox task."""
    if event.status in ["pending", "failed", "processing"]:
        event.status = "cancelled"
        event.locked_by = None
        event.locked_at = None
        event.save(update_fields=["status", "locked_by", "locked_at"])
        audit_log(
            action_type="OUTBOX_EVENT_CANCELLED",
            event_category="WORKFLOW",
            target_model="workflow.OutboxEvent",
            target_object_id=event.id,
            source_app="workflow",
            metadata={"event_type": event.event_type}
        )


def process_outbox_batch(worker_id: str, batch_size: int = 20, lock_timeout_seconds: int = 300) -> int:
    """
    Executes a claimed batch of pending outbox events using registered handlers.
    """
    claimed = claim_outbox_events(worker_id, batch_size, lock_timeout_seconds)
    processed_count = 0

    for event in claimed:
        try:
            validate_outbox_payload(event.event_type, event.payload_json)

            handler = get_outbox_handler(event.event_type)
            if not handler:
                raise ValueError(f"No handler registered for event type: {event.event_type}")

            with transaction.atomic():
                handler(event.payload_json, event)

            event.status = "sent"
            event.processed_at = timezone.now()
            event.locked_by = None
            event.locked_at = None
            event.save(update_fields=["status", "processed_at", "locked_by", "locked_at"])

            audit_log(
                action_type="OUTBOX_EVENT_PROCESSED",
                event_category="WORKFLOW",
                target_model="workflow.OutboxEvent",
                target_object_id=event.id,
                source_app="workflow",
                metadata={"event_type": event.event_type}
            )
            processed_count += 1

        except UnsafePayloadError as upe:
            mark_dead(event, f"Unsafe payload: {str(upe)}")
            audit_log(
                action_type="UNSAFE_PAYLOAD_REJECTED",
                event_category="SECURITY",
                target_model="workflow.OutboxEvent",
                target_object_id=event.id,
                severity="WARNING",
                source_app="workflow",
                metadata={"event_type": event.event_type, "error": str(upe)}
            )
        except Exception as e:
            error_summary = str(e)[:500]
            if event.attempts + 1 >= event.max_attempts:
                mark_dead(event, error_summary)
            else:
                schedule_retry(event, error_summary)

    return processed_count
