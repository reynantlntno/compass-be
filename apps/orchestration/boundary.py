"""Framework-neutral composition primitives.

The boundary stores no model instances and performs no implicit imports.  A
caller supplies a serializable event payload and an after-commit callback.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Callable, Mapping

from django.db import transaction

from apps.common.contracts import to_json_object
from apps.common.exceptions import ValidationError


_EVENT_TYPE_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_EVENT_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._/-]*$")
_MAX_EVENT_TYPE_LENGTH = 128
_MAX_EVENT_KEY_LENGTH = 256
_FORBIDDEN_PAYLOAD_KEY_PARTS = frozenset({
    "token", "password", "passwd", "otp", "secret", "credential",
    "encrypted", "ciphertext", "private_key", "raw_token", "raw_password",
})


def _validate_event_identity(event_type: str, event_key: str) -> tuple[str, str]:
    if not isinstance(event_type, str):
        raise ValidationError("Event type must be a string.")
    if not isinstance(event_key, str):
        raise ValidationError("Event key must be a string.")
    event_type = event_type.strip()
    event_key = event_key.strip()
    if (
        not event_type
        or len(event_type) > _MAX_EVENT_TYPE_LENGTH
        or not _EVENT_TYPE_RE.fullmatch(event_type)
    ):
        raise ValidationError("Event type is invalid.")
    if (
        not event_key
        or len(event_key) > _MAX_EVENT_KEY_LENGTH
        or not _EVENT_KEY_RE.fullmatch(event_key)
    ):
        raise ValidationError("Event key is invalid.")
    return event_type, event_key


def _validate_payload_keys(value, path: str = "payload") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized_key = str(key).strip().lower()
            parts = set(re.split(r"[^a-z0-9]+", normalized_key))
            if parts & _FORBIDDEN_PAYLOAD_KEY_PARTS:
                raise ValidationError(f"{path} contains protected metadata.")
            _validate_payload_keys(child, f"{path}.{normalized_key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _validate_payload_keys(child, f"{path}[{index}]")


@dataclass(frozen=True, slots=True)
class DomainEvent:
    event_type: str
    payload: Mapping[str, object]
    event_key: str

    def __post_init__(self) -> None:
        event_type, event_key = _validate_event_identity(self.event_type, self.event_key)
        try:
            payload = to_json_object(self.payload)
        except (TypeError, ValueError) as exc:
            raise ValidationError("Event payload must contain JSON-safe values.") from exc
        _validate_payload_keys(payload)
        object.__setattr__(self, "event_type", event_type)
        object.__setattr__(self, "event_key", event_key)
        object.__setattr__(self, "payload", payload)


def dispatch_after_commit(event: DomainEvent, dispatcher: Callable[[DomainEvent], object]):
    """Dispatch a domain event only after the surrounding transaction commits."""

    event = require_serializable_event(event)
    transaction.on_commit(lambda: dispatcher(event))


def require_serializable_event(event: DomainEvent) -> DomainEvent:
    """Validate an event before it enters the after-commit/outbox edge."""

    if not isinstance(event, DomainEvent):
        raise ValidationError("A typed DomainEvent is required.")
    from apps.workflow.services import get_outbox_handler

    if get_outbox_handler(event.event_type) is None:
        raise ValidationError("Event type is not registered.")
    return event
