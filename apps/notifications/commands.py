"""Framework-neutral mutation commands for the notifications domain."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from apps.common.exceptions import ValidationError


class CommandInput(Protocol):
    """Marker protocol for validated, immutable domain command DTOs."""


class DeadLetterReason(StrEnum):
    PROVIDER_PERMANENT_FAILURE = "provider_permanent_failure"
    RECIPIENT_INVALID = "recipient_invalid"
    MANUAL_OPERATIONAL_REVIEW = "manual_operational_review"


@dataclass(frozen=True, slots=True)
class NotificationReadCommand:
    """Marks one owned notification as read."""

    expected_status: str | None = None

    def __post_init__(self) -> None:
        if self.expected_status is not None and self.expected_status not in {"unread", "read", "archived"}:
            raise ValidationError(field_errors={"expected_status": ["Invalid notification status."]})


@dataclass(frozen=True, slots=True)
class NotificationArchiveCommand:
    """Archives one owned notification."""

    expected_status: str | None = None

    def __post_init__(self) -> None:
        if self.expected_status is not None and self.expected_status not in {"unread", "read", "archived"}:
            raise ValidationError(field_errors={"expected_status": ["Invalid notification status."]})


@dataclass(frozen=True, slots=True)
class NotificationBulkArchiveItemCommand:
    """One owned notification and the status observed by the client."""

    notification_id: UUID
    expected_status: str

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "notification_id", UUID(str(self.notification_id)))
        except (AttributeError, TypeError, ValueError) as exc:
            raise ValidationError(field_errors={"notification_id": ["Invalid notification identifier."]}) from exc
        if not isinstance(self.expected_status, str) or self.expected_status not in {"unread", "read"}:
            raise ValidationError(field_errors={"expected_status": ["Invalid notification status."]})


@dataclass(frozen=True, slots=True)
class NotificationBulkArchiveCommand:
    """Archives a bounded set of owned notifications atomically."""

    items: tuple[NotificationBulkArchiveItemCommand, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.items, tuple):
            object.__setattr__(self, "items", tuple(self.items or ()))
        if not self.items or len(self.items) > 100:
            raise ValidationError(field_errors={"items": ["Select between 1 and 100 notifications."]})
        if any(not isinstance(item, NotificationBulkArchiveItemCommand) for item in self.items):
            raise ValidationError(field_errors={"items": ["Invalid notification selection."]})
        identifiers = [item.notification_id for item in self.items]
        if len(set(identifiers)) != len(identifiers):
            raise ValidationError(field_errors={"items": ["A notification cannot be selected more than once."]})


@dataclass(frozen=True, slots=True)
class NotificationPreferenceUpdateCommand:
    """Replaces one allowlisted notification preference override."""

    notification_type: str
    in_app_enabled: bool
    email_enabled: bool

    def __post_init__(self) -> None:
        if not isinstance(self.notification_type, str) or not self.notification_type.strip():
            raise ValidationError(field_errors={"notification_type": ["A notification type is required."]})
        normalized = self.notification_type.strip()
        if len(normalized) > 100:
            raise ValidationError(field_errors={"notification_type": ["Notification type is too long."]})
        object.__setattr__(self, "notification_type", normalized)
        if not isinstance(self.in_app_enabled, bool):
            raise ValidationError(field_errors={"in_app_enabled": ["Expected a boolean."]})
        if not isinstance(self.email_enabled, bool):
            raise ValidationError(field_errors={"email_enabled": ["Expected a boolean."]})


@dataclass(frozen=True, slots=True)
class EmailDeliveryRetryCommand:
    """Requeues one failed or dead delivery."""

    allow_dead: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.allow_dead, bool):
            raise ValidationError(field_errors={"allow_dead": ["Expected a boolean."]})


@dataclass(frozen=True, slots=True)
class EmailDeliveryCancelCommand:
    """Cancels a pending delivery because its owning workflow was cancelled."""

    reason: str = "workflow_cancelled"

    def __post_init__(self) -> None:
        if self.reason not in {"workflow_cancelled", "invitation_revoked", "request_cancelled"}:
            raise ValidationError(field_errors={"reason": ["Unsupported cancellation reason."]})


@dataclass(frozen=True, slots=True)
class EmailDeliveryDeadLetterCommand:
    """Explicitly dead-letters one delivery with a bounded reason."""

    reason: DeadLetterReason

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "reason", DeadLetterReason(self.reason))
        except (TypeError, ValueError) as exc:
            raise ValidationError(field_errors={"reason": ["Unsupported dead-letter reason."]}) from exc
