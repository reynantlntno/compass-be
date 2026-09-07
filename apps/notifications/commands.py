"""Framework-neutral mutation commands for the notifications domain."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

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
