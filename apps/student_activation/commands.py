"""Framework-neutral command values for the student activation boundary."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from apps.common.exceptions import ValidationError


class CommandInput(Protocol):
    """Marker protocol for validated, immutable domain command DTOs."""


@dataclass(frozen=True, slots=True)
class StudentActivationCommand:
    """Raw token/password values accepted only at the activation edge.

    The command is request-local.  Services must never persist or include any
    of these values in audit, outbox, or idempotency metadata.
    """

    token: str = field(repr=False)
    password: str = field(repr=False)
    password_confirmation: str = field(repr=False)

    def __post_init__(self) -> None:
        for field_name in ("token", "password", "password_confirmation"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value:
                raise ValidationError(f"{field_name} is required.")
            if len(value) > 512:
                raise ValidationError(f"{field_name} is too long.")


@dataclass(frozen=True, slots=True)
class ActivationInvitationReceipt:
    """Safe delivery receipt; it intentionally contains no verifier."""

    invitation_id: str
    expires_at: datetime
    delivery_queued: bool = True
