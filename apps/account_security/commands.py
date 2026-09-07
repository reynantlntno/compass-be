"""Framework-neutral command boundary for account-security operations."""

from dataclasses import dataclass, field
from uuid import UUID
from typing import Protocol

from apps.account_security.recovery_assistance import STAFF_RECOVERY_REASON_CODES
from apps.common.exceptions import ValidationError


class CommandInput(Protocol):
    """Marker protocol for validated, immutable domain command DTOs."""


_ACTIVITY_CATEGORIES = frozenset({"security", "work", "technical", "privacy", "all"})


def _bounded_text(value: object, *, field_name: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValidationError(field_errors={field_name: ["The value is invalid."]})
    return value.strip()


def _bounded_secret(value: object, *, field_name: str, maximum: int = 512) -> str:
    """Validate request-local secret material without normalizing its value."""
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or any(character in value for character in ("\r", "\n", "\x00"))
    ):
        raise ValidationError(field_errors={field_name: ["The value is invalid."]})
    return value


@dataclass(frozen=True, slots=True)
class ActivityQueryCommand:
    """Bounded category selection for the user-owned activity feed."""

    category: str = "all"

    def __post_init__(self) -> None:
        category = _bounded_text(self.category, field_name="category", maximum=20).lower()
        if category not in _ACTIVITY_CATEGORIES:
            raise ValidationError(field_errors={"category": ["The activity category is invalid."]})
        object.__setattr__(self, "category", category)


@dataclass(frozen=True, slots=True)
class SessionRevokeCommand:
    session_token: str = field(repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "session_token", _bounded_text(self.session_token, field_name="session_token"))


@dataclass(frozen=True, slots=True)
class SessionRevokeOthersCommand:
    """Marker command for terminating every other owned session."""


@dataclass(frozen=True, slots=True)
class TrustedDeviceRevokeCommand:
    device_id: UUID

    def __post_init__(self) -> None:
        if not isinstance(self.device_id, UUID):
            raise ValidationError(field_errors={"device_id": ["The device identifier is invalid."]})


@dataclass(frozen=True, slots=True)
class TrustedDeviceRevokeAllCommand:
    """Marker command for terminating every owned trusted device."""


@dataclass(frozen=True, slots=True)
class PasswordChangeCommand:
    current_password: str = field(repr=False)
    new_password: str = field(repr=False)
    password_confirmation: str = field(repr=False)

    def __post_init__(self) -> None:
        for name in ("current_password", "new_password", "password_confirmation"):
            _bounded_text(getattr(self, name), field_name=name, maximum=512)
        if self.new_password != self.password_confirmation:
            raise ValidationError(field_errors={"password_confirmation": ["The passwords do not match."]})


@dataclass(frozen=True, slots=True)
class RecoveryRequestCommand:
    email: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "email", _bounded_text(self.email, field_name="email", maximum=320))


@dataclass(frozen=True, slots=True)
class RecoveryResetCommand:
    token: str = field(repr=False)
    new_password: str = field(repr=False)
    password_confirmation: str = field(repr=False)

    def __post_init__(self) -> None:
        for name in ("token", "new_password", "password_confirmation"):
            _bounded_text(getattr(self, name), field_name=name, maximum=1024 if name == "token" else 512)
        if self.new_password != self.password_confirmation:
            raise ValidationError(field_errors={"password_confirmation": ["The passwords do not match."]})


@dataclass(frozen=True, slots=True)
class ITAdminRecoveryCommand:
    """Operator-only input for recovering an existing IT Admin account.

    The password is request-local input.  It is excluded from representation
    and equality so the command cannot leak credentials through diagnostics,
    idempotency fingerprints, or audit metadata.
    """

    email: str
    new_password: str = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "email", _bounded_text(self.email, field_name="email", maximum=320))
        _bounded_secret(self.new_password, field_name="new_password", maximum=512)


@dataclass(frozen=True, slots=True)
class StaffAssistedRecoveryCommand:
    """Bounded target and reason input for the IT Admin recovery API."""

    target_account_id: int
    reason_category: str
    email_ownership_attested: bool = False

    def __post_init__(self) -> None:
        if type(self.target_account_id) is not int or self.target_account_id <= 0:
            raise ValidationError(field_errors={"target_account_id": ["The account identifier is invalid."]})
        reason = _bounded_text(self.reason_category, field_name="reason_category", maximum=64).lower()
        if reason not in STAFF_RECOVERY_REASON_CODES:
            raise ValidationError(field_errors={"reason_category": ["The recovery reason is invalid."]})
        if type(self.email_ownership_attested) is not bool:
            raise ValidationError(field_errors={"email_ownership_attested": ["The attestation value is invalid."]})
        object.__setattr__(self, "reason_category", reason)


@dataclass(frozen=True, slots=True)
class OtpResendCommand:
    challenge_id: UUID
    pending_nonce: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.challenge_id, UUID):
            raise ValidationError(field_errors={"challenge_id": ["The challenge identifier is invalid."]})
        object.__setattr__(self, "pending_nonce", _bounded_text(self.pending_nonce, field_name="pending_nonce"))
