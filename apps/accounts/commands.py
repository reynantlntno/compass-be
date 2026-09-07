"""Framework-neutral mutation command boundary for the accounts domain.

Commands are frozen value objects. Domain-specific commands are added here
when a route is introduced; HTTP requests and arbitrary data dictionaries do
not cross this boundary.
"""

from dataclasses import dataclass, field
from typing import Protocol

from apps.accounts.models import RoleChoices
from apps.common.exceptions import ValidationError


class CommandInput(Protocol):
    """Marker protocol for validated, immutable domain command DTOs."""


def _bounded_text(value: object, *, label: str, maximum: int, required: bool = True) -> str:
    if type(value) is not str:
        raise ValidationError(f"{label} must be a bounded text value.")
    normalized = value.strip()
    if required and not normalized:
        raise ValidationError(f"{label} is required.")
    if len(normalized) > maximum or "\x00" in normalized:
        raise ValidationError(f"{label} exceeds its allowed length.")
    return normalized


def _bootstrap_password(value: object) -> str:
    if type(value) is not str or not value or len(value) > 256:
        raise ValidationError("The bootstrap password is invalid.")
    if any(character in value for character in ("\r", "\n", "\x00")):
        raise ValidationError("The bootstrap password is invalid.")
    return value


@dataclass(frozen=True)
class StaffAccountCreateCommand:
    email: str
    first_name: str
    last_name: str
    role: str
    license_number: str = ""
    designation: str = ""
    validity_days: int | None = None
    source_reference: str = ""

    def __post_init__(self):
        if self.role not in {RoleChoices.COUNSELOR, RoleChoices.GCO_STAFF, RoleChoices.IT_ADMIN}:
            raise ValueError("Unsupported staff account role.")


@dataclass(frozen=True)
class StaffInvitationActivationCommand:
    token: str
    password: str
    password_confirmation: str


@dataclass(frozen=True, slots=True)
class ITAdminBootstrapCommand:
    """The one-time IT Admin bootstrap input.

    The password is intentionally excluded from equality and repr output.  It
    exists only at the secure command boundary and is never suitable for
    audit, request-deduplication, or logging metadata.
    """

    email: str
    first_name: str
    last_name: str
    password: str = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "email", _bounded_text(self.email, label="Email", maximum=254))
        object.__setattr__(self, "first_name", _bounded_text(self.first_name, label="First name", maximum=150))
        object.__setattr__(self, "last_name", _bounded_text(self.last_name, label="Last name", maximum=150))
        object.__setattr__(self, "password", _bootstrap_password(self.password))


@dataclass(frozen=True, slots=True)
class InitialHeadGuidanceBootstrapCommand:
    """Bounded identity input for the first inactive Head Guidance counselor."""

    email: str
    first_name: str
    last_name: str
    license_number: str = ""
    validity_days: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "email", _bounded_text(self.email, label="Email", maximum=254))
        object.__setattr__(self, "first_name", _bounded_text(self.first_name, label="First name", maximum=150))
        object.__setattr__(self, "last_name", _bounded_text(self.last_name, label="Last name", maximum=150))
        object.__setattr__(
            self,
            "license_number",
            _bounded_text(self.license_number, label="License number", maximum=50, required=False),
        )
        if self.validity_days is not None and (
            type(self.validity_days) is not int or not 1 <= self.validity_days <= 14
        ):
            raise ValidationError("Invitation validity must be between one and fourteen days.")
