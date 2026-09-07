"""Frozen, framework-neutral commands for student onboarding.

The API and management-command adapters construct these values explicitly.
No Django request, model, uploaded-file object, or arbitrary mapping crosses
the domain mutation boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from apps.common.exceptions import ValidationError
from apps.common.form_values import normalize_command_id, normalize_command_text, normalize_expected_updated_at


class CommandInput(Protocol):
    """Marker protocol for validated, immutable domain command DTOs."""


UNSET = object()


def _text(value, name: str, *, maximum: int = 255, required: bool = False) -> str:
    return normalize_command_text(value, name, maximum=maximum, required=required)


def _id(value, name: str, *, required: bool = False) -> str | None:
    return normalize_command_id(value, name, required=required)


@dataclass(frozen=True, slots=True)
class ImportBatchCreateCommand:
    """Metadata for one student_onboarding CSV staging operation."""

    source_name: str
    academic_year: str
    filename: str = ""
    content_type: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_name", _text(self.source_name, "source_name", maximum=255, required=True))
        object.__setattr__(self, "academic_year", _text(self.academic_year, "academic_year", maximum=9, required=True))
        object.__setattr__(self, "filename", _text(self.filename, "filename", maximum=255))
        object.__setattr__(self, "content_type", _text(self.content_type, "content_type", maximum=100))


@dataclass(frozen=True, slots=True)
class ImportBatchReplacementCommand:
    source_name: str
    academic_year: str
    filename: str = ""
    content_type: str = ""
    expected_updated_at: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_name", _text(self.source_name, "source_name", maximum=255, required=True))
        object.__setattr__(self, "academic_year", _text(self.academic_year, "academic_year", maximum=9, required=True))
        object.__setattr__(self, "filename", _text(self.filename, "filename", maximum=255))
        object.__setattr__(self, "content_type", _text(self.content_type, "content_type", maximum=100))
        object.__setattr__(self, "expected_updated_at", normalize_expected_updated_at(self.expected_updated_at))


@dataclass(frozen=True, slots=True)
class StudentAccountProvisionCommand:
    """Allowlisted student fields used by the student_onboarding execution step."""

    email: str = field(repr=False)
    first_name: str = field(repr=False)
    last_name: str = field(repr=False)
    student_number: str | None = field(default=None, repr=False)
    control_number: str | None = field(default=None, repr=False)
    campus: str = ""
    college: str = ""
    department: str = ""
    program: str = ""
    year_level: int | None = None
    lifecycle_status: str = "ACTIVE"

    def __post_init__(self) -> None:
        object.__setattr__(self, "email", _text(self.email, "email", maximum=254, required=True))
        object.__setattr__(self, "first_name", _text(self.first_name, "first_name", maximum=150, required=True))
        object.__setattr__(self, "last_name", _text(self.last_name, "last_name", maximum=150, required=True))
        for name in ("student_number", "control_number"):
            value = getattr(self, name)
            object.__setattr__(self, name, None if value in (None, "") else _text(value, name, maximum=50))
        for name in ("campus", "college", "department", "program"):
            object.__setattr__(self, name, _text(getattr(self, name), name, maximum=100))
        if self.year_level is not None and (
            isinstance(self.year_level, bool) or not isinstance(self.year_level, int) or not 1 <= self.year_level <= 99
        ):
            raise ValidationError("year_level is invalid.")
        object.__setattr__(self, "lifecycle_status", _text(self.lifecycle_status, "lifecycle_status", maximum=30, required=True))


@dataclass(frozen=True, slots=True)
class ImportBatchLifecycleCommand:
    expected_updated_at: str | None = None
    reason: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "expected_updated_at", normalize_expected_updated_at(self.expected_updated_at))
        object.__setattr__(self, "reason", _text(self.reason, "reason", maximum=1000))


@dataclass(frozen=True, slots=True)
class ImportRowCorrectionCommand:
    """Allowlisted correction fields; omitted fields remain unchanged."""

    student_number: str | None | object = field(default=UNSET, repr=False)
    control_number: str | None | object = field(default=UNSET, repr=False)
    email: str | None | object = field(default=UNSET, repr=False)
    first_name: str | object = field(default=UNSET, repr=False)
    last_name: str | object = field(default=UNSET, repr=False)
    program_code: str | object = field(default=UNSET, repr=False)
    campus: str | object = field(default=UNSET, repr=False)
    college: str | object = field(default=UNSET, repr=False)
    department: str | object = field(default=UNSET, repr=False)
    program: str | object = field(default=UNSET, repr=False)
    year_level: int | None | object = field(default=UNSET, repr=False)
    lifecycle_status: str | object = field(default=UNSET, repr=False)
    expected_updated_at: str | None = None

    def __post_init__(self) -> None:
        for name in (
            "student_number", "control_number", "email", "first_name", "last_name",
            "program_code", "campus", "college", "department", "program", "lifecycle_status",
        ):
            value = getattr(self, name)
            if value is not UNSET and value is not None:
                object.__setattr__(self, name, _text(value, name, maximum=254 if name == "email" else 150, required=name in {"first_name", "last_name"}))
        if self.year_level is not UNSET and self.year_level is not None:
            if isinstance(self.year_level, bool) or not isinstance(self.year_level, int) or not 1 <= self.year_level <= 99:
                raise ValidationError("year_level is invalid.")
        object.__setattr__(self, "expected_updated_at", normalize_expected_updated_at(self.expected_updated_at))
        if not any(getattr(self, name) is not UNSET for name in self.field_names()):
            raise ValidationError("At least one correctable field is required.")

    @classmethod
    def field_names(cls) -> tuple[str, ...]:
        return (
            "student_number", "control_number", "email", "first_name", "last_name",
            "program_code", "campus", "college", "department", "program", "year_level", "lifecycle_status",
        )

    def updates(self) -> dict:
        return {name: getattr(self, name) for name in self.field_names() if getattr(self, name) is not UNSET}


@dataclass(frozen=True, slots=True)
class ImportRowReconciliationCommand:
    student_profile_id: str
    reason: str = ""
    expected_updated_at: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "student_profile_id", _id(self.student_profile_id, "student_profile_id", required=True))
        object.__setattr__(self, "reason", _text(self.reason, "reason", maximum=1000))
        object.__setattr__(self, "expected_updated_at", normalize_expected_updated_at(self.expected_updated_at))


@dataclass(frozen=True, slots=True)
class ImportRowDecisionCommand:
    reason: str = ""
    expected_updated_at: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason", _text(self.reason, "reason", maximum=1000))
        object.__setattr__(self, "expected_updated_at", normalize_expected_updated_at(self.expected_updated_at))


@dataclass(frozen=True, slots=True)
class ImportBatchExecuteCommand:
    expected_updated_at: str | None = None
    request_key_digest: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "expected_updated_at", normalize_expected_updated_at(self.expected_updated_at))
        digest = _text(self.request_key_digest, "request_key_digest", maximum=64, required=True)
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest.lower()):
            raise ValidationError("request_key_digest is invalid.")
        object.__setattr__(self, "request_key_digest", digest.lower())


@dataclass(frozen=True, slots=True)
class ActivationInvitationIssueCommand:
    expected_updated_at: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "expected_updated_at", normalize_expected_updated_at(self.expected_updated_at))


@dataclass(frozen=True, slots=True)
class ActivationInvitationReissueCommand:
    reason: str = "manual_reissue"
    expected_updated_at: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason", _text(self.reason, "reason", maximum=80, required=True))
        object.__setattr__(self, "expected_updated_at", normalize_expected_updated_at(self.expected_updated_at))


@dataclass(frozen=True, slots=True)
class ActivationInvitationRevokeCommand:
    reason: str = "manual_revocation"
    expected_updated_at: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason", _text(self.reason, "reason", maximum=80, required=True))
        object.__setattr__(self, "expected_updated_at", normalize_expected_updated_at(self.expected_updated_at))
