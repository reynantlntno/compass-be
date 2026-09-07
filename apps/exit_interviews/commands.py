"""Frozen commands for the Exit Interview response boundary."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from apps.common.exceptions import ValidationError
from apps.common.form_values import (
    ValidatedAnswerSet,
    normalize_command_id,
    normalize_command_text,
    normalize_expected_updated_at,
)


_id = normalize_command_id
_text = normalize_command_text
_expected_updated_at = normalize_expected_updated_at


@dataclass(frozen=True, slots=True)
class ExitInterviewStartCommand:
    form_revision_id: str
    student_profile_id: str | None = None
    form_collection_id: str | None = None
    form_invitation_id: str | None = None
    academic_year: str | None = None

    def __post_init__(self) -> None:
        for field_name in ("student_profile_id", "form_revision_id", "form_collection_id", "form_invitation_id"):
            object.__setattr__(self, field_name, _id(getattr(self, field_name), field_name, required=field_name == "form_revision_id"))
        object.__setattr__(self, "academic_year", _text(self.academic_year, "academic_year", maximum=32))
        if not self.student_profile_id and not self.form_invitation_id:
            raise ValidationError("student_profile_id or form_invitation_id is required.")


@dataclass(frozen=True, slots=True)
class ExitInterviewDraftCommand:
    answers: ValidatedAnswerSet
    expected_updated_at: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.answers, ValidatedAnswerSet):
            raise ValidationError("answers must be a revision-validated answer set.")
        object.__setattr__(self, "expected_updated_at", _expected_updated_at(self.expected_updated_at))


@dataclass(frozen=True, slots=True)
class ExitInterviewReasonCommand:
    reason: str
    expected_updated_at: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason", _text(self.reason, "reason", maximum=1000, required=True))
        object.__setattr__(self, "expected_updated_at", _expected_updated_at(self.expected_updated_at))


@dataclass(frozen=True, slots=True)
class ExitInterviewAssignmentCommand:
    student_profile_id: str
    collection_id: str | None = None
    due_at: datetime | None = None
    graduation_year: str = ""
    expected_updated_at: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "student_profile_id", _id(self.student_profile_id, "student_profile_id", required=True))
        object.__setattr__(self, "collection_id", _id(self.collection_id, "collection_id"))
        if self.due_at is not None and not isinstance(self.due_at, datetime):
            raise ValidationError("due_at is invalid.")
        object.__setattr__(self, "graduation_year", _text(self.graduation_year, "graduation_year", maximum=20))
        object.__setattr__(self, "expected_updated_at", _expected_updated_at(self.expected_updated_at))


@dataclass(frozen=True, slots=True)
class ExitInterviewAssignmentReassignCommand:
    assignment_id: str
    student_profile_id: str
    due_at: datetime | None = None
    graduation_year: str = ""
    expected_updated_at: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "assignment_id", _id(self.assignment_id, "assignment_id", required=True))
        object.__setattr__(self, "student_profile_id", _id(self.student_profile_id, "student_profile_id", required=True))
        if self.due_at is not None and not isinstance(self.due_at, datetime):
            raise ValidationError("due_at is invalid.")
        object.__setattr__(self, "graduation_year", _text(self.graduation_year, "graduation_year", maximum=20))
        object.__setattr__(self, "expected_updated_at", _expected_updated_at(self.expected_updated_at))


@dataclass(frozen=True, slots=True)
class ExitInterviewLifecycleCommand:
    expected_updated_at: str | None = None
    reason: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "expected_updated_at", _expected_updated_at(self.expected_updated_at))
        object.__setattr__(self, "reason", _text(self.reason, "reason", maximum=1000))


@dataclass(frozen=True, slots=True)
class ExitInterviewAcknowledgeCommand:
    expected_updated_at: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "expected_updated_at", _expected_updated_at(self.expected_updated_at))
