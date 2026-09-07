"""Frozen commands for the Graduate Tracer response boundary."""

from __future__ import annotations

from dataclasses import dataclass

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
class GraduateTracerStartCommand:
    student_profile_id: str | None
    form_revision_id: str
    form_collection_id: str | None = None
    form_invitation_id: str | None = None
    unlinked_submission_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "student_profile_id", _id(self.student_profile_id, "student_profile_id"))
        object.__setattr__(self, "form_revision_id", _id(self.form_revision_id, "form_revision_id", required=True))
        object.__setattr__(self, "form_collection_id", _id(self.form_collection_id, "form_collection_id"))
        object.__setattr__(self, "form_invitation_id", _id(self.form_invitation_id, "form_invitation_id"))
        object.__setattr__(self, "unlinked_submission_id", _id(self.unlinked_submission_id, "unlinked_submission_id"))
        if not self.student_profile_id and not self.unlinked_submission_id and not self.form_invitation_id:
            raise ValidationError("student_profile_id, unlinked_submission_id, or form_invitation_id is required.")
        if self.student_profile_id and self.unlinked_submission_id:
            raise ValidationError("Only one response owner may be supplied.")


@dataclass(frozen=True, slots=True)
class GraduateTracerDraftCommand:
    answers: ValidatedAnswerSet
    expected_updated_at: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.answers, ValidatedAnswerSet):
            raise ValidationError("answers must be a revision-validated answer set.")
        object.__setattr__(self, "expected_updated_at", _expected_updated_at(self.expected_updated_at))


@dataclass(frozen=True, slots=True)
class GraduateTracerLifecycleCommand:
    expected_updated_at: str | None = None
    reason: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "expected_updated_at", _expected_updated_at(self.expected_updated_at))
        object.__setattr__(self, "reason", _text(self.reason, "reason", maximum=1000))
