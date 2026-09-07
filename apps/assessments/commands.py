"""Frozen, framework-neutral commands for the assessment boundary.

Commands deliberately contain identifiers and bounded primitives only. Django
models, request objects, uploaded files, encrypted values, and arbitrary
metadata stop at the adapter/service boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar
from uuid import UUID

from apps.assessments.choices import AssessmentInterpretationVisibility
from apps.common.exceptions import ValidationError


_MAX_SOURCE_REFERENCE = 100
_MAX_SCORE = 50
_MAX_SCORE_LABEL = 100
_MAX_INTERPRETATION = 8000
_MAX_REASON = 80
_MAX_NOTES = 500
_UPDATE_FIELDS = frozenset(
    {
        "administered_at",
        "source_form_reference",
        "raw_score",
        "scaled_score",
        "score_label",
        "interpretation_text",
        "interpretation_visibility",
    }
)


def _bounded_text(value: str | None, *, name: str, maximum: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError(f"{name} must be text.")
    value = value.strip()
    if len(value) > maximum:
        raise ValidationError(f"{name} is too long.")
    return value


def _stable_id(value: int, *, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValidationError(f"{name} must be a valid stable identifier.")
    return value


def _expected_timestamp(value: datetime | None) -> datetime | None:
    if value is not None and not isinstance(value, datetime):
        raise ValidationError("expected_updated_at must be a timestamp.")
    return value


def _reason(value: str | None) -> str | None:
    value = _bounded_text(value, name="reason_code", maximum=_MAX_REASON)
    if value and any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for char in value):
        raise ValidationError("reason_code contains unsupported characters.")
    return value


@dataclass(frozen=True, slots=True)
class AssessmentCreateCommand:
    student_profile_id: int
    instrument_id: int
    administered_at: datetime | None = None
    source_form_reference: str | None = None
    expected_instrument_updated_at: datetime | None = None

    def __post_init__(self) -> None:
        _stable_id(self.student_profile_id, name="student_profile_id")
        _stable_id(self.instrument_id, name="instrument_id")
        object.__setattr__(self, "source_form_reference", _bounded_text(self.source_form_reference, name="source_form_reference", maximum=_MAX_SOURCE_REFERENCE))
        _expected_timestamp(self.administered_at)
        _expected_timestamp(self.expected_instrument_updated_at)


@dataclass(frozen=True, slots=True)
class AssessmentUpdateCommand:
    """Explicit patch command; ``fields`` is the allowlisted field mask."""

    fields: tuple[str, ...] = ()
    administered_at: datetime | None = None
    source_form_reference: str | None = None
    raw_score: str | None = None
    scaled_score: str | None = None
    score_label: str | None = None
    interpretation_text: str | None = None
    interpretation_visibility: AssessmentInterpretationVisibility | None = None
    expected_updated_at: datetime | None = None

    _allowed_fields: ClassVar[frozenset[str]] = _UPDATE_FIELDS

    def __post_init__(self) -> None:
        if not isinstance(self.fields, tuple) or any(field not in self._allowed_fields for field in self.fields):
            raise ValidationError("Assessment update contains an unsupported field.")
        if len(set(self.fields)) != len(self.fields):
            raise ValidationError("Assessment update fields must be unique.")
        object.__setattr__(self, "source_form_reference", _bounded_text(self.source_form_reference, name="source_form_reference", maximum=_MAX_SOURCE_REFERENCE))
        object.__setattr__(self, "raw_score", _bounded_text(self.raw_score, name="raw_score", maximum=_MAX_SCORE))
        object.__setattr__(self, "scaled_score", _bounded_text(self.scaled_score, name="scaled_score", maximum=_MAX_SCORE))
        object.__setattr__(self, "score_label", _bounded_text(self.score_label, name="score_label", maximum=_MAX_SCORE_LABEL))
        object.__setattr__(self, "interpretation_text", _bounded_text(self.interpretation_text, name="interpretation_text", maximum=_MAX_INTERPRETATION))
        if self.interpretation_visibility is not None and not isinstance(self.interpretation_visibility, AssessmentInterpretationVisibility):
            raise ValidationError("interpretation_visibility is invalid.")
        _expected_timestamp(self.administered_at)
        _expected_timestamp(self.expected_updated_at)


@dataclass(frozen=True, slots=True)
class AssessmentRecordCommand:
    fields: tuple[str, ...] = ()
    raw_score: str | None = None
    scaled_score: str | None = None
    score_label: str | None = None
    interpretation_text: str | None = None
    interpretation_visibility: AssessmentInterpretationVisibility | None = None
    expected_updated_at: datetime | None = None

    def __post_init__(self) -> None:
        allowed = _UPDATE_FIELDS - {"administered_at", "source_form_reference"}
        if not isinstance(self.fields, tuple) or any(field not in allowed for field in self.fields):
            raise ValidationError("Assessment result contains an unsupported field.")
        if len(set(self.fields)) != len(self.fields):
            raise ValidationError("Assessment result fields must be unique.")
        object.__setattr__(self, "raw_score", _bounded_text(self.raw_score, name="raw_score", maximum=_MAX_SCORE))
        object.__setattr__(self, "scaled_score", _bounded_text(self.scaled_score, name="scaled_score", maximum=_MAX_SCORE))
        object.__setattr__(self, "score_label", _bounded_text(self.score_label, name="score_label", maximum=_MAX_SCORE_LABEL))
        object.__setattr__(self, "interpretation_text", _bounded_text(self.interpretation_text, name="interpretation_text", maximum=_MAX_INTERPRETATION))
        if self.interpretation_visibility is not None and not isinstance(self.interpretation_visibility, AssessmentInterpretationVisibility):
            raise ValidationError("interpretation_visibility is invalid.")
        _expected_timestamp(self.expected_updated_at)


@dataclass(frozen=True, slots=True)
class AssessmentSubmitReviewCommand:
    expected_updated_at: datetime | None = None

    def __post_init__(self) -> None:
        _expected_timestamp(self.expected_updated_at)


@dataclass(frozen=True, slots=True)
class AssessmentReviewCommand:
    notes: str | None = None
    expected_updated_at: datetime | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "notes", _bounded_text(self.notes, name="notes", maximum=_MAX_NOTES))
        _expected_timestamp(self.expected_updated_at)


@dataclass(frozen=True, slots=True)
class AssessmentReleaseCommand:
    expected_updated_at: datetime | None = None

    def __post_init__(self) -> None:
        _expected_timestamp(self.expected_updated_at)


@dataclass(frozen=True, slots=True)
class AssessmentVoidCommand:
    reason_code: str | None = None
    expected_updated_at: datetime | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason_code", _reason(self.reason_code))
        _expected_timestamp(self.expected_updated_at)


@dataclass(frozen=True, slots=True)
class AssessmentSupersedeCommand:
    replacement_record_id: int
    reason_code: str | None = None
    expected_updated_at: datetime | None = None

    def __post_init__(self) -> None:
        _stable_id(self.replacement_record_id, name="replacement_record_id")
        object.__setattr__(self, "reason_code", _reason(self.reason_code))
        _expected_timestamp(self.expected_updated_at)


@dataclass(frozen=True, slots=True)
class AssessmentArchiveCommand:
    reason_code: str | None = None
    expected_updated_at: datetime | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason_code", _reason(self.reason_code))
        _expected_timestamp(self.expected_updated_at)


@dataclass(frozen=True, slots=True)
class AssessmentFileUploadReceipt:
    protected_file_id: UUID

    def __post_init__(self) -> None:
        if not isinstance(self.protected_file_id, UUID):
            raise ValidationError("protected_file_id is invalid.")
