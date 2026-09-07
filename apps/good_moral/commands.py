"""Frozen, framework-neutral commands for Good Moral mutations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from typing import Protocol

from apps.common.exceptions import ValidationError


UNSET = object()
_MAX_ID = 64
_MAX_CODE = 64
_MAX_TEXT = 500
_MAX_NOTE = 1000


def _text(value, field: str, *, maximum: int = _MAX_TEXT, required: bool = False) -> str:
    if value is not None and not isinstance(value, str):
        raise ValidationError(f"{field} must be a string.")
    normalized = "" if value is None else value.strip()
    if required and not normalized:
        raise ValidationError(f"{field} is required.")
    if len(normalized) > maximum:
        raise ValidationError(f"{field} is too long.")
    return normalized


def _id(value, field: str, *, required: bool = False) -> str | None:
    if value in (None, ""):
        if required:
            raise ValidationError(f"{field} is required.")
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValidationError(f"{field} is invalid.")
    normalized = str(value).strip()
    if not normalized or len(normalized) > _MAX_ID or any(char.isspace() for char in normalized):
        raise ValidationError(f"{field} is invalid.")
    return normalized


def _optional(value, field: str, *, maximum: int = _MAX_TEXT):
    if value is UNSET:
        return UNSET
    if value is None:
        return None
    return _text(value, field, maximum=maximum)


def _date(value, field: str, *, required: bool = False):
    if value in (None, ""):
        if required:
            raise ValidationError(f"{field} is required.")
        return None
    if not isinstance(value, date):
        raise ValidationError(f"{field} is invalid.")
    return value


def _amount(value) -> Decimal:
    if isinstance(value, bool):
        raise ValidationError("receipt_amount is invalid.")
    try:
        amount = value if isinstance(value, Decimal) else Decimal(str(value))
    except Exception as exc:
        raise ValidationError("receipt_amount is invalid.") from exc
    if amount < 0 or amount.as_tuple().exponent < -2:
        raise ValidationError("receipt_amount is invalid.")
    if len(amount.as_tuple().digits) > 10:
        raise ValidationError("receipt_amount is invalid.")
    return amount


def _expected_updated_at(value):
    if value in (None, ""):
        return None
    if not isinstance(value, str) or len(value) > 40:
        raise ValidationError("expected_updated_at is invalid.")
    return value


class CommandInput(Protocol):
    """Marker protocol for validated, immutable domain command DTOs."""


@dataclass(frozen=True, slots=True)
class GoodMoralDraftCommand:
    requester_user_id: str
    student_profile_id: str
    purpose_text: str
    academic_year: str | None = None
    semester: str = ""
    major: str = ""
    graduation_date: date | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "requester_user_id", _id(self.requester_user_id, "requester_user_id", required=True))
        object.__setattr__(self, "student_profile_id", _id(self.student_profile_id, "student_profile_id", required=True))
        object.__setattr__(self, "purpose_text", _text(self.purpose_text, "purpose_text", required=True))
        object.__setattr__(self, "academic_year", _optional(self.academic_year, "academic_year", maximum=32))
        object.__setattr__(self, "semester", _text(self.semester, "semester", maximum=100))
        object.__setattr__(self, "major", _text(self.major, "major", maximum=100))
        object.__setattr__(self, "graduation_date", _date(self.graduation_date, "graduation_date"))


@dataclass(frozen=True, slots=True)
class GoodMoralDraftUpdateCommand:
    purpose_text: str | object = UNSET
    semester: str | object = UNSET
    major: str | object = UNSET
    graduation_date: date | None | object = UNSET
    expected_updated_at: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "purpose_text", _optional(self.purpose_text, "purpose_text"))
        object.__setattr__(self, "semester", _optional(self.semester, "semester", maximum=100))
        object.__setattr__(self, "major", _optional(self.major, "major", maximum=100))
        if self.graduation_date is not UNSET:
            object.__setattr__(self, "graduation_date", _date(self.graduation_date, "graduation_date"))
        object.__setattr__(self, "expected_updated_at", _expected_updated_at(self.expected_updated_at))

    def has(self, field: str) -> bool:
        return getattr(self, field) is not UNSET


@dataclass(frozen=True, slots=True)
class GoodMoralReasonCommand:
    reason_code: str = ""
    note: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason_code", _text(self.reason_code, "reason_code", maximum=_MAX_CODE))
        object.__setattr__(self, "note", _text(self.note, "note", maximum=_MAX_NOTE))


@dataclass(frozen=True, slots=True)
class GoodMoralReceiptEncodeCommand:
    receipt_number: str
    receipt_date: date
    receipt_amount: Decimal

    def __post_init__(self) -> None:
        object.__setattr__(self, "receipt_number", _text(self.receipt_number, "receipt_number", maximum=100, required=True))
        object.__setattr__(self, "receipt_date", _date(self.receipt_date, "receipt_date", required=True))
        object.__setattr__(self, "receipt_amount", _amount(self.receipt_amount))


@dataclass(frozen=True, slots=True)
class GoodMoralReceiptVerificationCommand:
    approved: bool
    rejection_code: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.approved, bool):
            raise ValidationError("approved must be a boolean.")
        object.__setattr__(self, "rejection_code", _text(self.rejection_code, "rejection_code", maximum=_MAX_CODE))
        if not self.approved and not self.rejection_code:
            raise ValidationError("rejection_code is required when receipt verification is rejected.")


@dataclass(frozen=True, slots=True)
class GoodMoralReviewerCommand:
    reviewer_user_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "reviewer_user_id", _id(self.reviewer_user_id, "reviewer_user_id", required=True))


@dataclass(frozen=True, slots=True)
class GoodMoralOssdVerificationCommand:
    status: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", _text(self.status, "status", maximum=_MAX_CODE, required=True))


@dataclass(frozen=True, slots=True)
class GoodMoralApprovalCommand:
    signatory_name: str
    signatory_title: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "signatory_name", _text(self.signatory_name, "signatory_name", maximum=255, required=True))
        object.__setattr__(self, "signatory_title", _text(self.signatory_title, "signatory_title", maximum=255, required=True))


@dataclass(frozen=True, slots=True)
class GoodMoralLifecycleCommand:
    """Marker command for lifecycle operations with no caller-controlled data."""


@dataclass(frozen=True, slots=True)
class GoodMoralArchiveCommand:
    reason_code: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason_code", _text(self.reason_code, "reason_code", maximum=_MAX_CODE))
