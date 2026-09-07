"""Frozen, framework-neutral commands for Referral mutations.

Only bounded primitives and stable identifiers cross the service boundary.
HTTP payload dictionaries and Django model instances stay in their adapters
and selectors respectively.
"""

from dataclasses import dataclass
from datetime import date, datetime

from apps.common.exceptions import ValidationError


UNSET = object()
_MAX_ID = 64
_MAX_CODE = 64
_MAX_TEXT = 2000
_MAX_NOTE = 4000


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
    if not normalized or len(normalized) > _MAX_ID:
        raise ValidationError(f"{field} is invalid.")
    return normalized


def _optional(value, field: str, *, maximum: int = _MAX_TEXT):
    if value is UNSET:
        return UNSET
    if value is None:
        return None
    return _text(value, field, maximum=maximum)


@dataclass(frozen=True)
class ReferralDraftCommand:
    source_type: str
    reason_category_code: str = "UNCATEGORIZED"
    reason_text: str = ""
    referred_by_user_id: str | None = None
    referrer_display_snapshot: str = ""
    occurred_at: datetime | None = None
    source_signed_on: date | None = None
    course_snapshot: str = ""
    year_level_snapshot: str = ""
    block_snapshot: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_type", _text(self.source_type, "source_type", maximum=_MAX_CODE, required=True))
        object.__setattr__(self, "reason_category_code", _text(self.reason_category_code, "reason_category_code", maximum=_MAX_CODE, required=True))
        object.__setattr__(self, "reason_text", _text(self.reason_text, "reason_text"))
        object.__setattr__(self, "referred_by_user_id", _id(self.referred_by_user_id, "referred_by_user_id"))
        for field in ("referrer_display_snapshot", "course_snapshot", "year_level_snapshot", "block_snapshot"):
            object.__setattr__(self, field, _text(getattr(self, field), field, maximum=255))
        if self.occurred_at is not None and not isinstance(self.occurred_at, datetime):
            raise ValidationError("occurred_at is invalid.")
        if self.source_signed_on is not None and not isinstance(self.source_signed_on, date):
            raise ValidationError("source_signed_on is invalid.")


@dataclass(frozen=True)
class ReferralSubmitCommand:
    reason_category_code: str | object = UNSET
    reason_text: str | object = UNSET
    referrer_display_snapshot: str | object = UNSET
    course_snapshot: str | object = UNSET
    year_level_snapshot: str | object = UNSET
    block_snapshot: str | object = UNSET
    occurred_at: datetime | None | object = UNSET
    source_signed_on: date | None | object = UNSET

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason_category_code", _optional(self.reason_category_code, "reason_category_code", maximum=_MAX_CODE))
        for field in ("reason_text", "referrer_display_snapshot", "course_snapshot", "year_level_snapshot", "block_snapshot"):
            object.__setattr__(self, field, _optional(getattr(self, field), field, maximum=255 if field != "reason_text" else _MAX_TEXT))
        if self.occurred_at is not UNSET and self.occurred_at is not None and not isinstance(self.occurred_at, datetime):
            raise ValidationError("occurred_at is invalid.")
        if self.source_signed_on is not UNSET and self.source_signed_on is not None and not isinstance(self.source_signed_on, date):
            raise ValidationError("source_signed_on is invalid.")

    def has(self, field: str) -> bool:
        return getattr(self, field) is not UNSET


@dataclass(frozen=True)
class ReferralActionCommand:
    action_code: str
    outcome_code: str = ""
    remarks: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "action_code", _text(self.action_code, "action_code", maximum=_MAX_CODE, required=True))
        object.__setattr__(self, "outcome_code", _text(self.outcome_code, "outcome_code", maximum=_MAX_CODE))
        object.__setattr__(self, "remarks", _text(self.remarks, "remarks", maximum=_MAX_NOTE))


@dataclass(frozen=True)
class ReferralTransitionCommand:
    reason_code: str
    reason_detail: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason_code", _text(self.reason_code, "reason_code", maximum=_MAX_CODE, required=True))
        object.__setattr__(self, "reason_detail", _text(self.reason_detail, "reason_detail", maximum=_MAX_NOTE))


@dataclass(frozen=True)
class ReferralAssignmentCommand:
    counselor_id: str
    reason_code: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "counselor_id", _id(self.counselor_id, "counselor_id", required=True))
        object.__setattr__(self, "reason_code", _text(self.reason_code, "reason_code", maximum=_MAX_CODE, required=True))


@dataclass(frozen=True)
class ReferralReassignmentRequestCommand:
    proposed_counselor_id: str | None
    request_reason_code: str
    request_detail: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "proposed_counselor_id", _id(self.proposed_counselor_id, "proposed_counselor_id"))
        object.__setattr__(self, "request_reason_code", _text(self.request_reason_code, "request_reason_code", maximum=_MAX_CODE, required=True))
        object.__setattr__(self, "request_detail", _text(self.request_detail, "request_detail", maximum=_MAX_NOTE))


@dataclass(frozen=True)
class ReferralReassignmentDecisionCommand:
    decision: str
    decision_code: str
    decision_detail: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "decision", _text(self.decision, "decision", maximum=_MAX_CODE, required=True))
        object.__setattr__(self, "decision_code", _text(self.decision_code, "decision_code", maximum=_MAX_CODE, required=True))
        object.__setattr__(self, "decision_detail", _text(self.decision_detail, "decision_detail", maximum=_MAX_NOTE))
