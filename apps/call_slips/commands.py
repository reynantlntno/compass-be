"""Frozen, framework-neutral commands for Call Slip mutations."""

from dataclasses import dataclass
from datetime import datetime

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
class CallSlipDraftCommand:
    student_id: str
    source_type: str
    purpose_code: str
    destination_code: str
    referral_reference: str | None = None
    appointment_reference: str | None = None
    reissued_from_reference: str | None = None
    reissue_reason_code: str = ""
    assigned_counselor_id: str | None = None
    report_to_destination: str = ""
    mode: str = "ONSITE"
    student_safe_location: str = ""
    student_safe_instructions: str = ""
    office_only_remarks: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "student_id", _id(self.student_id, "student_id", required=True))
        for field in ("source_type", "purpose_code", "destination_code", "reissue_reason_code", "mode"):
            object.__setattr__(self, field, _text(getattr(self, field), field, maximum=_MAX_CODE, required=field in {"source_type", "purpose_code", "destination_code"}))
        for field in ("referral_reference", "appointment_reference", "reissued_from_reference", "assigned_counselor_id"):
            object.__setattr__(self, field, _id(getattr(self, field), field))
        for field in ("report_to_destination", "student_safe_location"):
            object.__setattr__(self, field, _text(getattr(self, field), field, maximum=255))
        object.__setattr__(self, "student_safe_instructions", _text(self.student_safe_instructions, "student_safe_instructions", maximum=_MAX_NOTE))
        object.__setattr__(self, "office_only_remarks", _text(self.office_only_remarks, "office_only_remarks", maximum=_MAX_NOTE))

    def has(self, field: str) -> bool:
        return hasattr(self, field)


@dataclass(frozen=True)
class CallSlipCreateFromReferralCommand:
    referral_reference: str
    reissued_from_reference: str | None = None
    reissue_reason_code: str = ""
    destination_code: str = "GUIDANCE_OFFICE"
    report_to_destination: str = ""
    mode: str = "ONSITE"
    student_safe_location: str = ""
    student_safe_instructions: str = ""
    office_only_remarks: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "referral_reference", _id(self.referral_reference, "referral_reference", required=True))
        object.__setattr__(self, "reissued_from_reference", _id(self.reissued_from_reference, "reissued_from_reference"))
        object.__setattr__(self, "reissue_reason_code", _text(self.reissue_reason_code, "reissue_reason_code", maximum=_MAX_CODE))
        object.__setattr__(self, "destination_code", _text(self.destination_code, "destination_code", maximum=_MAX_CODE, required=True))
        object.__setattr__(self, "report_to_destination", _text(self.report_to_destination, "report_to_destination", maximum=255))
        object.__setattr__(self, "mode", _text(self.mode, "mode", maximum=_MAX_CODE, required=True))
        object.__setattr__(self, "student_safe_location", _text(self.student_safe_location, "student_safe_location", maximum=255))
        object.__setattr__(self, "student_safe_instructions", _text(self.student_safe_instructions, "student_safe_instructions", maximum=_MAX_NOTE))
        object.__setattr__(self, "office_only_remarks", _text(self.office_only_remarks, "office_only_remarks", maximum=_MAX_NOTE))


@dataclass(frozen=True)
class CallSlipDraftUpdateCommand:
    source_type: str | object = UNSET
    purpose_code: str | object = UNSET
    destination_code: str | object = UNSET
    assigned_counselor_id: str | None | object = UNSET
    report_to_destination: str | object = UNSET
    mode: str | object = UNSET
    student_safe_location: str | object = UNSET
    student_safe_instructions: str | object = UNSET
    office_only_remarks: str | object = UNSET

    def __post_init__(self) -> None:
        for field in ("source_type", "purpose_code", "destination_code", "mode"):
            object.__setattr__(self, field, _optional(getattr(self, field), field, maximum=_MAX_CODE))
        value = self.assigned_counselor_id
        object.__setattr__(self, "assigned_counselor_id", UNSET if value is UNSET else _id(value, "assigned_counselor_id"))
        for field in ("report_to_destination", "student_safe_location"):
            object.__setattr__(self, field, _optional(getattr(self, field), field, maximum=255))
        for field in ("student_safe_instructions", "office_only_remarks"):
            object.__setattr__(self, field, _optional(getattr(self, field), field, maximum=_MAX_NOTE))

    def has(self, field: str) -> bool:
        return getattr(self, field) is not UNSET


@dataclass(frozen=True)
class CallSlipIssueCommand:
    scheduled_start_at: datetime
    scheduled_end_at: datetime
    expected_duration_minutes: int = 60
    assigned_counselor_id: str | None | object = UNSET
    mode: str | object = UNSET
    report_to_destination: str | object = UNSET
    student_safe_location: str | object = UNSET
    student_safe_instructions: str | object = UNSET

    def __post_init__(self) -> None:
        if not isinstance(self.scheduled_start_at, datetime) or not isinstance(self.scheduled_end_at, datetime):
            raise ValidationError("Call Slip schedule timestamps are invalid.")
        if isinstance(self.expected_duration_minutes, bool) or not isinstance(self.expected_duration_minutes, int) or not 1 <= self.expected_duration_minutes <= 480:
            raise ValidationError("expected_duration_minutes is invalid.")
        if self.scheduled_end_at <= self.scheduled_start_at:
            raise ValidationError("scheduled_end_at must be after scheduled_start_at.")
        if self.assigned_counselor_id is not UNSET:
            object.__setattr__(self, "assigned_counselor_id", _id(self.assigned_counselor_id, "assigned_counselor_id"))
        object.__setattr__(self, "mode", _optional(self.mode, "mode", maximum=_MAX_CODE))
        object.__setattr__(self, "report_to_destination", _optional(self.report_to_destination, "report_to_destination", maximum=255))
        object.__setattr__(self, "student_safe_location", _optional(self.student_safe_location, "student_safe_location", maximum=255))
        object.__setattr__(self, "student_safe_instructions", _optional(self.student_safe_instructions, "student_safe_instructions", maximum=_MAX_NOTE))

    def has(self, field: str) -> bool:
        return getattr(self, field) is not UNSET


@dataclass(frozen=True)
class CallSlipRescheduleCommand:
    proposed_start_at: datetime
    proposed_end_at: datetime
    proposed_expected_duration_minutes: int
    student_reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.proposed_start_at, datetime) or not isinstance(self.proposed_end_at, datetime):
            raise ValidationError("Reschedule timestamps are invalid.")
        if self.proposed_end_at <= self.proposed_start_at:
            raise ValidationError("proposed_end_at must be after proposed_start_at.")
        if isinstance(self.proposed_expected_duration_minutes, bool) or not isinstance(self.proposed_expected_duration_minutes, int) or not 1 <= self.proposed_expected_duration_minutes <= 480:
            raise ValidationError("proposed_expected_duration_minutes is invalid.")
        object.__setattr__(self, "student_reason", _text(self.student_reason, "student_reason", maximum=_MAX_NOTE, required=True))


@dataclass(frozen=True)
class CallSlipDecisionCommand:
    decision: str
    decision_code: str
    decision_detail: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "decision", _text(self.decision, "decision", maximum=_MAX_CODE, required=True))
        object.__setattr__(self, "decision_code", _text(self.decision_code, "decision_code", maximum=_MAX_CODE, required=True))
        object.__setattr__(self, "decision_detail", _text(self.decision_detail, "decision_detail", maximum=_MAX_NOTE))


@dataclass(frozen=True)
class CallSlipAttendanceCommand:
    reported_at: datetime | None = None
    interview_ended_at: datetime | None = None

    def __post_init__(self) -> None:
        for field in ("reported_at", "interview_ended_at"):
            value = getattr(self, field)
            if value is not None and not isinstance(value, datetime):
                raise ValidationError(f"{field} is invalid.")

    def has(self, field: str) -> bool:
        """Return whether an optional attendance value was explicitly supplied."""
        return getattr(self, field) is not None


@dataclass(frozen=True)
class CallSlipReasonCommand:
    reason_code: str
    detail: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason_code", _text(self.reason_code, "reason_code", maximum=_MAX_CODE, required=True))
        object.__setattr__(self, "detail", _text(self.detail, "detail", maximum=_MAX_NOTE))


@dataclass(frozen=True)
class CallSlipAssignmentCommand:
    target_counselor_id: str
    reason_code: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "target_counselor_id", _id(self.target_counselor_id, "target_counselor_id", required=True))
        object.__setattr__(self, "reason_code", _text(self.reason_code, "reason_code", maximum=_MAX_CODE, required=True))
