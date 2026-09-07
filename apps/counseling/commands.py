"""Framework-neutral mutation command boundary for the counseling domain.

Commands are frozen value objects carrying only bounded primitives, stable
references, enums, dates, timestamps, and explicitly allowlisted text fields.
HTTP requests, Django models, and arbitrary data dictionaries do not cross the
mutation-service boundary.
"""

from dataclasses import dataclass
from datetime import date, datetime, time
from apps.common.exceptions import ValidationError


_MAX_ID_LENGTH = 64
_MAX_TEXT_LENGTH = 2000
_MAX_SHORT_TEXT_LENGTH = 500


def _text(value, field_name: str, *, maximum: int = _MAX_TEXT_LENGTH, required: bool = False) -> str:
    normalized = "" if value is None else str(value).strip()
    if required and not normalized:
        raise ValidationError(f"{field_name} is required.")
    if len(normalized) > maximum:
        raise ValidationError(f"{field_name} is too long.")
    return normalized


def _id(value, field_name: str) -> str | None:
    if value in (None, ""):
        return None
    normalized = str(value).strip()
    if not normalized or len(normalized) > _MAX_ID_LENGTH:
        raise ValidationError(f"{field_name} is invalid.")
    return normalized


def _choice(value, field_name: str, maximum: int = 64) -> str:
    return _text(value, field_name, maximum=maximum)


def _strict_text(value, field_name: str, *, maximum: int = _MAX_TEXT_LENGTH) -> str:
    """Accept only wire-safe strings at the recording/provider boundary."""

    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be a string.")
    return _text(value, field_name, maximum=maximum)


@dataclass(frozen=True)
class CounselingNoteCommand:
    student_visible_summary: str = ""
    counselor_narrative: str = ""
    recommendations: str = ""
    special_concerns: str = ""
    follow_up_needed: bool = False
    follow_up_notes: str = ""

    def __post_init__(self) -> None:
        for field_name in (
            "student_visible_summary",
            "counselor_narrative",
            "recommendations",
            "special_concerns",
            "follow_up_notes",
        ):
            object.__setattr__(self, field_name, _text(getattr(self, field_name), field_name))
        if not isinstance(self.follow_up_needed, bool):
            raise ValidationError("follow_up_needed must be a boolean.")


@dataclass(frozen=True)
class ECounselingCompletionCommand:
    """Validated note fields passed to the existing counseling note writer."""

    note: CounselingNoteCommand | None = None

    def __post_init__(self) -> None:
        if self.note is not None and not isinstance(self.note, CounselingNoteCommand):
            raise ValidationError("ECounseling completion requires a CounselingNoteCommand note.")


@dataclass(frozen=True)
class SessionCreateCommand:
    student_id: str = ""
    appointment_reference: str | None = None
    assigned_counselor_id: str | None = None
    session_type: str = ""
    session_mode: str = ""
    session_source: str = ""
    concern_summary: str = ""
    scheduled_start_at: datetime | None = None
    scheduled_end_at: datetime | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "student_id",
            _text(self.student_id, "student_id", required=True, maximum=_MAX_ID_LENGTH),
        )
        object.__setattr__(self, "appointment_reference", _id(self.appointment_reference, "appointment_reference"))
        object.__setattr__(self, "assigned_counselor_id", _id(self.assigned_counselor_id, "assigned_counselor_id"))
        for field_name in ("session_type", "session_mode", "session_source"):
            object.__setattr__(self, field_name, _choice(getattr(self, field_name), field_name))
        object.__setattr__(self, "concern_summary", _text(self.concern_summary, "concern_summary"))
        for field_name in ("scheduled_start_at", "scheduled_end_at"):
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, datetime):
                raise ValidationError(f"{field_name} must be a timestamp.")


@dataclass(frozen=True)
class SessionAssignmentCommand:
    counselor_id: str = ""

    def __post_init__(self) -> None:
        counselor_id = _id(self.counselor_id, "counselor_id")
        if counselor_id is None:
            raise ValidationError("counselor_id is required.")
        object.__setattr__(self, "counselor_id", counselor_id)


@dataclass(frozen=True)
class SessionCancellationCommand:
    reason: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason", _text(self.reason, "reason"))


@dataclass(frozen=True)
class StudentVisibleSummaryCommand:
    student_visible_summary: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "student_visible_summary",
            _text(self.student_visible_summary, "student_visible_summary"),
        )

@dataclass(frozen=True)
class RoutineIntakeCommand:
    """Student-owned routine interview intake fields (metadata + confidential)."""

    visit_date: date | None = None
    visit_time: time | None = None
    duration_minutes: int | None = None
    nature_of_visit: str = ""
    coping_challenges: str = ""
    coping_remarks: str = ""
    ucn_experience: str = ""
    reason_for_coming: str = ""
    difficulties_encountered: str = ""
    stress_anxiety_causes: str = ""
    stress_anxiety_management: str = ""
    family_background_notes: str = ""
    concerns_explanation: str = ""
    college_adjustment: str = ""
    academic_goals: str = ""
    career_goals: str = ""
    concern_academic: bool = False
    concern_friends: bool = False
    concern_classmates: bool = False
    concern_vices: bool = False
    concern_love_life: bool = False
    concern_sleeping_problems: bool = False
    concern_family: bool = False
    concern_financial: bool = False
    concern_suicidal_thought: bool = False
    concern_dorm_boarding_house: bool = False
    concern_past_painful_experience: bool = False
    concern_others: bool = False
    concern_others_text: str = ""

    def __post_init__(self) -> None:
        if self.visit_date is not None and not isinstance(self.visit_date, date):
            raise ValidationError("visit_date must be a date.")
        if self.visit_time is not None and not isinstance(self.visit_time, time):
            raise ValidationError("visit_time must be a time.")
        if self.duration_minutes is not None and (
            isinstance(self.duration_minutes, bool)
            or not isinstance(self.duration_minutes, int)
            or self.duration_minutes < 0
        ):
            raise ValidationError("duration_minutes is invalid.")
        for field_name in (
            "nature_of_visit",
            "coping_challenges",
            "coping_remarks",
            "ucn_experience",
            "reason_for_coming",
            "difficulties_encountered",
            "stress_anxiety_causes",
            "stress_anxiety_management",
            "family_background_notes",
            "concerns_explanation",
            "college_adjustment",
            "academic_goals",
            "career_goals",
            "concern_others_text",
        ):
            object.__setattr__(self, field_name, _text(getattr(self, field_name), field_name))
        for field_name in (
            "concern_academic",
            "concern_friends",
            "concern_classmates",
            "concern_vices",
            "concern_love_life",
            "concern_sleeping_problems",
            "concern_family",
            "concern_financial",
            "concern_suicidal_thought",
            "concern_dorm_boarding_house",
            "concern_past_painful_experience",
            "concern_others",
        ):
            if not isinstance(getattr(self, field_name), bool):
                raise ValidationError(f"{field_name} must be a boolean.")


@dataclass(frozen=True)
class RoutineEvaluationCommand:
    """Counselor-owned routine interview evaluation fields."""

    rating_emotionally: str = ""
    rating_academically: str = ""
    rating_physically: str = ""
    rating_socially: str = ""
    rating_spiritually: str = ""
    rating_financially: str = ""
    rating_others_label: str = ""
    rating_others: str = ""
    special_concern: str = ""
    recommendations: str = ""
    assigned_counselor_confirmation: bool = False
    evaluation_date: date | None = None

    def __post_init__(self) -> None:
        for field_name in (
            "rating_emotionally",
            "rating_academically",
            "rating_physically",
            "rating_socially",
            "rating_spiritually",
            "rating_financially",
            "rating_others_label",
            "rating_others",
            "special_concern",
            "recommendations",
        ):
            object.__setattr__(
                self,
                field_name,
                _text(getattr(self, field_name), field_name, maximum=_MAX_SHORT_TEXT_LENGTH),
            )
        if not isinstance(self.assigned_counselor_confirmation, bool):
            raise ValidationError("assigned_counselor_confirmation must be a boolean.")
        if self.evaluation_date is not None and not isinstance(self.evaluation_date, date):
            raise ValidationError("evaluation_date must be a date.")

@dataclass(frozen=True)
class CaseCreateCommand:
    student_id: str = ""
    assigned_counselor_id: str | None = None
    concern_category: str = ""
    priority: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "student_id",
            _text(self.student_id, "student_id", required=True, maximum=_MAX_ID_LENGTH),
        )
        object.__setattr__(self, "assigned_counselor_id", _id(self.assigned_counselor_id, "assigned_counselor_id"))
        object.__setattr__(self, "concern_category", _choice(self.concern_category, "concern_category"))
        object.__setattr__(self, "priority", _choice(self.priority, "priority"))


@dataclass(frozen=True)
class CaseAssignmentCommand:
    counselor_id: str = ""
    reason_code: str = ""

    def __post_init__(self) -> None:
        counselor_id = _id(self.counselor_id, "counselor_id")
        if counselor_id is None:
            raise ValidationError("counselor_id is required.")
        object.__setattr__(self, "counselor_id", counselor_id)
        object.__setattr__(self, "reason_code", _choice(self.reason_code, "reason_code"))


@dataclass(frozen=True)
class CaseCollaboratorCommand:
    counselor_id: str = ""
    reason_code: str = ""

    def __post_init__(self) -> None:
        counselor_id = _id(self.counselor_id, "counselor_id")
        if counselor_id is None:
            raise ValidationError("counselor_id is required.")
        object.__setattr__(self, "counselor_id", counselor_id)
        object.__setattr__(self, "reason_code", _choice(self.reason_code, "reason_code"))


@dataclass(frozen=True)
class CaseSessionLinkCommand:
    session_reference_code: str = ""
    link_type: str = ""

    def __post_init__(self) -> None:
        reference = _id(self.session_reference_code, "session_reference_code")
        if reference is None:
            raise ValidationError("session_reference_code is required.")
        object.__setattr__(self, "session_reference_code", reference)
        object.__setattr__(self, "link_type", _choice(self.link_type, "link_type"))


@dataclass(frozen=True)
class CaseTransitionCommand:
    reason_code: str = ""
    target_status: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason_code", _choice(self.reason_code, "reason_code"))
        object.__setattr__(self, "target_status", _choice(self.target_status, "target_status"))

@dataclass(frozen=True)
class UrgentSupportCreateCommand:
    student_id: str = ""
    source_type: str = ""
    urgency_level: str = ""
    originating_session_reference: str | None = None
    counseling_case_reference: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "student_id",
            _text(self.student_id, "student_id", required=True, maximum=_MAX_ID_LENGTH),
        )
        object.__setattr__(self, "source_type", _choice(self.source_type, "source_type"))
        object.__setattr__(self, "urgency_level", _choice(self.urgency_level, "urgency_level"))
        object.__setattr__(
            self,
            "originating_session_reference",
            _id(self.originating_session_reference, "originating_session_reference"),
        )
        object.__setattr__(
            self,
            "counseling_case_reference",
            _id(self.counseling_case_reference, "counseling_case_reference"),
        )


@dataclass(frozen=True)
class UrgentSupportTriageCommand:
    assigned_counselor_id: str | None = None
    session_mode: str = ""
    scheduled_start_at: datetime | None = None
    scheduled_end_at: datetime | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "assigned_counselor_id", _id(self.assigned_counselor_id, "assigned_counselor_id"))
        object.__setattr__(self, "session_mode", _choice(self.session_mode, "session_mode"))
        for field_name in ("scheduled_start_at", "scheduled_end_at"):
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, datetime):
                raise ValidationError(f"{field_name} must be a timestamp.")


@dataclass(frozen=True)
class TemporarySupportAccessCommand:
    grantee_id: str = ""
    grant_type: str = ""
    purpose_code: str = ""
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        grantee_id = _id(self.grantee_id, "grantee_id")
        if grantee_id is None:
            raise ValidationError("grantee_id is required.")
        object.__setattr__(self, "grantee_id", grantee_id)
        object.__setattr__(self, "grant_type", _choice(self.grant_type, "grant_type"))
        object.__setattr__(self, "purpose_code", _choice(self.purpose_code, "purpose_code"))
        if self.expires_at is not None and not isinstance(self.expires_at, datetime):
            raise ValidationError("expires_at must be a timestamp.")


@dataclass(frozen=True)
class TemporarySupportRevokeCommand:
    grant_id: str = ""
    reason_code: str = ""

    def __post_init__(self) -> None:
        grant_id = _id(self.grant_id, "grant_id")
        if grant_id is None:
            raise ValidationError("grant_id is required.")
        object.__setattr__(self, "grant_id", grant_id)
        object.__setattr__(self, "reason_code", _choice(self.reason_code, "reason_code"))

@dataclass(frozen=True)
class UrgentSupportReviewCommand:
    review_status: str = ""
    followup_action: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "review_status", _choice(self.review_status, "review_status"))
        object.__setattr__(self, "followup_action", _choice(self.followup_action, "followup_action"))


@dataclass(frozen=True)
class UrgentSupportClosureCommand:
    closure_reason_code: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "closure_reason_code",
            _choice(self.closure_reason_code, "closure_reason_code"),
        )


@dataclass(frozen=True)
class UrgentLinkCommand:
    target_reference_code: str = ""
    documentation: bool = False

    def __post_init__(self) -> None:
        reference = _id(self.target_reference_code, "target_reference_code")
        if reference is None:
            raise ValidationError("target_reference_code is required.")
        object.__setattr__(self, "target_reference_code", reference)
        if not isinstance(self.documentation, bool):
            raise ValidationError("documentation must be a boolean.")


@dataclass(frozen=True)
class ECounselingCreateCommand:
    """E-counseling creation fields for a counseling session."""

    student_id: str = ""
    assigned_counselor_id: str | None = None
    session_type: str = ""
    scheduled_start_at: datetime | None = None
    scheduled_end_at: datetime | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "student_id",
            _text(self.student_id, "student_id", required=True, maximum=_MAX_ID_LENGTH),
        )
        object.__setattr__(self, "assigned_counselor_id", _id(self.assigned_counselor_id, "assigned_counselor_id"))
        object.__setattr__(self, "session_type", _choice(self.session_type, "session_type"))
        for field_name in ("scheduled_start_at", "scheduled_end_at"):
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, datetime):
                raise ValidationError(f"{field_name} must be a timestamp.")

@dataclass(frozen=True)
class ECounselingConsentRequestCommand:
    purpose_code: str = "COUNSELING_DELIVERY"
    scope_code: str = "AUDIO_ONLY"
    retention_policy_code: str = "GOVERNANCE_RETENTION_POLICY"

    def __post_init__(self) -> None:
        object.__setattr__(self, "purpose_code", _strict_text(self.purpose_code, "purpose_code"))
        scope_code = _strict_text(self.scope_code, "scope_code")
        if scope_code not in {"AUDIO_ONLY", "AUDIO_VIDEO"}:
            raise ValidationError("scope_code is invalid.")
        object.__setattr__(self, "scope_code", scope_code)
        object.__setattr__(
            self,
            "retention_policy_code",
            _strict_text(self.retention_policy_code, "retention_policy_code"),
        )


@dataclass(frozen=True)
class ECounselingRecordingStartCommand:
    """Bounded recording-start request; scope is rechecked by the service."""

    scope_code: str = "AUDIO_ONLY"

    def __post_init__(self) -> None:
        scope_code = _strict_text(self.scope_code, "scope_code")
        if scope_code not in {"AUDIO_ONLY", "AUDIO_VIDEO"}:
            raise ValidationError("scope_code is invalid.")
        object.__setattr__(self, "scope_code", scope_code)


@dataclass(frozen=True)
class ECounselingRecordingStopCommand:
    safe_reason_code: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "safe_reason_code", _strict_text(self.safe_reason_code, "safe_reason_code", maximum=50))


@dataclass(frozen=True)
class ECounselingProviderLifecycleReceipt:
    event_type: str = ""
    provider_recording_id: str | None = None
    provider_transcript_id: str | None = None
    provider_instance_id: str | None = None
    safe_failure_code: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "event_type", _strict_text(self.event_type, "event_type", maximum=64))
        for field_name in ("provider_recording_id", "provider_transcript_id", "provider_instance_id"):
            object.__setattr__(self, field_name, _id(getattr(self, field_name), field_name))
        object.__setattr__(self, "safe_failure_code", _strict_text(self.safe_failure_code, "safe_failure_code", maximum=50))


@dataclass(frozen=True)
class ECounselingConsentDecisionCommand:
    decision: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "decision", _choice(self.decision, "decision"))


@dataclass(frozen=True)
class ECounselingParticipantAddCommand:
    user_id: str = ""
    role: str = ""
    purpose_code: str = ""

    def __post_init__(self) -> None:
        user_id = _id(self.user_id, "user_id")
        if user_id is None:
            raise ValidationError("user_id is required.")
        object.__setattr__(self, "user_id", user_id)
        object.__setattr__(self, "role", _choice(self.role, "role"))
        object.__setattr__(self, "purpose_code", _choice(self.purpose_code, "purpose_code"))


@dataclass(frozen=True)
class ECounselingParticipantRevokeCommand:
    participant_id: str = ""

    def __post_init__(self) -> None:
        participant_id = _id(self.participant_id, "participant_id")
        if participant_id is None:
            raise ValidationError("participant_id is required.")
        object.__setattr__(self, "participant_id", participant_id)


@dataclass(frozen=True)
class ECounselingCancelCommand:
    reason_code: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason_code", _choice(self.reason_code, "reason_code"))


@dataclass(frozen=True)
class RoutineReopenCommand:
    reason: str = ""
    correction_target: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason", _text(self.reason, "reason", required=True))
        object.__setattr__(
            self,
            "correction_target",
            _choice(self.correction_target, "correction_target"),
        )
