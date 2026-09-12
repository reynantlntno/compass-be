"""Client-facing Counseling API.

All routes run the shared operation preparation (no-store caching, correlation
headers, central rate limits) and use the shared idempotency adapter for
state-changing operations except the e-counseling join flow, which keeps its
dedicated replay protection and extracts request context only at this edge.
"""

from dataclasses import asdict, is_dataclass
from datetime import date as date_type
from datetime import datetime as datetime_type
from datetime import time as time_type
from uuid import UUID

from ninja import Query, Router, Schema

from apps.account_security.network import get_client_ip_from_headers
from apps.counseling import queries as counseling_queries
from apps.counseling.commands import (
    CaseAssignmentCommand,
    CaseCollaboratorCommand,
    CaseCreateCommand,
    CaseSessionLinkCommand,
    CaseTransitionCommand,
    CounselingNoteCommand,
    ECounselingCancelCommand,
    ECounselingConsentDecisionCommand,
    ECounselingConsentRequestCommand,
    ECounselingRecordingStartCommand,
    ECounselingRecordingStopCommand,
    ECounselingCreateCommand,
    ECounselingParticipantAddCommand,
    ECounselingParticipantRevokeCommand,
    RoutineEvaluationCommand,
    RoutineIntakeCommand,
    RoutineReopenCommand,
    SessionAssignmentCommand,
    SessionCancellationCommand,
    SessionCreateCommand,
    StudentVisibleSummaryCommand,
    TemporarySupportAccessCommand,
    TemporarySupportRevokeCommand,
    UrgentLinkCommand,
    UrgentSupportClosureCommand,
    UrgentSupportCreateCommand,
    UrgentSupportReviewCommand,
    UrgentSupportTriageCommand,
)
from apps.common.api.idempotency import ApiMutationOutcome, run_api_mutation
from apps.common.api.operations import prepare_api_operation
from apps.common.api.pagination import PageQuery, PageSizeQuery, page_request_from_values
from apps.common.api.response_docs import binary_response_openapi
from apps.common.api.schemas import PageResultSchema
from apps.common.contracts import ContractValidationError, RequestMetadata, to_json_object
from apps.common.exceptions import NotFoundError, ValidationError
from apps.documents.workflow_api import (
    GeneratedDocumentMetadataSchema,
    download as workflow_document_download,
    generate as workflow_document_generate,
    preview as workflow_document_preview,
    workflow_download_openapi,
    workflow_preview_openapi,
)


router = Router(tags=["counseling"])


class CounselingSessionProjectionSchema(Schema):
    """Output-only superset of the staff and student session projections."""

    reference_code: str
    session_type: str
    session_mode: str
    status: str

    # Staff metadata is omitted from the student projection.
    student_id: int | None = None
    appointment_id: int | None = None
    assigned_counselor_id: int | None = None
    session_source: str | None = None
    ended_early_flag: bool | None = None
    finalized_at: datetime_type | None = None
    locked_at: datetime_type | None = None

    scheduled_start_at: datetime_type | None = None
    scheduled_end_at: datetime_type | None = None
    actual_started_at: datetime_type | None = None
    actual_ended_at: datetime_type | None = None
    actual_duration_minutes: int | None = None
    completed_at: datetime_type | None = None
    student_display_name: str | None = None
    student_number: str | None = None
    assignment_state: str | None = None


class CounselingSessionPageSchema(PageResultSchema):
    items: list[CounselingSessionProjectionSchema]


class CounselingSessionWorkspaceContextSchema(Schema):
    """Safe counselor workspace context without raw identifiers or tokens."""

    reference_code: str
    session_type: str
    session_mode: str
    session_source: str
    status: str
    scheduled_start_at: datetime_type | None = None
    scheduled_end_at: datetime_type | None = None
    actual_started_at: datetime_type | None = None
    actual_ended_at: datetime_type | None = None
    completed_at: datetime_type | None = None
    finalized_at: datetime_type | None = None
    locked_at: datetime_type | None = None
    student_display_name: str | None = None
    student_number: str | None = None
    assignment_state: str | None = None
    routine_interview_available: bool
    ecounseling_reference_code: str | None = None
    ecounseling_join_code: str | None = None
    ecounseling_join_available: bool
    ecounseling_next_action: str | None = None
    recording_consent_status: str | None = None
    recording_requested: bool | None = None
    recording_controls_enabled: bool


class CounselingNoteProjectionSchema(Schema):
    """Authorized note content; encrypted storage and actor fields are absent."""

    student_visible_summary: str
    counselor_narrative: str
    recommendations: str
    special_concerns: str
    follow_up_needed: bool
    follow_up_notes: str


class CounselingStudentSummarySchema(Schema):
    """The sole student-safe session-note projection."""

    student_visible_summary: str


class RoutineInterviewProjectionSchema(Schema):
    """Output-only union of routine metadata and student intake projections."""

    session_reference_code: str
    status: str

    # Staff metadata fields.
    student_id: int | None = None
    assigned_counselor_id: int | None = None
    visit_date: date_type | None = None
    visit_time: time_type | None = None
    duration_minutes: int | None = None
    nature_of_visit: str | None = None

    # Structured concern flags are safe metadata/intake fields; the text
    # answers below are only populated for the authorized student projection.
    concern_academic: bool | None = None
    concern_friends: bool | None = None
    concern_classmates: bool | None = None
    concern_vices: bool | None = None
    concern_love_life: bool | None = None
    concern_sleeping_problems: bool | None = None
    concern_family: bool | None = None
    concern_financial: bool | None = None
    concern_suicidal_thought: bool | None = None
    concern_dorm_boarding_house: bool | None = None
    concern_past_painful_experience: bool | None = None
    concern_others: bool | None = None
    concern_others_text: str | None = None

    rating_emotionally: int | None = None
    rating_academically: int | None = None
    rating_physically: int | None = None
    rating_socially: int | None = None
    rating_spiritually: int | None = None
    rating_financially: int | None = None
    rating_others: int | None = None
    evaluation_date: date_type | None = None

    submitted_at: datetime_type | None = None
    evaluated_at: datetime_type | None = None
    completed_at: datetime_type | None = None
    finalized_at: datetime_type | None = None
    locked_at: datetime_type | None = None
    reopened_at: datetime_type | None = None

    coping_challenges: str | None = None
    coping_remarks: str | None = None
    ucn_experience: str | None = None
    reason_for_coming: str | None = None
    difficulties_encountered: str | None = None
    stress_anxiety_causes: str | None = None
    stress_anxiety_management: str | None = None
    family_background_notes: str | None = None
    concerns_explanation: str | None = None
    college_adjustment: str | None = None
    academic_goals: str | None = None
    career_goals: str | None = None

class RoutineInterviewSensitiveDetailSchema(Schema):
    """Policy-gated routine detail without database or actor identifiers."""

    session_reference_code: str
    status: str
    visit_date: date_type | None = None
    visit_time: time_type | None = None
    duration_minutes: int | None = None
    nature_of_visit: str | None = None

    concern_academic: bool | None = None
    concern_friends: bool | None = None
    concern_classmates: bool | None = None
    concern_vices: bool | None = None
    concern_love_life: bool | None = None
    concern_sleeping_problems: bool | None = None
    concern_family: bool | None = None
    concern_financial: bool | None = None
    concern_suicidal_thought: bool | None = None
    concern_dorm_boarding_house: bool | None = None
    concern_past_painful_experience: bool | None = None
    concern_others: bool | None = None
    concern_others_text: str | None = None

    rating_emotionally: int | None = None
    rating_academically: int | None = None
    rating_physically: int | None = None
    rating_socially: int | None = None
    rating_spiritually: int | None = None
    rating_financially: int | None = None
    rating_others: int | None = None
    rating_others_label: str | None = None
    evaluation_date: date_type | None = None

    submitted_at: datetime_type | None = None
    evaluated_at: datetime_type | None = None
    completed_at: datetime_type | None = None
    finalized_at: datetime_type | None = None
    locked_at: datetime_type | None = None
    reopened_at: datetime_type | None = None

    coping_challenges: str | None = None
    coping_remarks: str | None = None
    ucn_experience: str | None = None
    reason_for_coming: str | None = None
    difficulties_encountered: str | None = None
    stress_anxiety_causes: str | None = None
    stress_anxiety_management: str | None = None
    family_background_notes: str | None = None
    concerns_explanation: str | None = None
    college_adjustment: str | None = None
    academic_goals: str | None = None
    career_goals: str | None = None
    special_concern: str | None = None
    recommendations: str | None = None


class RoutineInterviewQueueProjectionSchema(Schema):
    """Safe staff queue projection without database or counselor identifiers."""

    session_reference_code: str
    status: str
    visit_date: date_type | None = None
    visit_time: time_type | None = None
    duration_minutes: int | None = None
    nature_of_visit: str | None = None

    concern_academic: bool | None = None
    concern_friends: bool | None = None
    concern_classmates: bool | None = None
    concern_vices: bool | None = None
    concern_love_life: bool | None = None
    concern_sleeping_problems: bool | None = None
    concern_family: bool | None = None
    concern_financial: bool | None = None
    concern_suicidal_thought: bool | None = None
    concern_dorm_boarding_house: bool | None = None
    concern_past_painful_experience: bool | None = None
    concern_others: bool | None = None

    rating_emotionally: int | None = None
    rating_academically: int | None = None
    rating_physically: int | None = None
    rating_socially: int | None = None
    rating_spiritually: int | None = None
    rating_financially: int | None = None
    rating_others: int | None = None
    evaluation_date: date_type | None = None

    submitted_at: datetime_type | None = None
    evaluated_at: datetime_type | None = None
    completed_at: datetime_type | None = None
    finalized_at: datetime_type | None = None
    locked_at: datetime_type | None = None
    reopened_at: datetime_type | None = None

    student_display_name: str | None = None
    student_number: str | None = None
    assignment_state: str | None = None
    updated_at: datetime_type | None = None


class RoutineInterviewPageSchema(PageResultSchema):
    items: list[RoutineInterviewQueueProjectionSchema]


class CounselingCaseProjectionSchema(Schema):
    """Output-only superset of staff and student case metadata."""

    reference_code: str
    status: str
    student_id: int | None = None
    assigned_counselor_id: int | None = None
    concern_category: str | None = None
    priority: str | None = None
    created_at: datetime_type | None = None
    updated_at: datetime_type | None = None
    resolved_at: datetime_type | None = None
    closed_at: datetime_type | None = None
    reopened_at: datetime_type | None = None


class CounselingCaseQueueProjectionSchema(Schema):
    """Safe staff queue projection without database or actor identifiers."""

    reference_code: str
    status: str
    concern_category: str | None = None
    priority: str | None = None
    created_at: datetime_type | None = None
    updated_at: datetime_type | None = None
    resolved_at: datetime_type | None = None
    closed_at: datetime_type | None = None
    reopened_at: datetime_type | None = None
    student_display_name: str | None = None
    student_number: str | None = None
    assignment_state: str | None = None


class CounselingCaseQueuePageSchema(PageResultSchema):
    items: list[CounselingCaseQueueProjectionSchema]


class UrgentSupportAccessGrantProjectionSchema(Schema):
    selection_token: str
    display_name: str
    grant_type: str
    purpose_code: str
    starts_at: datetime_type
    expires_at: datetime_type
    status: str


class UrgentSupportQueueProjectionSchema(Schema):
    """Bounded operational queue projection."""

    reference_code: str
    status: str
    urgency_level: str
    source_type: str
    documentation_status: str
    review_status: str | None = None
    student_display_name: str | None = None
    student_number: str | None = None
    assignment_state: str | None = None
    created_at: datetime_type | None = None
    updated_at: datetime_type | None = None
    reviewed_at: datetime_type | None = None
    closed_at: datetime_type | None = None
    expires_at: datetime_type | None = None
    counseling_case_reference: str | None = None
    originating_session_reference: str | None = None
    documentation_session_reference: str | None = None


class UrgentSupportProjectionSchema(UrgentSupportQueueProjectionSchema):
    """Safe urgent-support detail projection."""

    active_access_grants: list[UrgentSupportAccessGrantProjectionSchema] | None = None


class UrgentSupportCounselorOptionSchema(Schema):
    selection_token: str
    display_name: str


class UrgentSupportCounselorOptionPageSchema(PageResultSchema):
    items: list[UrgentSupportCounselorOptionSchema]


class UrgentSupportPageSchema(PageResultSchema):
    items: list[UrgentSupportQueueProjectionSchema]


class CounselingRelatedRecordSchema(Schema):
    """One safe, policy-filtered relationship in the session context."""

    record_type: str
    reference_code: str
    status: str | None = None
    created_at: datetime_type | None = None
    updated_at: datetime_type | None = None


class CounselingRelatedRecordsSchema(Schema):
    items: list[CounselingRelatedRecordSchema]


class CounselingLinkOptionSchema(Schema):
    reference_code: str
    status: str | None = None


class CounselingLinkOptionPageSchema(PageResultSchema):
    items: list[CounselingLinkOptionSchema]


class CounselingUrgentLinkOptionsSchema(Schema):
    sessions: list[CounselingLinkOptionSchema]
    cases: list[CounselingLinkOptionSchema]


class CounselingMutationResponseSchema(Schema):
    """Bounded superset for counseling mutation and idempotent replay outputs."""

    reference_code: str | None = None
    status: str | None = None
    saved: bool | None = None
    submitted: bool | None = None
    added: bool | None = None
    granted: bool | None = None
    revoked: bool | None = None
    requested: bool | None = None
    decided: bool | None = None
    withdrawn: bool | None = None
    cancelled: bool | None = None
    created: bool | None = None


class ECounselingJoinStateSchema(Schema):
    """Safe state response; provider credentials are not part of this schema."""

    code: str
    message: str
    scheduled_start_at: datetime_type | None = None
    next_action: str


class ECounselingJoinContextSchema(Schema):
    """Authorized, ephemeral provider join context."""

    provider: str
    provider_mode: str
    room_url: str
    public_base_url: str
    room_slug: str
    meeting_token: str
    display_name: str
    recording_allowed: bool
    recording_controls_enabled: bool
    provider_auth_enabled: bool
    production_ready: bool


class RecordingAvailabilitySchema(Schema):
    state: str
    available: bool
    available_scopes: list[str]
    transcription_available: bool
    reason_code: str
    message: str


class RecordingRunProjectionSchema(Schema):
    """Safe recording-run projection without provider/storage identifiers."""

    run_id: str
    reference_code: str
    status: str
    scope: str
    consent_status: str
    transcription_status: str
    started_at: datetime_type | None = None
    stopped_at: datetime_type | None = None
    available_at: datetime_type | None = None
    expires_at: datetime_type | None = None
    transcription_started_at: datetime_type | None = None
    transcription_available_at: datetime_type | None = None
    transcription_expires_at: datetime_type | None = None
    transcript_available: bool
    safe_failure_code: str | None = None
    transcription_failure_code: str | None = None


class RecordingStatusSchema(Schema):
    reference_code: str
    status: str
    run: RecordingRunProjectionSchema | None = None


class RecordingMutationResponseSchema(Schema):
    started: bool | None = None
    stopped: bool | None = None
    run: RecordingRunProjectionSchema | None = None


class TranscriptionStatusSchema(Schema):
    status: str
    available: bool
    available_at: datetime_type | None = None
    expires_at: datetime_type | None = None
    failure_code: str | None = None


class TranscriptMetadataSchema(Schema):
    available: bool
    content_type: str
    file_size_bytes: int
    expires_at: datetime_type | None = None


class ProviderWebhookResponseSchema(Schema):
    accepted: bool


class SessionCreateSchema(Schema):
    # ``student_id`` remains accepted for older trusted clients. New staff
    # clients must use the opaque workflow-bound selection token instead.
    student_id: int | None = None
    student_selection_token: str | None = None
    appointment_reference: str | None = None
    assigned_counselor: int | None = None
    session_type: str
    session_mode: str
    session_source: str = ""
    concern_summary: str = ""
    scheduled_start_at: str | None = None
    scheduled_end_at: str | None = None


class NoteSchema(Schema):
    student_visible_summary: str = ""
    counselor_narrative: str = ""
    recommendations: str = ""
    special_concerns: str = ""
    follow_up_needed: bool = False
    follow_up_notes: str = ""


class SummarySchema(Schema):
    student_visible_summary: str


class AssignmentSchema(Schema):
    counselor: int


class CounselingReasonSchema(Schema):
    reason: str


class IntakeSchema(Schema):
    visit_date: str | None = None
    visit_time: str | None = None
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


class EvaluationSchema(Schema):
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
    evaluation_date: str | None = None


class ReopenSchema(Schema):
    reason: str
    correction_target: str


class CaseCreateSchema(Schema):
    student_id: int
    assigned_counselor: int | None = None
    concern_category: str
    priority: str = ""


class CaseReasonSchema(Schema):
    reason_code: str


class CollaboratorSchema(Schema):
    counselor: int
    reason_code: str = ""


class LinkSchema(Schema):
    session_reference_code: str
    link_type: str


class UrgentCreateSchema(Schema):
    student_id: int | None = None
    source_type: str
    urgency_level: str
    originating_session_reference: str | None = None
    counseling_case_reference: str | None = None

class UrgentTriageSchema(Schema):
    assigned_counselor: int | None = None
    counselor_selection_token: str | None = None
    session_mode: str = ""
    scheduled_start_at: str | None = None
    scheduled_end_at: str | None = None


class AccessGrantSchema(Schema):
    grantee_id: int | None = None
    grantee_selection_token: str | None = None
    grant_type: str
    purpose_code: str
    expires_at: datetime_type | None = None


class UrgentSupportRevokeSchema(Schema):
    grant_id: int | None = None
    grant_selection_token: str | None = None
    reason_code: str = ""


class UrgentSupportLinkSchema(Schema):
    target_reference_code: str
    # Session links must declare their operational meaning.  Case links leave
    # this unset; both values are kept as public workflow vocabulary rather
    # than exposing the service's internal boolean command field.
    intent: str | None = None


class UrgentSupportReviewSchema(Schema):
    review_status: str
    followup_action: str = ""


class ClosureSchema(Schema):
    closure_reason_code: str


class ConsentRequestSchema(Schema):
    purpose_code: str = "COUNSELING_DELIVERY"
    scope_code: str = "AUDIO_ONLY"
    retention_policy_code: str = "GOVERNANCE_RETENTION_POLICY"


class ConsentDecisionSchema(Schema):
    decision: str


class ParticipantAddSchema(Schema):
    user_id: int
    role: str
    purpose_code: str


class ParticipantRevokeSchema(Schema):
    participant_id: int


class CancelSchema(Schema):
    reason_code: str = ""


class JoinSchema(Schema):
    pass


class RecordingStartSchema(Schema):
    scope_code: str = "AUDIO_ONLY"


class RecordingStopSchema(Schema):
    safe_reason_code: str = ""


def _actor(request):
    return request.auth.user


def _page(page: PageQuery, page_size: PageSizeQuery):
    try:
        return page_request_from_values(page, page_size)
    except ContractValidationError as error:
        raise ValidationError() from error


def _payload(payload):
    data = payload.dict(exclude_unset=True)
    for field_name in ("visit_date", "evaluation_date"):
        if isinstance(data.get(field_name), str) and data[field_name]:
            try:
                data[field_name] = date_type.fromisoformat(data[field_name])
            except ValueError as error:
                raise ValidationError() from error
    if isinstance(data.get("visit_time"), str) and data["visit_time"]:
        try:
            data["visit_time"] = time_type.fromisoformat(data["visit_time"])
        except ValueError as error:
            raise ValidationError() from error
    for field_name in ("scheduled_start_at", "scheduled_end_at"):
        if isinstance(data.get(field_name), str) and data[field_name]:
            try:
                data[field_name] = datetime_type.fromisoformat(data[field_name])
            except ValueError as error:
                raise ValidationError() from error
        elif field_name in data and data[field_name] is None:
            data.pop(field_name)
    return data


def _session_outcome(session, path_suffix="/"):
    return ApiMutationOutcome(
        value={"reference_code": session.reference_code, "status": session.status},
        related_object=session,
        safe_response_path=f"/api/v1/counseling/sessions/{session.reference_code}{path_suffix}",
    )


def _fingerprint_payload(*, reference_code=None, command=None, **extra):
    """Build the bounded idempotency fingerprint input for one command.

    The API adapter hashes this value before persistence.  The command is
    converted to a JSON-safe value here so a reused key with a different
    command cannot be mistaken for a replay of the first request.
    """
    payload = dict(extra)
    if reference_code is not None:
        payload["reference_code"] = str(reference_code)
    if command is not None:
        if not is_dataclass(command):
            raise ValidationError()
        payload["command"] = asdict(command)
    return to_json_object(payload)


def _session_id(reference_code):
    """Resolve a public session reference to the stable orchestration ID."""
    from apps.counseling.models import CounselingSession

    session_id = (
        CounselingSession.objects.filter(
            reference_code=str(reference_code or "").strip(),
        )
        .values_list("pk", flat=True)
        .first()
    )
    if session_id is None:
        raise NotFoundError()
    return str(session_id)


def _flag_outcome(flag, related_object, safe_response_path="/"):
    return ApiMutationOutcome(
        value={flag: True},
        related_object=related_object,
        safe_response_path=safe_response_path,
    )


def _replay(key):
    action_scope = str(getattr(key, "action_scope", ""))
    object_id = getattr(key, "related_object_id", None)
    if not object_id:
        return None
    flag_replays = {
        "counseling_routine_intake_save": ("saved", "routine"),
        "counseling_routine_intake_submit": ("submitted", "routine"),
        "counseling_routine_evaluation_save": ("saved", "routine"),
        "counseling_note_save": ("saved", "session"),
        "counseling_case_collaborator_add": ("added", "case"),
        "counseling_urgent_access_grant": ("granted", "urgent"),
        "counseling_urgent_access_revoke": ("revoked", "urgent"),
        "counseling_ecounseling_consent_request": ("requested", "session"),
        "counseling_ecounseling_consent_decision": ("decided", "session"),
        "counseling_ecounseling_consent_withdraw": ("withdrawn", "session"),
        "counseling_ecounseling_participant_add": ("added", "session"),
        "counseling_ecounseling_participant_revoke": ("revoked", "session"),
        "counseling_ecounseling_cancel": ("cancelled", "session"),
    }
    if action_scope in flag_replays:
        flag, target = flag_replays[action_scope]
        if target == "routine":
            from apps.counseling.models import RoutineInterviewRecord

            exists = RoutineInterviewRecord.objects.filter(pk=object_id).exists()
        elif target == "case":
            from apps.counseling.models import CounselingCase

            exists = CounselingCase.objects.filter(pk=object_id).exists()
        elif target == "urgent":
            from apps.counseling.models import UrgentSupportRequest

            exists = UrgentSupportRequest.objects.filter(pk=object_id).exists()
        else:
            from apps.counseling.models import CounselingSession

            exists = CounselingSession.objects.filter(pk=object_id).exists()
        return {flag: True} if exists else None
    if action_scope in {
        "counseling_ecounseling_recording_start",
        "counseling_ecounseling_recording_stop",
    }:
        from apps.counseling.models import ECounselingRecordingRun

        run = ECounselingRecordingRun.objects.select_related("ecounseling_session").filter(pk=object_id).first()
        if run is None:
            return None
        return {
            "started" if action_scope.endswith("_start") else "stopped": True,
            "run": _recording_run_projection(run),
        }
    if action_scope.startswith("counseling_routine"):
        from apps.counseling.models import RoutineInterviewRecord

        record = RoutineInterviewRecord.objects.select_related("session").filter(pk=object_id).first()
        if record is None:
            return None
        return {
            "reference_code": record.session.reference_code,
            "status": record.status,
        }
    if action_scope.startswith("counseling_case"):
        from apps.counseling.models import CounselingCase

        case = CounselingCase.objects.filter(pk=object_id).first()
        if case is None:
            return None
        return {"reference_code": case.reference_code, "status": case.status}
    if action_scope.startswith("counseling_urgent"):
        from apps.counseling.models import UrgentSupportRequest

        urgent = UrgentSupportRequest.objects.filter(pk=object_id).first()
        if urgent is None:
            return None
        return {"reference_code": urgent.reference_code, "status": urgent.status}
    from apps.counseling.models import CounselingSession

    session = CounselingSession.objects.filter(pk=object_id).first()
    if session is None:
        return None
    return {"reference_code": session.reference_code, "status": session.status}


def _run(request, operation_id, payload, operation):
    prepared = prepare_api_operation(request, operation_id)
    return run_api_mutation(
        request,
        operation_id,
        payload,
        operation,
        _replay,
        prepared_operation=prepared,
    )


def _load_session_or_404(actor, reference_code):
    from apps.counseling.selectors import get_session_by_reference_code

    session = get_session_by_reference_code(actor, reference_code)
    if session is None:
        raise NotFoundError()
    return session

# ---------------------------------------------------------------------------
# Session reads
# ---------------------------------------------------------------------------


@router.get(
    "/sessions/",
    response=CounselingSessionPageSchema,
    exclude_unset=True,
    operation_id="counseling_sessions_list",
)
def list_sessions(
    request,
    page: PageQuery,
    page_size: PageSizeQuery,
    q: str | None = Query(default=None, max_length=120),
    status: str | None = Query(default=None, max_length=400),
    session_type: str | None = Query(default=None),
    session_mode: str | None = Query(default=None),
    session_source: str | None = Query(default=None),
    assignment: str = Query(default="all"),
    date_from: date_type | None = Query(default=None),
    date_to: date_type | None = Query(default=None),
    order: str = Query(default="recent"),
):
    prepare_api_operation(request, "counseling_sessions_list")
    try:
        return counseling_queries.get_session_metadata_page(
            _actor(request),
            _page(page, page_size),
            q=q,
            statuses=status,
            session_type=session_type,
            session_mode=session_mode,
            session_source=session_source,
            assignment=assignment,
            date_from=date_from,
            date_to=date_to,
            order=order,
        ).as_dict()
    except ValueError as error:
        raise ValidationError(field_errors={"filters": ["Invalid counseling session filters."]}) from error


@router.get(
    "/sessions/{reference_code}/",
    response=CounselingSessionProjectionSchema,
    exclude_unset=True,
    operation_id="counseling_session_detail",
)
def session_detail(request, reference_code: str):
    from apps.counseling.projections import (
        project_staff_session_metadata,
        project_student_session_metadata,
    )
    from apps.access_control.rules import is_student

    prepare_api_operation(request, "counseling_session_detail")
    actor = _actor(request)
    session = get_session_or_404(actor, reference_code)
    if is_student(actor):
        payload = project_student_session_metadata(actor, session)
    else:
        payload = project_staff_session_metadata(actor, session)
    if payload is None:
        raise NotFoundError()
    return payload


@router.get(
    "/sessions/{reference_code}/workspace/",
    response=CounselingSessionWorkspaceContextSchema,
    exclude_unset=True,
    operation_id="counseling_session_workspace",
)
def session_workspace_context(request, reference_code: str):
    from apps.counseling.projections import project_staff_session_workspace_context

    prepare_api_operation(request, "counseling_session_workspace")
    actor = _actor(request)
    payload = project_staff_session_workspace_context(
        actor,
        get_session_or_404(actor, reference_code),
    )
    if payload is None:
        raise NotFoundError()
    return payload


@router.get(
    "/sessions/{reference_code}/related-records/",
    response=CounselingRelatedRecordsSchema,
    exclude_unset=True,
    operation_id="counseling_session_related_records",
)
def session_related_records(request, reference_code: str):
    from apps.counseling.integrations import project_related_records

    prepare_api_operation(request, "counseling_session_related_records")
    actor = _actor(request)
    return {"items": project_related_records(actor, get_session_or_404(actor, reference_code))}


@router.get(
    "/sessions/{reference_code}/urgent-support-options/",
    response=CounselingLinkOptionPageSchema,
    exclude_unset=True,
    operation_id="counseling_session_urgent_support_options",
)
def session_urgent_support_options(
    request,
    reference_code: str,
    page: PageQuery,
    page_size: PageSizeQuery,
):
    from apps.counseling.integrations import get_session_urgent_support_options

    prepare_api_operation(request, "counseling_session_urgent_support_options")
    actor = _actor(request)
    return get_session_urgent_support_options(
        actor,
        get_session_or_404(actor, reference_code),
        _page(page, page_size),
    ).as_dict()


@router.get(
    "/sessions/{reference_code}/note/",
    response=CounselingNoteProjectionSchema,
    exclude_unset=True,
    operation_id="counseling_note_detail",
)
def session_note_detail(request, reference_code: str):
    from apps.counseling.projections import project_counselor_note_detail

    prepare_api_operation(request, "counseling_note_detail")
    actor = _actor(request)
    payload = project_counselor_note_detail(
        actor,
        get_session_or_404(actor, reference_code),
    )
    if payload is None:
        raise NotFoundError()
    return payload


@router.get(
    "/sessions/{reference_code}/summary/",
    response=CounselingStudentSummarySchema,
    exclude_unset=True,
    operation_id="counseling_session_summary",
)
def session_summary(request, reference_code: str):
    from apps.counseling.projections import project_student_session_summary

    prepare_api_operation(request, "counseling_session_summary")
    actor = _actor(request)
    session = get_session_or_404(actor, reference_code)
    payload = project_student_session_summary(actor, session)
    if payload is None:
        raise NotFoundError()
    return payload


def get_session_or_404(actor, reference_code):
    return _load_session_or_404(actor, reference_code)


# ---------------------------------------------------------------------------
# Session mutations
# ---------------------------------------------------------------------------


@router.post(
    "/sessions/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_session_create",
)
def create_session_route(request, payload: SessionCreateSchema):
    from apps.counseling.services import create_session
    from apps.access_control.student_selectors import resolve_student_selection_token

    actor = _actor(request)
    create_data = _payload(payload)
    student_id = create_data.get("student_id")
    selection_token = str(create_data.get("student_selection_token") or "").strip()
    has_student_id = student_id is not None
    has_selection_token = bool(selection_token)
    if has_student_id == has_selection_token:
        raise ValidationError(
            field_errors={
                "student": [
                    "Choose a student using one available selection method.",
                ],
            },
        )
    if has_selection_token:
        if len(selection_token) > 500:
            raise ValidationError(
                field_errors={
                    "student_selection_token": [
                        "The student selection is no longer available.",
                    ],
                },
            )
        selected_profile = resolve_student_selection_token(
            actor,
            "counseling_session",
            selection_token,
        )
        if selected_profile is None:
            raise ValidationError(
                field_errors={
                    "student_selection_token": [
                        "The student selection is no longer available.",
                    ],
                },
            )
        student_id = selected_profile.user_id
    command = SessionCreateCommand(
        student_id=student_id,
        appointment_reference=create_data.get("appointment_reference"),
        assigned_counselor_id=create_data.get("assigned_counselor"),
        session_type=create_data["session_type"],
        session_mode=create_data["session_mode"],
        session_source=create_data.get("session_source", ""),
        concern_summary=create_data.get("concern_summary", ""),
        scheduled_start_at=create_data.get("scheduled_start_at"),
        scheduled_end_at=create_data.get("scheduled_end_at"),
    )
    return _run(
        request,
        "counseling_session_create",
        _fingerprint_payload(command=command),
        lambda: _session_outcome(create_session(actor, command)),
    )


@router.post(
    "/sessions/{reference_code}/start/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_session_start",
)
def start_session_route(request, reference_code: str):
    from apps.counseling.services import start_session

    actor = _actor(request)
    return _run(
        request,
        "counseling_session_start",
        {"reference_code": reference_code},
        lambda: _session_outcome(start_session(actor, reference_code)),
    )


@router.put(
    "/sessions/{reference_code}/note/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_note_save",
)
def save_note_route(request, reference_code: str, payload: NoteSchema):
    from apps.counseling.services import save_session_note

    actor = _actor(request)
    command = CounselingNoteCommand(**_payload(payload))

    def operation():
        note = save_session_note(actor, reference_code, command)
        return ApiMutationOutcome(
            value={"saved": True},
            related_object=getattr(note, "session", None),
            safe_response_path=f"/api/v1/counseling/sessions/{reference_code}/",
        )

    return _run(
        request,
        "counseling_note_save",
        _fingerprint_payload(reference_code=reference_code, command=command),
        operation,
    )


@router.post(
    "/sessions/{reference_code}/complete/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_session_complete",
)
def complete_session_route(request, reference_code: str, payload: NoteSchema):
    from apps.orchestration.commands import CompleteCounselingSessionCommand
    from apps.orchestration.use_cases import complete_counseling_session_with_linked_appointment

    actor = _actor(request)
    command = CompleteCounselingSessionCommand(
        session_id=_session_id(reference_code),
        note=CounselingNoteCommand(**_payload(payload)),
    )
    return _run(
        request,
        "counseling_session_complete",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _session_outcome(
            complete_counseling_session_with_linked_appointment(actor, command),
            path_suffix="/",
        ),
    )

@router.post(
    "/sessions/{reference_code}/finalize/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_session_finalize",
)
def finalize_session_route(request, reference_code: str):
    from apps.counseling.services import finalize_session

    actor = _actor(request)
    return _run(
        request,
        "counseling_session_finalize",
        _fingerprint_payload(reference_code=reference_code),
        lambda: _session_outcome(finalize_session(actor, reference_code)),
    )


@router.post(
    "/sessions/{reference_code}/lock/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_session_lock",
)
def lock_session_route(request, reference_code: str):
    from apps.counseling.services import lock_session

    actor = _actor(request)
    return _run(
        request,
        "counseling_session_lock",
        _fingerprint_payload(reference_code=reference_code),
        lambda: _session_outcome(lock_session(actor, reference_code)),
    )


@router.post(
    "/sessions/{reference_code}/cancel/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_session_cancel",
)
def cancel_session_route(request, reference_code: str, payload: CounselingReasonSchema):
    from apps.orchestration.commands import LinkedCounselingSessionCommand
    from apps.orchestration.use_cases import cancel_counseling_session_with_linked_appointment

    actor = _actor(request)
    data = _payload(payload)
    command = LinkedCounselingSessionCommand(
        session_id=_session_id(reference_code),
        reason=data.get("reason", ""),
    )
    return _run(
        request,
        "counseling_session_cancel",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _session_outcome(
            cancel_counseling_session_with_linked_appointment(actor, command),
        ),
    )


@router.post(
    "/sessions/{reference_code}/no-show/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_session_no_show",
)
def no_show_session_route(request, reference_code: str):
    from apps.orchestration.commands import LinkedCounselingSessionCommand
    from apps.orchestration.use_cases import (
        mark_counseling_session_no_show_with_linked_appointment,
    )

    actor = _actor(request)
    command = LinkedCounselingSessionCommand(session_id=_session_id(reference_code))
    return _run(
        request,
        "counseling_session_no_show",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _session_outcome(
            mark_counseling_session_no_show_with_linked_appointment(actor, command),
        ),
    )


@router.post(
    "/sessions/{reference_code}/assign-counselor/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_session_assign",
)
def assign_session_route(request, reference_code: str, payload: AssignmentSchema):
    from apps.counseling.services import assign_session_counselor

    actor = _actor(request)
    command = SessionAssignmentCommand(counselor_id=payload.counselor)
    return _run(
        request,
        "counseling_session_assign",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _session_outcome(assign_session_counselor(actor, reference_code, command)),
    )

# ---------------------------------------------------------------------------
# Routine interviews
# ---------------------------------------------------------------------------


@router.get(
    "/routine-interviews/",
    response=RoutineInterviewPageSchema,
    exclude_unset=True,
    operation_id="counseling_routine_interviews_list",
)
def list_routine_interviews(
    request,
    page: PageQuery,
    page_size: PageSizeQuery,
    status: str | None = Query(default=None, max_length=400),
):
    prepare_api_operation(request, "counseling_routine_interviews_list")
    try:
        return counseling_queries.get_routine_interview_queue_metadata_page(
            _actor(request),
            _page(page, page_size),
            statuses=status,
        ).as_dict()
    except ValueError as error:
        raise ValidationError(field_errors={"filters": ["Invalid routine interview filters."]}) from error


@router.get(
    "/routine-interviews/{reference_code}/sensitive/",
    response=RoutineInterviewSensitiveDetailSchema,
    exclude_unset=True,
    operation_id="counseling_routine_interview_sensitive_detail",
)
def routine_interview_sensitive_detail(request, reference_code: str):
    from apps.counseling.projections import project_routine_interview_api_sensitive_detail

    prepare_api_operation(request, "counseling_routine_interview_sensitive_detail")
    actor = _actor(request)
    record = _routine_record_or_404(actor, reference_code)
    payload = project_routine_interview_api_sensitive_detail(actor, record)
    if payload is None:
        raise NotFoundError()
    return payload


@router.get(
    "/routine-interviews/{reference_code}/document/preview/",
    response=None,
    openapi_extra=workflow_preview_openapi(),
    operation_id="counseling_routine_interviews_document_preview",
)
def routine_interview_document_preview(request, reference_code: str):
    return workflow_document_preview(
        request, operation_id="counseling_routine_interviews_document_preview",
        domain="routine_interviews", stable_key="routine_interview", target_reference=reference_code,
    )


class RoutineDocumentGenerateSchema(Schema):
    expected_updated_at: str = ""


@router.post(
    "/routine-interviews/{reference_code}/document/generate/",
    response=GeneratedDocumentMetadataSchema,
    exclude_unset=True,
    operation_id="counseling_routine_interviews_document_generate",
)
def routine_interview_document_generate(request, reference_code: str, payload: RoutineDocumentGenerateSchema):
    return workflow_document_generate(
        request, operation_id="counseling_routine_interviews_document_generate",
        domain="routine_interviews", stable_key="routine_interview", target_reference=reference_code,
        expected_updated_at=payload.expected_updated_at,
    )


@router.get(
    "/routine-interviews/{reference_code}/document/download/",
    response=None,
    openapi_extra=workflow_download_openapi(),
    operation_id="counseling_routine_interviews_document_download",
)
def routine_interview_document_download(request, reference_code: str):
    return workflow_document_download(
        request, operation_id="counseling_routine_interviews_document_download",
        domain="routine_interviews", stable_key="routine_interview", target_reference=reference_code,
    )


def _routine_record_or_404(actor, reference_code):
    from apps.counseling.selectors import get_routine_interview_by_session_reference

    record = get_routine_interview_by_session_reference(actor, reference_code)
    if record is None:
        raise NotFoundError()
    return record


@router.get(
    "/routine-interviews/{reference_code}/",
    response=RoutineInterviewProjectionSchema,
    exclude_unset=True,
    operation_id="counseling_routine_interview_detail",
)
def routine_interview_detail(request, reference_code: str):
    from apps.access_control.rules import is_student
    from apps.counseling.projections import (
        project_routine_interview_metadata,
        project_student_routine_interview,
    )

    prepare_api_operation(request, "counseling_routine_interview_detail")
    actor = _actor(request)
    record = _routine_record_or_404(actor, reference_code)
    payload = (
        project_student_routine_interview(actor, record)
        if is_student(actor)
        else project_routine_interview_metadata(actor, record)
    )
    if payload is None:
        raise NotFoundError()
    return payload


@router.put(
    "/sessions/{reference_code}/routine-intake/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_routine_intake_save",
)
def save_intake_route(request, reference_code: str, payload: IntakeSchema):
    from apps.counseling.services import save_student_intake_draft

    actor = _actor(request)
    command = RoutineIntakeCommand(**_payload(payload))
    return _run(
        request,
        "counseling_routine_intake_save",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _flag_outcome(
            "saved",
            save_student_intake_draft(actor, reference_code, command),
            f"/api/v1/counseling/sessions/{reference_code}/",
        ),
    )


@router.post(
    "/sessions/{reference_code}/routine-intake/submit/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_routine_intake_submit",
)
def submit_intake_route(request, reference_code: str):
    from apps.counseling.services import submit_student_intake

    actor = _actor(request)
    return _run(
        request,
        "counseling_routine_intake_submit",
        _fingerprint_payload(reference_code=reference_code),
        lambda: _flag_outcome(
            "submitted",
            submit_student_intake(actor, reference_code),
            f"/api/v1/counseling/sessions/{reference_code}/",
        ),
    )


@router.put(
    "/sessions/{reference_code}/routine-evaluation/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_routine_evaluation_save",
)
def save_evaluation_route(request, reference_code: str, payload: EvaluationSchema):
    from apps.counseling.services import save_counselor_evaluation_draft

    actor = _actor(request)
    command = RoutineEvaluationCommand(**_payload(payload))
    return _run(
        request,
        "counseling_routine_evaluation_save",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _flag_outcome(
            "saved",
            save_counselor_evaluation_draft(actor, reference_code, command),
            f"/api/v1/counseling/sessions/{reference_code}/",
        ),
    )

def _routine_outcome(record, reference_code):
    return ApiMutationOutcome(
        value={"reference_code": reference_code, "status": record.status},
        related_object=record,
        safe_response_path=f"/api/v1/counseling/routine-interviews/{reference_code}/",
    )


def _routine_action(operation_id, service_name, takes_command=False):
    def route(request, reference_code: str, payload: ReopenSchema | None = None):
        from apps.counseling import services as counseling_services
        from apps.common.exceptions import ValidationError as DomainValidationError

        actor = _actor(request)
        service = getattr(counseling_services, service_name)
        if takes_command:
            if payload is None:
                raise DomainValidationError()
            command = RoutineReopenCommand(**_payload(payload))
            operation = lambda: _routine_outcome(service(actor, reference_code, command), reference_code)
        else:
            operation = lambda: _routine_outcome(service(actor, reference_code), reference_code)
        return _run(
            request,
            operation_id,
            _fingerprint_payload(reference_code=reference_code, command=command)
            if takes_command
            else _fingerprint_payload(reference_code=reference_code),
            operation,
        )

    return route


router.post(
    "/sessions/{reference_code}/routine-interview/complete/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_routine_complete",
)(_routine_action("counseling_routine_complete", "complete_routine_interview"))

router.post(
    "/sessions/{reference_code}/routine-interview/finalize/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_routine_finalize",
)(_routine_action("counseling_routine_finalize", "finalize_routine_interview"))

router.post(
    "/sessions/{reference_code}/routine-interview/lock/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_routine_lock",
)(_routine_action("counseling_routine_lock", "lock_routine_interview"))

router.post(
    "/sessions/{reference_code}/routine-interview/reopen/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_routine_reopen",
)(_routine_action("counseling_routine_reopen", "reopen_routine_interview_for_correction", takes_command=True))

def _case_outcome(case):
    return ApiMutationOutcome(
        value={"reference_code": case.reference_code, "status": case.status},
        related_object=case,
        safe_response_path=f"/api/v1/counseling/cases/{case.reference_code}/",
    )


# ---------------------------------------------------------------------------
# Counseling cases
# ---------------------------------------------------------------------------


@router.get(
    "/cases/",
    response=CounselingCaseQueuePageSchema,
    exclude_unset=True,
    operation_id="counseling_cases_list",
)
def list_cases(
    request,
    page: PageQuery,
    page_size: PageSizeQuery,
    q: str | None = Query(default=None, max_length=120),
    status: str | None = Query(default=None, max_length=400),
    concern_category: str | None = Query(default=None, max_length=40),
    priority: str | None = Query(default=None, max_length=20),
    assignment: str = Query(default="all", max_length=20),
    order: str = Query(default="recent", max_length=20),
):
    prepare_api_operation(request, "counseling_cases_list")
    try:
        return counseling_queries.get_counseling_case_metadata_page(
            _actor(request),
            _page(page, page_size),
            q=q,
            statuses=status,
            concern_category=concern_category,
            priority=priority,
            assignment=assignment,
            order=order,
        ).as_dict()
    except ValueError as exc:
        raise ValidationError(
            field_errors={"filters": ["Invalid counseling case filters."]}
        ) from exc


@router.get(
    "/cases/{reference_code}/",
    response=CounselingCaseProjectionSchema,
    exclude_unset=True,
    operation_id="counseling_case_detail",
)
def case_detail(request, reference_code: str):
    from apps.access_control.rules import is_student
    from apps.counseling.projections import project_case_metadata, project_student_case_metadata
    from apps.counseling.selectors import get_counseling_case_by_reference_code

    prepare_api_operation(request, "counseling_case_detail")
    projector = project_student_case_metadata if is_student(_actor(request)) else project_case_metadata
    payload = projector(
        _actor(request),
        get_counseling_case_by_reference_code(_actor(request), reference_code),
    )
    if payload is None:
        raise NotFoundError()
    return payload


@router.post(
    "/cases/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_case_create",
)
def create_case_route(request, payload: CaseCreateSchema):
    from apps.counseling.services import create_counseling_case

    actor = _actor(request)
    command = CaseCreateCommand(**_payload(payload))
    return _run(
        request,
        "counseling_case_create",
        _fingerprint_payload(command=command),
        lambda: _case_outcome(create_counseling_case(actor, command)),
    )


@router.post(
    "/cases/{reference_code}/assign-counselor/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_case_assign",
)
def assign_case_route(request, reference_code: str, payload: AssignmentSchema):
    from apps.counseling.models import CounselingCaseReasonCode
    from apps.counseling.services import assign_counseling_case_counselor

    actor = _actor(request)
    command = CaseAssignmentCommand(
        counselor_id=payload.counselor,
        reason_code=CounselingCaseReasonCode.ASSIGNMENT_CHANGE,
    )
    return _run(
        request,
        "counseling_case_assign",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _case_outcome(assign_counseling_case_counselor(actor, reference_code, command)),
    )


def _transition_action(operation_id, service_name):
    takes_reason = service_name in {
        "put_case_on_hold",
        "close_counseling_case",
        "reopen_counseling_case",
    }

    if takes_reason:
        def route(request, reference_code: str, payload: CaseReasonSchema | None = None):
            from apps.counseling import services as counseling_services

            actor = _actor(request)
            service = getattr(counseling_services, service_name)
            command = CaseTransitionCommand(
                reason_code=payload.reason_code if payload is not None else "",
            )
            return _run(
                request,
                operation_id,
                _fingerprint_payload(reference_code=reference_code, command=command),
                lambda: _case_outcome(service(actor, reference_code, command)),
            )

        return route

    def route(request, reference_code: str):
        from apps.counseling import services as counseling_services

        actor = _actor(request)
        service = getattr(counseling_services, service_name)
        return _run(
            request,
            operation_id,
            _fingerprint_payload(reference_code=reference_code),
            lambda: _case_outcome(service(actor, reference_code)),
        )

    return route


router.post(
    "/cases/{reference_code}/monitoring/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_case_transition_monitoring",
)(
    _transition_action("counseling_case_transition_monitoring", "transition_counseling_case_to_monitoring")
)
router.post(
    "/cases/{reference_code}/follow-up/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_case_transition_follow_up",
)(
    _transition_action("counseling_case_transition_follow_up", "transition_counseling_case_to_follow_up")
)
router.post(
    "/cases/{reference_code}/resolve/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_case_resolve",
)(
    _transition_action("counseling_case_resolve", "resolve_counseling_case")
)
router.post(
    "/cases/{reference_code}/close/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_case_close",
)(
    _transition_action("counseling_case_close", "close_counseling_case")
)
router.post(
    "/cases/{reference_code}/reopen/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_case_reopen",
)(
    _transition_action("counseling_case_reopen", "reopen_counseling_case")
)


class HoldSchema(Schema):
    reason_code: str


@router.post(
    "/cases/{reference_code}/hold/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_case_hold",
)
def hold_case_route(request, reference_code: str, payload: HoldSchema):
    from apps.counseling.services import put_case_on_hold

    actor = _actor(request)
    command = CaseTransitionCommand(reason_code=payload.reason_code)
    return _run(
        request,
        "counseling_case_hold",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _case_outcome(put_case_on_hold(actor, reference_code, command)),
    )


class ResumeSchema(Schema):
    target_status: str


@router.post(
    "/cases/{reference_code}/resume/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_case_resume",
)
def resume_case_route(request, reference_code: str, payload: ResumeSchema):
    from apps.counseling.services import resume_case_from_hold

    actor = _actor(request)
    command = CaseTransitionCommand(target_status=payload.target_status)
    return _run(
        request,
        "counseling_case_resume",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _case_outcome(resume_case_from_hold(actor, reference_code, command)),
    )


@router.post(
    "/cases/{reference_code}/collaborators/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_case_collaborator_add",
)
def add_collaborator_route(request, reference_code: str, payload: CollaboratorSchema):
    from apps.counseling.services import add_case_collaborator

    actor = _actor(request)
    command = CaseCollaboratorCommand(
        counselor_id=payload.counselor,
        reason_code=payload.reason_code,
    )
    return _run(
        request,
        "counseling_case_collaborator_add",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _flag_outcome(
            "added",
            add_case_collaborator(actor, reference_code, command).counseling_case,
            f"/api/v1/counseling/cases/{reference_code}/",
        ),
    )


@router.delete(
    "/cases/{reference_code}/collaborators/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_case_collaborator_remove",
)
def remove_collaborator_route(request, reference_code: str, payload: CollaboratorSchema):
    from apps.counseling.services import remove_case_collaborator

    actor = _actor(request)
    command = CaseCollaboratorCommand(
        counselor_id=payload.counselor,
        reason_code=payload.reason_code,
    )
    return _run(
        request,
        "counseling_case_collaborator_remove",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _case_outcome(remove_case_collaborator(actor, reference_code, command).counseling_case),
    )


@router.post(
    "/cases/{reference_code}/sessions/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_case_link_session",
)
def link_session_route(request, reference_code: str, payload: LinkSchema):
    from apps.counseling.services import link_session_to_counseling_case

    actor = _actor(request)
    command = CaseSessionLinkCommand(**_payload(payload))
    return _run(
        request,
        "counseling_case_link_session",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _case_outcome(link_session_to_counseling_case(actor, reference_code, command).counseling_case),
    )

def _urgent_outcome(urgent_support):
    return ApiMutationOutcome(
        value={"reference_code": urgent_support.reference_code, "status": urgent_support.status},
        related_object=urgent_support,
        safe_response_path=f"/api/v1/counseling/urgent-support/{urgent_support.reference_code}/",
    )


# ---------------------------------------------------------------------------
# Urgent support
# ---------------------------------------------------------------------------


@router.get(
    "/urgent-support/",
    response=UrgentSupportPageSchema,
    exclude_unset=True,
    operation_id="counseling_urgent_list",
)
def list_urgent(
    request,
    page: PageQuery,
    page_size: PageSizeQuery,
    q: str | None = Query(default=None, max_length=120),
    status: str | None = Query(default=None, max_length=400),
    urgency_level: str | None = Query(default=None, max_length=40),
    source_type: str | None = Query(default=None, max_length=40),
    assignment: str = Query(default="all", max_length=20),
    review_status: str | None = Query(default=None, max_length=60),
    order: str = Query(default="recent", max_length=20),
):
    prepare_api_operation(request, "counseling_urgent_list")
    try:
        return counseling_queries.get_urgent_support_metadata_page(
            _actor(request),
            _page(page, page_size),
            q=q,
            statuses=status,
            urgency_level=urgency_level,
            source_type=source_type,
            assignment=assignment,
            review_status=review_status,
            order=order,
        ).as_dict()
    except ValueError as error:
        raise ValidationError(field_errors={"filters": ["Invalid urgent-support filters."]}) from error


@router.get(
    "/urgent-support/{reference_code}/",
    response=UrgentSupportProjectionSchema,
    exclude_unset=True,
    operation_id="counseling_urgent_detail",
)
def urgent_detail(request, reference_code: str):
    from apps.counseling.selectors import get_urgent_support_request_by_reference_code

    prepare_api_operation(request, "counseling_urgent_detail")
    payload = counseling_queries.project_urgent_support_metadata(
        _actor(request),
        get_urgent_support_request_by_reference_code(_actor(request), reference_code),
    )
    if payload is None:
        raise NotFoundError()
    return payload


@router.get(
    "/urgent-support/{reference_code}/counselor-options/",
    response=UrgentSupportCounselorOptionPageSchema,
    exclude_unset=True,
    operation_id="counseling_urgent_counselor_options",
)
def urgent_counselor_options(
    request,
    reference_code: str,
    page: PageQuery,
    page_size: PageSizeQuery,
    q: str | None = Query(default=None, max_length=80),
):
    from apps.counseling.selectors import get_urgent_support_request_by_reference_code

    prepare_api_operation(request, "counseling_urgent_counselor_options")
    actor = _actor(request)
    urgent_support = get_urgent_support_request_by_reference_code(actor, reference_code)
    if urgent_support is None:
        raise NotFoundError()
    return counseling_queries.get_urgent_support_options(
        actor,
        urgent_support,
        q=q,
        page=_page(page, page_size),
    ).as_dict()


@router.get(
    "/urgent-support/{reference_code}/link-options/",
    response=CounselingUrgentLinkOptionsSchema,
    exclude_unset=True,
    operation_id="counseling_urgent_link_options",
)
def urgent_link_options(request, reference_code: str):
    from apps.counseling.integrations import get_urgent_link_options
    from apps.counseling.selectors import get_urgent_support_request_by_reference_code

    prepare_api_operation(request, "counseling_urgent_link_options")
    actor = _actor(request)
    urgent_support = get_urgent_support_request_by_reference_code(actor, reference_code)
    if urgent_support is None:
        raise NotFoundError()
    return get_urgent_link_options(actor, urgent_support)


@router.post(
    "/urgent-support/{reference_code}/link-session/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_urgent_link_session",
)
def link_urgent_session_route(request, reference_code: str, payload: UrgentSupportLinkSchema):
    from apps.counseling.services import link_urgent_support_to_session

    actor = _actor(request)
    data = _payload(payload)
    intent = str(data.pop("intent", "") or "").strip().lower()
    if intent not in {"originating", "documentation"}:
        raise ValidationError(field_errors={"intent": ["Choose originating or documentation."]})
    command = UrgentLinkCommand(
        target_reference_code=data["target_reference_code"],
        documentation=intent == "documentation",
    )
    return _run(
        request,
        "counseling_urgent_link_session",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _urgent_outcome(link_urgent_support_to_session(actor, reference_code, command)),
    )


@router.post(
    "/urgent-support/{reference_code}/link-case/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_urgent_link_case",
)
def link_urgent_case_route(request, reference_code: str, payload: UrgentSupportLinkSchema):
    from apps.counseling.services import link_urgent_support_to_case

    actor = _actor(request)
    data = _payload(payload)
    command = UrgentLinkCommand(target_reference_code=data["target_reference_code"])
    return _run(
        request,
        "counseling_urgent_link_case",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _urgent_outcome(link_urgent_support_to_case(actor, reference_code, command)),
    )


@router.post(
    "/urgent-support/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_urgent_create",
)
def create_urgent_route(request, payload: UrgentCreateSchema):
    from apps.counseling.services import create_urgent_support_request

    actor = request.auth.user
    data = _payload(payload)
    student_id = data.get("student_id")
    if student_id in (None, ""):
        from apps.access_control.rules import is_student

        if is_student(actor):
            student_id = str(actor.pk)
        else:
            raise ValidationError("student_id is required for staff-initiated urgent support.")
    command = UrgentSupportCreateCommand(
        student_id=str(student_id),
        source_type=data["source_type"],
        urgency_level=data["urgency_level"],
        originating_session_reference=data.get("originating_session_reference"),
        counseling_case_reference=data.get("counseling_case_reference"),
    )
    return _run(
        request,
        "counseling_urgent_create",
        _fingerprint_payload(command=command),
        lambda: _urgent_outcome(create_urgent_support_request(actor, command)),
    )


@router.post(
    "/urgent-support/{reference_code}/triage/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_urgent_triage",
)
def triage_urgent_route(request, reference_code: str, payload: UrgentTriageSchema):
    from apps.counseling.services import create_urgent_support_triage_session
    from apps.counseling.selectors import get_urgent_support_request_by_reference_code
    from apps.counseling.urgent_support_selectors import resolve_counselor_selection_token

    actor = _actor(request)
    data = _payload(payload)
    selection_token = data.pop("counselor_selection_token", None)
    if selection_token:
        urgent_support = get_urgent_support_request_by_reference_code(actor, reference_code)
        counselor = (
            resolve_counselor_selection_token(actor, urgent_support, selection_token)
            if urgent_support is not None
            else None
        )
        if counselor is None:
            raise ValidationError(field_errors={"counselor_selection_token": ["Invalid counselor selection."]})
        data["assigned_counselor"] = counselor.pk
    command = UrgentSupportTriageCommand(
        assigned_counselor_id=data.pop("assigned_counselor", None),
        **data,
    )
    return _run(
        request,
        "counseling_urgent_triage",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _run_triage(actor, reference_code, command),
    )


def _run_triage(actor, reference_code, command):
    session = create_urgent_support_triage_session(actor, reference_code, command)
    return ApiMutationOutcome(
        value={"reference_code": session.reference_code, "status": session.status},
        related_object=session,
        safe_response_path=f"/api/v1/counseling/sessions/{session.reference_code}/",
    )


@router.post(
    "/urgent-support/{reference_code}/review/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_urgent_review",
)
def review_urgent_route(request, reference_code: str, payload: UrgentSupportReviewSchema):
    from apps.counseling.services import confirm_urgent_support_review

    actor = _actor(request)
    command = UrgentSupportReviewCommand(**_payload(payload))
    return _run(
        request,
        "counseling_urgent_review",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _urgent_outcome(confirm_urgent_support_review(actor, reference_code, command)),
    )


@router.post(
    "/urgent-support/{reference_code}/close/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_urgent_close",
)
def close_urgent_route(request, reference_code: str, payload: ClosureSchema):
    from apps.counseling.services import close_urgent_support_request

    actor = _actor(request)
    command = UrgentSupportClosureCommand(**_payload(payload))
    return _run(
        request,
        "counseling_urgent_close",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _urgent_outcome(close_urgent_support_request(actor, reference_code, command)),
    )

@router.post(
    "/urgent-support/{reference_code}/access-grants/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_urgent_access_grant",
)
def grant_access_route(request, reference_code: str, payload: AccessGrantSchema):
    from apps.counseling.services import grant_temporary_support_access
    from apps.counseling.selectors import get_urgent_support_request_by_reference_code
    from apps.counseling.urgent_support_selectors import resolve_counselor_selection_token

    actor = _actor(request)
    data = _payload(payload)
    selection_token = data.pop("grantee_selection_token", None)
    if selection_token:
        urgent_support = get_urgent_support_request_by_reference_code(actor, reference_code)
        counselor = (
            resolve_counselor_selection_token(actor, urgent_support, selection_token)
            if urgent_support is not None
            else None
        )
        if counselor is None:
            raise ValidationError(field_errors={"grantee_selection_token": ["Invalid counselor selection."]})
        data["grantee_id"] = counselor.pk
    command = TemporarySupportAccessCommand(**data)
    return _run(
        request,
        "counseling_urgent_access_grant",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _flag_outcome(
            "granted",
            grant_temporary_support_access(actor, reference_code, command).urgent_support,
            f"/api/v1/counseling/urgent-support/{reference_code}/",
        ),
    )


@router.delete(
    "/urgent-support/access-grants/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_urgent_access_revoke",
)
def revoke_access_route(request, payload: UrgentSupportRevokeSchema):
    from apps.counseling.services import revoke_temporary_support_access
    from apps.counseling.selectors import get_urgent_support_requests_visible_to
    from apps.counseling.urgent_support_selectors import resolve_grant_selection_token

    actor = _actor(request)
    data = _payload(payload)
    selection_token = data.pop("grant_selection_token", None)
    if selection_token:
        grant = None
        for urgent_support in get_urgent_support_requests_visible_to(actor):
            grant = resolve_grant_selection_token(actor, urgent_support, selection_token)
            if grant is not None:
                data["grant_id"] = grant.pk
                break
        if grant is None:
            raise ValidationError(field_errors={"grant_selection_token": ["Invalid grant selection."]})
    command = TemporarySupportRevokeCommand(**data)
    return _run(
        request,
        "counseling_urgent_access_revoke",
        _fingerprint_payload(command=command),
        lambda: _flag_outcome(
            "revoked",
            revoke_temporary_support_access(actor, command).urgent_support,
            "/api/v1/counseling/urgent-support/",
        ),
    )

# ---------------------------------------------------------------------------
# E-counseling
# ---------------------------------------------------------------------------


def _load_ecounseling_or_404(actor, reference_code):
    from apps.counseling.selectors import get_ecounseling_session_by_reference_code

    ecounseling_session = get_ecounseling_session_by_reference_code(actor, reference_code)
    if ecounseling_session is None:
        raise NotFoundError()
    return ecounseling_session


def _safe_recording_timestamp(value):
    return value.isoformat() if value else None


def _recording_run_projection(run):
    """Return a fixed projection with no provider or protected-storage identifiers."""

    return {
        "run_id": str(run.pk),
        "reference_code": run.ecounseling_session.reference_code,
        "status": run.status,
        "scope": run.scope_code_snapshot,
        "consent_status": run.ecounseling_session.recording_consent_status,
        "transcription_status": run.transcription_status,
        "started_at": _safe_recording_timestamp(run.started_at),
        "stopped_at": _safe_recording_timestamp(run.stopped_at),
        "available_at": _safe_recording_timestamp(run.available_at),
        "expires_at": _safe_recording_timestamp(run.expires_at),
        "transcription_started_at": _safe_recording_timestamp(run.transcription_started_at),
        "transcription_available_at": _safe_recording_timestamp(run.transcription_available_at),
        "transcription_expires_at": _safe_recording_timestamp(run.transcription_expires_at),
        "transcript_available": bool(
            run.transcript_protected_file_id
            and run.transcription_status == "AVAILABLE"
        ),
        "safe_failure_code": run.safe_failure_code or None,
        "transcription_failure_code": run.transcription_failure_code or None,
    }


def _recording_run_for_actor(actor, reference_code, run_id=None, *, technical_metadata=False):
    from apps.counseling.models import ECounselingRecordingRun, ECounselingSession

    try:
        session = _load_ecounseling_or_404(actor, reference_code)
    except NotFoundError:
        from apps.access_control.authority import has_fixed_capability
        from apps.access_control.capabilities import Capability

        if not technical_metadata or not has_fixed_capability(actor, Capability.PROTECTED_FILES_METADATA_INSPECT):
            raise
        session = ECounselingSession.objects.filter(reference_code=str(reference_code).strip()).first()
        if session is None:
            raise
    query = ECounselingRecordingRun.objects.select_related("ecounseling_session").filter(
        ecounseling_session_id=session.pk,
    )
    if run_id:
        query = query.filter(pk=str(run_id))
    return query.order_by("-created_at").first()


@router.get(
    "/ecounseling/recording-availability/",
    response=RecordingAvailabilitySchema,
    exclude_unset=True,
    operation_id="counseling_ecounseling_recording_availability",
)
def recording_availability_route(request):
    from apps.counseling.recording_policy import recording_availability_projection

    prepare_api_operation(request, "counseling_ecounseling_recording_availability")
    projection = recording_availability_projection()
    return {
        "state": projection.state.value,
        "available": not projection.blocked,
        "available_scopes": list(projection.available_scopes),
        "transcription_available": projection.transcription_available,
        "reason_code": projection.reason_code,
        "message": projection.user_message,
    }


@router.get(
    "/ecounseling/{reference_code}/recording/status/",
    response=RecordingStatusSchema,
    exclude_unset=True,
    operation_id="counseling_ecounseling_recording_status",
)
def recording_status_route(request, reference_code: str):
    prepare_api_operation(request, "counseling_ecounseling_recording_status")
    run = _recording_run_for_actor(_actor(request), reference_code, technical_metadata=True)
    if run is None:
        return {"reference_code": reference_code, "status": "NOT_REQUESTED", "run": None}
    return {"reference_code": reference_code, "status": run.status, "run": _recording_run_projection(run)}


@router.post(
    "/ecounseling/{reference_code}/recording/start/",
    response=RecordingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_ecounseling_recording_start",
)
def recording_start_route(request, reference_code: str, payload: RecordingStartSchema | None = None):
    from apps.counseling.recording_services import start_recording

    actor = _actor(request)
    command = ECounselingRecordingStartCommand(**(_payload(payload) if payload is not None else {}))

    def operation():
        run = start_recording(actor, reference_code, command)
        return ApiMutationOutcome(
            value={"started": True, "run": _recording_run_projection(run)},
            related_object=run,
            safe_response_path=f"/api/v1/counseling/ecounseling/{reference_code}/recording/status/",
        )

    return _run(
        request,
        "counseling_ecounseling_recording_start",
        _fingerprint_payload(reference_code=reference_code, command=command),
        operation,
    )


@router.post(
    "/ecounseling/{reference_code}/recording/{run_id}/stop/",
    response=RecordingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_ecounseling_recording_stop",
)
def recording_stop_route(
    request,
    reference_code: str,
    run_id: UUID,
    payload: RecordingStopSchema | None = None,
):
    from apps.counseling.recording_services import request_recording_stop

    run_id = str(run_id)
    actor = _actor(request)
    command = ECounselingRecordingStopCommand(**(_payload(payload) if payload is not None else {}))

    def operation():
        run = _recording_run_for_actor(actor, reference_code, run_id)
        if run is None:
            raise NotFoundError()
        run = request_recording_stop(actor, str(run.pk), command)
        return ApiMutationOutcome(
            value={"stopped": True, "run": _recording_run_projection(run)},
            related_object=run,
            safe_response_path=f"/api/v1/counseling/ecounseling/{reference_code}/recording/status/",
        )

    return _run(
        request,
        "counseling_ecounseling_recording_stop",
        _fingerprint_payload(reference_code=reference_code, run_id=run_id, command=command),
        operation,
    )


@router.get(
    "/ecounseling/{reference_code}/recording/{run_id}/status/",
    response=RecordingRunProjectionSchema,
    exclude_unset=True,
    operation_id="counseling_ecounseling_recording_run_status",
)
def recording_run_status_route(request, reference_code: str, run_id: UUID):
    prepare_api_operation(request, "counseling_ecounseling_recording_run_status")
    run_id = str(run_id)
    run = _recording_run_for_actor(_actor(request), reference_code, run_id)
    if run is None:
        raise NotFoundError()
    return _recording_run_projection(run)


@router.get(
    "/ecounseling/{reference_code}/transcript/status/",
    response=TranscriptionStatusSchema,
    exclude_unset=True,
    operation_id="counseling_ecounseling_transcription_status",
)
def transcription_status_route(request, reference_code: str):
    prepare_api_operation(request, "counseling_ecounseling_transcription_status")
    run = _recording_run_for_actor(_actor(request), reference_code, technical_metadata=True)
    if run is None:
        return {"status": "NOT_REQUESTED", "available": False}
    return {
        "status": run.transcription_status,
        "available": bool(run.transcript_protected_file_id),
        "available_at": _safe_recording_timestamp(run.transcription_available_at),
        "expires_at": _safe_recording_timestamp(run.transcription_expires_at),
        "failure_code": run.transcription_failure_code or None,
    }


@router.get(
    "/ecounseling/{reference_code}/transcript/metadata/",
    response=TranscriptMetadataSchema,
    exclude_unset=True,
    operation_id="counseling_ecounseling_transcript_metadata",
)
def transcript_metadata_route(request, reference_code: str):
    prepare_api_operation(request, "counseling_ecounseling_transcript_metadata")
    run = _recording_run_for_actor(_actor(request), reference_code, technical_metadata=True)
    if run is None or not run.transcript_protected_file_id:
        raise NotFoundError()
    file = run.transcript_protected_file
    return {
        "available": run.transcription_status == "AVAILABLE",
        "content_type": file.content_type,
        "file_size_bytes": file.file_size_bytes,
        "expires_at": _safe_recording_timestamp(run.transcription_expires_at),
    }


@router.get(
    "/ecounseling/{reference_code}/transcript/download/",
    response=None,
    openapi_extra=workflow_download_openapi(),
    operation_id="counseling_ecounseling_transcript_download",
)
def transcript_download_route(request, reference_code: str):
    from apps.security.downloads import (
        ProtectedFileDownloadDenied,
        build_protected_file_stream_download_response,
    )

    prepare_api_operation(request, "counseling_ecounseling_transcript_download")
    run = _recording_run_for_actor(_actor(request), reference_code)
    if run is None or not run.transcript_protected_file_id:
        raise NotFoundError()
    try:
        return build_protected_file_stream_download_response(
            _actor(request),
            run.transcript_protected_file_id,
            filename="ecounseling-transcript.vtt",
        )
    except ProtectedFileDownloadDenied:
        raise NotFoundError()


@router.get(
    "/ecounseling/{reference_code}/recording/{run_id}/download/",
    response=None,
    openapi_extra=binary_response_openapi(
        "video/mp4",
        description="Authorized e-counseling recording content",
    ),
    operation_id="counseling_ecounseling_recording_download",
)
def recording_download_route(request, reference_code: str, run_id: str):
    """Stream an available recording to its assigned counselor only."""

    from apps.counseling.recording_services import recording_file_policy
    from apps.security.downloads import (
        ProtectedFileDownloadDenied,
        build_protected_file_stream_download_response,
    )

    prepare_api_operation(request, "counseling_ecounseling_recording_download")
    try:
        UUID(str(run_id))
    except (TypeError, ValueError):
        raise NotFoundError()

    actor = _actor(request)
    run = _recording_run_for_actor(actor, reference_code, str(run_id))
    if run is None or not run.protected_file_id:
        raise NotFoundError()
    if not recording_file_policy(actor, run.protected_file, "download"):
        raise NotFoundError()
    try:
        return build_protected_file_stream_download_response(actor, run.protected_file_id)
    except ProtectedFileDownloadDenied:
        raise NotFoundError()


@router.post(
    "/ecounseling/provider-webhook/",
    auth=None,
    response=ProviderWebhookResponseSchema,
    exclude_unset=True,
    operation_id="counseling_ecounseling_provider_webhook",
)
def provider_webhook_route(request):
    from apps.counseling.recording_services import process_provider_callback

    meta = getattr(request, "META", {}) or {}
    process_provider_callback(
        signature_header=str(meta.get("HTTP_X_WEBHOOK_SIGNATURE", "") or ""),
        timestamp_header=str(meta.get("HTTP_X_WEBHOOK_TIMESTAMP", "") or ""),
        body=request.body,
    )
    return {"accepted": True}


@router.get(
    "/ecounseling/{reference_code}/",
    response=ECounselingJoinStateSchema,
    exclude_unset=True,
    operation_id="counseling_ecounseling_detail",
)
def ecounseling_detail(request, reference_code: str):
    from apps.counseling.ecounseling_services import get_ecounseling_join_state

    prepare_api_operation(request, "counseling_ecounseling_detail")
    actor = _actor(request)
    state = get_ecounseling_join_state(actor, _load_ecounseling_or_404(actor, reference_code))
    if state is None:
        raise NotFoundError()
    return state


@router.post(
    "/ecounseling/{reference_code}/consent/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_ecounseling_consent_request",
)
def consent_request_route(request, reference_code: str, payload: ConsentRequestSchema):
    from apps.counseling.ecounseling_services import request_recording_consent

    actor = _actor(request)
    command = ECounselingConsentRequestCommand(**_payload(payload))
    return _run(
        request,
        "counseling_ecounseling_consent_request",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _flag_outcome(
            "requested",
            request_recording_consent(actor, reference_code, command).counseling_session,
            f"/api/v1/counseling/ecounseling/{reference_code}/",
        ),
    )


@router.post(
    "/ecounseling/{reference_code}/consent/decision/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_ecounseling_consent_decision",
)
def consent_decision_route(request, reference_code: str, payload: ConsentDecisionSchema):
    from apps.counseling.ecounseling_services import decide_recording_consent

    actor = _actor(request)
    command = ECounselingConsentDecisionCommand(**_payload(payload))
    return _run(
        request,
        "counseling_ecounseling_consent_decision",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _flag_outcome(
            "decided",
            decide_recording_consent(actor, reference_code, command).counseling_session,
            f"/api/v1/counseling/ecounseling/{reference_code}/",
        ),
    )


@router.delete(
    "/ecounseling/{reference_code}/consent/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_ecounseling_consent_withdraw",
)
def consent_withdraw_route(request, reference_code: str):
    from apps.counseling.ecounseling_services import withdraw_recording_consent

    actor = _actor(request)
    return _run(
        request,
        "counseling_ecounseling_consent_withdraw",
        _fingerprint_payload(reference_code=reference_code),
        lambda: _flag_outcome(
            "withdrawn",
            withdraw_recording_consent(actor, reference_code).counseling_session,
            f"/api/v1/counseling/ecounseling/{reference_code}/",
        ),
    )

@router.post(
    "/ecounseling/{reference_code}/participants/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_ecounseling_participant_add",
)
def participant_add_route(request, reference_code: str, payload: ParticipantAddSchema):
    from apps.counseling.ecounseling_services import add_ecounseling_participant

    actor = _actor(request)
    command = ECounselingParticipantAddCommand(**_payload(payload))
    return _run(
        request,
        "counseling_ecounseling_participant_add",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _flag_outcome(
            "added",
            add_ecounseling_participant(actor, reference_code, command).ecounseling_session.counseling_session,
            f"/api/v1/counseling/ecounseling/{reference_code}/",
        ),
    )


@router.delete(
    "/ecounseling/{reference_code}/participants/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_ecounseling_participant_revoke",
)
def participant_revoke_route(request, reference_code: str, payload: ParticipantRevokeSchema):
    from apps.counseling.ecounseling_services import revoke_ecounseling_participant

    actor = _actor(request)
    command = ECounselingParticipantRevokeCommand(**_payload(payload))
    return _run(
        request,
        "counseling_ecounseling_participant_revoke",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _flag_outcome(
            "revoked",
            revoke_ecounseling_participant(actor, reference_code, command).ecounseling_session.counseling_session,
            f"/api/v1/counseling/ecounseling/{reference_code}/",
        ),
    )


@router.post(
    "/ecounseling/{reference_code}/join/",
    response=ECounselingJoinContextSchema,
    exclude_unset=True,
    operation_id="counseling_ecounseling_join",
)
def join_route(request, reference_code: str, payload: JoinSchema | None = None):
    """Join boundary: request context is extracted here and never returned."""
    from apps.counseling.ecounseling_services import generate_join_context

    prepare_api_operation(request, "counseling_ecounseling_join")
    actor = _actor(request)
    meta = getattr(request, "META", {}) or {}
    request_context = RequestMetadata(
        ip_address=get_client_ip_from_headers(meta),
        user_agent=str(meta.get("HTTP_USER_AGENT", "") or "")[:512],
    )
    context = generate_join_context(
        actor,
        _load_ecounseling_or_404(actor, reference_code),
        request_context=request_context,
    )
    if context is None:
        raise NotFoundError()
    return context


@router.post(
    "/ecounseling/{reference_code}/end/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_ecounseling_end",
)
def end_route(request, reference_code: str, payload: NoteSchema | None = None):
    from apps.orchestration.commands import CompleteCounselingSessionCommand
    from apps.orchestration.use_cases import complete_counseling_session_with_linked_appointment

    actor = _actor(request)
    note = CounselingNoteCommand(**(_payload(payload) if payload is not None else {}))

    def operation():
        ecounseling_session = _load_ecounseling_or_404(actor, reference_code)
        command = CompleteCounselingSessionCommand(
            session_id=str(ecounseling_session.counseling_session_id),
            note=note,
        )
        session = complete_counseling_session_with_linked_appointment(actor, command)
        return _session_outcome(session)

    return _run(
        request,
        "counseling_ecounseling_end",
        _fingerprint_payload(reference_code=reference_code, command=note),
        operation,
    )


@router.post(
    "/ecounseling/{reference_code}/cancel/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_ecounseling_cancel",
)
def cancel_route(request, reference_code: str, payload: CancelSchema | None = None):
    from apps.counseling.ecounseling_services import cancel_ecounseling_session

    actor = _actor(request)
    command = ECounselingCancelCommand(**(_payload(payload) if payload is not None else {}))
    return _run(
        request,
        "counseling_ecounseling_cancel",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _flag_outcome(
            "cancelled",
            cancel_ecounseling_session(actor, reference_code, command).counseling_session,
            f"/api/v1/counseling/ecounseling/{reference_code}/",
        ),
    )

@router.post(
    "/appointments/{reference_code}/open-session/",
    response=CounselingMutationResponseSchema,
    exclude_unset=True,
    operation_id="counseling_session_open_from_appointment",
)
def open_session_from_appointment(request, reference_code: str):
    """Open (or return) the counseling session linked to a scheduled appointment."""
    from apps.appointments.models import Appointment
    from apps.common.exceptions import NotFoundError as DomainNotFoundError
    from apps.orchestration.commands import LinkedAppointmentCommand
    from apps.orchestration.use_cases import create_or_open_session_from_scheduled_appointment

    actor = _actor(request)
    appointment = Appointment.objects.filter(reference_code=reference_code).first()
    if appointment is None:
        raise DomainNotFoundError()

    def operation():
        command = LinkedAppointmentCommand(appointment_id=str(appointment.pk))
        session, created = create_or_open_session_from_scheduled_appointment(actor, command)
        return ApiMutationOutcome(
            value={
                "reference_code": session.reference_code,
                "status": session.status,
                "created": created,
            },
            related_object=session,
            safe_response_path=f"/api/v1/counseling/sessions/{session.reference_code}/",
        )

    return _run(
        request,
        "counseling_session_open_from_appointment",
        {"reference_code": reference_code},
        operation,
    )
