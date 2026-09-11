# Project: COMPASS
# File: apps/counseling/services.py
# Module: apps.counseling
# Purpose: Transactional counseling session workflow services
# Domain boundary and service policy.

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.access_control.rules import (
    is_active_nonlegacy_actor,
    is_counselor,
    is_gco_staff,
    is_head_guidance,
    is_student,
)
from apps.audit.services import audit_assignment_change, audit_log, audit_status_transition
from apps.counseling.models import (
    CounselingAssignmentHistoryReasonChoices,
    CounselingSession,
    CounselingSessionNote,
    CounselingStatusHistoryReasonChoices,
    RoutineInterviewCorrectionTargetChoices,
    RoutineInterviewRecord,
    RoutineInterviewStatusChoices,
    RoutineStatusHistoryReasonChoices,
    SessionModeChoices,
    SessionSourceChoices,
    SessionStatusChoices,
    SessionTypeChoices,
    CounselingCaseStatus,
    CounselingCasePriority,
    CounselingCaseConcernCategory,
    CounselingCaseReasonCode,
    CounselingCaseSessionLinkType,
    CounselingCase,
    CounselingCaseCollaborator,
    CounselingCaseSession,
    CounselingCaseStatusHistory,
    CounselingCaseAssignmentHistory,
    UrgentSupportRequest,
    TemporarySupportAccessGrant,
    UrgentSupportHistory,
    UrgentSupportSourceType,
    UrgentSupportStatus,
    UrgentSupportReviewStatus,
    UrgentSupportDocumentationStatus,
    UrgentSupportUrgencyLevel,
    TemporarySupportAccessType,
    TemporarySupportAccessPurpose,
    TemporarySupportAccessStatus,
    UrgentSupportClosureReasonCode,
)
from apps.counseling.commands import (
    CaseAssignmentCommand,
    CaseCollaboratorCommand,
    CaseCreateCommand,
    CaseSessionLinkCommand,
    CaseTransitionCommand,
    CounselingNoteCommand,
    ECounselingCreateCommand,
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
from apps.counseling.encryption import (
    NOTE_COUNSELOR,
    NOTE_SHARED,
    ROUTINE_CORRECTION,
    ROUTINE_EVALUATION,
    ROUTINE_INTAKE,
    ROUTINE_CONFIDENTIAL_FIELDS,
    SESSION_CANCEL,
    SESSION_CONCERN,
    SESSION_CONFIDENTIAL_FIELDS,
    CounselingEncryptionError,
    initialize_group,
    prepare_group_write,
)
from apps.counseling.history import (
    create_routine_status_history,
    create_session_assignment_history,
    create_session_status_history,
)
from apps.counseling.policies import (
    can_assign_session,
    can_assign_session_to,
    can_cancel_session,
    can_create_session_for,
    can_edit_counseling_notes,
    can_edit_session,
    can_finalize_session,
    can_lock_session,
    can_mark_session_no_show,
    can_transition_session,
    can_complete_routine_interview,
    can_create_routine_interview_record,
    can_edit_routine_interview_evaluation,
    can_edit_routine_interview_intake,
    can_finalize_routine_interview,
    can_lock_routine_interview,
    can_reopen_routine_interview,
    can_submit_routine_interview_intake,
)
from apps.counseling.reference_codes import generate_session_reference_code
from apps.counseling.workspace import WorkspaceStateStale
from apps.common.exceptions import PermissionDeniedError, ValidationError, WorkflowError


class SessionPermissionError(PermissionDeniedError):
    pass


class SessionTransitionError(WorkflowError):
    pass


class SessionValidationError(ValidationError):
    pass


class DuplicateCounselingSessionError(SessionValidationError):
    pass


class CasePermissionError(PermissionDeniedError):
    pass


class CaseTransitionError(WorkflowError):
    pass


class CaseValidationError(ValidationError):
    pass


SUPPORTED_SOURCES = {
    SessionSourceChoices.APPOINTMENT,
    SessionSourceChoices.COUNSELOR_INITIATED,
    SessionSourceChoices.WALK_IN,
}

DEFERRED_SOURCES = {
    SessionSourceChoices.REFERRED,
    SessionSourceChoices.CALL_SLIP,
    SessionSourceChoices.ECOUNSELING,
    SessionSourceChoices.URGENT_SUPPORT,
    SessionSourceChoices.ROUTINE_COLLECTION,
    SessionSourceChoices.CALLED_IN,
}

URGENT_SUPPORT_TRIAGE_CONCERN_SUMMARY = "Urgent student support triage session"

_VALID_TRANSITIONS = {
    SessionStatusChoices.SCHEDULED: [
        SessionStatusChoices.IN_PROGRESS,
        SessionStatusChoices.CANCELLED,
        SessionStatusChoices.NO_SHOW,
    ],
    SessionStatusChoices.IN_PROGRESS: [
        SessionStatusChoices.COUNSELOR_NOTES_DRAFT,
        SessionStatusChoices.COMPLETED,
    ],
    SessionStatusChoices.COUNSELOR_NOTES_DRAFT: [SessionStatusChoices.COMPLETED],
    SessionStatusChoices.COMPLETED: [SessionStatusChoices.FINALIZED],
    SessionStatusChoices.FINALIZED: [SessionStatusChoices.LOCKED],
    SessionStatusChoices.LOCKED: [],
    SessionStatusChoices.CANCELLED: [],
    SessionStatusChoices.NO_SHOW: [],
}

NOTE_FIELDS = {
    "student_visible_summary",
    "counselor_narrative",
    "recommendations",
    "special_concerns",
    "follow_up_needed",
    "follow_up_notes",
}
NOTE_SHARED_FIELDS = {"student_visible_summary"}
NOTE_COUNSELOR_FIELDS = {
    "counselor_narrative",
    "recommendations",
    "special_concerns",
    "follow_up_notes",
}

ROUTINE_INTAKE_FIELDS = {
    "visit_date",
    "visit_time",
    "duration_minutes",
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
    "concern_others_text",
}
ROUTINE_INTAKE_CONFIDENTIAL_FIELDS = {
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
}
ROUTINE_INTAKE_METADATA_FIELDS = ROUTINE_INTAKE_FIELDS - ROUTINE_INTAKE_CONFIDENTIAL_FIELDS

ROUTINE_EVALUATION_FIELDS = {
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
    "assigned_counselor_confirmation",
    "evaluation_date",
}
ROUTINE_EVALUATION_CONFIDENTIAL_FIELDS = {
    "rating_others_label",
    "special_concern",
    "recommendations",
}
ROUTINE_EVALUATION_METADATA_FIELDS = (
    ROUTINE_EVALUATION_FIELDS - ROUTINE_EVALUATION_CONFIDENTIAL_FIELDS
)

ROUTINE_VALID_TRANSITIONS = {
    RoutineInterviewStatusChoices.NOT_STARTED: [
        RoutineInterviewStatusChoices.INTAKE_DRAFT,
        RoutineInterviewStatusChoices.INTAKE_SUBMITTED,
    ],
    RoutineInterviewStatusChoices.INTAKE_DRAFT: [
        RoutineInterviewStatusChoices.INTAKE_SUBMITTED,
    ],
    RoutineInterviewStatusChoices.INTAKE_SUBMITTED: [
        RoutineInterviewStatusChoices.EVALUATION_DRAFT,
        RoutineInterviewStatusChoices.COMPLETED,
    ],
    RoutineInterviewStatusChoices.EVALUATION_DRAFT: [
        RoutineInterviewStatusChoices.COMPLETED,
    ],
    RoutineInterviewStatusChoices.COMPLETED: [
        RoutineInterviewStatusChoices.FINALIZED,
    ],
    RoutineInterviewStatusChoices.FINALIZED: [
        RoutineInterviewStatusChoices.LOCKED,
        RoutineInterviewStatusChoices.REOPENED_FOR_CORRECTION,
    ],
    RoutineInterviewStatusChoices.LOCKED: [
        RoutineInterviewStatusChoices.REOPENED_FOR_CORRECTION,
    ],
    RoutineInterviewStatusChoices.REOPENED_FOR_CORRECTION: [
        RoutineInterviewStatusChoices.INTAKE_DRAFT,
        RoutineInterviewStatusChoices.INTAKE_SUBMITTED,
        RoutineInterviewStatusChoices.EVALUATION_DRAFT,
    ],
}


def _validate_transition(session, new_status):
    valid_next = _VALID_TRANSITIONS.get(session.status, [])
    if new_status not in valid_next:
        raise SessionTransitionError(
            f"Cannot transition from {session.status} to {new_status}."
        )


def _validate_choice(value, choices, field_name):
    allowed = {choice for choice, _label in choices}
    if value not in allowed:
        raise SessionValidationError(f"Invalid {field_name}: {value}")


def _validate_routine_transition(record, new_status):
    valid_next = ROUTINE_VALID_TRANSITIONS.get(record.status, [])
    if new_status not in valid_next:
        raise SessionTransitionError(
            f"Cannot transition routine interview from {record.status} to {new_status}."
        )


def _validate_routine_parent(session):
    if session.session_type != SessionTypeChoices.ROUTINE_INTERVIEW:
        raise SessionValidationError("Routine Interview records require a Routine Interview session.")


def _validate_supported_source(source):
    _validate_choice(source, SessionSourceChoices.choices, "session_source")
    if source in DEFERRED_SOURCES or source not in SUPPORTED_SOURCES:
        raise SessionValidationError(f"Session source is deferred: {source}")


def _validate_schedule(start_at, end_at):
    if start_at and end_at and start_at >= end_at:
        raise SessionValidationError("Scheduled end must be after scheduled start.")


def _calculate_duration_minutes(session):
    if not session.actual_started_at or not session.actual_ended_at:
        return None
    seconds = (session.actual_ended_at - session.actual_started_at).total_seconds()
    if seconds < 0:
        raise SessionValidationError("Actual end must be on or after actual start.")
    return int(seconds // 60)


def _safe_status_metadata(action, session, from_status, to_status):
    return {
        "action": action,
        "from_status": from_status,
        "to_status": to_status,
        "session_id": str(session.pk),
        "session_type": session.session_type,
    }


def _safe_assignment_metadata(action, from_counselor, to_counselor):
    return {
        "action": action,
        "from_counselor_id": str(from_counselor.pk) if from_counselor else None,
        "to_counselor_id": str(to_counselor.pk) if to_counselor else None,
    }


def _actor_category(user):
    if not is_active_nonlegacy_actor(user):
        return "other"
    if is_head_guidance(user):
        return "head_guidance"
    if is_counselor(user):
        return "counselor"
    if is_student(user):
        return "student"
    if is_gco_staff(user):
        return "gco_staff"
    return "other"


def _safe_routine_metadata(action, record, from_status, to_status, reopen_target=""):
    return {
        "action": action,
        "record_id": str(record.pk),
        "session_id": str(record.session_id),
        "session_reference": record.session.reference_code,
        "from_status": from_status,
        "to_status": to_status,
        "actor_category": "",
        "reopen_target": reopen_target or "",
    }


def _create_status_history(
    session,
    new_status,
    changed_by,
    reason=CounselingStatusHistoryReasonChoices.NONE,
):
    create_session_status_history(
        session=session,
        from_status=session.status,
        to_status=new_status,
        changed_by=changed_by,
        reason=reason,
    )


def _create_assignment_history(
    session,
    from_counselor,
    to_counselor,
    changed_by,
    reason=CounselingAssignmentHistoryReasonChoices.NONE,
):
    create_session_assignment_history(
        session=session,
        from_counselor=from_counselor,
        to_counselor=to_counselor,
        changed_by=changed_by,
        reason=reason,
    )


def _create_routine_status_history(
    record,
    new_status,
    changed_by,
    reason=RoutineStatusHistoryReasonChoices.NONE,
):
    create_routine_status_history(
        record=record,
        from_status=record.status,
        to_status=new_status,
        changed_by=changed_by,
        reason=reason,
    )


def _transition_session(
    user,
    session,
    new_status,
    action,
    reason=CounselingStatusHistoryReasonChoices.NONE,
    update_fields=None,
):
    _validate_transition(session, new_status)
    from_status = session.status
    _create_status_history(session, new_status, user, reason)
    session.status = new_status
    fields = ["status", "updated_at"] + list(update_fields or [])
    session.save(update_fields=fields)
    audit_status_transition(
        actor_user=user,
        target_model="CounselingSession",
        target_object_id=str(session.pk),
        reference_code=session.reference_code,
        metadata=_safe_status_metadata(action, session, from_status, new_status),
    )
    if session.session_mode == SessionModeChoices.ONLINE:
        from apps.counseling.ecounseling_services import sync_ecounseling_projection

        sync_ecounseling_projection(session)
    return session

def _load_routine_record(reference_code):
    """Resolve a routine interview record by its session reference code."""
    from apps.counseling.models import RoutineInterviewRecord

    normalized = str(reference_code or "").strip()
    if not normalized:
        raise SessionValidationError("A counseling session reference is required.")
    record = RoutineInterviewRecord.objects.defer(*ROUTINE_CONFIDENTIAL_FIELDS).filter(
        session__reference_code=normalized
    ).first()
    if record is None:
        from apps.common.exceptions import NotFoundError

        raise NotFoundError("The routine interview record was not found.")
    return record


def _load_session(reference_code):
    """Resolve a stable session reference (without locking)."""
    from apps.counseling.models import CounselingSession

    normalized = str(reference_code or "").strip()
    if not normalized:
        raise SessionValidationError("A counseling session reference is required.")
    session = CounselingSession.objects.defer(*SESSION_CONFIDENTIAL_FIELDS).filter(
        reference_code=normalized
    ).first()
    if session is None:
        from apps.common.exceptions import NotFoundError

        raise NotFoundError("The counseling session was not found.")
    return session


def _lock_session(session):
    from apps.appointments.availability_services import lock_schedule_scope

    # Appointment-linked counseling transitions share the office schedule
    # coordination lock.  Acquire it before either linked row so direct domain
    # callers cannot reintroduce the reverse appointment/session lock order.
    lock_schedule_scope()
    appointment_id = (
        CounselingSession.objects.filter(pk=session.pk)
        .values_list("appointment_id", flat=True)
        .first()
    )
    if appointment_id:
        # The shared order is schedule coordination -> appointment -> session.
        from apps.appointments.models import Appointment

        Appointment.objects.select_for_update().get(pk=appointment_id)
    return (
        CounselingSession.objects.select_for_update(of=("self",))
        .defer(*SESSION_CONFIDENTIAL_FIELDS)
        .select_related("student", "assigned_counselor", "appointment")
        .get(pk=session.pk)
    )


def _transition_routine_record(
    user,
    record,
    new_status,
    action,
    reason=RoutineStatusHistoryReasonChoices.NONE,
    update_fields=None,
):
    _validate_routine_transition(record, new_status)
    from_status = record.status
    _create_routine_status_history(record, new_status, user, reason)
    record.status = new_status
    if new_status != RoutineInterviewStatusChoices.REOPENED_FOR_CORRECTION:
        record.reopen_target = ""
    fields = ["status", "updated_at", "reopen_target"] + list(update_fields or [])
    record.save(update_fields=fields)
    metadata = _safe_routine_metadata(
        action,
        record,
        from_status,
        new_status,
        reopen_target=record.reopen_target,
    )
    metadata["actor_category"] = _actor_category(user)
    audit_status_transition(
        actor_user=user,
        target_model="RoutineInterviewRecord",
        target_object_id=str(record.pk),
        reference_code=record.session.reference_code,
        metadata=metadata,
    )
    return record


def _audit_routine_event(user, record, action, from_status=None, to_status=None):
    metadata = _safe_routine_metadata(
        action,
        record,
        from_status or record.status,
        to_status or record.status,
        reopen_target=record.reopen_target,
    )
    metadata["actor_category"] = _actor_category(user)
    audit_log(
        action_type=action,
        event_category="WORKFLOW",
        severity="INFO",
        target_model="RoutineInterviewRecord",
        target_object_id=str(record.pk),
        actor_user=user,
        reference_code=record.session.reference_code,
        source_app="counseling",
        source_view=action,
        metadata=metadata,
    )


def _snapshot_student_metadata(record):
    student = record.session.student
    profile = getattr(student, "student_profile", None)
    record.student_name_snapshot = student.get_full_name() or ""
    record.course_snapshot = getattr(profile, "program", "") or ""
    record.major_snapshot = ""
    record.snapshot_taken_at = timezone.now()
    if record.session.scheduled_start_at:
        record.visit_date = record.visit_date or record.session.scheduled_start_at.date()
        record.visit_time = record.visit_time or record.session.scheduled_start_at.time()
    record.duration_minutes = record.duration_minutes or record.session.actual_duration_minutes


@transaction.atomic
def create_session(user, command: SessionCreateCommand):
    if not isinstance(command, SessionCreateCommand):
        raise SessionValidationError("Session creation requires a SessionCreateCommand.")

    User = get_user_model()
    student = User.objects.filter(pk=command.student_id, is_active=True).first()
    if student is None:
        raise SessionValidationError("The student is not available.")

    appointment = None
    if command.appointment_reference:
        from apps.appointments.models import Appointment

        appointment = Appointment.objects.filter(
            reference_code=command.appointment_reference,
        ).first()
        if appointment is None:
            raise SessionValidationError("The linked appointment was not found.")

    assigned_counselor = None
    if command.assigned_counselor_id:
        assigned_counselor = User.objects.filter(
            pk=command.assigned_counselor_id,
            is_active=True,
        ).first()
        if assigned_counselor is None:
            raise SessionValidationError("The assigned counselor is not available.")

    session_source = command.session_source or SessionSourceChoices.COUNSELOR_INITIATED

    _validate_supported_source(session_source)
    _validate_choice(command.session_type, SessionTypeChoices.choices, "session_type")
    _validate_choice(command.session_mode, SessionModeChoices.choices, "session_mode")
    _validate_schedule(command.scheduled_start_at, command.scheduled_end_at)

    if appointment and appointment.student_id != student.pk:
        raise SessionValidationError("Appointment does not belong to the target student.")
    if session_source == SessionSourceChoices.APPOINTMENT and not appointment:
        raise SessionValidationError("Appointment source requires an appointment.")
    if appointment and CounselingSession.objects.filter(appointment=appointment).exists():
        raise DuplicateCounselingSessionError("A counseling session already exists for this appointment.")

    if not can_create_session_for(
        user,
        student,
        appointment=appointment,
        assigned_counselor=assigned_counselor,
        source=session_source,
    ):
        raise SessionPermissionError("You do not have permission to create this counseling session.")

    reference_code = generate_session_reference_code()

    try:
        session = CounselingSession(
            reference_code=reference_code,
            student=student,
            appointment=appointment,
            assigned_counselor=assigned_counselor,
            session_type=command.session_type,
            session_mode=command.session_mode,
            session_source=session_source,
            status=SessionStatusChoices.SCHEDULED,
            concern_summary=command.concern_summary,
            scheduled_start_at=command.scheduled_start_at,
            scheduled_end_at=command.scheduled_end_at,
        )
        initialize_group(
            session,
            SESSION_CONCERN,
            {"concern_summary": command.concern_summary},
        )
        session.save()
    except IntegrityError as exc:
        if appointment:
            raise DuplicateCounselingSessionError(
                "A counseling session already exists for this appointment."
            ) from exc
        raise

    create_session_status_history(
        session=session,
        from_status="",
        to_status=SessionStatusChoices.SCHEDULED,
        changed_by=user,
        reason=CounselingStatusHistoryReasonChoices.CREATED,
    )
    if assigned_counselor is not None:
        _create_assignment_history(
            session,
            None,
            assigned_counselor,
            user,
            CounselingAssignmentHistoryReasonChoices.INITIAL,
        )

    audit_status_transition(
        actor_user=user,
        target_model="CounselingSession",
        target_object_id=str(session.pk),
        reference_code=session.reference_code,
        metadata=_safe_status_metadata("create_session", session, "", SessionStatusChoices.SCHEDULED),
    )

    if (
        session.session_mode == SessionModeChoices.ONLINE
        and session.scheduled_start_at
        and session.scheduled_end_at
    ):
        from apps.counseling.ecounseling_services import attach_ecounseling_to_session

        attach_ecounseling_to_session(
            user,
            session,
            ECounselingCreateCommand(
                student_id=str(session.student_id),
                assigned_counselor_id=(
                    str(session.assigned_counselor_id)
                    if session.assigned_counselor_id is not None
                    else None
                ),
                session_type=session.session_type,
                scheduled_start_at=session.scheduled_start_at,
                scheduled_end_at=session.scheduled_end_at,
            ),
        )

    return session


@transaction.atomic
def start_session(user, reference_code):
    session = _lock_session(_load_session(reference_code))
    if not can_transition_session(user, session):
        raise SessionPermissionError("You do not have permission to start this session.")
    if (
        session.appointment_id
        and session.appointment.status != "SCHEDULED"
    ):
        raise SessionTransitionError(
            "This session cannot start because its appointment is no longer scheduled."
        )
    session.actual_started_at = timezone.now()
    return _transition_session(
        user,
        session,
        SessionStatusChoices.IN_PROGRESS,
        "start_session",
        update_fields=["actual_started_at"],
    )


@transaction.atomic
def move_to_notes_draft(user, reference_code):
    session = _lock_session(_load_session(reference_code))
    if not can_transition_session(user, session):
        raise SessionPermissionError("You do not have permission to move this session to notes draft.")
    session.actual_ended_at = timezone.now()
    session.actual_duration_minutes = _calculate_duration_minutes(session)
    return _transition_session(
        user,
        session,
        SessionStatusChoices.COUNSELOR_NOTES_DRAFT,
        "move_to_notes_draft",
        update_fields=["actual_ended_at", "actual_duration_minutes"],
    )


@transaction.atomic
def save_session_note(user, reference_code, command: CounselingNoteCommand, *, expected_updated_at=None):
    if not isinstance(command, CounselingNoteCommand):
        raise SessionPermissionError("Counseling notes require a CounselingNoteCommand.")
    session = CounselingSession.objects.select_for_update(of=("self",)).defer(
        *SESSION_CONFIDENTIAL_FIELDS
    ).select_related(
        "student", "assigned_counselor"
    ).get(pk=_load_session(reference_code).pk)
    if expected_updated_at and session.updated_at.isoformat() != expected_updated_at:
        raise WorkspaceStateStale("This panel is out of date. Refresh it before saving again.")
    if not can_edit_session(user, session) or not can_edit_counseling_notes(user, session):
        raise SessionPermissionError("You do not have permission to edit counseling notes.")
    try:
        note = CounselingSessionNote.objects.select_for_update().get(session=session)
    except CounselingSessionNote.DoesNotExist:
        if expected_updated_at and session.updated_at.isoformat() != expected_updated_at:
            raise WorkspaceStateStale("This panel is out of date. Refresh it before saving again.")
        note = CounselingSessionNote(session=session)
        initialize_group(
            note,
            NOTE_SHARED,
            {field: getattr(command, field) for field in NOTE_SHARED_FIELDS},
        )
        initialize_group(
            note,
            NOTE_COUNSELOR,
            {field: getattr(command, field) for field in NOTE_COUNSELOR_FIELDS},
        )
        note.follow_up_needed = command.follow_up_needed
        note.authored_by = user
        note.save()
        return note
    update_fields = [
        *prepare_group_write(
            note,
            NOTE_SHARED,
            {field: getattr(command, field) for field in NOTE_SHARED_FIELDS},
        ),
        *prepare_group_write(
            note,
            NOTE_COUNSELOR,
            {field: getattr(command, field) for field in NOTE_COUNSELOR_FIELDS},
        ),
    ]
    note.follow_up_needed = command.follow_up_needed
    note.authored_by = user
    note.save(update_fields=[*update_fields, "follow_up_needed", "authored_by", "updated_at"])
    return note


@transaction.atomic
def save_counselor_private_note(user, reference_code, command: CounselingNoteCommand, *, expected_updated_at=None):
    """Persist only the counselor-owned note group for workspace saves."""
    if not isinstance(command, CounselingNoteCommand):
        raise SessionPermissionError("Counselor notes require a CounselingNoteCommand.")
    session = CounselingSession.objects.select_for_update(of=("self",)).defer(
        *SESSION_CONFIDENTIAL_FIELDS
    ).select_related("student", "assigned_counselor").get(pk=_load_session(reference_code).pk)
    if not can_edit_session(user, session) or not can_edit_counseling_notes(user, session):
        raise SessionPermissionError("You do not have permission to edit counseling notes.")
    try:
        note = CounselingSessionNote.objects.select_for_update().get(session=session)
    except CounselingSessionNote.DoesNotExist:
        if expected_updated_at and session.updated_at.isoformat() != expected_updated_at:
            raise WorkspaceStateStale("This panel is out of date. Refresh it before saving again.")
        note = CounselingSessionNote(session=session)
        initialize_group(note, NOTE_SHARED, {"student_visible_summary": ""})
        initialize_group(note, NOTE_COUNSELOR, {
            field: getattr(command, field) for field in NOTE_COUNSELOR_FIELDS
        })
        note.follow_up_needed = command.follow_up_needed
        note.authored_by = user
        note.save()
        return note
    if expected_updated_at and note.updated_at.isoformat() != expected_updated_at:
        raise WorkspaceStateStale("This panel is out of date. Refresh it before saving again.")
    update_fields = list(prepare_group_write(
        note,
        NOTE_COUNSELOR,
        {field: getattr(command, field) for field in NOTE_COUNSELOR_FIELDS},
    ))
    note.follow_up_needed = command.follow_up_needed
    note.authored_by = user
    note.save(update_fields=[*update_fields, "follow_up_needed", "authored_by", "updated_at"])
    return note


@transaction.atomic
def save_shared_summary(
    user,
    reference_code,
    command: StudentVisibleSummaryCommand,
    *,
    expected_updated_at=None,
):
    """Persist only the explicitly student-visible note group."""
    if not isinstance(command, StudentVisibleSummaryCommand):
        raise SessionPermissionError("The shared summary requires a StudentVisibleSummaryCommand.")
    summary = command.student_visible_summary
    session = CounselingSession.objects.select_for_update(of=("self",)).defer(
        *SESSION_CONFIDENTIAL_FIELDS
    ).select_related("student", "assigned_counselor").get(pk=_load_session(reference_code).pk)
    if not can_edit_session(user, session) or not can_edit_counseling_notes(user, session):
        raise SessionPermissionError("You do not have permission to edit the shared summary.")
    try:
        note = CounselingSessionNote.objects.select_for_update().get(session=session)
    except CounselingSessionNote.DoesNotExist:
        if expected_updated_at and session.updated_at.isoformat() != expected_updated_at:
            raise WorkspaceStateStale("This panel is out of date. Refresh it before saving again.")
        note = CounselingSessionNote(session=session)
        initialize_group(note, NOTE_SHARED, {"student_visible_summary": summary or ""})
        initialize_group(note, NOTE_COUNSELOR, {field: "" for field in NOTE_COUNSELOR_FIELDS})
        note.authored_by = user
        note.save()
        return note
    if expected_updated_at and note.updated_at.isoformat() != expected_updated_at:
        raise WorkspaceStateStale("This panel is out of date. Refresh it before saving again.")
    update_fields = list(prepare_group_write(
        note,
        NOTE_SHARED,
        {"student_visible_summary": summary or ""},
    ))
    note.authored_by = user
    note.save(update_fields=[*update_fields, "authored_by", "updated_at"])
    return note


def complete_session(user, reference_code, command: CounselingNoteCommand):
    if not isinstance(command, CounselingNoteCommand):
        raise SessionPermissionError("Session completion requires a CounselingNoteCommand.")
    session = _load_session(reference_code)
    if session.session_mode == SessionModeChoices.ONLINE:
        from apps.counseling.recording_services import (
            RecordingFinalizationPending,
            ensure_no_active_recording_before_completion,
        )

        try:
            # This guard deliberately runs before the authoritative completion
            # transaction. A recording engine stop request is an external side effect, so
            # its corresponding STOP_REQUESTED state must not be rolled back
            # when completion pauses for provider finalization.
            ensure_no_active_recording_before_completion(user, session)
        except RecordingFinalizationPending as exc:
            raise SessionTransitionError(str(exc)) from exc
    return _complete_session_after_recording(user, session, command)


@transaction.atomic
def _complete_session_after_recording(user, session, command: CounselingNoteCommand):
    session = _lock_session(session)
    if not can_transition_session(user, session):
        raise SessionPermissionError("You do not have permission to complete this session.")
    _validate_transition(session, SessionStatusChoices.COMPLETED)
    save_session_note(user, session.reference_code, command)
    if not session.actual_ended_at:
        session.actual_ended_at = timezone.now()
    session.actual_duration_minutes = _calculate_duration_minutes(session)
    session.completed_at = timezone.now()
    session = _transition_session(
        user,
        session,
        SessionStatusChoices.COMPLETED,
        "complete_session",
        CounselingStatusHistoryReasonChoices.COMPLETED,
        update_fields=["actual_ended_at", "actual_duration_minutes", "completed_at"],
    )
    return session


@transaction.atomic
def finalize_session(user, reference_code):
    session = _lock_session(_load_session(reference_code))
    if not can_finalize_session(user, session):
        raise SessionPermissionError("You do not have permission to finalize this session.")
    session.finalized_at = timezone.now()
    session.finalized_by = user
    return _transition_session(
        user,
        session,
        SessionStatusChoices.FINALIZED,
        "finalize_session",
        update_fields=["finalized_at", "finalized_by"],
    )


@transaction.atomic
def lock_session(user, reference_code):
    session = _lock_session(_load_session(reference_code))
    if not can_lock_session(user, session):
        raise SessionPermissionError("You do not have permission to lock this session.")
    session.locked_at = timezone.now()
    return _transition_session(
        user,
        session,
        SessionStatusChoices.LOCKED,
        "lock_session",
        update_fields=["locked_at"],
    )


@transaction.atomic
def cancel_session(user, reference_code, command: SessionCancellationCommand):
    if not isinstance(command, SessionCancellationCommand):
        raise SessionValidationError("Session cancellation requires a SessionCancellationCommand.")
    reason = command.reason
    session = _lock_session(_load_session(reference_code))
    if not can_cancel_session(user, session):
        raise SessionPermissionError("You do not have permission to cancel this session.")
    prepare_group_write(session, SESSION_CANCEL, {"cancellation_reason": reason})
    session = _transition_session(
        user,
        session,
        SessionStatusChoices.CANCELLED,
        "cancel_session",
        CounselingStatusHistoryReasonChoices.CANCELLED,
        update_fields=["cancellation_reason", "cancellation_reason_encrypted"],
    )
    return session


@transaction.atomic
def mark_session_no_show(user, reference_code):
    session = _lock_session(_load_session(reference_code))
    if not can_mark_session_no_show(user, session):
        raise SessionPermissionError("You do not have permission to mark this session no-show.")
    session = _transition_session(
        user,
        session,
        SessionStatusChoices.NO_SHOW,
        "mark_session_no_show",
        CounselingStatusHistoryReasonChoices.NO_SHOW,
    )
    return session


@transaction.atomic
def assign_session_counselor(user, reference_code, command: SessionAssignmentCommand):
    if not isinstance(command, SessionAssignmentCommand):
        raise SessionValidationError(
            "Counselor assignment requires a SessionAssignmentCommand."
        )
    session = _load_session(reference_code)
    counselor = (
        get_user_model()
        .objects.select_for_update()
        .filter(pk=command.counselor_id, is_active=True)
        .first()
    )
    if counselor is None:
        raise SessionValidationError("The selected counselor is not available.")
    if not can_assign_session(user, session):
        raise SessionPermissionError("You do not have permission to assign counseling sessions.")
    if not can_assign_session_to(user, session, counselor):
        raise SessionPermissionError("You do not have permission to assign this counselor.")

    from_counselor = session.assigned_counselor
    if from_counselor == counselor:
        return session

    _create_assignment_history(
        session,
        from_counselor,
        counselor,
        user,
        CounselingAssignmentHistoryReasonChoices.CHANGED,
    )
    session.assigned_counselor = counselor
    session.save(update_fields=["assigned_counselor", "updated_at"])
    audit_assignment_change(
        actor_user=user,
        target_model="CounselingSession",
        target_object_id=str(session.pk),
        reference_code=session.reference_code,
        metadata=_safe_assignment_metadata("assign_session_counselor", from_counselor, counselor),
    )
    if session.session_mode == SessionModeChoices.ONLINE:
        from apps.counseling.ecounseling_services import _create_derived_participants
        from apps.counseling.models import (
            ECounselingParticipantRoleChoices,
            ECounselingSession,
        )

        try:
            ecounseling_session = session.ecounseling_session
        except ECounselingSession.DoesNotExist:
            ecounseling_session = None
        if ecounseling_session is not None:
            now = timezone.now()
            if from_counselor is not None:
                ecounseling_session.participants.filter(
                    user=from_counselor,
                    role=ECounselingParticipantRoleChoices.COUNSELOR,
                    is_active=True,
                ).update(is_active=False, revoked_by=user, revoked_at=now, updated_at=now)
            ecounseling_session.moderator_user = counselor
            ecounseling_session.save(update_fields=["moderator_user", "updated_at"])
            _create_derived_participants(user, ecounseling_session)
    return session


@transaction.atomic
def create_or_get_routine_interview_record(user, reference_code):
    session = _load_session(reference_code)
    _validate_routine_parent(session)
    if not can_create_routine_interview_record(user, session):
        raise SessionPermissionError("You do not have permission to create this routine interview record.")

    locked_session = CounselingSession.objects.select_for_update().defer(
        *SESSION_CONFIDENTIAL_FIELDS
    ).get(pk=session.pk)
    _validate_routine_parent(locked_session)
    try:
        record, created = RoutineInterviewRecord.objects.select_for_update().defer(
            *ROUTINE_CONFIDENTIAL_FIELDS
        ).get_or_create(
            session=locked_session,
        )
    except IntegrityError:
        record = RoutineInterviewRecord.objects.select_for_update().defer(
            *ROUTINE_CONFIDENTIAL_FIELDS
        ).get(session=locked_session)
        created = False

    if created or not record.snapshot_taken_at:
        _snapshot_student_metadata(record)
        record.save()
    return record


@transaction.atomic
def save_student_intake_draft(
    user,
    reference_code,
    command: RoutineIntakeCommand,
    *,
    expected_updated_at=None,
):
    if not isinstance(command, RoutineIntakeCommand):
        raise SessionValidationError("Routine intake requires a RoutineIntakeCommand.")
    data = {field: getattr(command, field) for field in ROUTINE_INTAKE_FIELDS}
    record = RoutineInterviewRecord.objects.select_for_update(of=("self",)).defer(
        *ROUTINE_CONFIDENTIAL_FIELDS
    ).select_related("session", "session__student").get(
        pk=_load_routine_record(reference_code).pk,
    )
    if not can_edit_routine_interview_intake(user, record):
        raise SessionPermissionError("You do not have permission to edit this routine interview intake.")
    if expected_updated_at and record.updated_at.isoformat() != expected_updated_at:
        raise WorkspaceStateStale("This panel is out of date. Refresh it before saving again.")

    for field in ROUTINE_INTAKE_METADATA_FIELDS:
        if field in data:
            setattr(record, field, data.get(field))
    confidential_update_fields = prepare_group_write(
        record,
        ROUTINE_INTAKE,
        {field: data.get(field, "") for field in ROUTINE_INTAKE_CONFIDENTIAL_FIELDS},
    )
    update_fields = [*ROUTINE_INTAKE_METADATA_FIELDS, *confidential_update_fields]

    if record.status == RoutineInterviewStatusChoices.INTAKE_DRAFT:
        record.save(update_fields=[*update_fields, "updated_at"])
        return record

    return _transition_routine_record(
        user,
        record,
        RoutineInterviewStatusChoices.INTAKE_DRAFT,
        "save_student_intake_draft",
        update_fields=update_fields,
    )


@transaction.atomic
def submit_student_intake(user, reference_code):
    record = RoutineInterviewRecord.objects.select_for_update(of=("self",)).defer(
        *ROUTINE_CONFIDENTIAL_FIELDS
    ).select_related("session", "session__student").get(
        pk=_load_routine_record(reference_code).pk,
    )
    if not can_submit_routine_interview_intake(user, record):
        raise SessionPermissionError("You do not have permission to submit this routine interview intake.")

    now = timezone.now()
    record.submitted_at = now
    record.submitted_by = user
    return _transition_routine_record(
        user,
        record,
        RoutineInterviewStatusChoices.INTAKE_SUBMITTED,
        "routine_interview_intake_submitted",
        RoutineStatusHistoryReasonChoices.INTAKE_SUBMITTED,
        update_fields=["submitted_at", "submitted_by"],
    )


@transaction.atomic
def save_counselor_evaluation_draft(user, reference_code, command: RoutineEvaluationCommand):
    if not isinstance(command, RoutineEvaluationCommand):
        raise SessionValidationError("Routine evaluation requires a RoutineEvaluationCommand.")
    data = {field: getattr(command, field) for field in ROUTINE_EVALUATION_FIELDS}
    record = RoutineInterviewRecord.objects.select_for_update(of=("self",)).defer(
        *ROUTINE_CONFIDENTIAL_FIELDS
    ).select_related(
        "session",
        "session__student",
    ).get(pk=_load_routine_record(reference_code).pk)
    if not can_edit_routine_interview_evaluation(user, record):
        raise SessionPermissionError("You do not have permission to edit this routine interview evaluation.")

    for field in ROUTINE_EVALUATION_METADATA_FIELDS:
        if field in data:
            setattr(record, field, data.get(field))
    confidential_update_fields = prepare_group_write(
        record,
        ROUTINE_EVALUATION,
        {field: data.get(field, "") for field in ROUTINE_EVALUATION_CONFIDENTIAL_FIELDS},
    )
    record.evaluated_at = timezone.now()
    record.evaluated_by = user

    if record.status == RoutineInterviewStatusChoices.EVALUATION_DRAFT:
        record.save(
            update_fields=[
                *ROUTINE_EVALUATION_METADATA_FIELDS,
                *confidential_update_fields,
                "evaluated_at",
                "evaluated_by",
                "updated_at",
            ]
        )
        _audit_routine_event(user, record, "routine_interview_evaluation_updated")
        return record

    return _transition_routine_record(
        user,
        record,
        RoutineInterviewStatusChoices.EVALUATION_DRAFT,
        "routine_interview_evaluation_updated",
        update_fields=[
            *ROUTINE_EVALUATION_METADATA_FIELDS,
            *confidential_update_fields,
            "evaluated_at",
            "evaluated_by",
        ],
    )


@transaction.atomic
def complete_routine_interview(user, reference_code):
    record = RoutineInterviewRecord.objects.select_for_update(of=("self",)).defer(
        *ROUTINE_CONFIDENTIAL_FIELDS
    ).select_related("session").get(pk=_load_routine_record(reference_code).pk)
    if not can_complete_routine_interview(user, record):
        raise SessionPermissionError("You do not have permission to complete this routine interview.")
    record.completed_at = timezone.now()
    record.completed_by = user
    return _transition_routine_record(
        user,
        record,
        RoutineInterviewStatusChoices.COMPLETED,
        "routine_interview_completed",
        RoutineStatusHistoryReasonChoices.COMPLETED,
        update_fields=["completed_at", "completed_by"],
    )


@transaction.atomic
def finalize_routine_interview(user, reference_code):
    record = RoutineInterviewRecord.objects.select_for_update(of=("self",)).defer(
        *ROUTINE_CONFIDENTIAL_FIELDS
    ).select_related("session").get(pk=_load_routine_record(reference_code).pk)
    if not can_finalize_routine_interview(user, record):
        raise SessionPermissionError("You do not have permission to finalize this routine interview.")
    record.finalized_at = timezone.now()
    record.finalized_by = user
    return _transition_routine_record(
        user,
        record,
        RoutineInterviewStatusChoices.FINALIZED,
        "routine_interview_finalized",
        RoutineStatusHistoryReasonChoices.FINALIZED,
        update_fields=["finalized_at", "finalized_by"],
    )


@transaction.atomic
def lock_routine_interview(user, reference_code):
    record = RoutineInterviewRecord.objects.select_for_update().defer(
        *ROUTINE_CONFIDENTIAL_FIELDS
    ).select_related("session").get(pk=_load_routine_record(reference_code).pk)
    if not can_lock_routine_interview(user, record):
        raise SessionPermissionError("You do not have permission to lock this routine interview.")
    record.locked_at = timezone.now()
    record.locked_by = user
    return _transition_routine_record(
        user,
        record,
        RoutineInterviewStatusChoices.LOCKED,
        "routine_interview_locked",
        RoutineStatusHistoryReasonChoices.LOCKED,
        update_fields=["locked_at", "locked_by"],
    )


@transaction.atomic
def reopen_routine_interview_for_correction(
    user,
    reference_code,
    command: RoutineReopenCommand,
):
    if not isinstance(command, RoutineReopenCommand):
        raise SessionValidationError("Routine reopening requires a RoutineReopenCommand.")
    reason = command.reason
    correction_target = command.correction_target
    record = RoutineInterviewRecord.objects.select_for_update().defer(
        *ROUTINE_CONFIDENTIAL_FIELDS
    ).select_related("session").get(pk=_load_routine_record(reference_code).pk)
    if not can_reopen_routine_interview(user, record):
        raise SessionPermissionError("You do not have permission to reopen this routine interview.")
    if not reason or not reason.strip():
        raise SessionValidationError("Reopen reason is required.")
    allowed_targets = {choice for choice, _label in RoutineInterviewCorrectionTargetChoices.choices}
    if correction_target not in allowed_targets:
        raise SessionValidationError("A valid correction target is required.")

    record.reopened_at = timezone.now()
    record.reopened_by = user
    prepare_group_write(
        record,
        ROUTINE_CORRECTION,
        {"reopen_reason": reason.strip()},
    )
    record.reopen_target = correction_target
    return _transition_routine_record(
        user,
        record,
        RoutineInterviewStatusChoices.REOPENED_FOR_CORRECTION,
        "routine_interview_reopened",
        RoutineStatusHistoryReasonChoices.REOPENED,
        update_fields=[
            "reopened_at", "reopened_by", "reopen_reason",
            "reopen_reason_encrypted", "reopen_target",
        ],
    )


# --- Counseling Folder Services ---

_CASE_VALID_TRANSITIONS = {
    CounselingCaseStatus.OPEN: [
        CounselingCaseStatus.MONITORING,
        CounselingCaseStatus.FOLLOW_UP_PENDING,
        CounselingCaseStatus.ON_HOLD,
        CounselingCaseStatus.RESOLVED,
        CounselingCaseStatus.CLOSED,
    ],
    CounselingCaseStatus.MONITORING: [
        CounselingCaseStatus.FOLLOW_UP_PENDING,
        CounselingCaseStatus.ON_HOLD,
        CounselingCaseStatus.RESOLVED,
        CounselingCaseStatus.CLOSED,
    ],
    CounselingCaseStatus.FOLLOW_UP_PENDING: [
        CounselingCaseStatus.MONITORING,
        CounselingCaseStatus.ON_HOLD,
        CounselingCaseStatus.RESOLVED,
        CounselingCaseStatus.CLOSED,
    ],
    CounselingCaseStatus.ON_HOLD: [
        CounselingCaseStatus.OPEN,
        CounselingCaseStatus.MONITORING,
        CounselingCaseStatus.FOLLOW_UP_PENDING,
        CounselingCaseStatus.CLOSED,
    ],
    CounselingCaseStatus.RESOLVED: [
        CounselingCaseStatus.CLOSED,
        CounselingCaseStatus.REOPENED,
    ],
    CounselingCaseStatus.CLOSED: [
        CounselingCaseStatus.REOPENED,
    ],
    CounselingCaseStatus.REOPENED: [
        CounselingCaseStatus.OPEN,
        CounselingCaseStatus.MONITORING,
        CounselingCaseStatus.FOLLOW_UP_PENDING,
        CounselingCaseStatus.CLOSED,
    ],
}


def _validate_case_transition(counseling_case, new_status):
    valid_next = _CASE_VALID_TRANSITIONS.get(counseling_case.status, [])
    if new_status not in valid_next:
        raise CaseTransitionError(
            f"Cannot transition case from {counseling_case.status} to {new_status}."
        )


def _validate_case_choice(value, choices, field_name):
    allowed = {choice for choice, _label in choices}
    if value not in allowed:
        raise CaseValidationError(f"Invalid {field_name}: {value}")


def _create_case_status_history(counseling_case, new_status, changed_by, reason_code=""):
    CounselingCaseStatusHistory.objects.create(
        counseling_case=counseling_case,
        from_status=counseling_case.status,
        to_status=new_status,
        changed_by=changed_by,
        reason_code=reason_code,
    )


def _safe_case_status_metadata(action, counseling_case, from_status, to_status, reason_code=""):
    return {
        "action": action,
        "from_status": from_status,
        "to_status": to_status,
        "case_id": str(counseling_case.pk),
        "reason_code": reason_code,
    }


def _transition_case(user, counseling_case, new_status, action, reason_code="", update_fields=None):
    _validate_case_transition(counseling_case, new_status)
    from_status = counseling_case.status
    _create_case_status_history(counseling_case, new_status, user, reason_code)
    counseling_case.status = new_status
    fields = ["status", "updated_at"] + list(update_fields or [])
    counseling_case.save(update_fields=fields)

    audit_status_transition(
        actor_user=user,
        target_model="CounselingCase",
        target_object_id=str(counseling_case.pk),
        reference_code=counseling_case.reference_code,
        metadata=_safe_case_status_metadata(action, counseling_case, from_status, new_status, reason_code),
    )
    return counseling_case


@transaction.atomic
def create_counseling_case(user, command: CaseCreateCommand):
    from apps.counseling.policies import can_create_counseling_case
    from apps.counseling.reference_codes import generate_counseling_case_reference_code

    if not isinstance(command, CaseCreateCommand):
        raise CaseValidationError("Case creation requires a CaseCreateCommand.")

    User = get_user_model()
    student = User.objects.filter(pk=command.student_id, is_active=True).first()
    if student is None:
        raise CaseValidationError("The student is not available.")
    assigned_counselor = None
    if command.assigned_counselor_id:
        assigned_counselor = User.objects.filter(
            pk=command.assigned_counselor_id,
            is_active=True,
        ).first()
        if assigned_counselor is None:
            raise CaseValidationError("The assigned counselor is not available.")
    concern_category = command.concern_category
    priority = command.priority or CounselingCasePriority.MEDIUM

    if not student or not concern_category:
        raise CaseValidationError("Student and concern category are required.")

    _validate_case_choice(concern_category, CounselingCaseConcernCategory.choices, "concern_category")
    _validate_case_choice(priority, CounselingCasePriority.choices, "priority")

    if not can_create_counseling_case(user, student, assigned_counselor):
        raise CasePermissionError("You do not have permission to create this counseling folder.")

    reference_code = generate_counseling_case_reference_code()

    counseling_case = CounselingCase.objects.create(
        reference_code=reference_code,
        student=student,
        assigned_counselor=assigned_counselor,
        concern_category=concern_category,
        priority=priority,
        status=CounselingCaseStatus.OPEN,
        opened_by=user,
    )

    CounselingCaseStatusHistory.objects.create(
        counseling_case=counseling_case,
        from_status="",
        to_status=CounselingCaseStatus.OPEN,
        changed_by=user,
        reason_code="",
    )

    if assigned_counselor is not None:
        CounselingCaseAssignmentHistory.objects.create(
            counseling_case=counseling_case,
            from_counselor=None,
            to_counselor=assigned_counselor,
            changed_by=user,
            reason_code=CounselingCaseReasonCode.ASSIGNMENT_CHANGE,
        )

    audit_status_transition(
        actor_user=user,
        target_model="CounselingCase",
        target_object_id=str(counseling_case.pk),
        reference_code=counseling_case.reference_code,
        metadata={
            "action": "create_counseling_case",
            "from_status": "",
            "to_status": CounselingCaseStatus.OPEN,
            "case_id": str(counseling_case.pk),
            "reason_code": "",
        },
    )

    if assigned_counselor is not None:
        audit_assignment_change(
            actor_user=user,
            target_model="CounselingCase",
            target_object_id=str(counseling_case.pk),
            reference_code=counseling_case.reference_code,
            metadata={
                "action": "assign_counseling_case_counselor",
                "from_counselor_id": None,
                "to_counselor_id": str(assigned_counselor.pk),
                "reason_code": CounselingCaseReasonCode.ASSIGNMENT_CHANGE,
            },
        )

    return counseling_case


def _load_case(reference_code):
    """Resolve a stable counseling-case reference."""
    from apps.counseling.models import CounselingCase

    normalized = str(reference_code or "").strip()
    if not normalized:
        raise CaseValidationError("A counseling folder reference is required.")
    counseling_case = CounselingCase.objects.filter(reference_code=normalized).first()
    if counseling_case is None:
        from apps.common.exceptions import NotFoundError

        raise NotFoundError("The counseling folder was not found.")
    return counseling_case


@transaction.atomic
def transition_counseling_case_to_monitoring(user, reference_code):
    from apps.counseling.policies import can_transition_case
    counseling_case = _load_case(reference_code)
    if not can_transition_case(user, counseling_case):
        raise CasePermissionError("You do not have permission to transition this case.")
    return _transition_case(
        user,
        counseling_case,
        CounselingCaseStatus.MONITORING,
        "transition_counseling_case_to_monitoring",
    )


@transaction.atomic
def transition_counseling_case_to_follow_up(user, reference_code):
    from apps.counseling.policies import can_transition_case
    counseling_case = _load_case(reference_code)
    if not can_transition_case(user, counseling_case):
        raise CasePermissionError("You do not have permission to transition this case.")
    return _transition_case(
        user,
        counseling_case,
        CounselingCaseStatus.FOLLOW_UP_PENDING,
        "transition_counseling_case_to_follow_up",
    )


@transaction.atomic
def put_case_on_hold(user, reference_code, command: CaseTransitionCommand):
    from apps.counseling.policies import can_transition_case
    if not isinstance(command, CaseTransitionCommand):
        raise CaseValidationError("Case transitions require a CaseTransitionCommand.")
    reason_code = command.reason_code
    counseling_case = _load_case(reference_code)
    _validate_case_choice(reason_code, CounselingCaseReasonCode.choices, "reason_code")
    if not can_transition_case(user, counseling_case):
        raise CasePermissionError("You do not have permission to transition this case.")
    return _transition_case(
        user,
        counseling_case,
        CounselingCaseStatus.ON_HOLD,
        "put_case_on_hold",
        reason_code=reason_code,
    )


@transaction.atomic
def resume_case_from_hold(user, reference_code, command: CaseTransitionCommand):
    from apps.counseling.policies import can_transition_case
    if not isinstance(command, CaseTransitionCommand):
        raise CaseValidationError("Case resumption requires a CaseTransitionCommand.")
    counseling_case = _load_case(reference_code)
    target_status = command.target_status
    _validate_case_choice(target_status, CounselingCaseStatus.choices, "target_status")
    if target_status not in (CounselingCaseStatus.OPEN, CounselingCaseStatus.MONITORING, CounselingCaseStatus.FOLLOW_UP_PENDING):
        raise CaseValidationError(f"Invalid resume target status: {target_status}")
    if not can_transition_case(user, counseling_case):
        raise CasePermissionError("You do not have permission to transition this case.")
    return _transition_case(
        user,
        counseling_case,
        target_status,
        "resume_case_from_hold",
    )


@transaction.atomic
def resolve_counseling_case(user, reference_code):
    from apps.counseling.policies import can_resolve_counseling_case
    counseling_case = _load_case(reference_code)
    if not can_resolve_counseling_case(user, counseling_case):
        raise CasePermissionError("You do not have permission to resolve this case.")
    counseling_case.resolved_at = timezone.now()
    counseling_case.resolved_by = user
    return _transition_case(
        user,
        counseling_case,
        CounselingCaseStatus.RESOLVED,
        "resolve_counseling_case",
        update_fields=["resolved_at", "resolved_by"],
    )


@transaction.atomic
def close_counseling_case(user, reference_code, command: CaseTransitionCommand):
    from apps.counseling.policies import can_close_counseling_case
    if not isinstance(command, CaseTransitionCommand):
        raise CaseValidationError("Case closure requires a CaseTransitionCommand.")
    reason_code = command.reason_code
    counseling_case = _load_case(reference_code)
    _validate_case_choice(reason_code, CounselingCaseReasonCode.choices, "reason_code")
    if not can_close_counseling_case(user, counseling_case):
        raise CasePermissionError("You do not have permission to close this case.")
    counseling_case.closed_at = timezone.now()
    counseling_case.closed_by = user
    counseling_case.close_reason_code = reason_code
    return _transition_case(
        user,
        counseling_case,
        CounselingCaseStatus.CLOSED,
        "close_counseling_case",
        reason_code=reason_code,
        update_fields=["closed_at", "closed_by", "close_reason_code"],
    )


@transaction.atomic
def reopen_counseling_case(user, reference_code, command: CaseTransitionCommand):
    from apps.counseling.policies import can_reopen_counseling_case
    if not isinstance(command, CaseTransitionCommand):
        raise CaseValidationError("Case reopening requires a CaseTransitionCommand.")
    reason_code = command.reason_code
    counseling_case = _load_case(reference_code)
    _validate_case_choice(reason_code, CounselingCaseReasonCode.choices, "reason_code")
    if not can_reopen_counseling_case(user, counseling_case):
        raise CasePermissionError("You do not have permission to reopen this case.")
    counseling_case.reopened_at = timezone.now()
    counseling_case.reopened_by = user
    counseling_case.reopen_reason_code = reason_code
    return _transition_case(
        user,
        counseling_case,
        CounselingCaseStatus.REOPENED,
        "reopen_counseling_case",
        reason_code=reason_code,
        update_fields=["reopened_at", "reopened_by", "reopen_reason_code"],
    )


@transaction.atomic
def assign_counseling_case_counselor(user, reference_code, command: CaseAssignmentCommand):
    from apps.counseling.policies import can_assign_case_to
    if not isinstance(command, CaseAssignmentCommand):
        raise CaseValidationError("Case assignment requires a CaseAssignmentCommand.")
    counseling_case = _load_case(reference_code)
    counselor = (
        get_user_model()
        .objects.select_for_update()
        .filter(pk=command.counselor_id, is_active=True)
        .first()
    )
    if counselor is None:
        raise CaseValidationError("The selected counselor is not available.")
    from_counselor = counseling_case.assigned_counselor

    if not can_assign_case_to(user, counseling_case, counselor):
        raise CasePermissionError("You do not have permission to assign case counselor.")

    if from_counselor == counselor:
        return counseling_case

    CounselingCaseAssignmentHistory.objects.create(
        counseling_case=counseling_case,
        from_counselor=from_counselor,
        to_counselor=counselor,
        changed_by=user,
        reason_code=CounselingCaseReasonCode.ASSIGNMENT_CHANGE,
    )

    counseling_case.assigned_counselor = counselor
    counseling_case.save(update_fields=["assigned_counselor", "updated_at"])

    audit_assignment_change(
        actor_user=user,
        target_model="CounselingCase",
        target_object_id=str(counseling_case.pk),
        reference_code=counseling_case.reference_code,
        metadata={
            "action": "assign_counseling_case_counselor",
            "from_counselor_id": str(from_counselor.pk) if from_counselor else None,
            "to_counselor_id": str(counselor.pk) if counselor else None,
            "reason_code": CounselingCaseReasonCode.ASSIGNMENT_CHANGE,
        },
    )
    return counseling_case


@transaction.atomic
def add_case_collaborator(user, reference_code, command: CaseCollaboratorCommand):
    from apps.counseling.policies import can_add_case_collaborator, can_assign_case_to
    if not isinstance(command, CaseCollaboratorCommand):
        raise CaseValidationError("Case collaborators require a CaseCollaboratorCommand.")
    reason_code = command.reason_code
    counseling_case = _load_case(reference_code)
    counselor = (
        get_user_model()
        .objects.select_for_update()
        .filter(pk=command.counselor_id, is_active=True)
        .first()
    )
    if counselor is None:
        raise CaseValidationError("The selected counselor is not available.")
    _validate_case_choice(reason_code, CounselingCaseReasonCode.choices, "reason_code")
    if not can_add_case_collaborator(user, counseling_case):
        raise CasePermissionError("You do not have permission to add case collaborators.")

    if not can_assign_case_to(user, counseling_case, counselor):
        raise CaseValidationError("Case collaborator must be an active counselor.")

    if CounselingCaseCollaborator.objects.filter(counseling_case=counseling_case, counselor=counselor, is_active=True).exists():
        raise CaseValidationError("This counselor is already an active case collaborator for this case.")

    case_collaborator = CounselingCaseCollaborator.objects.create(
        counseling_case=counseling_case,
        counselor=counselor,
        is_active=True,
        added_by=user,
        reason_code=reason_code,
    )

    audit_assignment_change(
        actor_user=user,
        target_model="CounselingCaseCollaborator",
        target_object_id=str(case_collaborator.pk),
        reference_code=counseling_case.reference_code,
        metadata={
            "action": "add_case_collaborator",
            "case_id": str(counseling_case.pk),
            "counselor_id": str(counselor.pk),
            "reason_code": reason_code,
        },
    )
    return case_collaborator


@transaction.atomic
def remove_case_collaborator(user, reference_code, command: CaseCollaboratorCommand):
    from apps.counseling.policies import can_remove_case_collaborator
    if not isinstance(command, CaseCollaboratorCommand):
        raise CaseValidationError("Case collaborators require a CaseCollaboratorCommand.")
    reason_code = command.reason_code
    counseling_case = _load_case(reference_code)
    counselor = (
        get_user_model()
        .objects.filter(pk=command.counselor_id, is_active=True)
        .first()
    )
    if counselor is None:
        raise CaseValidationError("The selected counselor is not available.")
    _validate_case_choice(reason_code, CounselingCaseReasonCode.choices, "reason_code")
    if not can_remove_case_collaborator(user, counseling_case):
        raise CasePermissionError("You do not have permission to remove case collaborators.")

    try:
        case_collaborator = CounselingCaseCollaborator.objects.get(
            counseling_case=counseling_case,
            counselor=counselor,
            is_active=True,
        )
    except CounselingCaseCollaborator.DoesNotExist:
        raise CaseValidationError("This counselor is not an active case collaborator for this case.")

    case_collaborator.is_active = False
    case_collaborator.removed_by = user
    case_collaborator.removed_at = timezone.now()
    case_collaborator.reason_code = reason_code
    case_collaborator.save(update_fields=["is_active", "removed_by", "removed_at", "reason_code", "updated_at"])

    audit_assignment_change(
        actor_user=user,
        target_model="CounselingCaseCollaborator",
        target_object_id=str(case_collaborator.pk),
        reference_code=counseling_case.reference_code,
        metadata={
            "action": "remove_case_collaborator",
            "case_id": str(counseling_case.pk),
            "counselor_id": str(counselor.pk),
            "reason_code": reason_code,
        },
    )
    return case_collaborator


@transaction.atomic
def link_session_to_counseling_case(user, reference_code, command: CaseSessionLinkCommand):
    from apps.counseling.policies import can_link_session_to_counseling_case
    if not isinstance(command, CaseSessionLinkCommand):
        raise CaseValidationError("Case session links require a CaseSessionLinkCommand.")
    link_type = command.link_type
    counseling_case = _load_case(reference_code)
    session = _load_session(command.session_reference_code)
    _validate_case_choice(link_type, CounselingCaseSessionLinkType.choices, "link_type")
    if not can_link_session_to_counseling_case(user, counseling_case, session):
        raise CasePermissionError("You do not have permission to link this session to the case.")

    if CounselingCaseSession.objects.filter(counseling_case=counseling_case, session=session).exists():
        raise CaseValidationError("This session is already linked to this case.")

    link = CounselingCaseSession.objects.create(
        counseling_case=counseling_case,
        session=session,
        linked_by=user,
        link_type=link_type,
    )

    audit_log(
        action_type="link_session_to_counseling_case",
        event_category="WORKFLOW",
        severity="INFO",
        target_model="CounselingCaseSession",
        target_object_id=str(link.pk),
        actor_user=user,
        reference_code=counseling_case.reference_code,
        source_app="counseling",
        source_view="link_session_to_counseling_case",
        metadata={
            "action": "link_session_to_counseling_case",
            "case_id": str(counseling_case.pk),
            "session_id": str(session.pk),
            "session_reference": session.reference_code,
            "link_type": link_type,
        },
    )
    return link


# --- Urgent Student Support Exceptions ---

class UrgentSupportPermissionError(PermissionDeniedError):
    pass


class UrgentSupportValidationError(ValidationError):
    pass


class UrgentSupportTransitionError(WorkflowError):
    pass


# --- Urgent Student Support Services ---

@transaction.atomic
def create_urgent_support_request(user, command: UrgentSupportCreateCommand):
    from apps.counseling.policies import can_create_urgent_support_request
    from apps.counseling.reference_codes import generate_urgent_support_request_reference_code
    from apps.counseling.models import (
        CounselingCase, CounselingSession,
        UrgentSupportRequest, UrgentSupportHistory,
        UrgentSupportStatus, UrgentSupportReviewStatus,
        UrgentSupportDocumentationStatus, UrgentSupportUrgencyLevel,
        UrgentSupportSourceType, ACTIVE_URGENT_SUPPORT_SOURCE_TYPES
    )

    if not isinstance(command, UrgentSupportCreateCommand):
        raise UrgentSupportValidationError(
            "Urgent support creation requires an UrgentSupportCreateCommand."
        )

    User = get_user_model()
    student = User.objects.filter(pk=command.student_id, is_active=True).first()
    if student is None:
        raise UrgentSupportValidationError("The student is not available.")

    source_type = command.source_type
    urgency_level = command.urgency_level
    originating_session = None
    if command.originating_session_reference:
        originating_session = CounselingSession.objects.filter(
            reference_code=command.originating_session_reference,
        ).first()
        if originating_session is None:
            raise UrgentSupportValidationError("The linked session was not found.")
    counseling_case = None
    if command.counseling_case_reference:
        counseling_case = CounselingCase.objects.filter(
            reference_code=command.counseling_case_reference,
        ).first()
        if counseling_case is None:
            raise UrgentSupportValidationError("The linked counseling folder was not found.")

    allowed_sources = {choice for choice, _label in UrgentSupportSourceType.choices}
    if source_type not in allowed_sources or source_type not in ACTIVE_URGENT_SUPPORT_SOURCE_TYPES:
        raise UrgentSupportValidationError("This urgent support source is not active right now.")
    _validate_choice(urgency_level, UrgentSupportUrgencyLevel.choices, "urgency_level")

    if not can_create_urgent_support_request(user, student, source=source_type, session=originating_session, counseling_case=counseling_case):
        raise UrgentSupportPermissionError("You do not have permission to create this urgent student support case.")

    active_statuses = [
        UrgentSupportStatus.OPEN,
        UrgentSupportStatus.TRIAGE_ACCESS_GRANTED,
        UrgentSupportStatus.TRIAGE_IN_PROGRESS,
        UrgentSupportStatus.PENDING_HEAD_REVIEW,
        UrgentSupportStatus.CONFIRMED,
    ]
    if originating_session:
        if UrgentSupportRequest.objects.filter(
            originating_session=originating_session,
            status__in=active_statuses,
        ).exists():
            raise UrgentSupportValidationError("An active urgent student support case already exists for this session.")
    if counseling_case:
        if UrgentSupportRequest.objects.filter(
            counseling_case=counseling_case,
            status__in=active_statuses,
        ).exists():
            raise UrgentSupportValidationError("An active urgent student support case already exists for this counseling folder.")

    reference_code = generate_urgent_support_request_reference_code()
    urgent_support = UrgentSupportRequest.objects.create(
        reference_code=reference_code,
        student=student,
        source_type=source_type,
        originating_session=originating_session,
        counseling_case=counseling_case,
        urgency_level=urgency_level,
        status=UrgentSupportStatus.OPEN,
        initiated_by=user,
        initiated_at=timezone.now(),
    )

    UrgentSupportHistory.objects.create(
        urgent_support=urgent_support,
        from_status="",
        to_status=UrgentSupportStatus.OPEN,
        changed_by=user,
        reason_code="Escalation initiated",
    )

    audit_log(
        action_type="create_urgent_support_request",
        event_category="WORKFLOW",
        severity="INFO",
        target_model="UrgentSupportRequest",
        target_object_id=str(urgent_support.pk),
        actor_user=user,
        reference_code=urgent_support.reference_code,
        source_app="counseling",
        source_view="create_urgent_support_request",
        metadata={
            "action": "create_urgent_support_request",
            "urgent_support_id": str(urgent_support.pk),
            "urgent_support_reference": urgent_support.reference_code,
            "actor_category": _actor_category(user),
            "source_type": source_type,
        }
    )

    return urgent_support


@transaction.atomic
def create_urgent_support_triage_session(user, reference_code, command: UrgentSupportTriageCommand):
    from apps.counseling.policies import (
        can_assign_urgent_support_triage_counselor,
        can_create_urgent_support_triage_session,
    )
    from apps.counseling.reference_codes import generate_session_reference_code
    from apps.counseling.models import (
        CounselingSession, CounselingSessionStatusHistory,
        UrgentSupportHistory, UrgentSupportStatus,
        UrgentSupportDocumentationStatus, SessionTypeChoices,
        SessionSourceChoices, SessionStatusChoices, SessionModeChoices
    )
    from datetime import timedelta

    if not isinstance(command, UrgentSupportTriageCommand):
        raise UrgentSupportValidationError(
            "Triage session creation requires an UrgentSupportTriageCommand."
        )

    urgent_support = _load_urgent_support(reference_code)

    if not can_create_urgent_support_triage_session(user, urgent_support):
        raise UrgentSupportPermissionError("You do not have permission to create this urgent support triage session.")

    assigned_counselor = None
    if command.assigned_counselor_id:
        assigned_counselor = (
            get_user_model()
            .objects.filter(pk=command.assigned_counselor_id, is_active=True)
            .first()
        )
        if assigned_counselor is None or not is_counselor(assigned_counselor):
            raise UrgentSupportValidationError("The selected counselor is not available.")
        if not can_assign_urgent_support_triage_counselor(
            user,
            urgent_support,
            assigned_counselor,
        ):
            raise UrgentSupportPermissionError("You do not have permission to assign this counselor.")
    elif not is_counselor(user):
        raise UrgentSupportValidationError(
            "An active counselor must be assigned before creating a triage session."
        )

    _validate_choice(command.session_mode or SessionModeChoices.ONSITE, SessionModeChoices.choices, "session_mode")
    
    session_ref = generate_session_reference_code()
    session = CounselingSession(
        reference_code=session_ref,
        student=urgent_support.student,
        assigned_counselor=assigned_counselor or user,
        session_type=SessionTypeChoices.TRIAGE,
        session_mode=command.session_mode or SessionModeChoices.ONSITE,
        session_source=SessionSourceChoices.URGENT_SUPPORT,
        status=SessionStatusChoices.SCHEDULED,
        concern_summary=URGENT_SUPPORT_TRIAGE_CONCERN_SUMMARY,
        scheduled_start_at=command.scheduled_start_at or timezone.now(),
        scheduled_end_at=command.scheduled_end_at or (timezone.now() + timedelta(hours=1)),
    )
    initialize_group(
        session,
        SESSION_CONCERN,
        {"concern_summary": URGENT_SUPPORT_TRIAGE_CONCERN_SUMMARY},
    )
    session.save()

    from_status = urgent_support.status
    urgent_support.documentation_session = session
    urgent_support.documentation_status = UrgentSupportDocumentationStatus.TRIAGE_SESSION_CREATED
    urgent_support.status = UrgentSupportStatus.TRIAGE_IN_PROGRESS
    urgent_support.save(update_fields=["documentation_session", "documentation_status", "status", "updated_at"])

    create_session_status_history(
        session=session,
        from_status="",
        to_status=SessionStatusChoices.SCHEDULED,
        changed_by=user,
        reason=CounselingStatusHistoryReasonChoices.URGENT_SUPPORT_TRIAGE_CREATED,
    )

    UrgentSupportHistory.objects.create(
        urgent_support=urgent_support,
        from_status=from_status,
        to_status=UrgentSupportStatus.TRIAGE_IN_PROGRESS,
        changed_by=user,
        reason_code="Triage session created",
    )

    audit_log(
        action_type="create_urgent_support_triage_session",
        event_category="WORKFLOW",
        severity="INFO",
        target_model="CounselingSession",
        target_object_id=str(session.pk),
        actor_user=user,
        reference_code=session.reference_code,
        source_app="counseling",
        source_view="create_urgent_support_triage_session",
        metadata={
            "action": "create_urgent_support_triage_session",
            "urgent_support_id": str(urgent_support.pk),
            "urgent_support_reference": urgent_support.reference_code,
            "session_id": str(session.pk),
            "session_reference": session.reference_code,
            "actor_category": _actor_category(user),
        }
    )

    return session


@transaction.atomic
def _load_urgent_support(reference_code):
    """Resolve and row-lock a stable urgent-support reference."""
    from apps.counseling.models import UrgentSupportRequest

    normalized = str(reference_code or "").strip()
    if not normalized:
        raise UrgentSupportValidationError("An urgent support reference is required.")
    try:
        return UrgentSupportRequest.objects.select_for_update().get(
            reference_code=normalized,
        )
    except UrgentSupportRequest.DoesNotExist as exc:
        from apps.common.exceptions import NotFoundError

        raise NotFoundError("The urgent support case was not found.") from exc


def grant_temporary_support_access(user, reference_code, command: TemporarySupportAccessCommand):
    from apps.counseling.policies import can_grant_temporary_support_access
    from apps.counseling.models import (
        TemporarySupportAccessGrant, UrgentSupportHistory,
        TemporarySupportAccessType, TemporarySupportAccessPurpose,
        TemporarySupportAccessStatus, UrgentSupportStatus
    )
    from datetime import timedelta

    if not isinstance(command, TemporarySupportAccessCommand):
        raise UrgentSupportValidationError(
            "Temporary access grants require a TemporarySupportAccessCommand."
        )

    urgent_support = _load_urgent_support(reference_code)
    grantee = (
        get_user_model()
        .objects.filter(pk=command.grantee_id, is_active=True)
        .first()
    )
    if grantee is None:
        raise UrgentSupportValidationError("The grantee account is not available.")
    grant_type = command.grant_type
    purpose_code = command.purpose_code
    expires_at = command.expires_at

    _validate_choice(grant_type, TemporarySupportAccessType.choices, "grant_type")
    _validate_choice(purpose_code, TemporarySupportAccessPurpose.choices, "purpose_code")

    if not can_grant_temporary_support_access(user, urgent_support, grantee):
        raise UrgentSupportPermissionError("You do not have permission to grant access.")

    starts_at = timezone.now()
    if not expires_at:
        expires_at = starts_at + timedelta(hours=24)

    if expires_at <= starts_at:
        raise UrgentSupportValidationError("Expiry time must be in the future.")
    if expires_at - starts_at > timedelta(hours=24):
        raise UrgentSupportValidationError("Access grant duration cannot exceed 24 hours.")

    existing = TemporarySupportAccessGrant.objects.filter(
        urgent_support=urgent_support,
        grantee=grantee,
        grant_type=grant_type,
        purpose_code=purpose_code,
        status=TemporarySupportAccessStatus.ACTIVE,
        revoked_at__isnull=True,
        starts_at__lt=expires_at,
        expires_at__gt=starts_at,
    ).first()
    if existing:
        return existing

    grant = TemporarySupportAccessGrant.objects.create(
        urgent_support=urgent_support,
        grantee=grantee,
        granted_by=user,
        grant_type=grant_type,
        purpose_code=purpose_code,
        starts_at=starts_at,
        expires_at=expires_at,
        status=TemporarySupportAccessStatus.ACTIVE,
    )

    if urgent_support.status == UrgentSupportStatus.OPEN:
        from_status = urgent_support.status
        urgent_support.status = UrgentSupportStatus.TRIAGE_ACCESS_GRANTED
        urgent_support.save(update_fields=["status", "updated_at"])

        UrgentSupportHistory.objects.create(
            urgent_support=urgent_support,
            from_status=from_status,
            to_status=UrgentSupportStatus.TRIAGE_ACCESS_GRANTED,
            changed_by=user,
            reason_code="Access granted",
        )

    audit_log(
        action_type="grant_temporary_support_access",
        event_category="WORKFLOW",
        severity="INFO",
        target_model="TemporarySupportAccessGrant",
        target_object_id=str(grant.pk),
        actor_user=user,
        reference_code=urgent_support.reference_code,
        source_app="counseling",
        source_view="grant_temporary_support_access",
        metadata={
            "action": "grant_temporary_support_access",
            "urgent_support_id": str(urgent_support.pk),
            "urgent_support_reference": urgent_support.reference_code,
            "grant_id": str(grant.pk),
            "grant_type": grant_type,
            "purpose_code": purpose_code,
            "actor_category": _actor_category(user),
        }
    )

    return grant


@transaction.atomic
def revoke_temporary_support_access(user, command: TemporarySupportRevokeCommand):
    from apps.counseling.policies import can_revoke_temporary_support_access
    from apps.counseling.models import (
        TemporarySupportAccessGrant, TemporarySupportAccessStatus,
        UrgentSupportClosureReasonCode
    )

    if not isinstance(command, TemporarySupportRevokeCommand):
        raise UrgentSupportValidationError(
            "Grant revocation requires a TemporarySupportRevokeCommand."
        )
    reason_code = command.reason_code

    try:
        grant = TemporarySupportAccessGrant.objects.select_for_update().get(
            pk=command.grant_id,
        )
    except (TemporarySupportAccessGrant.DoesNotExist, ValueError, TypeError) as exc:
        from apps.common.exceptions import NotFoundError

        raise NotFoundError("The temporary access grant was not found.") from exc
    if not can_revoke_temporary_support_access(user, grant):
        raise UrgentSupportPermissionError("You do not have permission to revoke this access grant.")

    if grant.status != TemporarySupportAccessStatus.ACTIVE:
        raise UrgentSupportValidationError("Only active grants can be revoked.")

    grant.status = TemporarySupportAccessStatus.REVOKED
    grant.revoked_at = timezone.now()
    grant.revoked_by = user
    grant.save(update_fields=["status", "revoked_at", "revoked_by", "updated_at"])

    audit_log(
        action_type="revoke_temporary_support_access",
        event_category="WORKFLOW",
        severity="INFO",
        target_model="TemporarySupportAccessGrant",
        target_object_id=str(grant.pk),
        actor_user=user,
        reference_code=grant.urgent_support.reference_code,
        source_app="counseling",
        source_view="revoke_temporary_support_access",
        metadata={
            "action": "revoke_temporary_support_access",
            "urgent_support_id": str(grant.urgent_support.pk),
            "urgent_support_reference": grant.urgent_support.reference_code,
            "grant_id": str(grant.pk),
            "grant_type": grant.grant_type,
            "purpose_code": grant.purpose_code,
            "closure_reason_code": reason_code,
            "actor_category": _actor_category(user),
        }
    )

    return grant


@transaction.atomic
def confirm_urgent_support_review(user, reference_code, command: UrgentSupportReviewCommand):
    from apps.counseling.policies import can_review_urgent_support_request
    from apps.counseling.models import (
        UrgentSupportRequest, UrgentSupportHistory,
        UrgentSupportStatus, UrgentSupportReviewStatus
    )

    if not isinstance(command, UrgentSupportReviewCommand):
        raise UrgentSupportValidationError(
            "Urgent support review requires an UrgentSupportReviewCommand."
        )
    review_status = command.review_status
    followup_action = command.followup_action

    urgent_support = _load_urgent_support(reference_code)

    _validate_choice(review_status, UrgentSupportReviewStatus.choices, "review_status")

    if not can_review_urgent_support_request(user, urgent_support):
        raise UrgentSupportPermissionError("You do not have permission to review this urgent support case.")

    from_status = urgent_support.status
    urgent_support.review_status = review_status
    urgent_support.reviewed_by = user
    urgent_support.reviewed_at = timezone.now()

    if review_status == UrgentSupportReviewStatus.REVIEWED_CONFIRMED:
        urgent_support.status = UrgentSupportStatus.CONFIRMED
    elif review_status == UrgentSupportReviewStatus.REVIEWED_REVOKED:
        urgent_support.status = UrgentSupportStatus.REVOKED
    else:
        urgent_support.status = UrgentSupportStatus.PENDING_HEAD_REVIEW

    urgent_support.save(update_fields=["review_status", "reviewed_by", "reviewed_at", "status", "updated_at"])

    if urgent_support.status != from_status:
        UrgentSupportHistory.objects.create(
            urgent_support=urgent_support,
            from_status=from_status,
            to_status=urgent_support.status,
            changed_by=user,
            reason_code="Review confirmed status transition",
        )

    audit_log(
        action_type="confirm_urgent_support_review",
        event_category="WORKFLOW",
        severity="INFO",
        target_model="UrgentSupportRequest",
        target_object_id=str(urgent_support.pk),
        actor_user=user,
        reference_code=urgent_support.reference_code,
        source_app="counseling",
        source_view="confirm_urgent_support_review",
        metadata={
            "action": "confirm_urgent_support_review",
            "urgent_support_id": str(urgent_support.pk),
            "urgent_support_reference": urgent_support.reference_code,
            "from_status": from_status,
            "to_status": urgent_support.status,
            "review_status": review_status,
            "actor_category": _actor_category(user),
        }
    )

    return urgent_support


@transaction.atomic
def close_urgent_support_request(user, reference_code, command: UrgentSupportClosureCommand):
    from apps.counseling.policies import can_close_urgent_support_request
    from apps.counseling.models import (
        UrgentSupportRequest, UrgentSupportHistory,
        UrgentSupportStatus, UrgentSupportDocumentationStatus,
        UrgentSupportClosureReasonCode
    )

    if not isinstance(command, UrgentSupportClosureCommand):
        raise UrgentSupportValidationError(
            "Urgent support closure requires an UrgentSupportClosureCommand."
        )
    closure_reason_code = command.closure_reason_code

    urgent_support = _load_urgent_support(reference_code)

    _validate_choice(closure_reason_code, UrgentSupportClosureReasonCode.choices, "closure_reason_code")

    if not can_close_urgent_support_request(user, urgent_support):
        raise UrgentSupportPermissionError("You do not have permission to close this urgent support case.")

    from_status = urgent_support.status
    urgent_support.status = UrgentSupportStatus.CLOSED
    urgent_support.closed_by = user
    urgent_support.closed_at = timezone.now()
    urgent_support.closure_reason_code = closure_reason_code
    urgent_support.documentation_status = UrgentSupportDocumentationStatus.NOT_REQUIRED_CLOSED
    urgent_support.save(update_fields=["status", "closed_by", "closed_at", "closure_reason_code", "documentation_status", "updated_at"])

    UrgentSupportHistory.objects.create(
        urgent_support=urgent_support,
        from_status=from_status,
        to_status=UrgentSupportStatus.CLOSED,
        changed_by=user,
        reason_code="Escalation closed",
    )

    audit_log(
        action_type="close_urgent_support_request",
        event_category="WORKFLOW",
        severity="INFO",
        target_model="UrgentSupportRequest",
        target_object_id=str(urgent_support.pk),
        actor_user=user,
        reference_code=urgent_support.reference_code,
        source_app="counseling",
        source_view="close_urgent_support_request",
        metadata={
            "action": "close_urgent_support_request",
            "urgent_support_id": str(urgent_support.pk),
            "urgent_support_reference": urgent_support.reference_code,
            "from_status": from_status,
            "to_status": UrgentSupportStatus.CLOSED,
            "closure_reason_code": closure_reason_code,
            "actor_category": _actor_category(user),
        }
    )

    return urgent_support


def expire_temporary_support_grants(now=None, actor=None):
    from apps.counseling.models import TemporarySupportAccessGrant, TemporarySupportAccessStatus

    if not now:
        now = timezone.now()

    with transaction.atomic():
        expired_grants = TemporarySupportAccessGrant.objects.select_for_update().filter(
            status=TemporarySupportAccessStatus.ACTIVE,
            revoked_at__isnull=True,
            expires_at__lte=now,
        )

        count = 0
        for grant in expired_grants:
            grant.status = TemporarySupportAccessStatus.EXPIRED
            grant.save(update_fields=["status", "updated_at"])
            count += 1

            audit_log(
                action_type="expire_temporary_support_access_grant",
                event_category="WORKFLOW",
                severity="INFO",
                target_model="TemporarySupportAccessGrant",
                target_object_id=str(grant.pk),
                actor_user=actor or grant.granted_by,
                reference_code=grant.urgent_support.reference_code,
                source_app="counseling",
                source_view="expire_temporary_support_grants",
                metadata={
                    "action": "expire_temporary_support_access_grant",
                    "urgent_support_id": str(grant.urgent_support_id),
                    "urgent_support_reference": grant.urgent_support.reference_code,
                    "grant_id": str(grant.pk),
                    "grant_type": grant.grant_type,
                    "purpose_code": grant.purpose_code,
                }
            )
        return count


@transaction.atomic
def link_urgent_support_to_case(user, reference_code, command: UrgentLinkCommand):
    from apps.counseling.policies import can_link_urgent_support_to_case
    from apps.counseling.models import UrgentSupportRequest

    if not isinstance(command, UrgentLinkCommand):
        raise UrgentSupportValidationError("Urgent support links require an UrgentLinkCommand.")
    urgent_support = _load_urgent_support(reference_code)
    counseling_case = _load_case(command.target_reference_code)

    if not can_link_urgent_support_to_case(user, urgent_support, counseling_case):
        raise UrgentSupportPermissionError("You do not have permission to link this urgent support case to a counseling folder.")

    if urgent_support.student_id != counseling_case.student_id:
        raise UrgentSupportValidationError("The student does not match the selected urgent support case and counseling folder.")

    urgent_support = UrgentSupportRequest.objects.select_for_update().get(pk=urgent_support.pk)
    urgent_support.counseling_case = counseling_case
    urgent_support.save(update_fields=["counseling_case", "updated_at"])

    audit_log(
        action_type="link_urgent_support_to_case",
        event_category="WORKFLOW",
        severity="INFO",
        target_model="UrgentSupportRequest",
        target_object_id=str(urgent_support.pk),
        actor_user=user,
        reference_code=urgent_support.reference_code,
        source_app="counseling",
        source_view="link_urgent_support_to_case",
        metadata={
            "action": "link_urgent_support_to_case",
            "urgent_support_id": str(urgent_support.pk),
            "urgent_support_reference": urgent_support.reference_code,
            "case_id": str(counseling_case.pk),
            "case_reference": counseling_case.reference_code,
            "actor_category": _actor_category(user),
        }
    )

    return urgent_support


@transaction.atomic
def link_urgent_support_to_session(user, reference_code, command: UrgentLinkCommand):
    from apps.counseling.policies import can_link_urgent_support_to_session
    from apps.counseling.models import UrgentSupportRequest, UrgentSupportDocumentationStatus

    if not isinstance(command, UrgentLinkCommand):
        raise UrgentSupportValidationError("Urgent support links require an UrgentLinkCommand.")
    documentation = command.documentation
    urgent_support = _load_urgent_support(reference_code)
    session = _lock_session(_load_session(command.target_reference_code))

    if not can_link_urgent_support_to_session(user, urgent_support, session):
        raise UrgentSupportPermissionError("You do not have permission to link this urgent support case to a session.")

    if urgent_support.student_id != session.student_id:
        raise UrgentSupportValidationError("The student does not match the selected urgent support case and session.")

    urgent_support = UrgentSupportRequest.objects.select_for_update().get(pk=urgent_support.pk)

    if documentation:
        urgent_support.documentation_session = session
        urgent_support.documentation_status = UrgentSupportDocumentationStatus.LINKED_TO_EXISTING_SESSION
        update_fields = ["documentation_session", "documentation_status", "updated_at"]
    else:
        urgent_support.originating_session = session
        update_fields = ["originating_session", "updated_at"]

    urgent_support.save(update_fields=update_fields)

    audit_log(
        action_type="link_urgent_support_to_session",
        event_category="WORKFLOW",
        severity="INFO",
        target_model="UrgentSupportRequest",
        target_object_id=str(urgent_support.pk),
        actor_user=user,
        reference_code=urgent_support.reference_code,
        source_app="counseling",
        source_view="link_urgent_support_to_session",
        metadata={
            "action": "link_urgent_support_to_session",
            "urgent_support_id": str(urgent_support.pk),
            "urgent_support_reference": urgent_support.reference_code,
            "session_id": str(session.pk),
            "session_reference": session.reference_code,
            "actor_category": _actor_category(user),
        }
    )

    return urgent_support


def record_temporary_support_access_grant_used(user, grant, target, source_view=""):
    from apps.access_control.rules import is_counselor
    from apps.counseling.models import (
        CounselingCase,
        CounselingSession,
        TemporarySupportAccessStatus,
        UrgentSupportRequest,
    )

    if grant.grantee_id != user.pk:
        raise UrgentSupportPermissionError("User is not the grantee of this access grant.")
    if not user.is_active or not is_counselor(user):
        raise UrgentSupportPermissionError("Urgent support access grant is not usable by this user.")
    if grant.status != TemporarySupportAccessStatus.ACTIVE or grant.revoked_at is not None:
        raise UrgentSupportPermissionError("Urgent support access grant is not active.")

    now = timezone.now()
    if grant.starts_at > now or grant.expires_at <= now:
        raise UrgentSupportPermissionError("Urgent support access grant is not currently valid.")

    target_is_covered = False
    if isinstance(target, UrgentSupportRequest):
        target_is_covered = target.pk == grant.urgent_support_id
    elif isinstance(target, CounselingSession):
        target_is_covered = (
            grant.urgent_support.originating_session_id == target.pk
            or grant.urgent_support.documentation_session_id == target.pk
        )
    elif isinstance(target, CounselingCase):
        target_is_covered = grant.urgent_support.counseling_case_id == target.pk

    if not target_is_covered:
        raise UrgentSupportPermissionError("Urgent support access grant does not cover this target.")

    target_model = target.__class__.__name__
    target_id = str(target.pk)
    target_ref = getattr(target, "reference_code", "")

    audit_log(
        action_type="use_temporary_support_access_grant",
        event_category="WORKFLOW",
        severity="WARNING",
        target_model=target_model,
        target_object_id=target_id,
        actor_user=user,
        reference_code=target_ref,
        source_app="counseling",
        source_view=source_view or "use_temporary_support_access_grant",
        metadata={
            "action": "use_temporary_support_access_grant",
            "urgent_support_id": str(grant.urgent_support_id),
            "urgent_support_reference": grant.urgent_support.reference_code,
            "grant_id": str(grant.pk),
            "grant_type": grant.grant_type,
            "purpose_code": grant.purpose_code,
            "actor_category": _actor_category(user),
        }
    )
