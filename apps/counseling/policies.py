# Project: COMPASS
# File: apps/counseling/policies.py
# Module: apps.counseling
# Purpose: Target-aware counseling session authorization policies
# Domain boundary and service policy.

from dataclasses import dataclass
from enum import Enum

from django.utils import timezone

# ``has_capability`` remains imported as an inert test seam for the explicit
# regression test proving that the removed legacy raw-note hook is ignored.
# Runtime decisions below use the fixed, target-aware predicates only.
from apps.access_control.authority import has_capability, has_fixed_capability
from apps.access_control.capabilities import Capability

from apps.access_control.rules import (
    is_active_nonlegacy_actor,
    is_student,
    is_counselor,
    is_gco_staff,
    is_head_guidance,
    owns_user,
)
from apps.access_control.scopes import (
    counselor_has_live_coverage_for_student,
    workflow_authority_authorizes_record,
)
from apps.counseling.models import (
    ECounselingParticipantRoleChoices,
    ECounselingPurposeCodeChoices,
    ECounselingStatusChoices,
    TemporarySupportAccessType,
    TemporarySupportAccessPurpose,
    RoutineInterviewCorrectionTargetChoices,
    RoutineInterviewStatusChoices,
    SessionModeChoices,
    SessionSourceChoices,
    SessionStatusChoices,
    SessionTypeChoices,
)


TERMINAL_STATUSES = {
    SessionStatusChoices.CANCELLED,
    SessionStatusChoices.NO_SHOW,
    SessionStatusChoices.LOCKED,
}

ROUTINE_PARENT_BLOCKED_STATUSES = {
    SessionStatusChoices.CANCELLED,
    SessionStatusChoices.NO_SHOW,
    SessionStatusChoices.LOCKED,
}

ROUTINE_SUBMITTED_STATUSES = {
    RoutineInterviewStatusChoices.INTAKE_SUBMITTED,
    RoutineInterviewStatusChoices.EVALUATION_DRAFT,
    RoutineInterviewStatusChoices.COMPLETED,
    RoutineInterviewStatusChoices.FINALIZED,
    RoutineInterviewStatusChoices.LOCKED,
    RoutineInterviewStatusChoices.REOPENED_FOR_CORRECTION,
}

ECOUNSELING_TERMINAL_STATUSES = {
    ECounselingStatusChoices.CANCELLED,
    ECounselingStatusChoices.COMPLETED,
    ECounselingStatusChoices.EXPIRED,
}

NOTE_RAW_ACCESS_GRANT_TYPES = frozenset({
    TemporarySupportAccessType.SESSION_REVIEW,
    TemporarySupportAccessType.CASE_REVIEW,
})
NOTE_RAW_ACCESS_PURPOSES = frozenset({
    TemporarySupportAccessPurpose.URGENT_TRIAGE,
    TemporarySupportAccessPurpose.HEAD_GUIDANCE_REVIEW,
    TemporarySupportAccessPurpose.POST_ACTION_DOCUMENTATION,
})


class ECounselingJoinStateCode(str, Enum):
    """Safe, server-derived states for the e-counseling join surface."""

    AVAILABLE = "available"
    NOT_YET_OPEN = "not_yet_open"
    ENDED = "ended"
    CANCELLED = "cancelled"
    CLOSED = "closed"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    UNAUTHORIZED_OR_NOT_FOUND = "unauthorized_or_not_found"


@dataclass(frozen=True)
class ECounselingJoinState:
    """Minimal presentation projection; never carries confidential/provider data."""

    code: str
    message: str
    scheduled_start_at: object | None = None
    next_action: str = "none"

    @property
    def available(self) -> bool:
        return self.code == ECounselingJoinStateCode.AVAILABLE.value


def _join_state(code, message, ecounseling_session=None, next_action="none"):
    return ECounselingJoinState(
        code=code.value if isinstance(code, ECounselingJoinStateCode) else code,
        message=message,
        scheduled_start_at=(
            ecounseling_session.scheduled_start_at
            if ecounseling_session is not None
            else None
        ),
        next_action=next_action,
    )


def _is_valid_student(user) -> bool:
    return bool(
        user
        and user.is_authenticated
        and user.is_active
        and not getattr(user, "is_superuser", False)
        and is_student(user)
        and hasattr(user, "student_profile")
    )


def _fail_closed(user) -> bool:
    """Fail closed for anonymous, deactivated, and legacy-superuser actors.

    Thin domain-local alias delegating to the single source of truth
    ``access_control.rules.is_active_nonlegacy_actor``. Object scope and field
    sensitivity stay in each domain policy.
    """
    return not is_active_nonlegacy_actor(user)


def _has_counselor_coverage_for_student(user, student) -> bool:
    student_profile = getattr(student, "student_profile", None)
    return counselor_has_live_coverage_for_student(user, student_profile)


def _is_counselor_assigned_to_session(user, session) -> bool:
    return bool(
        _is_active_counselor(user)
        and session.assigned_counselor_id
        and session.assigned_counselor_id == user.pk
    )


def _has_counselor_coverage_for_session(user, session) -> bool:
    return _has_counselor_coverage_for_student(user, session.student)


def _can_clinically_handle_session(user, session) -> bool:
    """Return direct-care scope, never a Head-wide clinical bypass."""
    if not _is_active_counselor(user) or not session:
        return False
    if session.assigned_counselor_id:
        return session.assigned_counselor_id == user.pk
    return _has_counselor_coverage_for_session(user, session)


def _is_explicitly_assigned_allowed_appointment(user, student, appointment, source) -> bool:
    if source != SessionSourceChoices.APPOINTMENT:
        return False
    if not appointment:
        return False
    return bool(
        appointment.student_id == student.pk
        and appointment.assigned_counselor_id == user.pk
    )


def _is_active_counselor(user) -> bool:
    return bool(
        user
        and user.is_authenticated
        and user.is_active
        and not getattr(user, "is_superuser", False)
        and is_counselor(user)
    )


def can_create_session_for(user, student, appointment=None, assigned_counselor=None, source=None) -> bool:
    if _fail_closed(user):
        return False
    if not _is_valid_student(student):
        return False
    if assigned_counselor is not None and not _is_active_counselor(assigned_counselor):
        return False

    # ``urgent_support.queue.review`` is an operational urgent-support
    # capability. It must not become a general counseling-session creation
    # bypass (especially for GCO Staff). Urgent-support triage creation has
    # its own target-aware policy below.
    if is_student(user) or is_gco_staff(user):
        return False

    if not is_counselor(user):
        return False

    if assigned_counselor is not None and assigned_counselor.pk != user.pk:
        return False

    if _has_counselor_coverage_for_student(user, student):
        return True

    return _is_explicitly_assigned_allowed_appointment(user, student, appointment, source)


def can_view_session(user, session) -> bool:
    if _fail_closed(user):
        return False
    if is_student(user):
        return owns_user(user, session.student_id)
    if has_fixed_capability(user, Capability.COUNSELING_SESSION_METADATA_VIEW_INSTITUTION):
        return True
    if _is_counselor_assigned_to_session(user, session):
        return True
    if is_counselor(user) and _has_counselor_coverage_for_session(user, session):
        return True
    if can_use_temporary_support_access_grant(user, session):
        return True
    if is_gco_staff(user):
        return False
    return False


def _active_ecounseling_participant(user, ecounseling_session):
    if _fail_closed(user):
        return None
    return ecounseling_session.participants.filter(
        user=user,
        role=ECounselingParticipantRoleChoices.APPROVED_PARTICIPANT,
        is_active=True,
        revoked_at__isnull=True,
    ).first()


def _is_online_counseling_session(session) -> bool:
    return bool(session and session.session_mode == SessionModeChoices.ONLINE)


def can_create_ecounseling_session(user, counseling_session=None, student=None, assigned_counselor=None) -> bool:
    if _fail_closed(user):
        return False
    if counseling_session is not None:
        if not _is_online_counseling_session(counseling_session):
            return False
        if counseling_session.status in TERMINAL_STATUSES:
            return False
        return _is_counselor_assigned_to_session(user, counseling_session)
    if student is None:
        return False
    return can_create_session_for(
        user,
        student,
        appointment=None,
        assigned_counselor=assigned_counselor or user,
        source=SessionSourceChoices.COUNSELOR_INITIATED,
    )


def can_view_ecounseling_session(user, ecounseling_session) -> bool:
    if _fail_closed(user) or not ecounseling_session:
        return False
    session = ecounseling_session.counseling_session
    if is_student(user):
        return owns_user(user, session.student_id)
    if _is_counselor_assigned_to_session(user, session):
        return True
    return _active_ecounseling_participant(user, ecounseling_session) is not None


def can_request_recording_consent(user, ecounseling_session) -> bool:
    if _fail_closed(user):
        return False
    if ecounseling_session.status in ECOUNSELING_TERMINAL_STATUSES:
        return False
    return _is_counselor_assigned_to_session(user, ecounseling_session.counseling_session)


def can_decide_recording_consent(user, ecounseling_session) -> bool:
    if _fail_closed(user):
        return False
    if ecounseling_session.status in ECOUNSELING_TERMINAL_STATUSES:
        return False
    return bool(
        is_student(user)
        and owns_user(user, ecounseling_session.counseling_session.student_id)
    )


def can_withdraw_recording_consent(user, ecounseling_session) -> bool:
    if _fail_closed(user):
        return False
    return can_decide_recording_consent(user, ecounseling_session)


def project_ecounseling_join_state(
    user,
    ecounseling_session,
    *,
    now=None,
    provider_available=True,
) -> ECounselingJoinState:
    """Project the one safe join state used by pages, policy, and join issuance.

    Authorization is evaluated before schedule/provider details for actors who do
    not have visibility.  The end boundary is deliberately exclusive: a Daily
    token cannot safely be issued at the exact end instant.
    """

    if not ecounseling_session or not can_view_ecounseling_session(user, ecounseling_session):
        return _join_state(
            ECounselingJoinStateCode.UNAUTHORIZED_OR_NOT_FOUND,
            "This online session is not available to your account.",
        )

    session = ecounseling_session.counseling_session
    if not _is_online_counseling_session(session):
        return _join_state(
            ECounselingJoinStateCode.UNAUTHORIZED_OR_NOT_FOUND,
            "This online session is not available right now.",
        )

    if now is None:
        now = timezone.now()

    if (
        ecounseling_session.status == ECounselingStatusChoices.CANCELLED
        or session.status == SessionStatusChoices.CANCELLED
    ):
        return _join_state(
            ECounselingJoinStateCode.CANCELLED,
            "This online session was cancelled. Your session record and notes remain safe.",
            ecounseling_session,
            next_action="return_to_sessions",
        )

    if ecounseling_session.status == ECounselingStatusChoices.EXPIRED:
        return _join_state(
            ECounselingJoinStateCode.ENDED,
            "This online session window has ended. Your session record and notes remain safe.",
            ecounseling_session,
            next_action="return_to_sessions",
        )

    if ecounseling_session.status == ECounselingStatusChoices.COMPLETED or session.status in (
        SessionStatusChoices.COMPLETED,
        SessionStatusChoices.FINALIZED,
        SessionStatusChoices.LOCKED,
        SessionStatusChoices.NO_SHOW,
    ):
        return _join_state(
            ECounselingJoinStateCode.CLOSED,
            "This online session is complete and closed. Your session record and notes remain safe.",
            ecounseling_session,
            next_action="return_to_sessions",
        )

    if ecounseling_session.join_window_start_at and now < ecounseling_session.join_window_start_at:
        return _join_state(
            ECounselingJoinStateCode.NOT_YET_OPEN,
            "Your session is scheduled. Refresh this page near the session time to check access.",
            ecounseling_session,
            next_action="refresh",
        )

    # Start is inclusive; end is exclusive.
    if ecounseling_session.join_window_end_at and now >= ecounseling_session.join_window_end_at:
        return _join_state(
            ECounselingJoinStateCode.ENDED,
            "This online session window has ended. Your session record and notes remain safe.",
            ecounseling_session,
            next_action="return_to_sessions",
        )

    if not ecounseling_session.participants.filter(
        user=user,
        is_active=True,
        revoked_at__isnull=True,
        user__is_active=True,
    ).exists():
        return _join_state(
            ECounselingJoinStateCode.UNAUTHORIZED_OR_NOT_FOUND,
            "This online session is not available to your account.",
            ecounseling_session,
        )

    if not provider_available:
        return _join_state(
            ECounselingJoinStateCode.PROVIDER_UNAVAILABLE,
            "The private video room is temporarily unavailable. Your session record and notes remain safe. Refresh or contact Guidance if the issue continues.",
            ecounseling_session,
            next_action="refresh",
        )

    return _join_state(
        ECounselingJoinStateCode.AVAILABLE,
        "Your private online counseling room is ready.",
        ecounseling_session,
        next_action="join",
    )


def can_join_ecounseling_session(user, ecounseling_session, now=None) -> bool:
    return project_ecounseling_join_state(
        user,
        ecounseling_session,
        now=now,
    ).available


def can_moderate_ecounseling_session(user, ecounseling_session) -> bool:
    if _fail_closed(user) or not ecounseling_session:
        return False
    return _is_counselor_assigned_to_session(user, ecounseling_session.counseling_session)


def can_end_ecounseling_session(user, ecounseling_session) -> bool:
    if not ecounseling_session or ecounseling_session.status in ECOUNSELING_TERMINAL_STATUSES:
        return False
    return can_moderate_ecounseling_session(user, ecounseling_session)


def can_cancel_ecounseling_session(user, ecounseling_session) -> bool:
    if not ecounseling_session or ecounseling_session.status in ECOUNSELING_TERMINAL_STATUSES:
        return False
    return can_moderate_ecounseling_session(user, ecounseling_session)


def can_manage_ecounseling_participants(user, ecounseling_session) -> bool:
    if _fail_closed(user) or not ecounseling_session:
        return False
    return bool(
        has_fixed_capability(user, Capability.ECOUNSELING_PARTICIPANTS_MANAGE)
        and ecounseling_session.status not in ECOUNSELING_TERMINAL_STATUSES
    )


def _eligible_ecounseling_participant_target(
    ecounseling_session,
    target_user,
    purpose_code,
) -> bool:
    """Require a session relationship before granting private-room access.

    The owner and assigned counselor receive derived participant rows during
    session creation.  The explicit-grant path is intentionally reserved for
    an active counselor who is either an active case case collaborator or a Head
    Guidance reviewer explicitly added for supervision/quality review.
    """
    if not ecounseling_session or not _is_active_counselor(target_user):
        return False
    if purpose_code not in ECounselingPurposeCodeChoices.values:
        return False

    session = ecounseling_session.counseling_session
    if target_user.pk in (session.student_id, session.assigned_counselor_id):
        return False

    if is_head_guidance(target_user):
        return purpose_code in {
            ECounselingPurposeCodeChoices.SUPERVISION,
            ECounselingPurposeCodeChoices.QUALITY_REVIEW,
        }

    return bool(
        _is_active_case_collaborator_on_session(target_user, session)
        and purpose_code == ECounselingPurposeCodeChoices.COUNSELING_DELIVERY
    )


def can_add_ecounseling_participant(
    user,
    ecounseling_session,
    target_user,
    role=None,
    purpose_code=None,
) -> bool:
    if not can_manage_ecounseling_participants(user, ecounseling_session):
        return False
    if role != ECounselingParticipantRoleChoices.APPROVED_PARTICIPANT:
        return False
    if _fail_closed(target_user):
        return False
    return _eligible_ecounseling_participant_target(
        ecounseling_session,
        target_user,
        purpose_code,
    )


def can_revoke_ecounseling_participant(user, participant) -> bool:
    if _fail_closed(user):
        return False
    if not participant or not participant.is_active:
        return False
    if participant.role != ECounselingParticipantRoleChoices.APPROVED_PARTICIPANT:
        return False
    return can_manage_ecounseling_participants(user, participant.ecounseling_session)


def can_view_counseling_notes(user, session) -> bool:
    """Return whether an active counselor may read the raw session note.

    Session visibility is intentionally broader than raw-note visibility.  A
    CounselorCoverage row or Head Guidance designation alone never grants
    counselor narrative access.
    """
    if _fail_closed(user) or not session:
        return False
    if _is_counselor_assigned_to_session(user, session):
        return True
    if _is_active_case_collaborator_on_session(user, session):
        return True
    if _has_note_access_urgent_support_grant(user, session):
        return True
    return False


def _is_active_case_collaborator_on_session(user, session) -> bool:
    """Return whether the actor collaborates on a case linked to ``session``."""
    if not _is_active_counselor(user) or not session:
        return False
    return session.case_links.filter(
        counseling_case__case_collaborator_entries__counselor=user,
        counseling_case__case_collaborator_entries__is_active=True,
    ).exists()


def _has_note_access_urgent_support_grant(user, session) -> bool:
    """Check the narrow, time-bound grant paths that permit raw notes."""
    if not _is_active_counselor(user) or not session:
        return False

    from django.db.models import Q
    from apps.counseling.models import (
        TemporarySupportAccessStatus,
        TemporarySupportAccessGrant,
    )

    now = timezone.now()
    return TemporarySupportAccessGrant.objects.filter(
        grantee=user,
        status=TemporarySupportAccessStatus.ACTIVE,
        revoked_at__isnull=True,
        starts_at__lte=now,
        expires_at__gt=now,
        grant_type__in=NOTE_RAW_ACCESS_GRANT_TYPES,
        purpose_code__in=NOTE_RAW_ACCESS_PURPOSES,
    ).filter(
        Q(urgent_support__originating_session=session)
        | Q(urgent_support__documentation_session=session)
        | Q(urgent_support__counseling_case__case_sessions__session=session)
    ).exists()


def can_edit_counseling_notes(user, session) -> bool:
    """Return whether the assigned counselor may mutate note content.

    This is deliberately narrower than ``can_view_counseling_notes`` so that
    case collaborator and temporary grant read access cannot become write access.
    Session lifecycle checks remain enforced by ``can_edit_session``.
    """
    if _fail_closed(user) or not session or session.status in TERMINAL_STATUSES:
        return False
    return _is_counselor_assigned_to_session(user, session)


def can_edit_session(user, session) -> bool:
    if _fail_closed(user):
        return False
    if session.status in TERMINAL_STATUSES:
        return False
    return _can_clinically_handle_session(user, session)


def can_transition_session(user, session) -> bool:
    return can_edit_session(user, session)


def can_finalize_session(user, session) -> bool:
    if _fail_closed(user):
        return False
    if session.status != SessionStatusChoices.COMPLETED:
        return False
    return _can_clinically_handle_session(user, session)


def can_lock_session(user, session) -> bool:
    if _fail_closed(user):
        return False
    return bool(
        has_fixed_capability(user, Capability.COUNSELING_SESSION_LOCK)
        and session.status == SessionStatusChoices.FINALIZED
    )


def can_cancel_session(user, session) -> bool:
    if _fail_closed(user):
        return False
    if session.status != SessionStatusChoices.SCHEDULED:
        return False
    return _can_clinically_handle_session(user, session)


def can_mark_session_no_show(user, session) -> bool:
    if _fail_closed(user):
        return False
    if session.status != SessionStatusChoices.SCHEDULED:
        return False
    return _can_clinically_handle_session(user, session)


def can_assign_session(user, session) -> bool:
    if _fail_closed(user):
        return False
    if has_fixed_capability(user, Capability.COUNSELING_SESSION_ASSIGN):
        return True
    if is_counselor(user) and _is_counselor_assigned_to_session(user, session):
        return True
    return False


def can_assign_session_to(user, session, target_counselor) -> bool:
    if _fail_closed(user):
        return False
    if not _is_active_counselor(target_counselor):
        return False
    if has_fixed_capability(user, Capability.COUNSELING_SESSION_ASSIGN):
        return True
    if is_counselor(user) and _is_counselor_assigned_to_session(user, session):
        return target_counselor.pk == user.pk
    return False


def _is_routine_session_open_for_intake(session) -> bool:
    return bool(
        session
        and session.session_type == SessionTypeChoices.ROUTINE_INTERVIEW
        and session.status not in ROUTINE_PARENT_BLOCKED_STATUSES
    )


def _is_own_routine_interview_student(user, record) -> bool:
    return bool(
        user
        and user.is_authenticated
        and user.is_active
        and not getattr(user, "is_superuser", False)
        and is_student(user)
        and owns_user(user, record.session.student_id)
    )


def _is_routine_record(record) -> bool:
    return bool(
        record
        and record.session_id
        and record.session.session_type == SessionTypeChoices.ROUTINE_INTERVIEW
    )


def _is_head_guidance_in_routine_scope(user, record) -> bool:
    """Return whether Head Guidance is acting within counselor scope."""
    return bool(
        is_head_guidance(user)
        and (
            _is_counselor_assigned_to_session(user, record.session)
            or _has_counselor_coverage_for_session(user, record.session)
        )
    )


def can_view_routine_interview_metadata(user, record) -> bool:
    """Authorize safe routine metadata without releasing raw text fields.

    Students see their own record.  Counselors see assigned or live
    CounselorCoverage-scoped records.  Head Guidance retains office-wide
    metadata visibility, while raw intake/evaluation fields remain subject to
    their separate readers below.
    """
    if _fail_closed(user) or not _is_routine_record(record):
        return False
    if _is_own_routine_interview_student(user, record):
        return True
    if has_fixed_capability(user, Capability.COUNSELING_SESSION_METADATA_VIEW_INSTITUTION):
        return True
    if is_counselor(user):
        return bool(
            _is_counselor_assigned_to_session(user, record.session)
            or _has_counselor_coverage_for_session(user, record.session)
        )
    return False


def _reopen_allows(record, target) -> bool:
    if record.status != RoutineInterviewStatusChoices.REOPENED_FOR_CORRECTION:
        return False
    if not record.reopen_target:
        return False
    return record.reopen_target in (target, RoutineInterviewCorrectionTargetChoices.BOTH)


def can_create_routine_interview_record(user, session) -> bool:
    if _fail_closed(user):
        return False
    if not _is_routine_session_open_for_intake(session):
        return False
    if is_gco_staff(user):
        return False
    if is_student(user):
        return owns_user(user, session.student_id)
    return _can_clinically_handle_session(user, session)


def can_view_routine_interview_intake(user, record) -> bool:
    """Authorize raw routine intake fields, not safe metadata."""
    if _fail_closed(user) or not _is_routine_record(record):
        return False
    if _is_own_routine_interview_student(user, record):
        return True
    if _is_counselor_assigned_to_session(user, record.session):
        return record.status in ROUTINE_SUBMITTED_STATUSES
    return _is_head_guidance_in_routine_scope(user, record)


def can_view_routine_interview_evaluation(user, record) -> bool:
    """Authorize raw routine evaluation fields, not safe metadata."""
    if _fail_closed(user) or not _is_routine_record(record):
        return False
    if _is_counselor_assigned_to_session(user, record.session):
        return True
    return _is_head_guidance_in_routine_scope(user, record)


def can_edit_routine_interview_intake(user, record) -> bool:
    if _fail_closed(user):
        return False
    if not _is_routine_record(record) or not _is_routine_session_open_for_intake(record.session):
        return False
    if not _is_own_routine_interview_student(user, record):
        return False
    if record.status in (
        RoutineInterviewStatusChoices.NOT_STARTED,
        RoutineInterviewStatusChoices.INTAKE_DRAFT,
    ):
        return True
    return _reopen_allows(record, RoutineInterviewCorrectionTargetChoices.INTAKE)


def can_submit_routine_interview_intake(user, record) -> bool:
    return can_edit_routine_interview_intake(user, record)


def can_edit_routine_interview_evaluation(user, record) -> bool:
    if _fail_closed(user):
        return False
    if not _is_routine_record(record) or not _is_routine_session_open_for_intake(record.session):
        return False
    if not (
        _can_clinically_handle_session(user, record.session)
    ):
        return False
    if record.status in (
        RoutineInterviewStatusChoices.INTAKE_SUBMITTED,
        RoutineInterviewStatusChoices.EVALUATION_DRAFT,
    ):
        return True
    return _reopen_allows(record, RoutineInterviewCorrectionTargetChoices.EVALUATION)


def can_complete_routine_interview(user, record) -> bool:
    if _fail_closed(user):
        return False
    if not _is_routine_record(record) or not _is_routine_session_open_for_intake(record.session):
        return False
    if record.status not in (
        RoutineInterviewStatusChoices.INTAKE_SUBMITTED,
        RoutineInterviewStatusChoices.EVALUATION_DRAFT,
    ):
        return False
    return _can_clinically_handle_session(user, record.session)


def can_finalize_routine_interview(user, record) -> bool:
    if _fail_closed(user):
        return False
    if not _is_routine_record(record):
        return False
    if record.status != RoutineInterviewStatusChoices.COMPLETED:
        return False
    return _can_clinically_handle_session(user, record.session)


def can_lock_routine_interview(user, record) -> bool:
    if _fail_closed(user):
        return False
    return bool(
        _is_routine_record(record)
        and has_fixed_capability(user, Capability.COUNSELING_SESSION_LOCK)
        and record.status == RoutineInterviewStatusChoices.FINALIZED
    )


def can_reopen_routine_interview(user, record) -> bool:
    if _fail_closed(user):
        return False
    return bool(
        _is_routine_record(record)
        and has_fixed_capability(user, Capability.ROUTINE_INTERVIEW_REOPEN)
        and record.status in (
            RoutineInterviewStatusChoices.FINALIZED,
            RoutineInterviewStatusChoices.LOCKED,
        )
    )


# --- Counseling Case Policies ---

from apps.counseling.models import CounselingCaseStatus


def _is_counselor_assigned_to_case(user, counseling_case) -> bool:
    return bool(
        _is_active_counselor(user)
        and counseling_case.assigned_counselor_id
        and counseling_case.assigned_counselor_id == user.pk
    )


def _is_active_case_collaborator_on_case(user, counseling_case) -> bool:
    return bool(
        _is_active_counselor(user)
        and counseling_case.case_collaborator_entries.filter(counselor=user, is_active=True).exists()
    )


def _has_student_workflow_capability(
    user,
    capability,
    student,
    *,
    assigned_counselor=None,
) -> bool:
    """Resolve a workflow capability against both student scope and assignment.

    Passing a bare ``User`` as the target loses the student's organization
    fields and makes coverage/organization grants fail closed.  This helper
    keeps the fixed Head path while constructing the bounded record target
    required by counselor and GCO grants.
    """
    if has_fixed_capability(user, capability):
        return True
    return workflow_authority_authorizes_record(
        user,
        capability=capability,
        student_profile=getattr(student, "student_profile", student),
        assigned_counselor=assigned_counselor,
    )


def can_create_counseling_case(user, student, assigned_counselor) -> bool:
    if _fail_closed(user):
        return False
    if not _is_valid_student(student):
        return False
    if assigned_counselor is not None and not _is_active_counselor(assigned_counselor):
        return False

    if _has_student_workflow_capability(
        user,
        Capability.COUNSELING_CASES_ASSIGN,
        student,
        assigned_counselor=assigned_counselor,
    ):
        return True

    if is_student(user) or is_gco_staff(user):
        return False

    if not is_counselor(user):
        return False

    # A regular counselor can assign only self
    if assigned_counselor is not None and assigned_counselor.pk != user.pk:
        return False

    # A regular counselor can only create for students within coverage
    if _has_counselor_coverage_for_student(user, student):
        return True

    return False


def can_view_counseling_case(user, counseling_case) -> bool:
    if _fail_closed(user):
        return False
    if is_student(user):
        return owns_user(user, counseling_case.student_id)
    if is_gco_staff(user):
        return False
    if _has_student_workflow_capability(
        user,
        Capability.COUNSELING_CASES_ASSIGN,
        counseling_case.student,
        assigned_counselor=counseling_case.assigned_counselor,
    ):
        return True
    if _is_counselor_assigned_to_case(user, counseling_case):
        return True
    if _is_active_case_collaborator_on_case(user, counseling_case):
        return True
    if can_use_temporary_support_access_grant(user, counseling_case):
        return True
    # Coverage grants read visibility for the student's case metadata. It
    # does not grant case mutations; those remain assignment/collaboration or
    # Head Guidance decisions in their own policies below.
    if is_counselor(user) and _has_counselor_coverage_for_student(user, counseling_case.student):
        return True
    return False


def can_edit_counseling_case(user, counseling_case) -> bool:
    if _fail_closed(user):
        return False
    if counseling_case.status == CounselingCaseStatus.CLOSED:
        return False
    if _has_student_workflow_capability(
        user,
        Capability.COUNSELING_CASES_ASSIGN,
        counseling_case.student,
        assigned_counselor=counseling_case.assigned_counselor,
    ):
        return True
    return _is_counselor_assigned_to_case(user, counseling_case)


def can_transition_case(user, counseling_case) -> bool:
    if _fail_closed(user):
        return False
    if _has_student_workflow_capability(
        user,
        Capability.COUNSELING_CASES_CLOSE,
        counseling_case.student,
        assigned_counselor=counseling_case.assigned_counselor,
    ):
        return True
    return _is_counselor_assigned_to_case(user, counseling_case)


def can_resolve_counseling_case(user, counseling_case) -> bool:
    if _fail_closed(user):
        return False
    if _has_student_workflow_capability(
        user,
        Capability.COUNSELING_CASES_CLOSE,
        counseling_case.student,
        assigned_counselor=counseling_case.assigned_counselor,
    ):
        return True
    return _is_counselor_assigned_to_case(user, counseling_case)


def can_close_counseling_case(user, counseling_case) -> bool:
    if _fail_closed(user):
        return False
    return _has_student_workflow_capability(
        user,
        Capability.COUNSELING_CASES_CLOSE,
        counseling_case.student,
        assigned_counselor=counseling_case.assigned_counselor,
    )


def can_reopen_counseling_case(user, counseling_case) -> bool:
    if _fail_closed(user):
        return False
    if counseling_case.status not in (CounselingCaseStatus.RESOLVED, CounselingCaseStatus.CLOSED):
        return False
    return bool(
        counseling_case.status in (CounselingCaseStatus.RESOLVED, CounselingCaseStatus.CLOSED)
        and _has_student_workflow_capability(
            user,
            Capability.COUNSELING_CASES_REOPEN,
            counseling_case.student,
            assigned_counselor=counseling_case.assigned_counselor,
        )
    )


def can_assign_case(user, counseling_case) -> bool:
    if _fail_closed(user):
        return False
    return _has_student_workflow_capability(
        user,
        Capability.COUNSELING_CASES_ASSIGN,
        counseling_case.student,
        assigned_counselor=counseling_case.assigned_counselor,
    )


def can_assign_case_to(user, counseling_case, target) -> bool:
    if _fail_closed(user):
        return False
    if not _is_active_counselor(target):
        return False
    if _has_student_workflow_capability(
        user,
        Capability.COUNSELING_CASES_ASSIGN,
        counseling_case.student,
        assigned_counselor=counseling_case.assigned_counselor,
    ):
        return True
    if _is_counselor_assigned_to_case(user, counseling_case):
        # Assigned counselor self-assignment is a no-op only
        return target.pk == user.pk
    return False


def can_add_case_collaborator(user, counseling_case) -> bool:
    if _fail_closed(user):
        return False
    return has_fixed_capability(user, Capability.COUNSELING_CASE_COLLABORATION_MANAGE)


def can_remove_case_collaborator(user, counseling_case) -> bool:
    if _fail_closed(user):
        return False
    return has_fixed_capability(user, Capability.COUNSELING_CASE_COLLABORATION_MANAGE)


def can_link_session_to_counseling_case(user, counseling_case, session) -> bool:
    if _fail_closed(user):
        return False
    if has_fixed_capability(user, Capability.COUNSELING_CASE_COLLABORATION_MANAGE):
        return True
    if _is_counselor_assigned_to_case(user, counseling_case):
        return True
    if _is_active_case_collaborator_on_case(user, counseling_case):
        return True
    return False


# --- Urgent Support Policies ---

def _has_active_grant_for_urgent_support(user, urgent_support) -> bool:
    from django.utils import timezone
    from apps.counseling.models import TemporarySupportAccessGrant, TemporarySupportAccessStatus
    now = timezone.now()
    return TemporarySupportAccessGrant.objects.filter(
        urgent_support=urgent_support,
        grantee=user,
        status=TemporarySupportAccessStatus.ACTIVE,
        revoked_at__isnull=True,
        starts_at__lte=now,
        expires_at__gt=now,
    ).exists()


def can_create_urgent_support_request(user, student, source=None, session=None, counseling_case=None) -> bool:
    if _fail_closed(user):
        return False
    if not _is_valid_student(student):
        return False
    assigned_counselor = (
        getattr(session, "assigned_counselor", None)
        or getattr(counseling_case, "assigned_counselor", None)
    )
    if _has_student_workflow_capability(
        user,
        Capability.URGENT_SUPPORT_QUEUE_REVIEW,
        student,
        assigned_counselor=assigned_counselor,
    ):
        return True
    if not is_counselor(user):
        return False
    
    # Regular counselor: must initiate from assigned session or case context
    if session:
        if session.student_id != student.pk:
            return False
        if session.assigned_counselor_id == user.pk:
            return True
    if counseling_case:
        if counseling_case.student_id != student.pk:
            return False
        if counseling_case.assigned_counselor_id == user.pk or _is_active_case_collaborator_on_case(user, counseling_case):
            return True
    return False


def can_view_urgent_support_request(user, urgent_support) -> bool:
    if _fail_closed(user):
        return False
    if is_student(user):
        return owns_user(user, urgent_support.student_id)
    if _has_student_workflow_capability(
        user,
        Capability.URGENT_SUPPORT_QUEUE_REVIEW,
        urgent_support.student,
        assigned_counselor=urgent_support.triage_counselor,
    ):
        return True
    if not is_counselor(user):
        return False
    
    # Initiator
    if urgent_support.initiated_by_id == user.pk:
        return True
    # Assigned triage counselor
    if urgent_support.triage_counselor_id == user.pk:
        return True
    # Originating session assigned counselor
    if urgent_support.originating_session and urgent_support.originating_session.assigned_counselor_id == user.pk:
        return True
    # Counseling-case counselor or case collaborator
    if urgent_support.counseling_case:
        if urgent_support.counseling_case.assigned_counselor_id == user.pk or _is_active_case_collaborator_on_case(user, urgent_support.counseling_case):
            return True
    # Active emergency grant holder
    if _has_active_grant_for_urgent_support(user, urgent_support):
        return True
    
    return False


def can_review_urgent_support_request(user, urgent_support) -> bool:
    if _fail_closed(user):
        return False
    return _has_student_workflow_capability(
        user,
        Capability.URGENT_SUPPORT_QUEUE_REVIEW,
        urgent_support.student,
        assigned_counselor=urgent_support.triage_counselor,
    )


def can_grant_temporary_support_access(user, urgent_support, target_user) -> bool:
    if _fail_closed(user):
        return False
    if not has_fixed_capability(user, Capability.URGENT_SUPPORT_TEMPORARY_ACCESS_MANAGE):
        return False
    if _fail_closed(target_user) or not is_counselor(target_user):
        return False
    return True


def can_open_temporary_support_access_grant_form(user, urgent_support) -> bool:
    if _fail_closed(user):
        return False
    if not has_fixed_capability(user, Capability.URGENT_SUPPORT_TEMPORARY_ACCESS_MANAGE):
        return False
    if not urgent_support:
        return False
    from apps.counseling.models import UrgentSupportStatus
    return urgent_support.status not in {
        UrgentSupportStatus.CLOSED,
        UrgentSupportStatus.REVOKED,
        UrgentSupportStatus.EXPIRED,
    }


def can_revoke_temporary_support_access(user, grant) -> bool:
    if _fail_closed(user):
        return False
    return has_fixed_capability(user, Capability.URGENT_SUPPORT_TEMPORARY_ACCESS_MANAGE)


def can_close_urgent_support_request(user, urgent_support) -> bool:
    if _fail_closed(user):
        return False
    return _has_student_workflow_capability(
        user,
        Capability.URGENT_SUPPORT_LIFECYCLE_MANAGE,
        urgent_support.student,
        assigned_counselor=urgent_support.triage_counselor,
    )


def can_use_temporary_support_access_grant(user, target) -> bool:
    if _fail_closed(user) or not is_counselor(user):
        return False
    
    from django.utils import timezone
    from django.db.models import Q
    from apps.counseling.models import (
        UrgentSupportRequest, CounselingSession, CounselingCase,
        TemporarySupportAccessGrant, TemporarySupportAccessStatus
    )
    
    now = timezone.now()
    base_qs = TemporarySupportAccessGrant.objects.filter(
        grantee=user,
        status=TemporarySupportAccessStatus.ACTIVE,
        revoked_at__isnull=True,
        starts_at__lte=now,
        expires_at__gt=now,
    )
    
    if isinstance(target, UrgentSupportRequest):
        return base_qs.filter(urgent_support=target).exists()
    
    if isinstance(target, CounselingSession):
        return base_qs.filter(
            Q(urgent_support__originating_session=target) |
            Q(urgent_support__documentation_session=target)
        ).exists()
        
    if isinstance(target, CounselingCase):
        return base_qs.filter(urgent_support__counseling_case=target).exists()
        
    return False


def can_create_urgent_support_triage_session(user, urgent_support) -> bool:
    if _fail_closed(user):
        return False
    if _has_student_workflow_capability(
        user,
        Capability.URGENT_SUPPORT_QUEUE_REVIEW,
        urgent_support.student,
        assigned_counselor=urgent_support.triage_counselor,
    ):
        return True
    if not is_counselor(user):
        return False
    if not can_view_urgent_support_request(user, urgent_support):
        return False
    if urgent_support.triage_counselor_id == user.pk or urgent_support.initiated_by_id == user.pk:
        return True
    return False


def can_assign_urgent_support_triage_counselor(user, urgent_support, counselor) -> bool:
    """Allow only policy-scoped counselor choices for urgent triage."""
    if _fail_closed(user) or urgent_support is None or not _is_active_counselor(counselor):
        return False
    if counselor.pk == getattr(user, "pk", None):
        return can_create_urgent_support_triage_session(user, urgent_support)
    return _has_student_workflow_capability(
        user,
        Capability.URGENT_SUPPORT_ASSIGN,
        urgent_support.student,
        assigned_counselor=counselor,
    )


def can_link_urgent_support_to_case(user, urgent_support, counseling_case) -> bool:
    if _fail_closed(user):
        return False
    if has_fixed_capability(user, Capability.COUNSELING_CASE_COLLABORATION_MANAGE):
        return True
    if not is_counselor(user):
        return False
    if not can_view_urgent_support_request(user, urgent_support):
        return False
    if not can_edit_counseling_case(user, counseling_case):
        return False
    return True


def can_link_urgent_support_to_session(user, urgent_support, session) -> bool:
    if _fail_closed(user):
        return False
    if has_fixed_capability(user, Capability.COUNSELING_CASE_COLLABORATION_MANAGE):
        return True
    if not is_counselor(user):
        return False
    if not can_view_urgent_support_request(user, urgent_support):
        return False
    if not can_edit_session(user, session):
        return False
    return True
