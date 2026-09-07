# Project: COMPASS
# File: apps/counseling/selectors.py
# Module: apps.counseling
# Purpose: Side-effect-free scoped selectors for counseling sessions
# Domain boundary and service policy.

from django.db import models
from django.db.models import Q

from apps.access_control.authority import has_fixed_capability
from apps.access_control.capabilities import Capability

from apps.access_control.rules import (
    is_active_nonlegacy_actor,
    is_student,
    is_counselor,
    is_gco_staff,
)
from apps.access_control.scopes import (
    build_geographic_scope_q,
    build_workflow_authority_scope_q,
    get_live_counselor_coverages,
)
from apps.counseling.models import (
    CounselingSession,
    ECounselingParticipantRoleChoices,
    ECounselingRecordingConsentEvent,
    ECounselingRecordingDecisionChoices,
    ECounselingSession,
    RoutineInterviewRecord,
)
from apps.counseling.encryption import (
    ROUTINE_CONFIDENTIAL_FIELDS,
    SESSION_CONFIDENTIAL_FIELDS,
)
from apps.counseling.policies import (
    can_view_ecounseling_session,
    _has_counselor_coverage_for_session,
    can_view_routine_interview_metadata,
    can_view_session,
)
from apps.counseling.projections import (
    project_case_metadata,
    project_student_case_metadata,
    project_counselor_note,
    project_routine_interview_metadata,
    project_routine_interview_sensitive_detail,
    project_student_routine_interview,
    project_staff_session_metadata,
    project_student_session_metadata,
)


def _fail_closed(user) -> bool:
    """Fail closed for anonymous, deactivated, and legacy-superuser actors.

    Selector-side thin alias delegating to the single source of truth
    ``access_control.rules.is_active_nonlegacy_actor``: an inactive account or
    a legacy superuser never receives a counseling record stream.
    """
    return not is_active_nonlegacy_actor(user)


def _session_queryset():
    return CounselingSession.objects.defer(*SESSION_CONFIDENTIAL_FIELDS)


def get_sessions_visible_to(user) -> models.QuerySet:
    """Return the internal ORM source for visible session rows.

    This selector intentionally returns ``CounselingSession`` instances for
    domain-internal work.  It is not an output boundary and must not be
    serialized directly; use ``get_session_metadata_visible_to()`` for plain
    dictionaries.
    """
    if _fail_closed(user):
        return CounselingSession.objects.none()
    if is_student(user):
        return _session_queryset().filter(student=user)
    if has_fixed_capability(user, Capability.COUNSELING_SESSION_METADATA_VIEW_INSTITUTION):
        return _session_queryset().all()
    if is_counselor(user):
        from django.db.models import Q
        from django.utils import timezone
        from apps.counseling.models import TemporarySupportAccessStatus

        now = timezone.now()
        grant_linked_q = Q(
            documented_urgent_supports__access_grants__grantee=user,
            documented_urgent_supports__access_grants__status=TemporarySupportAccessStatus.ACTIVE,
            documented_urgent_supports__access_grants__revoked_at__isnull=True,
            documented_urgent_supports__access_grants__starts_at__lte=now,
            documented_urgent_supports__access_grants__expires_at__gt=now,
        ) | Q(
            originating_urgent_supports__access_grants__grantee=user,
            originating_urgent_supports__access_grants__status=TemporarySupportAccessStatus.ACTIVE,
            originating_urgent_supports__access_grants__revoked_at__isnull=True,
            originating_urgent_supports__access_grants__starts_at__lte=now,
            originating_urgent_supports__access_grants__expires_at__gt=now,
        )
        coverage_q = build_geographic_scope_q(
            get_live_counselor_coverages(user),
            {
                "campus": "student__student_profile__campus",
                "college": "student__student_profile__college",
                "department": "student__student_profile__department",
                "program": "student__student_profile__program",
            },
        )
        return _session_queryset().filter(
            Q(assigned_counselor=user) | coverage_q | grant_linked_q,
        ).distinct()
    if is_gco_staff(user):
        return CounselingSession.objects.none()
    return CounselingSession.objects.none()


def get_student_sessions(user) -> models.QuerySet:
    """Return an internal student-session queryset, never a serialized output."""
    if _fail_closed(user) or not is_student(user):
        return CounselingSession.objects.none()
    return _session_queryset().filter(student=user)


def get_counselor_assigned_sessions(user) -> models.QuerySet:
    """Return an internal counselor-session queryset, never a serialized output."""
    if _fail_closed(user) or not is_counselor(user):
        return CounselingSession.objects.none()
    if has_fixed_capability(user, Capability.COUNSELING_SESSION_METADATA_VIEW_INSTITUTION):
        return _session_queryset().all()
    return _session_queryset().filter(assigned_counselor=user)


def get_session_by_reference_code(user, reference_code):
    """Return one internal ORM row after policy checking.

    Callers exposing data outside the counseling domain must use
    ``get_session_metadata_by_reference_code()`` instead of serializing this
    model instance.
    """
    try:
        session = _session_queryset().select_related("student", "assigned_counselor").get(
            reference_code=reference_code,
        )
    except CounselingSession.DoesNotExist:
        return None
    if not can_view_session(user, session):
        return None
    return session


def get_session_metadata_visible_to(user) -> list[dict]:
    """Return safe session metadata dictionaries within existing row scope."""
    projection = (
        project_student_session_metadata
        if is_student(user)
        else project_staff_session_metadata
    )
    return [
        payload
        for session in get_sessions_visible_to(user)
        if (payload := projection(user, session)) is not None
    ]


def get_session_metadata_by_reference_code(user, reference_code) -> dict | None:
    """Return one safe session metadata dictionary or ``None`` if unauthorized."""
    session = get_session_by_reference_code(user, reference_code)
    if session is None:
        return None
    if is_student(user):
        return project_student_session_metadata(user, session)
    return project_staff_session_metadata(user, session)


def get_counselor_notes_visible_to(user) -> list[dict]:
    """Return only projected raw notes authorized for the active counselor.

    This intentionally does not reuse the broader session-visibility stream:
    CounselorCoverage and Head Guidance office visibility do not grant raw-note
    access.  The ORM rows are internal sources; callers receive dictionaries
    only after the note policy and encrypted reader have approved each row.
    """
    if _fail_closed(user) or not is_counselor(user):
        return []
    sessions = _session_queryset().filter(note__isnull=False).select_related(
        "student", "assigned_counselor"
    )
    return [
        payload
        for session in sessions
        if (payload := project_counselor_note(user, session)) is not None
    ]


def get_counselor_note_by_reference_code(user, reference_code) -> dict | None:
    """Return one projected raw note or ``None`` when unauthorized/absent."""
    if _fail_closed(user) or not is_counselor(user):
        return None
    try:
        session = _session_queryset().select_related(
            "student", "assigned_counselor"
        ).get(reference_code=reference_code, note__isnull=False)
    except CounselingSession.DoesNotExist:
        return None
    return project_counselor_note(user, session)


def get_sessions_for_appointment(user, appointment) -> models.QuerySet:
    visible = get_sessions_visible_to(user)
    return visible.filter(appointment=appointment)


def get_ecounseling_sessions_visible_to(user) -> models.QuerySet:
    queryset = ECounselingSession.objects.defer(
        *(f"counseling_session__{name}" for name in SESSION_CONFIDENTIAL_FIELDS)
    ).select_related(
        "counseling_session",
        "counseling_session__student",
        "counseling_session__assigned_counselor",
    )
    if _fail_closed(user):
        return ECounselingSession.objects.none()
    if is_student(user):
        return queryset.filter(counseling_session__student=user)
    if is_counselor(user):
        return queryset.filter(
            models.Q(counseling_session__assigned_counselor=user)
            | models.Q(
                participants__user=user,
                participants__role=ECounselingParticipantRoleChoices.APPROVED_PARTICIPANT,
                participants__is_active=True,
                participants__revoked_at__isnull=True,
            )
        ).distinct()
    return queryset.filter(
        participants__user=user,
        participants__role=ECounselingParticipantRoleChoices.APPROVED_PARTICIPANT,
        participants__is_active=True,
        participants__revoked_at__isnull=True,
    )


def get_student_ecounseling_sessions(user) -> models.QuerySet:
    if _fail_closed(user) or not is_student(user):
        return ECounselingSession.objects.none()
    return get_ecounseling_sessions_visible_to(user)


def get_counselor_ecounseling_sessions(user) -> models.QuerySet:
    if _fail_closed(user) or not is_counselor(user):
        return ECounselingSession.objects.none()
    return get_ecounseling_sessions_visible_to(user)


def get_ecounseling_session_by_reference_code(user, reference_code):
    try:
        ecounseling_session = ECounselingSession.objects.defer(
            *(f"counseling_session__{name}" for name in SESSION_CONFIDENTIAL_FIELDS)
        ).select_related(
            "counseling_session",
            "counseling_session__student",
            "counseling_session__assigned_counselor",
        ).get(reference_code=reference_code)
    except ECounselingSession.DoesNotExist:
        return None
    if not can_view_ecounseling_session(user, ecounseling_session):
        return None
    return ecounseling_session


def get_ecounseling_session_for_counseling_session(user, session):
    try:
        ecounseling_session = ECounselingSession.objects.defer(
            *(f"counseling_session__{name}" for name in SESSION_CONFIDENTIAL_FIELDS)
        ).select_related(
            "counseling_session",
            "counseling_session__student",
            "counseling_session__assigned_counselor",
        ).get(counseling_session=session)
    except ECounselingSession.DoesNotExist:
        return None
    if not can_view_ecounseling_session(user, ecounseling_session):
        return None
    return ecounseling_session


def get_active_ecounseling_participants(user, ecounseling_session):
    if not can_view_ecounseling_session(user, ecounseling_session):
        return ecounseling_session.participants.none()
    return ecounseling_session.participants.filter(
        is_active=True,
        revoked_at__isnull=True,
    ).select_related("user")


def get_ecounseling_participant_grant(user, ecounseling_session):
    if _fail_closed(user):
        return None
    return ecounseling_session.participants.filter(
        user=user,
        role=ECounselingParticipantRoleChoices.APPROVED_PARTICIPANT,
        is_active=True,
        revoked_at__isnull=True,
    ).first()


def get_latest_recording_consent_request(ecounseling_session):
    return ECounselingRecordingConsentEvent.objects.filter(
        ecounseling_session=ecounseling_session,
        decision=ECounselingRecordingDecisionChoices.REQUESTED,
    ).order_by("-created_at").first()


def get_ecounseling_join_events_visible_to(user, ecounseling_session):
    if not can_view_ecounseling_session(user, ecounseling_session):
        return ecounseling_session.join_events.none()
    if is_student(user):
        return ecounseling_session.join_events.filter(user=user)
    if ecounseling_session.counseling_session.assigned_counselor_id == user.pk:
        return ecounseling_session.join_events.all()
    return ecounseling_session.join_events.filter(user=user)


def get_recording_consent_events_visible_to(user, ecounseling_session):
    if not can_view_ecounseling_session(user, ecounseling_session):
        return ecounseling_session.recording_consent_events.none()
    if is_student(user):
        return ecounseling_session.recording_consent_events.filter(
            ecounseling_session__counseling_session__student=user,
        )
    if ecounseling_session.counseling_session.assigned_counselor_id == user.pk:
        return ecounseling_session.recording_consent_events.all()
    return ecounseling_session.recording_consent_events.none()


def _routine_queryset():
    return RoutineInterviewRecord.objects.defer(
        *ROUTINE_CONFIDENTIAL_FIELDS,
        *(f"session__{field}" for field in SESSION_CONFIDENTIAL_FIELDS),
    ).select_related(
        "session",
        "session__student",
        "session__assigned_counselor",
        "assigned_counselor_confirmation",
    )


def get_routine_interviews_visible_to(user) -> models.QuerySet:
    """Return the internal ORM source for routine metadata visibility.

    This remains a model-returning query source for domain-internal work. Use
    ``get_routine_interview_metadata_visible_to()`` for plain dictionaries.
    Counselors receive the union of assigned and live coverage-scoped rows;
    Head Guidance retains office-wide metadata visibility.
    """
    if _fail_closed(user):
        return RoutineInterviewRecord.objects.none()
    if is_student(user):
        return _routine_queryset().filter(session__student=user)
    if has_fixed_capability(user, Capability.COUNSELING_SESSION_METADATA_VIEW_INSTITUTION):
        return _routine_queryset().all()
    if is_counselor(user):
        coverage_q = build_geographic_scope_q(
            get_live_counselor_coverages(user),
            {
                "campus": "session__student__student_profile__campus",
                "college": "session__student__student_profile__college",
                "department": "session__student__student_profile__department",
                "program": "session__student__student_profile__program",
            },
        )
        return _routine_queryset().filter(
            Q(session__assigned_counselor=user) | coverage_q
        ).distinct()
    return RoutineInterviewRecord.objects.none()


def get_student_routine_interviews(user) -> models.QuerySet:
    if _fail_closed(user) or not is_student(user):
        return RoutineInterviewRecord.objects.none()
    return _routine_queryset().filter(session__student=user)


def get_assigned_routine_interviews(user) -> models.QuerySet:
    if _fail_closed(user) or not is_counselor(user):
        return RoutineInterviewRecord.objects.none()
    if has_fixed_capability(user, Capability.COUNSELING_SESSION_METADATA_VIEW_INSTITUTION):
        return _routine_queryset().all()
    return _routine_queryset().filter(session__assigned_counselor=user)


def get_routine_interview_for_session(user, session):
    try:
        record = _routine_queryset().get(session=session)
    except RoutineInterviewRecord.DoesNotExist:
        return None
    if can_view_routine_interview_metadata(user, record):
        return record
    return None


def get_routine_interview_by_session_reference(user, reference_code):
    try:
        record = _routine_queryset().get(session__reference_code=reference_code)
    except RoutineInterviewRecord.DoesNotExist:
        return None
    if can_view_routine_interview_metadata(user, record):
        return record
    return None


def get_routine_interview_metadata_visible_to(user) -> list[dict]:
    """Return safe routine projections within the existing row scope."""
    projection = (
        project_student_routine_interview
        if is_student(user)
        else project_routine_interview_metadata
    )
    return [
        payload
        for record in get_routine_interviews_visible_to(user)
        if (payload := projection(user, record)) is not None
    ]


def get_routine_interview_metadata_by_session_reference(user, reference_code):
    """Return one safe routine projection or ``None`` when not visible."""
    record = get_routine_interview_by_session_reference(user, reference_code)
    if record is None:
        return None
    projection = (
        project_student_routine_interview
        if is_student(user)
        else project_routine_interview_metadata
    )
    return projection(user, record)


def get_routine_interview_sensitive_detail_by_session_reference(user, reference_code):
    """Return raw routine detail only through the explicit sensitive boundary."""
    record = get_routine_interview_by_session_reference(user, reference_code)
    if record is None:
        return None
    return project_routine_interview_sensitive_detail(user, record)


# --- Counseling Folder Selectors ---


def get_counseling_cases_visible_to(user) -> models.QuerySet:
    """Return the internal ORM source for visible counseling cases.

    This selector is not an output boundary. Use
    ``get_counseling_case_metadata_visible_to()`` for plain dictionaries rather than
    serializing returned ``CounselingCase`` instances directly.
    """
    from apps.counseling.models import CounselingCase
    from django.db.models import Q
    if _fail_closed(user):
        return CounselingCase.objects.none()
    if is_student(user):
        return CounselingCase.objects.filter(student=user)
    if has_fixed_capability(user, Capability.COUNSELING_SESSION_METADATA_VIEW_INSTITUTION):
        return CounselingCase.objects.all()
    if is_counselor(user):
        from django.utils import timezone
        from apps.counseling.models import TemporarySupportAccessStatus
        now = timezone.now()
        coverage_q = build_geographic_scope_q(
            get_live_counselor_coverages(user),
            {
                "campus": "student__student_profile__campus",
                "college": "student__student_profile__college",
                "department": "student__student_profile__department",
                "program": "student__student_profile__program",
            },
        )
        return CounselingCase.objects.filter(
            Q(assigned_counselor=user) |
            Q(case_collaborator_entries__counselor=user, case_collaborator_entries__is_active=True) |
            Q(
                urgent_support_requests__access_grants__grantee=user,
                urgent_support_requests__access_grants__status=TemporarySupportAccessStatus.ACTIVE,
                urgent_support_requests__access_grants__revoked_at__isnull=True,
                urgent_support_requests__access_grants__starts_at__lte=now,
                urgent_support_requests__access_grants__expires_at__gt=now,
            ) |
            coverage_q
        ).distinct()
    return CounselingCase.objects.none()


def get_student_counseling_cases(user) -> models.QuerySet:
    from apps.counseling.models import CounselingCase
    if _fail_closed(user) or not is_student(user):
        return CounselingCase.objects.none()
    return CounselingCase.objects.filter(student=user)


def get_counselor_assigned_counseling_cases(user) -> models.QuerySet:
    from apps.counseling.models import CounselingCase
    if _fail_closed(user) or not is_counselor(user):
        return CounselingCase.objects.none()
    if has_fixed_capability(user, Capability.COUNSELING_SESSION_METADATA_VIEW_INSTITUTION):
        return CounselingCase.objects.all()
    return CounselingCase.objects.filter(assigned_counselor=user)


def get_counselor_case_collaborator_counseling_cases(user) -> models.QuerySet:
    from apps.counseling.models import CounselingCase
    if _fail_closed(user) or not is_counselor(user):
        return CounselingCase.objects.none()
    if has_fixed_capability(user, Capability.COUNSELING_SESSION_METADATA_VIEW_INSTITUTION):
        return CounselingCase.objects.all()
    return CounselingCase.objects.filter(case_collaborator_entries__counselor=user, case_collaborator_entries__is_active=True)


def get_counseling_case_by_reference_code(user, reference_code):
    """Return one internal ORM row after case visibility authorization.

    Callers exposing case data outside the counseling domain must use
    ``get_counseling_case_metadata_by_reference_code()`` instead of serializing this
    model instance.
    """
    from apps.counseling.models import CounselingCase
    from apps.counseling.policies import can_view_counseling_case
    try:
        counseling_case = CounselingCase.objects.select_related("student", "assigned_counselor").get(
            reference_code=reference_code
        )
    except CounselingCase.DoesNotExist:
        return None
    if not can_view_counseling_case(user, counseling_case):
        return None
    return counseling_case


def get_counseling_case_metadata_visible_to(user) -> list[dict]:
    """Return safe case metadata dictionaries within existing row scope."""
    projection = project_student_case_metadata if is_student(user) else project_case_metadata
    return [
        payload
        for counseling_case in get_counseling_cases_visible_to(user)
        if (payload := projection(user, counseling_case)) is not None
    ]


def get_counseling_case_metadata_by_reference_code(user, reference_code) -> dict | None:
    """Return one safe case metadata dictionary or ``None`` if unauthorized."""
    counseling_case = get_counseling_case_by_reference_code(user, reference_code)
    if counseling_case is None:
        return None
    projection = project_student_case_metadata if is_student(user) else project_case_metadata
    return projection(user, counseling_case)


def get_sessions_for_case(user, counseling_case) -> models.QuerySet:
    from apps.counseling.models import CounselingSession
    from apps.counseling.policies import can_view_counseling_case
    if not can_view_counseling_case(user, counseling_case):
        return CounselingSession.objects.none()
    return _session_queryset().filter(case_links__counseling_case=counseling_case)


def get_cases_for_session(user, session) -> models.QuerySet:
    visible_cases = get_counseling_cases_visible_to(user)
    return visible_cases.filter(case_sessions__session=session)


# --- Urgent Student Support Selectors ---

def get_urgent_support_requests_visible_to(user) -> models.QuerySet:
    from apps.counseling.models import UrgentSupportRequest, TemporarySupportAccessStatus
    from apps.access_control.rules import is_counselor, is_head_guidance
    from django.db.models import Q
    from django.utils import timezone

    if _fail_closed(user):
        return UrgentSupportRequest.objects.none()

    if has_fixed_capability(user, Capability.URGENT_SUPPORT_QUEUE_REVIEW):
        return UrgentSupportRequest.objects.all()

    if is_student(user):
        return UrgentSupportRequest.objects.filter(student=user)

    if is_counselor(user):
        now = timezone.now()
        active_grants_q = Q(
            access_grants__grantee=user,
            access_grants__status=TemporarySupportAccessStatus.ACTIVE,
            access_grants__revoked_at__isnull=True,
            access_grants__starts_at__lte=now,
            access_grants__expires_at__gt=now,
        )
        return UrgentSupportRequest.objects.filter(
            Q(initiated_by=user) |
            Q(triage_counselor=user) |
            Q(originating_session__assigned_counselor=user) |
            Q(counseling_case__assigned_counselor=user) |
            Q(counseling_case__case_collaborator_entries__counselor=user, counseling_case__case_collaborator_entries__is_active=True) |
            active_grants_q
        ).distinct()

    if is_gco_staff(user):
        scope_q = build_workflow_authority_scope_q(
            user,
            capability=Capability.URGENT_SUPPORT_QUEUE_REVIEW,
            field_map={
                "campus": "student__student_profile__campus",
                "college": "student__student_profile__college",
                "department": "student__student_profile__department",
                "program": "student__student_profile__program",
            },
            counselor_field="triage_counselor_id",
        )
        return UrgentSupportRequest.objects.filter(scope_q).distinct()

    return UrgentSupportRequest.objects.none()


def get_urgent_support_request_by_reference_code(user, reference_code):
    from apps.counseling.models import UrgentSupportRequest
    from apps.counseling.policies import can_view_urgent_support_request
    try:
        urgent_support = UrgentSupportRequest.objects.select_related(
            "student", "initiated_by", "triage_counselor", "originating_session", "counseling_case"
        ).get(reference_code=reference_code)
    except UrgentSupportRequest.DoesNotExist:
        return None

    if not can_view_urgent_support_request(user, urgent_support):
        return None
    return urgent_support


def get_urgent_support_requests_for_head_review(user) -> models.QuerySet:
    from apps.counseling.models import UrgentSupportRequest, UrgentSupportStatus
    from apps.access_control.rules import is_head_guidance

    if _fail_closed(user) or not has_fixed_capability(user, Capability.URGENT_SUPPORT_QUEUE_REVIEW):
        return UrgentSupportRequest.objects.none()

    return UrgentSupportRequest.objects.filter(
        status__in=[
            UrgentSupportStatus.OPEN,
            UrgentSupportStatus.TRIAGE_ACCESS_GRANTED,
            UrgentSupportStatus.TRIAGE_IN_PROGRESS,
            UrgentSupportStatus.PENDING_HEAD_REVIEW,
        ]
    )


def get_active_urgent_support_grants_for_user(user, now=None) -> models.QuerySet:
    from apps.counseling.models import TemporarySupportAccessGrant, TemporarySupportAccessStatus
    from apps.access_control.rules import is_counselor
    from django.utils import timezone

    if _fail_closed(user) or not is_counselor(user):
        return TemporarySupportAccessGrant.objects.none()

    if not now:
        now = timezone.now()

    return TemporarySupportAccessGrant.objects.filter(
        grantee=user,
        status=TemporarySupportAccessStatus.ACTIVE,
        revoked_at__isnull=True,
        starts_at__lte=now,
        expires_at__gt=now,
    )


def get_active_urgent_support_grant_for_target(user, urgent_support=None, session=None, counseling_case=None, now=None):
    from apps.counseling.models import TemporarySupportAccessStatus
    from django.db.models import Q
    
    grants = get_active_urgent_support_grants_for_user(user, now=now)
    if not grants.exists():
        return None

    if urgent_support:
        return grants.filter(urgent_support=urgent_support).first()
    if session:
        return grants.filter(
            Q(urgent_support__originating_session=session) |
            Q(urgent_support__documentation_session=session)
        ).first()
    if counseling_case:
        return grants.filter(urgent_support__counseling_case=counseling_case).first()

    return None


def get_urgent_support_requests_for_session(user, session) -> models.QuerySet:
    visible = get_urgent_support_requests_visible_to(user)
    return visible.filter(
        models.Q(originating_session=session) |
        models.Q(documentation_session=session)
    )


def get_urgent_support_requests_for_case(user, counseling_case) -> models.QuerySet:
    visible = get_urgent_support_requests_visible_to(user)
    return visible.filter(counseling_case=counseling_case)
