"""Actor-aware query boundary for the counseling domain.

Query functions belong here when the domain receives an API/UI read. They must
compose an existing scoped selector with a fixed projection and never return
HTTP responses or serialize ORM objects directly.
"""

from datetime import date as date_type

from django.db.models import F, Q

from apps.common.contracts import PageRequest, PageResult, page_queryset, to_json_value
from apps.access_control.rules import is_student
from apps.counseling.projections import (
    project_case_metadata,
    project_routine_interview_metadata,
    project_routine_interview_queue_metadata,
    project_staff_session_queue_metadata,
    project_student_case_metadata,
    project_student_routine_interview,
    project_student_session_metadata,
)
from apps.counseling.selectors import (
    get_counseling_cases_visible_to,
    get_routine_interviews_visible_to,
    get_sessions_visible_to,
    get_urgent_support_requests_visible_to,
)


SESSION_STATUSES = frozenset({
    "SCHEDULED",
    "IN_PROGRESS",
    "COUNSELOR_NOTES_DRAFT",
    "COMPLETED",
    "FINALIZED",
    "LOCKED",
    "CANCELLED",
    "NO_SHOW",
})
SESSION_TYPES = frozenset({
    "COUNSELING",
    "ROUTINE_INTERVIEW",
    "FOLLOW_UP",
    "TRIAGE",
    "ADMINISTRATIVE_INTERVIEW",
})
SESSION_MODES = frozenset({"ONSITE", "ONLINE"})
SESSION_SOURCES = frozenset({
    "WALK_IN",
    "CALLED_IN",
    "REFERRED",
    "APPOINTMENT",
    "COUNSELOR_INITIATED",
    "CALL_SLIP",
    "ROUTINE_COLLECTION",
    "ECOUNSELING",
    "URGENT_SUPPORT",
})
SESSION_ASSIGNMENTS = frozenset({"all", "mine", "unassigned"})
SESSION_ORDERS = frozenset({"recent", "upcoming"})
ROUTINE_STATUSES = frozenset({
    "NOT_STARTED",
    "INTAKE_DRAFT",
    "INTAKE_SUBMITTED",
    "EVALUATION_DRAFT",
    "COMPLETED",
    "FINALIZED",
    "LOCKED",
    "REOPENED_FOR_CORRECTION",
})
MAX_SESSION_SEARCH_LENGTH = 120


def _parse_values(value, allowed, label):
    if value is None or not str(value).strip():
        return None
    values = tuple(dict.fromkeys(
        item.strip().upper()
        for item in str(value).split(",")
        if item.strip()
    ))
    if not values or len(values) > len(allowed) or any(item not in allowed for item in values):
        raise ValueError(f"Invalid counseling {label} filter.")
    return values


def _filtered_session_queryset(
    actor,
    *,
    q=None,
    statuses=None,
    session_type=None,
    session_mode=None,
    session_source=None,
    assignment="all",
    date_from: date_type | None = None,
    date_to: date_type | None = None,
    order="recent",
):
    if q is not None and len(str(q).strip()) > MAX_SESSION_SEARCH_LENGTH:
        raise ValueError("Counseling session search is too long.")
    if session_type and session_type.upper() not in SESSION_TYPES:
        raise ValueError("Invalid counseling session type filter.")
    if session_mode and session_mode.upper() not in SESSION_MODES:
        raise ValueError("Invalid counseling session mode filter.")
    if session_source and session_source.upper() not in SESSION_SOURCES:
        raise ValueError("Invalid counseling session source filter.")
    if assignment not in SESSION_ASSIGNMENTS:
        raise ValueError("Invalid counseling session assignment filter.")
    if order not in SESSION_ORDERS:
        raise ValueError("Invalid counseling session order.")
    if date_from and date_to and date_from > date_to:
        raise ValueError("Counseling session date range is inverted.")

    queryset = get_sessions_visible_to(actor).select_related(
        "student",
        "student__student_profile",
        "assigned_counselor",
    )
    parsed_statuses = _parse_values(statuses, SESSION_STATUSES, "status")
    if parsed_statuses:
        queryset = queryset.filter(status__in=parsed_statuses)
    if session_type:
        queryset = queryset.filter(session_type=session_type.upper())
    if session_mode:
        queryset = queryset.filter(session_mode=session_mode.upper())
    if session_source:
        queryset = queryset.filter(session_source=session_source.upper())
    if assignment == "mine":
        queryset = queryset.filter(assigned_counselor_id=getattr(actor, "pk", None))
    elif assignment == "unassigned":
        queryset = queryset.filter(assigned_counselor_id__isnull=True)

    if date_from:
        queryset = queryset.filter(scheduled_start_at__date__gte=date_from)
    if date_to:
        queryset = queryset.filter(scheduled_start_at__date__lte=date_to)

    search = str(q or "").strip()
    if search:
        search_filter = Q(reference_code__icontains=search)
        if is_student(actor):
            queryset = queryset.filter(search_filter)
        else:
            identity_filter = Q()
            for term in search.split():
                identity_filter &= (
                    Q(student__first_name__icontains=term)
                    | Q(student__last_name__icontains=term)
                    | Q(student__student_profile__student_number__icontains=term)
                )
            queryset = queryset.filter(search_filter | identity_filter)

    if order == "upcoming":
        queryset = queryset.order_by(
            F("scheduled_start_at").asc(nulls_last=True),
            "-updated_at",
            "-pk",
        )
    else:
        queryset = queryset.order_by("-updated_at", "-pk")
    return queryset


def _page_from_dict(value: dict) -> PageResult[dict]:
    return PageResult(
        items=tuple(value["items"]),
        page=value["page"],
        page_size=value["page_size"],
        total=value["total"],
    )


def get_session_metadata_page(
    actor,
    page: PageRequest | None = None,
    *,
    q=None,
    statuses=None,
    session_type=None,
    session_mode=None,
    session_source=None,
    assignment="all",
    date_from: date_type | None = None,
    date_to: date_type | None = None,
    order="recent",
) -> PageResult[dict]:
    projector = (
        project_student_session_metadata
        if is_student(actor)
        else project_staff_session_queue_metadata
    )
    queryset = _filtered_session_queryset(
        actor,
        q=q,
        statuses=statuses,
        session_type=session_type,
        session_mode=session_mode,
        session_source=session_source,
        assignment=assignment,
        date_from=date_from,
        date_to=date_to,
        order=order,
    )
    return _page_from_dict(
        page_queryset(queryset, page or PageRequest(), lambda row: projector(actor, row))
    )


def get_counseling_case_metadata_page(actor, page: PageRequest | None = None) -> PageResult[dict]:
    projector = project_student_case_metadata if is_student(actor) else project_case_metadata
    queryset = get_counseling_cases_visible_to(actor).select_related(
        "student", "assigned_counselor"
    ).order_by("-updated_at", "-pk")
    return _page_from_dict(
        page_queryset(queryset, page or PageRequest(), lambda row: projector(actor, row))
    )


def get_routine_interview_metadata_page(
    actor,
    page: PageRequest | None = None,
    *,
    statuses=None,
) -> PageResult[dict]:
    projector = project_student_routine_interview if is_student(actor) else project_routine_interview_metadata
    queryset = get_routine_interviews_visible_to(actor).order_by("-updated_at", "-pk")
    parsed_statuses = _parse_values(statuses, ROUTINE_STATUSES, "routine interview status")
    if parsed_statuses:
        queryset = queryset.filter(status__in=parsed_statuses)
    return _page_from_dict(
        page_queryset(queryset, page or PageRequest(), lambda row: projector(actor, row))
    )


def get_routine_interview_queue_metadata_page(
    actor,
    page: PageRequest | None = None,
    *,
    statuses=None,
) -> PageResult[dict]:
    """Return the bounded staff queue projection for routine interviews."""
    projector = (
        project_student_routine_interview
        if is_student(actor)
        else project_routine_interview_queue_metadata
    )
    queryset = get_routine_interviews_visible_to(actor).order_by("-updated_at", "-pk")
    parsed_statuses = _parse_values(statuses, ROUTINE_STATUSES, "routine interview status")
    if parsed_statuses:
        queryset = queryset.filter(status__in=parsed_statuses)
    return _page_from_dict(
        page_queryset(queryset, page or PageRequest(), lambda row: projector(actor, row))
    )


URGENT_SUPPORT_METADATA_FIELDS = (
    "reference_code",
    "status",
    "urgency_level",
    "source_type",
    "documentation_status",
)


def project_urgent_support_metadata(actor, urgent_support, *, already_scoped=False) -> dict | None:
    """Return the safe operational urgent-support projection.

    Excludes student identity beyond the reference code, raw reasons,
    temporary-access details, actor relations, and any narrative content.
    """
    from apps.access_control.rules import is_active_nonlegacy_actor

    if urgent_support is None or not is_active_nonlegacy_actor(actor):
        return None
    if not already_scoped and not get_urgent_support_requests_visible_to(actor).filter(
        pk=urgent_support.pk,
    ).exists():
        return None
    payload = {
        field: to_json_value(getattr(urgent_support, field))
        for field in URGENT_SUPPORT_METADATA_FIELDS
    }
    if getattr(urgent_support, "counseling_case_id", None):
        payload["counseling_case_reference"] = (
            urgent_support.counseling_case.reference_code
        )
    return payload


def get_urgent_support_metadata_page(actor, page: PageRequest | None = None) -> PageResult[dict]:
    queryset = get_urgent_support_requests_visible_to(actor).select_related(
        "counseling_case"
    ).order_by("-created_at", "-pk")
    return _page_from_dict(
        page_queryset(
            queryset,
            page or PageRequest(),
            lambda row: project_urgent_support_metadata(actor, row, already_scoped=True),
        )
    )
