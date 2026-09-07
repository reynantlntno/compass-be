"""Actor-aware query boundary for the counseling domain.

Query functions belong here when the domain receives an API/UI read. They must
compose an existing scoped selector with a fixed projection and never return
HTTP responses or serialize ORM objects directly.
"""

from apps.common.contracts import PageRequest, PageResult, page_queryset, to_json_value
from apps.access_control.rules import is_student
from apps.counseling.projections import (
    project_case_metadata,
    project_routine_interview_metadata,
    project_staff_session_metadata,
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


def _page_from_dict(value: dict) -> PageResult[dict]:
    return PageResult(
        items=tuple(value["items"]),
        page=value["page"],
        page_size=value["page_size"],
        total=value["total"],
    )


def get_session_metadata_page(actor, page: PageRequest | None = None) -> PageResult[dict]:
    projector = project_student_session_metadata if is_student(actor) else project_staff_session_metadata
    queryset = get_sessions_visible_to(actor).select_related(
        "student", "assigned_counselor"
    ).order_by("-updated_at", "-pk")
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


def get_routine_interview_metadata_page(actor, page: PageRequest | None = None) -> PageResult[dict]:
    projector = project_student_routine_interview if is_student(actor) else project_routine_interview_metadata
    queryset = get_routine_interviews_visible_to(actor).order_by("-updated_at", "-pk")
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
