"""Actor-aware query boundary for the call_slips domain.

Query functions belong here when the domain receives an API/UI read. They must
compose an existing scoped selector with a fixed projection and never return
HTTP responses or serialize ORM objects directly.
"""

from apps.common.contracts import PageRequest, PageResult, page_queryset
from apps.call_slips.projections import project_call_slip_queue_item
from apps.call_slips.selectors import (
    get_assigned_call_slip_queue,
    get_coverage_call_slip_queue,
    get_head_call_slip_queue,
    get_reschedule_request_for_decision,
    get_staff_call_slip_queue,
    get_student_call_slips,
)


def _ordered_visible(actor):
    from apps.access_control.rules import is_counselor, is_gco_staff, is_student

    if is_student(actor):
        queryset = get_student_call_slips(actor)
    elif is_counselor(actor):
        queryset = (get_assigned_call_slip_queue(actor) | get_coverage_call_slip_queue(actor)).distinct()
    elif is_gco_staff(actor):
        queryset = get_staff_call_slip_queue(actor)
    else:
        queryset = get_head_call_slip_queue(actor)
    return queryset.select_related(
        "student", "student__student_profile", "assigned_counselor",
    ).order_by("-updated_at", "-pk")


def scoped_call_slip_page(actor, page: PageRequest | None = None) -> PageResult[dict]:
    request = page or PageRequest()
    result = page_queryset(
        _ordered_visible(actor),
        request,
        lambda slip: project_call_slip_queue_item(actor, slip),
    )
    return PageResult(
        items=tuple(item for item in result["items"] if item is not None),
        page=result["page"],
        page_size=result["page_size"],
        total=result["total"],
    )


def call_slip_detail(actor, reference_code: str) -> dict | None:
    from apps.call_slips.projections import project_call_slip_detail

    return project_call_slip_detail(actor, reference_code)


def student_call_slip_detail(actor, reference_code: str) -> dict | None:
    from apps.call_slips.projections import project_student_call_slip_detail

    return project_student_call_slip_detail(actor, reference_code)


def printable_call_slip(actor, reference_code: str) -> dict | None:
    from apps.call_slips.projections import project_printable_call_slip

    return project_printable_call_slip(actor, reference_code)


def reschedule_request_detail(actor, request_id) -> dict | None:
    from apps.call_slips.projections import project_reschedule_request

    return project_reschedule_request(actor, get_reschedule_request_for_decision(actor, request_id))


def replay_by_id(object_id) -> dict | None:
    from apps.call_slips.models import CallSlip

    slip = CallSlip.objects.filter(pk=object_id).only("reference_code", "status").first()
    if slip is None:
        return None
    return {"reference_code": slip.reference_code, "status": slip.status}


def replay_by_reference(reference_code: str) -> dict | None:
    from apps.call_slips.models import CallSlip

    slip = CallSlip.objects.filter(reference_code=str(reference_code or "").strip()).only(
        "reference_code", "status",
    ).first()
    if slip is None:
        return None
    return {"reference_code": slip.reference_code, "status": slip.status}
