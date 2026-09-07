"""Actor-aware Exit Interview query and projection boundary."""

from apps.common.contracts import PageRequest, PageResult
from apps.exit_interviews import projections, selectors
from apps.exit_interviews.policies import can_view_exit_free_text


def response_page(actor, request: PageRequest) -> PageResult:
    return _page(selectors.list_exit_responses_for_actor(actor), request, projections.response_metadata)


def response_detail(actor, reference_code: str):
    value = selectors.get_exit_detail_for_actor_by_reference(actor, reference_code)
    if value is None:
        return None
    return projections.response_sensitive(value) if can_view_exit_free_text(actor, value) else projections.response_metadata(value)


def response_sensitive_detail(actor, reference_code: str):
    value = selectors.get_exit_detail_for_actor_by_reference(actor, reference_code)
    if value is None or not can_view_exit_free_text(actor, value):
        return None
    return projections.response_sensitive(value)


def assignment_page(actor, request: PageRequest) -> PageResult:
    return _page(selectors.list_assignments_for_actor(actor), request, projections.assignment)


def student_status(actor):
    value = selectors.get_student_exit_status(actor)
    return projections.status(value) if value is not None else None


def _page(queryset, request, projector):
    total = queryset.count()
    rows = queryset[request.offset: request.offset + request.page_size]
    return PageResult(
        items=tuple(projector(row) for row in rows),
        page=request.page,
        page_size=request.page_size,
        total=total,
    )
