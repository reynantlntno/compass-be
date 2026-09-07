"""Actor-aware, model-free Good Moral query boundary."""

from apps.common.contracts import PageRequest, PageResult
from apps.good_moral.projections import request_projection
from apps.good_moral.selectors import (
    get_visible_request_by_reference,
    list_staff_review_queue,
    list_student_own_requests,
)


def request_page(actor, page: PageRequest) -> PageResult[dict]:
    queryset = (
        list_student_own_requests(actor)
        if getattr(actor, "role", "") == "STUDENT"
        else list_staff_review_queue(actor)
    )
    total = queryset.count()
    rows = queryset.select_related(
        "generated_document",
        "generated_document__template_version",
        "generated_document__template_version__template",
    )[page.offset: page.offset + page.page_size]
    return PageResult(
        items=tuple(request_projection(row, actor) for row in rows),
        page=page.page,
        page_size=page.page_size,
        total=total,
    )


def request_detail(actor, reference_code: str) -> dict | None:
    request = get_visible_request_by_reference(actor, reference_code)
    return request_projection(request, actor) if request else None


def replay_by_id(object_id, actor=None) -> dict | None:
    from apps.good_moral.models import GoodMoralRequest

    try:
        request = GoodMoralRequest.objects.select_related(
            "generated_document",
            "generated_document__template_version",
            "generated_document__template_version__template",
        ).get(pk=object_id)
    except (GoodMoralRequest.DoesNotExist, ValueError):
        return None
    if actor is not None:
        from apps.good_moral.policies import can_view_request
        if not can_view_request(actor, request):
            return None
        return request_projection(request, actor)
    return mutation_result(request)


def mutation_result(request):
    from apps.good_moral.projections import mutation_result as project_mutation
    return project_mutation(request)
