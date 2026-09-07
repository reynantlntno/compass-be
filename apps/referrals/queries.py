"""Actor-aware query boundary for the referrals domain.

Query functions belong here when the domain receives an API/UI read. They must
compose an existing scoped selector with a fixed projection and never return
HTTP responses or serialize ORM objects directly.
"""

from apps.common.contracts import PageRequest, PageResult, page_queryset
from apps.referrals.projections import (
    project_referral_detail,
    project_referral_queue_item,
    project_reassignment_request,
)
from apps.referrals.selectors import (
    get_referral_by_reference_code,
    get_referrals_visible_to,
    get_reassignment_request_for_decision,
)


def _ordered_visible(actor):
    return (
        get_referrals_visible_to(actor)
        .select_related("student", "student__student_profile", "assigned_counselor")
        .order_by("-updated_at", "-pk")
    )


def scoped_referral_page(actor, page: PageRequest | None = None) -> PageResult[dict]:
    request = page or PageRequest()
    result = page_queryset(
        _ordered_visible(actor),
        request,
        lambda referral: project_referral_queue_item(actor, referral),
    )
    return PageResult(
        items=tuple(item for item in result["items"] if item is not None),
        page=result["page"],
        page_size=result["page_size"],
        total=result["total"],
    )


def referral_detail(actor, reference_code: str) -> dict | None:
    referral = get_referral_by_reference_code(actor, reference_code)
    return project_referral_detail(actor, referral)


def reassignment_request_detail(actor, request_id) -> dict | None:
    request = get_reassignment_request_for_decision(actor, request_id)
    return project_reassignment_request(actor, request)


def replay_by_id(object_id) -> dict | None:
    from apps.referrals.models import Referral

    referral = Referral.objects.filter(pk=object_id).only("reference_code", "status").first()
    if referral is None:
        return None
    return {"reference_code": referral.reference_code, "status": referral.status}


def replay_by_reference(reference_code: str) -> dict | None:
    from apps.referrals.models import Referral

    referral = Referral.objects.filter(reference_code=str(reference_code or "").strip()).only(
        "reference_code", "status",
    ).first()
    if referral is None:
        return None
    return {"reference_code": referral.reference_code, "status": referral.status}
