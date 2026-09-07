"""Actor-aware query boundary for the support_needs domain.

Query functions compose an existing scoped selector with a fixed projection
and never return HTTP responses or serialize ORM objects directly.
"""

from __future__ import annotations

from django.db.models import Count

from apps.access_control.selectors import get_students_visible_to
from apps.common.contracts import PageRequest, page_queryset
from apps.common.exceptions import PermissionDeniedError
from apps.reports.suppression import MIN_SUPPRESSION_THRESHOLD, SUPPRESSION_LABEL
from apps.support_needs.choices import SupportNeedStatus
from apps.support_needs.models import StudentSupportNeed
from apps.support_needs.policies import can_view_support_need_aggregate
from apps.support_needs.projections import (
    project_support_need,
    project_support_need_summary,
    project_support_need_type,
)
from apps.support_needs.selectors import (
    get_support_need_for_actor,
    get_support_need_review_queue,
    get_support_need_type_catalog,
    get_support_needs_visible_to,
)


def _ordered_visible(actor):
    return (
        get_support_needs_visible_to(actor)
        .select_related("student_profile", "support_need_type")
        .order_by("-updated_at", "-pk")
    )


def scoped_support_need_page(actor, page: PageRequest | None = None, filters: dict | None = None) -> dict:
    """Return the scoped counselor/Head list as a bounded projection page.

    Bounded status/type/student-scope filters are applied database-side.
    """

    queryset = _ordered_visible(actor)
    if filters:
        status = filters.get("status")
        if status:
            queryset = queryset.filter(status=status)
        type_key = filters.get("type_key")
        if type_key:
            queryset = queryset.filter(support_need_type__key=type_key)
        student_profile_id = filters.get("student_profile_id")
        if student_profile_id:
            queryset = queryset.filter(student_profile_id=student_profile_id)
    return page_queryset(
        queryset,
        page or PageRequest(),
        project_support_need_summary,
    )


def support_need_detail(actor, support_need_id) -> dict | None:
    """Scoped safe metadata projection for one record."""

    record = get_support_need_for_actor(actor, support_need_id)
    return project_support_need(record) if record is not None else None


def review_queue_page(actor, page: PageRequest | None = None) -> dict:
    """Scoped ``needs_review`` records only."""

    records = (
        get_support_need_review_queue(actor)
        .select_related("student_profile", "support_need_type")
        .order_by("-updated_at", "-pk")
    )
    return page_queryset(
        records,
        page or PageRequest(),
        project_support_need_summary,
    )


def type_catalog(actor, page: PageRequest | None = None) -> dict:
    """Active controlled type catalog for authorized counselors/Head only."""

    return page_queryset(
        get_support_need_type_catalog(actor).order_by("key"),
        page or PageRequest(),
        project_support_need_type,
    )


def support_need_aggregate_dataset(actor, filters: dict | None = None) -> list[dict]:
    """Return scoped, verified-only aggregate rows for report consumers.

    This is a read query, not a Support Needs mutation or API surface. Reports
    own the external aggregate workflow; this boundary only supplies the
    already-scoped and suppression-safe dataset.
    """

    if not can_view_support_need_aggregate(actor, filters):
        raise PermissionDeniedError()

    queryset = StudentSupportNeed.objects.filter(
        student_profile__in=get_students_visible_to(actor),
        status=SupportNeedStatus.VERIFIED,
    )
    if filters and filters.get("category"):
        queryset = queryset.filter(support_need_type__category=filters["category"])

    aggregates = queryset.values(
        "support_need_type__key",
        "support_need_type__category",
        "status",
    ).annotate(count=Count("id"))

    rows = []
    for aggregate in aggregates:
        count = aggregate["count"]
        rows.append({
            "support_need_key": aggregate["support_need_type__key"],
            "support_need_type__category": aggregate["support_need_type__category"],
            "status": aggregate["status"],
            "count": SUPPRESSION_LABEL if 0 < count < MIN_SUPPRESSION_THRESHOLD else count,
        })
    return rows
