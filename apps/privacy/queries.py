"""Paginated privacy read queries returning only fixed projections."""

from apps.common.contracts import PageRequest, PageResult
from apps.access_control.rules import is_it_admin

from . import projections, selectors
from .policies import can_view_request_sensitive, is_current_dpo


def _page(queryset, page: PageRequest, projector):
    total = queryset.count()
    rows = queryset[page.offset:page.offset + page.page_size]
    return PageResult(
        items=tuple(projector(row) for row in rows),
        page=page.page,
        page_size=page.page_size,
        total=total,
    )


def request_page(actor, page):
    return _page(selectors.visible_requests(actor), page, projections.request_projection)


def request_detail(actor, reference_code):
    return projections.request_projection(selectors.request_for_actor(actor, reference_code))


def request_sensitive_detail(actor, reference_code):
    request = selectors.request_for_actor(actor, reference_code)
    return (
        projections.request_sensitive_projection(request)
        if can_view_request_sensitive(actor, request)
        else None
    )


def acceptance_page(actor, page, *, purpose_workflow=""):
    return _page(
        selectors.acceptance_events_for_actor(actor, purpose_workflow=purpose_workflow),
        page,
        projections.acceptance_projection,
    )


def incident_page(actor, page):
    technical_only = is_it_admin(actor) and not is_current_dpo(actor)
    return _page(
        selectors.visible_incidents(actor),
        page,
        lambda row: projections.incident_projection(row, technical_only=technical_only),
    )


def incident_detail(actor, incident_code):
    row = selectors.incident_for_actor(actor, incident_code)
    if row is None:
        return None
    technical_only = is_it_admin(actor) and not is_current_dpo(actor)
    result = projections.incident_projection(row, technical_only=technical_only)
    result["timeline"] = [
        projections.incident_transition_projection(item, technical_only=technical_only)
        for item in row.transitions.order_by("occurred_at", "created_at")
    ]
    return result


def legal_hold_page(actor, page):
    return _page(selectors.legal_holds_for_actor(actor), page, projections.legal_hold_projection)


def legal_hold_detail(actor, hold_id):
    return projections.legal_hold_projection(selectors.legal_hold_for_actor(actor, hold_id))


def retention_policy_page(actor, page, *, at=None):
    rows = tuple(
        projections.retention_policy_projection(item)
        for item in selectors.effective_retention_policies(actor, at=at)
    )
    return PageResult(
        items=rows[page.offset:page.offset + page.page_size],
        page=page.page,
        page_size=page.page_size,
        total=len(rows),
    )


def retention_evaluation_page(actor, page):
    return _page(
        selectors.retention_evaluations_for_actor(actor),
        page,
        projections.retention_evaluation_projection,
    )
