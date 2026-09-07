"""Actor-aware Form Collection query boundary."""

from apps.common.contracts import PageRequest, PageResult
from apps.common.contracts import page_queryset
from apps.form_collection import projections, selectors


def collection_page(actor, page_request: PageRequest) -> PageResult:
    return _page(selectors.list_collections_for_actor(actor), page_request, projections.collection)


def collection_detail(actor, collection_id):
    value = selectors.get_collection_for_actor(actor, collection_id)
    return projections.collection(value) if value else None


def invitation_batch_page(actor, collection_id, page_request: PageRequest) -> PageResult:
    return _page(selectors.list_invitation_batches_for_actor(actor, collection_id), page_request, projections.invitation_batch)


def invitation_page(actor, collection_id, page_request: PageRequest) -> PageResult:
    return _page(selectors.list_invitation_metadata_for_actor(actor, collection_id), page_request, projections.invitation_metadata)


def manual_match_page(actor, page_request: PageRequest) -> PageResult:
    return _page(selectors.list_manual_review_queue(actor), page_request, projections.manual_match)


def invitation_detail(actor, invitation_id):
    value = selectors.get_invitation_for_actor(actor, invitation_id)
    return projections.invitation_metadata(value) if value else None


def verified_access(invitation):
    return projections.verified_access(invitation)


def _page(queryset, request, projector):
    total = queryset.count()
    rows = queryset[request.offset: request.offset + request.page_size]
    return PageResult(
        items=tuple(projector(row) for row in rows),
        page=request.page,
        page_size=request.page_size,
        total=total,
    )
