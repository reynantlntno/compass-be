"""Actor-aware, model-free read boundary for content."""

from __future__ import annotations

from apps.common.contracts import PageRequest, PageResult, page_items
from apps.common.exceptions import NotFoundError, PermissionDeniedError
from apps.access_control.rules import is_active_nonlegacy_actor
from apps.content.cache import (
    get_cached_public_announcement_by_slug,
    get_cached_public_announcements,
    get_cached_public_page,
    get_cached_public_resource_by_slug,
    get_cached_public_resources,
    get_cached_public_service_guide,
)
from apps.content.projections import (
    project_contact_reply,
    project_contact_submission_detail,
    project_contact_submission_metadata,
    project_content_workspace_item,
    project_no_response_disposition,
    project_public_contact_result,
    project_public_content_item,
    project_public_service_guide,
)
from apps.content.selectors import (
    get_content_workspace_item,
    get_content_workspace_items,
    get_contact_delivery_metadata,
    get_contact_submission_by_id,
    get_contact_submission_metadata_by_id,
    get_contact_submission_by_reference,
    get_contact_submissions_queue,
    get_visible_published_announcements_for_user,
    get_visible_published_resources_for_user,
)


def _public_page(items, request: PageRequest) -> PageResult:
    return page_items(items, request)


def public_announcements(request: PageRequest) -> PageResult:
    return _public_page(get_cached_public_announcements(), request)


def public_resources(request: PageRequest) -> PageResult:
    return _public_page(get_cached_public_resources(), request)


def public_announcement(slug: str) -> dict | None:
    return get_cached_public_announcement_by_slug(slug)


def public_resource(slug: str) -> dict | None:
    return get_cached_public_resource_by_slug(slug)


def public_page(page_key: str) -> dict | None:
    return get_cached_public_page(page_key)


def public_service_guide() -> dict | None:
    return project_public_service_guide(get_cached_public_service_guide())


def visible_announcements(actor, request: PageRequest) -> PageResult:
    if not is_active_nonlegacy_actor(actor):
        raise PermissionDeniedError()
    queryset = get_visible_published_announcements_for_user(actor)
    total = queryset.count()
    rows = []
    for item in queryset[request.offset:request.offset + request.page_size]:
        from apps.content.selectors import _populate_public_html
        projected = project_public_content_item(_populate_public_html(item))
        if projected is not None:
            rows.append(projected)
    return PageResult(tuple(row for row in rows if row is not None), request.page, request.page_size, total)


def visible_resources(actor, request: PageRequest) -> PageResult:
    if not is_active_nonlegacy_actor(actor):
        raise PermissionDeniedError()
    queryset = get_visible_published_resources_for_user(actor)
    total = queryset.count()
    rows = []
    for item in queryset[request.offset:request.offset + request.page_size]:
        from apps.content.selectors import _populate_public_html
        projected = project_public_content_item(_populate_public_html(item))
        if projected is not None:
            rows.append(projected)
    return PageResult(tuple(row for row in rows if row is not None), request.page, request.page_size, total)


def content_workspace(actor, status_key: str, request: PageRequest) -> PageResult:
    rows = get_content_workspace_items(actor, status_key=status_key)
    projected = [
        project_content_workspace_item(
            row["object"],
            content_type=row["content_type"],
            effective_status=row["effective_status"],
            latest_review=row["latest_review"],
        )
        for row in rows
    ]
    return page_items(projected, request)


def content_workspace_detail(actor, content_type: str, object_id) -> dict:
    item = get_content_workspace_item(actor, content_type, object_id)
    if item is None:
        raise NotFoundError()
    return project_content_workspace_item(item, content_type=content_type)


def contact_queue(actor, request: PageRequest) -> PageResult:
    rows = get_contact_submissions_queue(actor)
    total = rows.count()
    items = [project_contact_submission_metadata(row) for row in rows[request.offset:request.offset + request.page_size]]
    return PageResult(tuple(items), request.page, request.page_size, total)


def contact_submission_detail(actor, submission_id, *, full: bool = True) -> dict:
    if not full:
        submission = get_contact_submission_metadata_by_id(submission_id, actor)
        if submission is None:
            raise NotFoundError()
        return project_contact_submission_metadata(submission)
    submission = get_contact_submission_by_id(submission_id, actor)
    if submission is None:
        raise NotFoundError()
    return project_contact_submission_detail(submission)


def contact_submission_by_reference(actor, reference_code: str) -> dict:
    submission = get_contact_submission_by_reference(actor, reference_code)
    return project_contact_submission_detail(submission)


def contact_delivery_metadata(actor, request: PageRequest) -> dict:
    result = get_contact_delivery_metadata(
        actor,
        offset=request.offset,
        limit=request.page_size,
    )
    items = [
        {
            **row,
            "created_at": row["created_at"].isoformat() if row.get("created_at") else None,
            "sent_at": row["sent_at"].isoformat() if row.get("sent_at") else None,
            "provider_status_updated_at": (
                row["provider_status_updated_at"].isoformat()
                if row.get("provider_status_updated_at") else None
            ),
        }
        for row in result["rows"]
    ]
    page = PageResult(tuple(items), request.page, request.page_size, result["total"])
    return {"counts": result["counts"], **page.as_dict()}


def contact_reply_projection(actor, reply, *, include_body: bool = False) -> dict:
    """Project a reply already authorized by the owning submission policy."""
    return project_contact_reply(reply, include_body=include_body)


def contact_replies(actor, submission_id, request: PageRequest) -> PageResult:
    """List correspondence only after the owning submission is authorized."""
    get_contact_submission_by_id(submission_id, actor)
    from apps.content.models import ContactReply

    rows = ContactReply.objects.filter(submission_id=submission_id).order_by("-created_at")
    total = rows.count()
    items = [
        project_contact_reply(row, include_body=True)
        for row in rows[request.offset:request.offset + request.page_size]
    ]
    return PageResult(tuple(items), request.page, request.page_size, total)


def public_contact_result(submission) -> dict:
    return project_public_contact_result(submission)


def no_response_projection(disposition) -> dict:
    return project_no_response_disposition(disposition)


__all__ = [
    "public_announcements", "public_resources", "public_announcement",
    "public_resource", "public_page", "public_service_guide",
    "visible_announcements", "visible_resources", "content_workspace",
    "content_workspace_detail", "contact_queue", "contact_submission_detail",
    "contact_submission_by_reference", "contact_delivery_metadata",
    "contact_reply_projection", "contact_replies", "public_contact_result", "no_response_projection",
]
