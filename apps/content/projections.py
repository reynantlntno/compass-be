"""Fixed JSON projection boundary for the content domain."""

from __future__ import annotations

def _timestamp(value):
    return value.isoformat() if value else None


def _date(value):
    return value.isoformat() if hasattr(value, "isoformat") else value


def _target_projection(item) -> dict:
    return {
        "target_scope_mode": item.target_scope_mode,
        "target_campus": getattr(item, "target_campus", None),
        "target_college": getattr(item, "target_college", None),
        "target_department": getattr(item, "target_department", None),
        "target_program": getattr(item, "target_program", None),
    }


def project_public_content_item(item) -> dict | None:
    """Project one published public announcement or resource."""
    if item is None:
        return None
    from apps.content.models import Announcement, Resource

    base = {
        "id": str(item.pk),
        "slug": item.slug,
        "title": item.title,
        "summary": item.summary,
        "body_html": item.body_html_sanitized,
        "status": item.status,
        "audience": item.audience,
        "target_scope_mode": item.target_scope_mode,
        "publish_start": _timestamp(item.publish_start),
        "publish_end": _timestamp(item.publish_end),
        "published_at": _timestamp(item.published_at),
    }
    if isinstance(item, Announcement):
        return {**base, "content_type": "announcement", "featured": bool(item.featured)}
    if isinstance(item, Resource):
        return {
            **base,
            "content_type": "resource",
            "category": item.category,
            "resource_type": item.resource_type,
            "external_url": item.external_url or None,
        }
    return None


def project_public_page(page) -> dict | None:
    if page is None:
        return None
    return {
        "id": str(page.pk),
        "page_key": page.page_key,
        "title": page.title,
        "summary": page.summary,
        "body_html": page.body_html_sanitized,
        "status": page.status,
        "audience": page.audience,
        "published_at": _timestamp(page.published_at),
    }


def project_public_service_guide(context: dict | None) -> dict | None:
    if not context:
        return None
    allowed = {
        "guide_key", "title", "summary", "version_label", "effective_date",
        "owner_office", "publication_state", "has_approved_revision", "readiness", "entries",
    }
    result = {key: context[key] for key in allowed if key in context}
    if "effective_date" in result:
        result["effective_date"] = _date(result["effective_date"])
    return result


def _revision_projection(revision, *, include_source: bool) -> dict | None:
    if revision is None:
        return None
    result = {
        "id": str(revision.pk),
        "revision_number": revision.revision_number,
        "status": revision.status,
        "created_at": _timestamp(revision.created_at),
        "reviewed_at": _timestamp(revision.reviewed_at),
        "published_at": _timestamp(revision.published_at),
    }
    if include_source:
        result["body_markdown"] = revision.body_markdown
    return result


def project_content_workspace_item(
    item,
    *,
    content_type: str,
    effective_status: str | None = None,
    latest_review=None,
    include_source: bool = True,
) -> dict:
    """Project a staff-authorized content item without actor relations."""
    result = {
        "id": str(item.pk),
        "content_type": content_type,
        "title": item.title,
        "summary": item.summary,
        "status": item.status,
        "effective_status": effective_status or item.status,
        "audience": item.audience,
        "publish_start": _timestamp(getattr(item, "publish_start", None)),
        "publish_end": _timestamp(getattr(item, "publish_end", None)),
        "published_at": _timestamp(item.published_at),
        "updated_at": _timestamp(item.updated_at),
        "created_at": _timestamp(item.created_at),
        "featured": bool(getattr(item, "featured", False)),
        "target": _target_projection(item) if hasattr(item, "target_scope_mode") else None,
        "slug": getattr(item, "slug", None),
        "page_key": getattr(item, "page_key", None),
        "guide_key": getattr(item, "guide_key", None),
        "category": getattr(item, "category", None),
        "resource_type": getattr(item, "resource_type", None),
        "external_url": getattr(item, "external_url", None),
        "body_markdown": getattr(item, "body_markdown", "") if include_source else None,
        "version_label": getattr(item, "version_label", None),
        "effective_date": _date(getattr(item, "effective_date", None)),
        "owner_office_id": getattr(item, "owner_office_id", None),
        "entries_json": list(getattr(item, "entries_json", []) or []) if include_source else None,
        "latest_review": _revision_projection(latest_review, include_source=include_source),
    }
    return result


def project_contact_submission_metadata(submission) -> dict:
    return {
        "id": str(submission.pk),
        "reference_code": submission.reference_code,
        "created_at": _timestamp(submission.created_at),
        "updated_at": _timestamp(submission.updated_at),
        "status": submission.status,
        "priority": submission.priority,
        "submission_type": submission.submission_type,
        "affiliation": submission.affiliation,
        "assigned_to_id": submission.assigned_to_id,
    }


def project_contact_submission_detail(submission) -> dict:
    return {
        **project_contact_submission_metadata(submission),
        "name": submission.name,
        "email": submission.email,
        "phone": submission.phone,
        "subject": submission.subject,
        "message_body": submission.get_message_body_for_staff(),
        "privacy_acknowledged": bool(submission.privacy_acknowledged),
        "urgent_support_disclaimer_acknowledged": bool(submission.urgent_support_disclaimer_acknowledged),
        "privacy_actioned_at": _timestamp(submission.privacy_actioned_at),
    }


def project_public_contact_result(submission) -> dict:
    return {
        "id": str(submission.pk),
        "reference_code": submission.reference_code,
        "status": submission.status,
        "created_at": _timestamp(submission.created_at),
    }


def project_contact_reply(reply, *, include_body: bool = False) -> dict:
    result = {
        "id": str(reply.pk),
        "submission_id": str(reply.submission_id),
        "status": reply.status,
        "created_at": _timestamp(reply.created_at),
        "updated_at": _timestamp(reply.updated_at),
        "approved_at": _timestamp(reply.approved_at),
        "delivery_state": reply.delivery_state,
        "evidence_scope": reply.evidence_scope,
        "evidence_recorded_at": _timestamp(reply.evidence_recorded_at),
        "sent_at": _timestamp(reply.sent_at),
        "last_failure_code": reply.last_failure_code,
    }
    if include_body:
        result["body"] = reply.get_body_for_send()
    return result


def project_no_response_disposition(disposition) -> dict:
    return {
        "id": str(disposition.pk),
        "submission_id": str(disposition.submission_id),
        "reason_code": disposition.reason_code,
        "created_at": _timestamp(disposition.created_at),
    }
