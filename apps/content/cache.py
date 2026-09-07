"""Read-through cache for institution-wide public content only."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from django.utils.dateparse import parse_datetime

from apps.common.cache.backend import cached_read
from apps.common.cache.invalidation import invalidate_after_commit
from apps.content.projections import project_public_content_item, project_public_page


def _soonest_expiry(value: Any):
    if not isinstance(value, list):
        return None
    dates = []
    for item in value:
        if isinstance(item, dict) and item.get("publish_end"):
            parsed = parse_datetime(str(item["publish_end"]))
            if parsed:
                dates.append(parsed)
    return min(dates) if dates else None


def get_cached_public_announcements(*, limit: int | None = None) -> list[dict]:
    def load():
        from apps.content.selectors import _populate_public_html, get_published_announcements

        return [
            projected
            for row in get_published_announcements()
            if (projected := project_public_content_item(_populate_public_html(row))) is not None
        ]

    values = cached_read(
        "content_public",
        "institution",
        ("announcements",),
        load,
        expires_at=_soonest_expiry,
    )
    return values[:limit] if limit is not None else values


def get_cached_public_resources(*, limit: int | None = None) -> list[dict]:
    def load():
        from apps.content.selectors import _populate_public_html, get_published_resources

        return [
            projected
            for row in get_published_resources()
            if (projected := project_public_content_item(_populate_public_html(row))) is not None
        ]

    values = cached_read(
        "content_public",
        "institution",
        ("resources",),
        load,
        expires_at=_soonest_expiry,
    )
    return values[:limit] if limit is not None else values


def get_cached_public_page(page_key: str) -> dict | None:
    def load():
        from apps.content.selectors import get_published_content_page

        page = get_published_content_page(page_key)
        return project_public_page(page)

    return cached_read("content_public", "institution", ("page", page_key), load)


def get_cached_public_service_guide() -> dict:
    def load():
        from apps.content.service_guide import get_public_service_guide_context

        return get_public_service_guide_context()

    return cached_read("content_public", "institution", ("service-guide",), load)


def get_cached_public_announcement_by_slug(slug: str) -> dict | None:
    return next((item for item in get_cached_public_announcements() if item.get("slug") == slug), None)


def get_cached_public_resource_by_slug(slug: str) -> dict | None:
    return next((item for item in get_cached_public_resources() if item.get("slug") == slug), None)


def invalidate_public_content_after_commit() -> None:
    invalidate_after_commit("content_public", "institution")
