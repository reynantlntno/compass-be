"""Internal ORM selectors for application-error diagnostics.

These functions return model rows only for internal diagnostic services. They
must not be serialized directly; use ``apps.system.projections`` through the
diagnostic service boundary instead.
"""

from apps.system.models import ApplicationErrorEvent
from apps.system.policies import (
    can_list_application_error_events,
    can_view_application_error_event,
)


DEFAULT_DIAGNOSTIC_LIMIT = 100
MAX_DIAGNOSTIC_LIMIT = 100


def _normalize_limit(limit) -> int:
    try:
        value = int(limit)
    except (TypeError, ValueError):
        value = DEFAULT_DIAGNOSTIC_LIMIT
    return min(max(value, 0), MAX_DIAGNOSTIC_LIMIT)


def get_application_error_events_visible_to(
    actor,
    *,
    unresolved_only: bool = False,
    category: str | None = None,
    limit: int = DEFAULT_DIAGNOSTIC_LIMIT,
):
    """Return the internal IT Admin-only application-error query source."""
    if not can_list_application_error_events(actor):
        return ApplicationErrorEvent.objects.none()

    queryset = ApplicationErrorEvent.objects.all().order_by("-created_at", "-pk")
    if unresolved_only:
        queryset = queryset.filter(is_resolved=False)
    if category:
        queryset = queryset.filter(category=category)
    return queryset[: _normalize_limit(limit)]


def get_application_error_event_by_error_id(actor, error_id: str):
    """Return one internal event row after the IT Admin policy check."""
    if not error_id or not can_view_application_error_event(actor, None):
        return None
    try:
        event = ApplicationErrorEvent.objects.get(error_id=error_id)
    except ApplicationErrorEvent.DoesNotExist:
        return None
    if not can_view_application_error_event(actor, event):
        return None
    return event
