"""Audited, projection-only application-error diagnostic services."""

from apps.audit.services import audit_log
from apps.system.projections import project_application_error_event
from apps.system.selectors import (
    get_application_error_event_by_error_id,
    get_application_error_events_visible_to,
)


def get_application_error_diagnostics_visible_to(
    actor,
    *,
    unresolved_only: bool = False,
    category: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """Return bounded diagnostic dictionaries for an authorized IT Admin."""
    return [
        projection
        for event in get_application_error_events_visible_to(
            actor,
            unresolved_only=unresolved_only,
            category=category,
            limit=limit,
        )
        if (projection := project_application_error_event(actor, event)) is not None
    ]


def get_application_error_diagnostic_by_error_id(actor, error_id: str) -> dict | None:
    """Return and audit one bounded diagnostic dictionary, or ``None``."""
    event = get_application_error_event_by_error_id(actor, error_id)
    projection = project_application_error_event(actor, event)
    if projection is None:
        return None

    audit_log(
        action_type="SYSTEM_ERROR_DIAGNOSTIC_VIEW",
        event_category="SYSTEM",
        severity="INFO",
        target_model="system.ApplicationErrorEvent",
        target_object_id=str(event.pk),
        actor_user=actor,
        reference_code=event.error_id,
        source_app="system",
        source_view="get_application_error_diagnostic_by_error_id",
        metadata={
            "error_id": event.error_id,
            "fingerprint": projection["fingerprint"],
        },
    )
    return projection
