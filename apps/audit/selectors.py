"""Scope-aware ORM selectors for the Audit Viewer."""

from __future__ import annotations

from django.db import models

from apps.audit.models import AuditLogEntry
from apps.audit.policies import audit_visibility_query, authorized_planes
from apps.audit.queries import AuditQuery


def get_audit_entries_visible_to(
    actor,
    query: AuditQuery | None = None,
    *,
    plane=None,
) -> models.QuerySet:
    """Return only rows belonging to the actor's currently allowed planes."""

    planes = authorized_planes(actor, plane)
    if not planes:
        return AuditLogEntry.objects.none()

    queryset = (
        AuditLogEntry.objects.filter(audit_visibility_query(planes))
        .only(
            "id",
            "actor_user_id",
            "actor_role",
            "action_type",
            "event_category",
            "severity",
            "target_model",
            "target_object_id",
            "reference_code",
            "request_id",
            "trace_id",
            "source_app",
            "safe_metadata",
            "created_at",
        )
        .order_by("-created_at", "-id")
    )
    if query is None:
        return queryset
    if query.event_category:
        queryset = queryset.filter(event_category=query.event_category)
    if query.action_type:
        queryset = queryset.filter(action_type=query.action_type)
    if query.severity:
        queryset = queryset.filter(severity=query.severity)
    if query.source_app:
        queryset = queryset.filter(source_app=query.source_app)
    if query.target_model:
        queryset = queryset.filter(target_model=query.target_model)
    if query.created_from:
        queryset = queryset.filter(created_at__gte=query.created_from)
    if query.created_until:
        queryset = queryset.filter(created_at__lte=query.created_until)
    if query.request_id:
        queryset = queryset.filter(request_id=query.request_id)
    if query.trace_id:
        queryset = queryset.filter(trace_id=query.trace_id)
    return queryset


def get_audit_entry_for_actor(actor, entry_id, *, plane=None) -> AuditLogEntry | None:
    try:
        entry_id = int(entry_id)
    except (TypeError, ValueError):
        return None
    if entry_id < 1:
        return None
    planes = authorized_planes(actor, plane)
    if not planes:
        return None
    return (
        AuditLogEntry.objects
        .filter(audit_visibility_query(planes), pk=entry_id)
        .only(
            "id",
            "actor_user_id",
            "actor_role",
            "action_type",
            "event_category",
            "severity",
            "target_model",
            "target_object_id",
            "reference_code",
            "request_id",
            "trace_id",
            "source_app",
            "safe_metadata",
            "created_at",
        )
        .first()
    )
