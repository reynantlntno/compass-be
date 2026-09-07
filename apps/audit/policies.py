"""Authorization and visibility planes for the Audit Viewer.

The audit writer is intentionally broader than this reader.  A viewer may
only see the event categories belonging to an authority plane that is active
for the current actor.
"""

from __future__ import annotations

from enum import StrEnum

from django.db.models import Q

from apps.access_control.authority import has_fixed_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import (
    is_active_nonlegacy_actor,
    is_head_guidance,
    is_it_admin,
)
from apps.common.exceptions import PermissionDeniedError, ValidationError


class AuditPlane(StrEnum):
    TECHNICAL = "technical"
    BUSINESS = "business"
    PRIVACY = "privacy"


def authorized_planes(actor, requested_plane: AuditPlane | str | None = None) -> frozenset[AuditPlane]:
    """Return the actor's planes, optionally narrowed to one authorized plane."""

    planes = viewer_planes(actor)
    if requested_plane is None:
        return planes
    try:
        plane = requested_plane if isinstance(requested_plane, AuditPlane) else AuditPlane(requested_plane)
    except (TypeError, ValueError) as exc:
        raise ValidationError() from exc
    if plane not in planes:
        raise PermissionDeniedError()
    return frozenset({plane})


_TECHNICAL_CATEGORIES = frozenset({
    "SECURITY",
    "SYSTEM",
    "AUTHORIZATION",
    "TOKEN_BATCH",
})
_BUSINESS_CATEGORIES = frozenset({
    "WORKFLOW",
    "CONTENT",
    "FORM",
    "FORM_COLLECTION",
    "UNLINKED_FORM_SUBMISSION",
    "GOVERNANCE",
    "AUTHORIZATION",
})
_PRIVACY_CATEGORIES = frozenset({
    "PRIVACY",
    "PRIVACY_GOVERNANCE",
    "DATA_ACCESS",
})
_DPO_GOVERNANCE_PREFIXES = (
    "DPO_",
    "PRIVACY_REVIEWER_",
    "PRIVACY_NOTICE_",
)


def viewer_planes(actor) -> frozenset[AuditPlane]:
    """Return all currently valid planes for one active actor."""

    if not is_active_nonlegacy_actor(actor):
        return frozenset()
    planes: set[AuditPlane] = set()
    if is_it_admin(actor) and has_fixed_capability(actor, Capability.AUDIT_VIEW):
        planes.add(AuditPlane.TECHNICAL)
    if is_head_guidance(actor) and has_fixed_capability(actor, Capability.AUDIT_VIEW):
        planes.add(AuditPlane.BUSINESS)
    if is_current_dpo(actor):
        planes.add(AuditPlane.PRIVACY)
    return frozenset(planes)


def is_current_dpo(actor) -> bool:
    """Resolve the DPO relationship without turning it into a role."""

    from apps.governance.dpo_services import is_current_dpo as governance_is_current_dpo

    return governance_is_current_dpo(actor)


def can_view_audit(actor) -> bool:
    return bool(viewer_planes(actor))


def _business_action_allowed(action_type: str) -> bool:
    return not str(action_type or "").startswith(_DPO_GOVERNANCE_PREFIXES)


def _privacy_action_allowed(action_type: str) -> bool:
    return str(action_type or "").startswith(_DPO_GOVERNANCE_PREFIXES)


def event_allowed_for_planes(
    planes: frozenset[AuditPlane],
    *,
    event_category: str,
    action_type: str = "",
) -> bool:
    """Apply category and governance-action containment for a viewer."""

    category = str(event_category or "")
    action = str(action_type or "")
    if AuditPlane.TECHNICAL in planes and category in _TECHNICAL_CATEGORIES:
        return True
    if AuditPlane.BUSINESS in planes and category in _BUSINESS_CATEGORIES:
        if category != "GOVERNANCE" or _business_action_allowed(action):
            return True
    if AuditPlane.PRIVACY in planes:
        if category in _PRIVACY_CATEGORIES:
            return True
        if category == "GOVERNANCE" and _privacy_action_allowed(action):
            return True
    return False


def allowed_event_categories(planes: frozenset[AuditPlane]) -> frozenset[str]:
    categories: set[str] = set()
    if AuditPlane.TECHNICAL in planes:
        categories.update(_TECHNICAL_CATEGORIES)
    if AuditPlane.BUSINESS in planes:
        categories.update(_BUSINESS_CATEGORIES)
    if AuditPlane.PRIVACY in planes:
        categories.update(_PRIVACY_CATEGORIES)
        categories.add("GOVERNANCE")
    return frozenset(categories)


def audit_visibility_query(planes: frozenset[AuditPlane]) -> Q:
    """Build the database-side category/action predicate for the planes."""

    predicate = Q(pk__in=[])
    dpo_governance_actions = Q(pk__in=[])
    for prefix in _DPO_GOVERNANCE_PREFIXES:
        dpo_governance_actions |= Q(action_type__startswith=prefix)
    if AuditPlane.TECHNICAL in planes:
        predicate |= Q(event_category__in=_TECHNICAL_CATEGORIES)
    if AuditPlane.BUSINESS in planes:
        predicate |= Q(event_category__in=_BUSINESS_CATEGORIES - {"GOVERNANCE"})
        predicate |= Q(
            event_category="GOVERNANCE",
        ) & ~dpo_governance_actions
    if AuditPlane.PRIVACY in planes:
        predicate |= Q(event_category__in=_PRIVACY_CATEGORIES)
        for prefix in _DPO_GOVERNANCE_PREFIXES:
            predicate |= Q(event_category="GOVERNANCE", action_type__startswith=prefix)
    return predicate


def can_view_audit_entry(actor, entry, *, plane: AuditPlane | str | None = None) -> bool:
    if entry is None:
        return False
    planes = authorized_planes(actor, plane)
    return event_allowed_for_planes(
        planes,
        event_category=entry.event_category,
        action_type=entry.action_type,
    )


def query_category_allowed(actor, category: str) -> bool:
    planes = viewer_planes(actor)
    if not planes:
        return False
    # Category-only filtering cannot bypass the governance action-prefix
    # predicate; a broad GOVERNANCE query is allowed but remains narrowed by
    # audit_visibility_query at the database boundary.
    return category in allowed_event_categories(planes)
