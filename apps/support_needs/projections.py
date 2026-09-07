"""Fixed JSON projection boundary for the support_needs domain.

Only named projection functions with explicit allowlists may be added here.
Raw model instances, QuerySets, encrypted fields, secrets, and arbitrary
metadata must not be returned to a client.
"""

from __future__ import annotations

from apps.common.contracts import to_json_object


# Exact allowlists; anything not listed here never crosses the API boundary.
_RECORD_KEYS = (
    "support_need_id",
    "student_profile_id",
    "type_key",
    "type_label",
    "type_category",
    "status",
    "source_type",
    "source_snapshot_label",
    "effective_from",
    "effective_until",
    "review_due_at",
    "verified_at",
    "disputed_at",
    "archived_at",
)

_TYPE_KEYS = (
    "key",
    "label",
    "category",
    "is_active",
)

_SAFE_METADATA_KEYS = ("review_code", "needs_review_reason", "dispute_reason")


def project_support_need(record) -> dict:
    """Scoped safe metadata projection.

    Never includes student number/control number, email, phone, employee
    data, actor relations, raw Inventory provenance payloads, encrypted
    fields, narrative content, or arbitrary JSON metadata.
    """

    payload = {
        "support_need_id": str(record.pk),
        "student_profile_id": str(record.student_profile_id),
        "type_key": record.support_need_type.key,
        "type_label": record.support_need_type.label,
        "type_category": record.support_need_type.category,
        "status": record.status,
        "source_type": record.source_type,
        # Safe source label only: the bounded operational label, never a
        # provenance payload.
        "source_snapshot_label": record.source_snapshot_label,
        "effective_from": record.effective_from,
        "effective_until": record.effective_until,
        "review_due_at": record.review_due_at,
        "verified_at": record.verified_at,
        "disputed_at": record.disputed_at,
        "archived_at": record.archived_at,
    }
    for key in _SAFE_METADATA_KEYS:
        value = (record.metadata_json or {}).get(key)
        if isinstance(value, str):
            payload[key] = value
    return to_json_object(payload)


def project_support_need_summary(record) -> dict:
    """Bounded list-row projection; identical allowlist to the detail view."""

    return project_support_need(record)


def project_support_need_type(support_need_type) -> dict:
    """Active controlled type catalog row."""

    return to_json_object({
        "key": support_need_type.key,
        "label": support_need_type.label,
        "category": support_need_type.category,
        "is_active": bool(support_need_type.is_active),
    })


def replay_support_need(record_id) -> dict | None:
    """Safe idempotent-replay projection; identity fields only."""

    from apps.support_needs.models import StudentSupportNeed

    record = (
        StudentSupportNeed.objects.select_related("support_need_type")
        .filter(pk=str(record_id or "").strip())
        .first()
    )
    if record is None:
        return None
    return {
        "support_need_id": str(record.pk),
        "type_key": record.support_need_type.key,
        "status": record.status,
    }
