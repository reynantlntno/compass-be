"""Staff-only Individual Inventory queue queries and safe projections."""

from __future__ import annotations

from django.db.models import Q

from apps.access_control.authority import has_capability
from apps.access_control.capabilities import Capability
from apps.access_control.display import safe_student_display_label
from apps.access_control.rules import is_counselor, is_student
from apps.common.contracts import PageRequest, PageResult, to_json_value
from apps.common.exceptions import ValidationError
from apps.inventory.models import InventoryStatusChoices, StudentInventorySnapshot
from apps.inventory.policies import can_view_submitted_inventory
from apps.inventory.selectors import get_inventory_snapshots_visible_to


QUEUE_STATUSES = frozenset(
    {
        InventoryStatusChoices.SUBMITTED,
        InventoryStatusChoices.REOPENED_FOR_CORRECTION,
    }
)
QUEUE_ORDERS = frozenset({"recent", "oldest"})
MAX_QUERY_LENGTH = 120
MAX_FILTER_LENGTH = 100


def _clean(value: str | None, *, limit: int = MAX_FILTER_LENGTH) -> str:
    value = " ".join(str(value or "").split()).strip()
    if len(value) > limit:
        raise ValidationError()
    return value


def _statuses(value: str | None) -> tuple[str, ...]:
    values = tuple(dict.fromkeys(item.strip().upper() for item in str(value or "").split(",") if item.strip()))
    if any(item not in QUEUE_STATUSES for item in values):
        raise ValidationError()
    return values


def _queue_queryset(actor):
    if is_student(actor) or not is_counselor(actor):
        return StudentInventorySnapshot.objects.none()
    if not has_capability(actor, Capability.INVENTORY_QUEUE_VIEW):
        return StudentInventorySnapshot.objects.none()

    return (
        get_inventory_snapshots_visible_to(actor)
        .filter(status__in=QUEUE_STATUSES)
        .select_related("student_profile", "student_profile__user")
    )


def _project_row(snapshot, actor, *, include_answers: bool = False) -> dict:
    profile = snapshot.student_profile
    payload = {
        "snapshot_id": int(snapshot.pk),
        "student_display_name": safe_student_display_label(profile),
        "student_number": str(profile.student_number).strip()[:50] if profile.student_number else None,
        "academic_year": snapshot.academic_year,
        "schema_key": snapshot.schema_key,
        "schema_version": snapshot.schema_version,
        "status": snapshot.status,
        "submitted_at": to_json_value(snapshot.submitted_at),
        "reopened_at": to_json_value(snapshot.reopened_at),
        "updated_at": to_json_value(snapshot.updated_at),
        "review_state": (
            "Correction review"
            if snapshot.status == InventoryStatusChoices.REOPENED_FOR_CORRECTION
            else "Submitted"
        ),
    }
    if include_answers and snapshot.status == InventoryStatusChoices.SUBMITTED and can_view_submitted_inventory(actor, snapshot):
        from apps.inventory.encryption import InventoryEncryptionError, read_confidential_snapshot

        try:
            payload["answers"] = to_json_value(read_confidential_snapshot(snapshot).data)
        except InventoryEncryptionError:
            payload["answers"] = None
    return payload


def queue_page(
    actor,
    page: PageRequest,
    *,
    query: str | None = None,
    statuses: str | None = None,
    academic_year: str | None = None,
    revision: str | None = None,
    order: str = "recent",
) -> dict[str, object]:
    query = _clean(query, limit=MAX_QUERY_LENGTH)
    academic_year = _clean(academic_year)
    revision = _clean(revision)
    order = _clean(order, limit=20).lower() or "recent"
    if order not in QUEUE_ORDERS:
        raise ValidationError()
    status_values = _statuses(statuses)

    queryset = _queue_queryset(actor)
    if status_values:
        queryset = queryset.filter(status__in=status_values)
    if academic_year:
        queryset = queryset.filter(academic_year=academic_year)
    if revision:
        queryset = queryset.filter(Q(schema_version__iexact=revision) | Q(schema_key__iexact=revision))
    if query:
        queryset = queryset.filter(
            Q(student_profile__student_number__icontains=query)
            | Q(student_profile__user__first_name__icontains=query)
            | Q(student_profile__user__last_name__icontains=query)
        )

    ordering = ("updated_at", "pk") if order == "oldest" else ("-updated_at", "-pk")
    queryset = queryset.order_by(*ordering)
    total = queryset.count()
    rows = queryset[page.offset : page.offset + page.page_size]
    return PageResult(
        items=tuple(_project_row(row, actor) for row in rows),
        page=page.page,
        page_size=page.page_size,
        total=total,
    ).as_dict()


def queue_detail(actor, snapshot_id: int) -> dict | None:
    snapshot = _queue_queryset(actor).filter(pk=snapshot_id).first()
    if snapshot is None:
        return None
    payload = _project_row(snapshot, actor)
    payload.pop("snapshot_id", None)
    return payload


def queue_sensitive_detail(actor, snapshot_id: int) -> dict | None:
    snapshot = _queue_queryset(actor).filter(pk=snapshot_id).first()
    if snapshot is None or snapshot.status != InventoryStatusChoices.SUBMITTED:
        return None
    if not can_view_submitted_inventory(actor, snapshot):
        return None
    payload = _project_row(snapshot, actor, include_answers=True)
    payload.pop("snapshot_id", None)
    return payload
