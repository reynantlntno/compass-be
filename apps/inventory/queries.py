"""Actor-aware query boundary for the inventory domain.

Query functions compose an existing scoped selector with a fixed projection
and never return HTTP responses or serialize ORM objects directly.  Staff
callers never receive draft or reopened answer bodies through this boundary.
"""

from __future__ import annotations

from apps.access_control.rules import is_student, owns_student_profile
from apps.common.contracts import PageRequest, page_queryset
from apps.inventory.encryption import InventoryEncryptionError, read_confidential_snapshot
from apps.inventory.models import (
    InventoryStatusChoices,
    StudentInventorySnapshot,
    StudentInventoryStatusHistory,
)
from apps.inventory.policies import can_view_submitted_inventory
from apps.inventory.projections import (
    project_history_event,
    project_owner_snapshot,
    project_staff_snapshot,
    staff_answer_projection_allowed,
)
from apps.inventory.selectors import get_inventory_snapshots_visible_to
from apps.common.exceptions import ValidationError


_LIST_FIELDS = (
    "id",
    "academic_year",
    "schema_version",
    "status",
    "submitted_at",
    "reopened_at",
    "updated_at",
    "student_profile_id",
)


def _visible_ordered(actor):
    queryset = (
        get_inventory_snapshots_visible_to(actor)
        .select_related("student_profile", "student_profile__user")
        .only(*_LIST_FIELDS, "student_profile__id", "student_profile__user_id")
        .order_by("-updated_at", "-pk")
    )
    if not is_student(actor):
        queryset = queryset.filter(
            status__in=(
                InventoryStatusChoices.SUBMITTED,
                InventoryStatusChoices.REOPENED_FOR_CORRECTION,
            )
        )
    return queryset


def _read_answers_or_fail(snapshot):
    try:
        return read_confidential_snapshot(snapshot).data
    except InventoryEncryptionError:
        raise ValidationError("Inventory confidential data is unavailable.") from None


def scoped_snapshot_page(actor, page: PageRequest | None = None) -> dict:
    """Return the actor-scoped inventory list as a bounded projection page."""

    snapshots = _visible_ordered(actor)
    return page_queryset(
        snapshots,
        page or PageRequest(),
        project_staff_snapshot,
    )


def snapshot_detail(actor, snapshot_id) -> dict | None:
    """Return one snapshot projection according to the caller's authority.

    - The student owner receives the full current answer projection.
    - An in-scope counselor/Head receives submitted answers only; drafts and
      reopened answer bodies are never exposed to staff.
    """

    normalized = str(snapshot_id or "").strip()
    if not normalized:
        return None
    snapshot = (
        get_inventory_snapshots_visible_to(actor)
        .select_related("student_profile", "student_profile__user")
        .filter(pk=normalized)
        .first()
    )
    if snapshot is None:
        return None

    if owns_student_profile(actor, snapshot.student_profile):
        return project_owner_snapshot(snapshot, answers=_read_answers_or_fail(snapshot))

    if staff_answer_projection_allowed(snapshot.status) and can_view_submitted_inventory(
        actor, snapshot
    ):
        return project_staff_snapshot(
            snapshot, submitted_answers=_read_answers_or_fail(snapshot)
        )
    return project_staff_snapshot(snapshot)


def history_page(actor, snapshot_id, page: PageRequest | None = None) -> dict | None:
    """Status/provenance history only; never answer payloads or narratives."""

    normalized = str(snapshot_id or "").strip()
    if not normalized:
        return None
    snapshot = get_inventory_snapshots_visible_to(actor).filter(pk=normalized).first()
    if snapshot is None:
        return None
    rows = (
        StudentInventoryStatusHistory.objects.filter(snapshot=snapshot)
        .only("id", "from_status", "to_status", "transitioned_at", "submission_sequence",
              "is_baseline", "schema_version")
        .order_by("-transitioned_at", "-pk")
    )
    return page_queryset(
        rows,
        page or PageRequest(),
        project_history_event,
    )


def replay_snapshot(snapshot_id) -> dict | None:
    """Safe idempotent-replay projection; identity fields only."""

    snapshot = StudentInventorySnapshot.objects.filter(
        pk=str(snapshot_id or "").strip()
    ).only(*_LIST_FIELDS).first()
    if snapshot is None:
        return None
    return {
        "snapshot_id": str(snapshot.pk),
        "academic_year": snapshot.academic_year,
        "status": snapshot.status,
    }
