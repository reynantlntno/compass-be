"""Fixed JSON projection boundary for the inventory domain.

Only named projection functions with explicit allowlists may be added here.
Raw model instances, QuerySets, encrypted fields, secrets, and arbitrary
metadata must not be returned to a client.
"""

from __future__ import annotations

from apps.common.contracts import to_json_object
from apps.inventory.models import InventoryStatusChoices


# Exact allowlists; anything not listed here never crosses the API boundary.
_OWNER_SNAPSHOT_KEYS = (
    "snapshot_id",
    "academic_year",
    "schema_key",
    "schema_version",
    "status",
    "submitted_at",
    "reopened_at",
    "updated_at",
)

_STAFF_SNAPSHOT_KEYS = (
    "snapshot_id",
    "academic_year",
    "schema_version",
    "status",
    "submitted_at",
    "reopened_at",
    "student_profile_id",
)

_HISTORY_KEYS = (
    "history_id",
    "status_from",
    "status_to",
    "transitioned_at",
    "submission_sequence",
    "is_baseline",
    "schema_version",
)


def _bounded_row(instance, keys):
    payload = {}
    for key in keys:
        value = getattr(instance, key, None)
        if hasattr(value, "isoformat"):
            value = value.isoformat()
        elif value is not None and not isinstance(value, (str, int, float, bool)):
            value = str(value)
        payload[key] = value
    return to_json_object(payload)


def _snapshot_row(snapshot, keys):
    payload = _bounded_row(snapshot, keys)
    payload["snapshot_id"] = str(snapshot.pk)
    return payload


def project_owner_snapshot(snapshot, *, answers: dict | None = None) -> dict:
    """Owner projection: current validated answer object plus safe metadata.

    ``answers`` must come from the encryption reader; it is embedded only for
    the owner's own snapshot.
    """

    payload = _snapshot_row(snapshot, _OWNER_SNAPSHOT_KEYS)
    if answers is not None:
        payload["answers"] = to_json_object(answers)
    return payload


def project_staff_snapshot(snapshot, *, submitted_answers: dict | None = None) -> dict:
    """Counselor/Head projection.

    Submitted-answer bodies are included only when the caller resolved them
    through the policy-approved submitted path.  Drafts and reopened answer
    bodies are never projected here.
    """

    payload = _snapshot_row(snapshot, _STAFF_SNAPSHOT_KEYS)
    if submitted_answers is not None:
        payload["answers"] = to_json_object(submitted_answers)
    return payload


def project_snapshot_summary(snapshot) -> dict:
    """Bounded list-row projection shared by every listing surface."""

    return _snapshot_row(snapshot, _STAFF_SNAPSHOT_KEYS)


def project_history_event(history) -> dict:
    """Status/provenance history row.

    Never includes submitted historical answer payloads, encrypted fields,
    or correction narratives.
    """

    payload = _bounded_row(history, _HISTORY_KEYS)
    payload["history_id"] = str(history.pk)
    return payload


def staff_answer_projection_allowed(status: str) -> bool:
    """Only submitted snapshots may expose answer bodies to staff."""

    return status == InventoryStatusChoices.SUBMITTED
