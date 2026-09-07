"""Single Release 1 boundary for confidential inventory storage access."""

from dataclasses import dataclass
import math

from django.db import transaction

from apps.inventory.checks import validate_inventory_compatibility_settings
from apps.security.field_encryption import canonical_json


MAX_CONFIDENTIAL_BYTES = 1_048_576
CONFIDENTIAL_FIELD_NAMES = (
    "data",
    "data_encrypted",
    "reopen_reason",
    "reopen_reason_encrypted",
    "correction_notes",
    "correction_notes_encrypted",
)


class InventoryEncryptionError(Exception):
    """Content-free inventory storage failure safe for callers and logs."""

    def __init__(self, code="inventory_confidential_state_invalid"):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class InventoryConfidentialValues:
    data: dict
    reopen_reason: str
    correction_notes: str


def _validate_exact_json(value, active=None):
    value_type = type(value)
    if value_type in {str, int, bool, type(None)}:
        return
    if value_type is float:
        if not math.isfinite(value):
            raise InventoryEncryptionError("inventory_confidential_payload_invalid")
        return
    if value_type not in {dict, list}:
        raise InventoryEncryptionError("inventory_confidential_payload_invalid")
    active = active if active is not None else set()
    identity = id(value)
    if identity in active:
        raise InventoryEncryptionError("inventory_confidential_payload_invalid")
    active.add(identity)
    try:
        if value_type is dict:
            for key, child in value.items():
                if type(key) is not str:
                    raise InventoryEncryptionError("inventory_confidential_payload_invalid")
                _validate_exact_json(child, active)
        else:
            for child in value:
                _validate_exact_json(child, active)
    finally:
        active.remove(identity)


def _validate_values(data, reopen_reason, correction_notes):
    if type(data) is not dict or type(reopen_reason) is not str or type(correction_notes) is not str:
        raise InventoryEncryptionError("inventory_confidential_payload_invalid")
    try:
        _validate_exact_json(data)
        data_size = len(canonical_json(data).encode("utf-8"))
        reason_size = len(reopen_reason.encode("utf-8"))
        notes_size = len(correction_notes.encode("utf-8"))
    except Exception:
        raise InventoryEncryptionError("inventory_confidential_payload_invalid") from None
    if max(data_size, reason_size, notes_size) > MAX_CONFIDENTIAL_BYTES:
        raise InventoryEncryptionError("inventory_confidential_payload_too_large")
    return InventoryConfidentialValues(data, reopen_reason, correction_notes)


def validate_confidential_values(data, reopen_reason, correction_notes):
    """Public boundary helper for content-free reconciliation validation."""
    return _validate_values(data, reopen_reason, correction_notes)


def compare_release1_twins(snapshot):
    """Return True only for exact, validated plaintext/encrypted twins."""
    sources = _validate_values(snapshot.data, snapshot.reopen_reason, snapshot.correction_notes)
    destinations = _validate_values(
        snapshot.data_encrypted,
        snapshot.reopen_reason_encrypted,
        snapshot.correction_notes_encrypted,
    )
    return sources == destinations


def read_confidential_snapshot(snapshot):
    """Read all confidential values under the bounded four-state contract."""
    destinations = (
        snapshot.data_encrypted,
        snapshot.reopen_reason_encrypted,
        snapshot.correction_notes_encrypted,
    )
    present = tuple(value is not None for value in destinations)
    if not any(present):
        configuration = validate_inventory_compatibility_settings()
        if not configuration.permits_legacy_fallback:
            raise InventoryEncryptionError(configuration.result_code)
        return _validate_values(snapshot.data, snapshot.reopen_reason, snapshot.correction_notes)
    if not all(present):
        raise InventoryEncryptionError("inventory_confidential_state_transition_mixed")
    destinations = _validate_values(*destinations)
    sources = _validate_values(snapshot.data, snapshot.reopen_reason, snapshot.correction_notes)
    if sources != destinations:
        raise InventoryEncryptionError("inventory_confidential_twin_mismatch")
    return destinations


def validate_snapshot_before_submit(snapshot):
    read_confidential_snapshot(snapshot)
    return snapshot


def _write_all_pairs(snapshot, values):
    snapshot.data = values.data
    snapshot.data_encrypted = values.data
    snapshot.reopen_reason = values.reopen_reason
    snapshot.reopen_reason_encrypted = values.reopen_reason
    snapshot.correction_notes = values.correction_notes
    snapshot.correction_notes_encrypted = values.correction_notes
    snapshot.save(update_fields=list(CONFIDENTIAL_FIELD_NAMES) + ["updated_at"])
    return snapshot


@transaction.atomic
def create_confidential_snapshot(*, student_profile, academic_year, status):
    from apps.inventory.models import StudentInventorySnapshot

    values = _validate_values({}, "", "")
    return StudentInventorySnapshot.objects.create(
        student_profile=student_profile,
        academic_year=academic_year,
        status=status,
        data=values.data,
        data_encrypted=values.data,
        reopen_reason=values.reopen_reason,
        reopen_reason_encrypted=values.reopen_reason,
        correction_notes=values.correction_notes,
        correction_notes_encrypted=values.correction_notes,
    )


def _lock_and_read(snapshot_pk):
    from apps.inventory.models import StudentInventorySnapshot

    snapshot = StudentInventorySnapshot.objects.select_for_update().get(pk=snapshot_pk)
    return snapshot, read_confidential_snapshot(snapshot)


@transaction.atomic
def update_draft_data(snapshot_pk, data):
    from apps.inventory.models import INVENTORY_SCHEMA_VERSION

    snapshot, current = _lock_and_read(snapshot_pk)
    values = _validate_values(data, current.reopen_reason, current.correction_notes)
    snapshot = _write_all_pairs(snapshot, values)
    # A legacy submitted snapshot keeps its historical schema until the
    # student's first correction save.  Reopened/new drafts therefore adopt
    # the current schema only at this explicit write boundary.
    if snapshot.schema_version != INVENTORY_SCHEMA_VERSION:
        snapshot.schema_version = INVENTORY_SCHEMA_VERSION
        snapshot.save(update_fields=["schema_version", "updated_at"])
    return snapshot


@transaction.atomic
def record_reopen_reason(snapshot_pk, reason):
    snapshot, current = _lock_and_read(snapshot_pk)
    values = _validate_values(current.data, reason, current.correction_notes)
    return _write_all_pairs(snapshot, values)


@transaction.atomic
def update_correction_notes(snapshot_pk, notes):
    snapshot, current = _lock_and_read(snapshot_pk)
    values = _validate_values(current.data, current.reopen_reason, notes)
    return _write_all_pairs(snapshot, values)
