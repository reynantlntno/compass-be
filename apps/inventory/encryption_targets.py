"""Temporary source-backed inventory targets for Release 1 only."""

from apps.inventory.models import StudentInventorySnapshot
from apps.security.exceptions import FieldEncryptionUnknownTarget
from apps.security.field_operations import (
    FieldOperationTarget,
    register_target,
    registered_targets,
)


TARGET_SPECS = (
    ("inventory.snapshot.data.backfill", "data", "data_encrypted", "json"),
    (
        "inventory.snapshot.reopen_reason.backfill",
        "reopen_reason",
        "reopen_reason_encrypted",
        "text",
    ),
    (
        "inventory.snapshot.correction_notes.backfill",
        "correction_notes",
        "correction_notes_encrypted",
        "text",
    ),
)


def register_inventory_encryption_targets():
    existing = {target.identifier: target for target in registered_targets()}
    registered = []
    for identifier, source, destination, payload_type in TARGET_SPECS:
        target = FieldOperationTarget(
            identifier=identifier,
            model=StudentInventorySnapshot,
            source_field=source,
            destination_field=destination,
            payload_type=payload_type,
            invalid_row_policy="STOP",
            allowed_operations=frozenset({"backfill", "rotation", "verify"}),
        )
        current = existing.get(identifier)
        if current is not None:
            if current != target:
                raise FieldEncryptionUnknownTarget()
            registered.append(current)
            continue
        registered.append(register_target(target))
    return tuple(registered)
