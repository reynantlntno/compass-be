"""Authorized staged migration target for legacy contact message plaintext."""

from apps.content.models import PublicContactSubmission
from apps.security.field_operations import (
    FieldOperationTarget,
    register_target,
    registered_targets,
)


TARGET_SPECS = (
    (
        "content.contact_submission.message_body.backfill",
        "message_body",
        "message_body_encrypted",
        "text",
    ),
)


def register_content_encryption_targets():
    existing = {target.identifier: target for target in registered_targets()}
    registered = []
    for identifier, source, destination, payload_type in TARGET_SPECS:
        target = FieldOperationTarget(
            identifier=identifier,
            model=PublicContactSubmission,
            source_field=source,
            destination_field=destination,
            payload_type=payload_type,
            invalid_row_policy="STOP",
            allowed_operations=frozenset({"backfill", "rotation", "verify"}),
        )
        current = existing.get(identifier)
        if current is not None:
            if current != target:
                raise ValueError("Conflicting content encryption target registration.")
            registered.append(current)
            continue
        registered.append(register_target(target))
    return tuple(registered)
