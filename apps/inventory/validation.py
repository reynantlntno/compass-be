"""Validation helpers for safe Inventory correction workflow input."""

from __future__ import annotations

import math

from apps.common.exceptions import ValidationError


MIN_CORRECTION_REASON_LENGTH = 10
MAX_CORRECTION_REASON_LENGTH = 500

# The validated questionnaire answer object is the only flexible JSON accepted
# at this domain boundary.  It shares the confidential storage byte budget.
MAX_ANSWER_JSON_BYTES = 1_048_576


def normalize_correction_reason(value: str) -> str:
    """Return a bounded, single-line, student-safe correction reason.

    The reason is operational guidance, not an Inventory answer.  It is stored
    encrypted and is never copied into generic audit or notification payloads.
    """

    if not isinstance(value, str):
        raise ValueError("A correction reason is required.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("Correction reason must not contain control characters.")
    normalized = " ".join(value.split())
    if len(normalized) < MIN_CORRECTION_REASON_LENGTH:
        raise ValueError("Correction reason must be at least 10 characters.")
    if len(normalized) > MAX_CORRECTION_REASON_LENGTH:
        raise ValueError("Correction reason must be 500 characters or fewer.")
    return normalized


def _validate_answer_json(value, active=None) -> None:
    """Recursive content-free JSON rules mirroring the storage boundary."""

    value_type = type(value)
    if value_type in {str, int, bool, type(None)}:
        return
    if value_type is float:
        if not math.isfinite(value):
            raise ValidationError("Inventory answers contain an invalid number.")
        return
    if value_type not in {dict, list}:
        raise ValidationError(
            "Inventory answers must contain JSON values only."
        )
    active = active if active is not None else set()
    identity = id(value)
    if identity in active:
        raise ValidationError("Inventory answers contain cyclic structure.")
    active.add(identity)
    try:
        if value_type is dict:
            for key, child in value.items():
                if type(key) is not str:
                    raise ValidationError("Inventory answer keys must be strings.")
                _validate_answer_json(child, active)
        else:
            for child in value:
                _validate_answer_json(child, active)
    finally:
        active.remove(identity)


def validate_inventory_answers(value) -> dict:
    """Validate the single allowed flexible payload: the answer object.

    Rules enforced here (fail closed, content-free errors):
    - exactly one plain ``dict`` (model instances, mappings such as
      ``MappingProxyType``, lists, and scalars are rejected);
    - top-level keys are restricted to the documented Inventory sections;
    - recursive plain-JSON rules (string keys, finite numbers, no cycles);
    - the serialized object fits the confidential storage byte budget.
    """

    from apps.inventory.models import INVENTORY_SECTIONS
    from apps.security.field_encryption import canonical_json

    if type(value) is not dict:
        raise ValidationError("Inventory answers must be a single JSON object.")
    unknown_sections = sorted(str(key) for key in value if key not in INVENTORY_SECTIONS)
    if unknown_sections:
        raise ValidationError(
            "Inventory answers contain an unsupported form section.",
            field_errors={"answers": ["Unsupported section: unknown keys are rejected."]},
        )
    _validate_answer_json(value)
    try:
        serialized_size = len(canonical_json(value).encode("utf-8"))
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise ValidationError("Inventory answers must be serializable JSON.") from None
    if serialized_size > MAX_ANSWER_JSON_BYTES:
        raise ValidationError("Inventory answers exceed the maximum allowed size.")
    return value
