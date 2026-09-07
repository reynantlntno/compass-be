"""Shared, bounded value objects for revision-backed form commands.

This module contains validation mechanics only.  Form Collection owns
invitation and collection workflows; response domains own their response
lifecycle and use these values without importing one another's commands.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from apps.common.contracts import to_json_object
from apps.common.exceptions import ValidationError


MAX_COMMAND_ID = 64
MAX_COMMAND_TEXT = 500
MAX_COMMAND_NOTE = 1000
MAX_ANSWER_BYTES = 256 * 1024


def normalize_command_text(
    value,
    field: str,
    *,
    maximum: int = MAX_COMMAND_TEXT,
    required: bool = False,
) -> str:
    if value is not None and not isinstance(value, str):
        raise ValidationError(f"{field} must be a string.")
    normalized = "" if value is None else value.strip()
    if required and not normalized:
        raise ValidationError(f"{field} is required.")
    if len(normalized) > maximum:
        raise ValidationError(f"{field} is too long.")
    return normalized


def normalize_command_id(value, field: str, *, required: bool = False) -> str | None:
    if value in (None, ""):
        if required:
            raise ValidationError(f"{field} is required.")
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValidationError(f"{field} is invalid.")
    normalized = str(value).strip()
    if not normalized or len(normalized) > MAX_COMMAND_ID or any(char.isspace() for char in normalized):
        raise ValidationError(f"{field} is invalid.")
    return normalized


def normalize_expected_updated_at(value):
    if value in (None, ""):
        return None
    if not isinstance(value, str) or len(value) > 40:
        raise ValidationError("expected_updated_at is invalid.")
    return value


def validated_json_mapping(
    value,
    field: str,
    *,
    maximum_bytes: int = MAX_ANSWER_BYTES,
) -> MappingProxyType:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{field} must be an object.")
    try:
        converted = to_json_object(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{field} contains unsupported values.") from exc
    if len(str(converted).encode("utf-8")) > maximum_bytes:
        raise ValidationError(f"{field} is too large.")
    return MappingProxyType(converted)


@dataclass(frozen=True, slots=True)
class ValidatedAnswerSet:
    """Revision-validated JSON answers, never an arbitrary service payload."""

    values: Mapping[str, object]
    form_revision_id: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "form_revision_id",
            normalize_command_id(self.form_revision_id, "form_revision_id", required=True),
        )
        object.__setattr__(self, "values", validated_json_mapping(self.values, "answers"))
