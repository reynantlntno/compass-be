"""Frozen typed commands for the inventory domain.

Commands are the only mutation input accepted by inventory services.  They
reject model instances, arbitrary mappings, unsupported lifecycle fields, and
unknown keywords; services additionally revalidate every command type.
"""

import datetime
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from apps.common.exceptions import ValidationError
from apps.inventory.validation import (
    normalize_correction_reason,
    validate_inventory_answers,
)


def _validated_academic_year(value) -> str:
    if not isinstance(value, str):
        raise ValidationError("Academic year must be explicitly provided.")
    normalized = value.strip()
    if not normalized:
        raise ValidationError("Academic year must be explicitly provided.")
    return normalized


def _validated_expected_updated_at(value) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str) or len(value) > 40:
        raise ValidationError("The expected updated timestamp is invalid.")
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValidationError("The expected updated timestamp is invalid.") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValidationError("The expected updated timestamp must include a timezone.")
    return value


@dataclass(frozen=True)
class InventoryDraftCommand:
    """Validated questionnaire JSON; arbitrary keys are rejected upstream."""

    answers: Mapping[str, Any]
    expected_updated_at: str | None = None

    def __post_init__(self):
        object.__setattr__(
            self, "answers", MappingProxyType(dict(validate_inventory_answers(self.answers)))
        )
        object.__setattr__(
            self,
            "expected_updated_at",
            _validated_expected_updated_at(self.expected_updated_at),
        )


@dataclass(frozen=True)
class InventoryDraftCreateCommand:
    """Create or retrieve the student's draft for one academic year."""

    academic_year: str

    def __post_init__(self):
        object.__setattr__(
            self, "academic_year", _validated_academic_year(self.academic_year)
        )


@dataclass(frozen=True)
class InventorySubmitCommand:
    """Submit a draft with an explicit privacy acknowledgement."""

    privacy_acknowledged: bool = False
    expected_updated_at: str | None = None

    def __post_init__(self):
        if not isinstance(self.privacy_acknowledged, bool):
            raise ValidationError(
                "The Individual Inventory privacy acknowledgement must be explicit."
            )
        object.__setattr__(
            self,
            "expected_updated_at",
            _validated_expected_updated_at(self.expected_updated_at),
        )


@dataclass(frozen=True)
class InventoryReopenCommand:
    """Reopen a submitted snapshot with an encrypted operational reason."""

    reason: str
    expected_state_token: str = ""

    def __post_init__(self):
        try:
            object.__setattr__(self, "reason", normalize_correction_reason(self.reason))
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc
        if self.expected_state_token is None:
            object.__setattr__(self, "expected_state_token", "")
        elif not isinstance(self.expected_state_token, str) or len(self.expected_state_token) > 512:
            raise ValidationError("The correction state token is invalid.")
