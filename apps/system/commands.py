"""Framework-neutral commands for system operations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from apps.common.exceptions import ValidationError
from apps.common.form_values import (
    normalize_command_id,
    normalize_command_text,
    normalize_expected_updated_at,
)


class CommandInput(Protocol):
    """Marker protocol for immutable, validated system commands."""


def _text(value, field: str, *, maximum: int = 255, required: bool = False) -> str:
    return normalize_command_text(value, field, maximum=maximum, required=required)


@dataclass(frozen=True, slots=True)
class HealthCheckCommand:
    component: str = "all"

    def __post_init__(self) -> None:
        value = _text(self.component, "component", maximum=80, required=True).lower()
        if value != "all" and not value.replace("_", "").isalnum():
            raise ValidationError(field_errors={"component": ["Unsupported health component."]})
        object.__setattr__(self, "component", value)


@dataclass(frozen=True, slots=True)
class DiagnosticTransitionCommand:
    error_id: str
    note: str = ""
    expected_updated_at: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "error_id", normalize_command_id(self.error_id, "error_id", required=True))
        object.__setattr__(self, "note", _text(self.note, "note", maximum=255))
        object.__setattr__(self, "expected_updated_at", normalize_expected_updated_at(self.expected_updated_at))


@dataclass(frozen=True, slots=True)
class MaintenanceScheduleCommand:
    starts_at: str
    ends_at: str
    public_message: str = ""
    reason_code: str = "scheduled_maintenance"

    def __post_init__(self) -> None:
        object.__setattr__(self, "starts_at", _text(self.starts_at, "starts_at", maximum=40, required=True))
        object.__setattr__(self, "ends_at", _text(self.ends_at, "ends_at", maximum=40, required=True))
        object.__setattr__(self, "public_message", _text(self.public_message, "public_message", maximum=1000))
        object.__setattr__(self, "reason_code", _text(self.reason_code, "reason_code", maximum=100, required=True))


@dataclass(frozen=True, slots=True)
class MaintenanceTransitionCommand:
    window_id: str
    expected_updated_at: str | None = None
    ends_at: str | None = None
    reason_code: str = "maintenance_operation"

    def __post_init__(self) -> None:
        object.__setattr__(self, "window_id", normalize_command_id(self.window_id, "window_id", required=True))
        object.__setattr__(self, "expected_updated_at", normalize_expected_updated_at(self.expected_updated_at))
        if self.ends_at is not None:
            object.__setattr__(self, "ends_at", _text(self.ends_at, "ends_at", maximum=40, required=True))
        object.__setattr__(self, "reason_code", _text(self.reason_code, "reason_code", maximum=100, required=True))


@dataclass(frozen=True, slots=True)
class OperationalCommandQuery:
    command_key: str
    mode: str = "read_only"
    reason_code: str = "operator_requested"

    def __post_init__(self) -> None:
        object.__setattr__(self, "command_key", _text(self.command_key, "command_key", maximum=100, required=True))
        object.__setattr__(self, "mode", _text(self.mode, "mode", maximum=20, required=True))
        object.__setattr__(self, "reason_code", _text(self.reason_code, "reason_code", maximum=100, required=True))
