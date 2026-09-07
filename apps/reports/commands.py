"""Typed, immutable command boundary for Reports."""

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from apps.common.exceptions import ValidationError


MAX_REPORT_KEY = 100
MAX_FILTER_KEYS = 12
MAX_FILTER_VALUE = 120
MAX_PURPOSE = 500


class CommandInput(Protocol):
    """Marker protocol for validated, immutable domain command DTOs."""


def _bounded_text(value: str, *, field: str, maximum: int, required: bool = False) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be text")
    value = value.strip()
    if required and not value:
        raise ValidationError(f"{field} is required")
    if len(value) > maximum:
        raise ValidationError(f"{field} is too long")
    return value


def _filters(value: dict | None) -> tuple[tuple[str, str], ...]:
    if value is None:
        return ()
    if not isinstance(value, dict) or len(value) > MAX_FILTER_KEYS:
        raise ValidationError("filters must be a bounded mapping")
    normalized = []
    for key, item in sorted(value.items()):
        key = _bounded_text(key, field="filter key", maximum=60, required=True)
        item = _bounded_text(str(item), field="filter value", maximum=MAX_FILTER_VALUE)
        normalized.append((key, item))
    return tuple(normalized)


@dataclass(frozen=True, slots=True)
class ReportRunCommand:
    report_key: str
    filters: tuple[tuple[str, str], ...] = ()
    expected_definition_updated_at: datetime | None = None

    def __post_init__(self):
        object.__setattr__(self, "report_key", _bounded_text(self.report_key, field="report_key", maximum=MAX_REPORT_KEY, required=True))
        object.__setattr__(self, "filters", _filters(dict(self.filters) if isinstance(self.filters, tuple) else self.filters))


@dataclass(frozen=True, slots=True)
class ReportExportCommand:
    report_key: str
    export_format: str
    filters: tuple[tuple[str, str], ...] = ()
    purpose: str = ""
    expected_definition_updated_at: datetime | None = None

    def __post_init__(self):
        object.__setattr__(self, "report_key", _bounded_text(self.report_key, field="report_key", maximum=MAX_REPORT_KEY, required=True))
        object.__setattr__(self, "export_format", _bounded_text(self.export_format, field="export_format", maximum=30, required=True).lower())
        object.__setattr__(self, "filters", _filters(dict(self.filters) if isinstance(self.filters, tuple) else self.filters))
        object.__setattr__(self, "purpose", _bounded_text(self.purpose, field="purpose", maximum=MAX_PURPOSE))


@dataclass(frozen=True, slots=True)
class ReportExportLifecycleCommand:
    export_id: str
    expected_status: str = ""
    reason: str = ""

    def __post_init__(self):
        object.__setattr__(self, "export_id", _bounded_text(self.export_id, field="export_id", maximum=80, required=True))
        object.__setattr__(self, "expected_status", _bounded_text(self.expected_status, field="expected_status", maximum=50))
        object.__setattr__(self, "reason", _bounded_text(self.reason, field="reason", maximum=MAX_PURPOSE))
