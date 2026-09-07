"""Framework-neutral audit query and paginated read contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re

from apps.common.exceptions import ValidationError
from apps.common.contracts import PageRequest, PageResult


_SAFE_FILTER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}\Z")
_MAX_FILTER_LENGTH = 100


def _filter_value(value: str | None, *, field: str) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValidationError()
    value = value.strip()
    if not value or len(value) > _MAX_FILTER_LENGTH or not _SAFE_FILTER.fullmatch(value):
        raise ValidationError(field_errors={field: ["The filter value is invalid."]})
    return value


@dataclass(frozen=True, slots=True)
class AuditQuery:
    event_category: str | None = None
    action_type: str | None = None
    severity: str | None = None
    source_app: str | None = None
    target_model: str | None = None
    created_from: datetime | None = None
    created_until: datetime | None = None
    request_id: str | None = None
    trace_id: str | None = None

    def __post_init__(self) -> None:
        for field in (
            "event_category",
            "action_type",
            "severity",
            "source_app",
            "target_model",
            "request_id",
            "trace_id",
        ):
            object.__setattr__(
                self,
                field,
                _filter_value(getattr(self, field), field=field),
            )
        if self.created_from is not None and not isinstance(self.created_from, datetime):
            raise ValidationError(field_errors={"created_from": ["The date is invalid."]})
        if self.created_until is not None and not isinstance(self.created_until, datetime):
            raise ValidationError(field_errors={"created_until": ["The date is invalid."]})
        if self.created_from and self.created_until and self.created_from > self.created_until:
            raise ValidationError(field_errors={"created_until": ["The end date must not precede the start date."]})


def audit_page(
    actor,
    page: PageRequest,
    query: AuditQuery | None = None,
    *,
    plane=None,
) -> PageResult[dict]:
    from apps.audit.projections import audit_entry_projection
    from apps.audit.selectors import get_audit_entries_visible_to

    queryset = get_audit_entries_visible_to(actor, query, plane=plane)
    return PageResult(
        items=tuple(
            audit_entry_projection(entry)
            for entry in queryset[page.offset:page.offset + page.page_size]
        ),
        page=page.page,
        page_size=page.page_size,
        total=queryset.count(),
    )


def audit_detail(actor, entry_id: int, *, plane=None) -> dict | None:
    from apps.audit.projections import audit_entry_projection
    from apps.audit.selectors import get_audit_entry_for_actor

    entry = get_audit_entry_for_actor(actor, entry_id, plane=plane)
    return audit_entry_projection(entry) if entry is not None else None
