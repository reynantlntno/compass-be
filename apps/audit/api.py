"""Read-only, plane-scoped Audit Viewer API."""

from __future__ import annotations

from datetime import datetime, time
from typing import Annotated, Literal

from django.utils import timezone
from django.utils.dateparse import parse_date, parse_datetime
from ninja import Query, Router, Schema

from apps.audit.policies import can_view_audit
from apps.audit.queries import AuditQuery, audit_detail, audit_page
from apps.common.api.operations import prepare_api_operation
from apps.common.api.pagination import PageQuery, PageSizeQuery, page_request_from_values
from apps.common.api.schemas import PageResultSchema
from apps.common.contracts import ContractValidationError
from apps.common.exceptions import NotFoundError, PermissionDeniedError, ValidationError


router = Router(tags=["audit"])

AuditPlaneQuery = Annotated[
    Literal["technical", "business", "privacy"] | None,
    Query(default=None, description="Optional visibility plane to narrow the response."),
]
AuditFilterQuery = Annotated[
    str | None,
    Query(default=None, max_length=100),
]


class AuditPageSchema(PageResultSchema):
    items: list["AuditEntryProjectionSchema"]


class AuditSafeContextSchema(Schema):
    status: str | None = None
    from_status: str | None = None
    to_status: str | None = None
    decision: str | None = None
    decision_code: str | None = None
    reason_code: str | None = None
    result_code: str | None = None
    operation: str | None = None
    outcome: str | None = None
    scope: str | None = None
    policy_key: str | None = None
    success: bool | None = None
    has_notes: bool | None = None
    count: int | None = None


class AuditEntryProjectionSchema(Schema):
    id: int
    created_at: datetime
    action_type: str
    event_category: str
    severity: str
    source_app: str
    actor_role: str
    actor_fingerprint: str | None = None
    target_model: str
    target_reference: str | None = None
    target_fingerprint: str | None = None
    request_id: str | None = None
    trace_id: str | None = None
    safe_context: AuditSafeContextSchema


def _actor(request):
    return request.auth.user


def _page(page: PageQuery, page_size: PageSizeQuery):
    try:
        return page_request_from_values(page, page_size)
    except ContractValidationError as exc:
        raise ValidationError() from exc


def _audit_query(
    *,
    event_category: str | None = None,
    action_type: str | None = None,
    severity: str | None = None,
    source_app: str | None = None,
    target_model: str | None = None,
    created_from: str | None = None,
    created_until: str | None = None,
    request_id: str | None = None,
    trace_id: str | None = None,
) -> AuditQuery:
    return AuditQuery(
        event_category=event_category,
        action_type=action_type,
        severity=severity,
        source_app=source_app,
        target_model=target_model,
        created_from=_parse_boundary_value(created_from, end=False, field="created_from"),
        created_until=_parse_boundary_value(created_until, end=True, field="created_until"),
        request_id=request_id,
        trace_id=trace_id,
    )


def _parse_boundary_value(raw: str | None, *, end: bool, field: str) -> datetime | None:
    if raw is None or raw == "":
        return None
    value = parse_datetime(raw)
    if value is None:
        date_value = parse_date(raw)
        if date_value is None:
            raise ValidationError(field_errors={field: ["The date range value is invalid."]})
        value = datetime.combine(date_value, time.max if end else time.min)
    if timezone.is_naive(value):
        value = timezone.make_aware(value, timezone.get_current_timezone())
    return value


def _require_viewer(actor) -> None:
    if not can_view_audit(actor):
        raise PermissionDeniedError()


@router.get(
    "/",
    response=AuditPageSchema,
    exclude_unset=True,
    operation_id="audit_entries_list",
)
def entries(
    request,
    page: PageQuery,
    page_size: PageSizeQuery,
    plane: AuditPlaneQuery,
    event_category: AuditFilterQuery,
    action_type: AuditFilterQuery,
    severity: AuditFilterQuery,
    source_app: AuditFilterQuery,
    target_model: AuditFilterQuery,
    created_from: AuditFilterQuery,
    created_until: AuditFilterQuery,
    request_id: AuditFilterQuery,
    trace_id: AuditFilterQuery,
):
    actor = _actor(request)
    _require_viewer(actor)
    prepare_api_operation(request, "audit_entries_list")
    return audit_page(
        actor,
        _page(page, page_size),
        _audit_query(
            event_category=event_category,
            action_type=action_type,
            severity=severity,
            source_app=source_app,
            target_model=target_model,
            created_from=created_from,
            created_until=created_until,
            request_id=request_id,
            trace_id=trace_id,
        ),
        plane=plane,
    ).as_dict()


@router.get(
    "/{entry_id}/",
    response=AuditEntryProjectionSchema,
    exclude_unset=True,
    operation_id="audit_entry_detail",
)
def entry_detail(request, entry_id: int, plane: AuditPlaneQuery):
    actor = _actor(request)
    _require_viewer(actor)
    prepare_api_operation(request, "audit_entry_detail")
    value = audit_detail(actor, entry_id, plane=plane)
    if value is None:
        raise NotFoundError()
    return value
