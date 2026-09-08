"""Django Ninja adapter for restricted IT system operations.

This module is deliberately a projection boundary.  It exposes only the
allowlisted operational workflows and delegates lifecycle decisions to the
system services, which re-load and re-authorize their targets.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from ninja import Query, Router, Schema

from apps.common.api.idempotency import ApiMutationOutcome, run_api_mutation
from apps.common.api.operations import prepare_api_operation
from apps.common.api.pagination import PageQuery, PageSizeQuery, page_request_from_values
from apps.common.api.schemas import PageResultSchema
from apps.common.contracts import ContractValidationError
from apps.common.exceptions import NotFoundError, PermissionDeniedError, ValidationError
from apps.system.commands import (
    DiagnosticTransitionCommand,
    HealthCheckCommand,
    MaintenanceScheduleCommand,
    MaintenanceTransitionCommand,
)
from apps.system.error_services import (
    reopen_application_error_by_id,
    resolve_application_error_by_id,
)
from apps.system.maintenance_services import (
    activate_maintenance_by_id,
    cancel_maintenance_by_id,
    complete_maintenance_by_id,
    extend_maintenance_by_id,
    public_service_status,
    schedule_maintenance_command,
)
from apps.system.operations import OPERATIONAL_COMMAND_CATALOG
from apps.system.policies import (
    can_list_application_error_events,
    can_run_health_checks,
    can_view_application_error_event,
    can_view_environment_summary,
    can_view_maintenance,
    can_view_operational_history,
    can_view_release_operations,
    can_view_system_health,
)
from apps.system.projections import (
    maintenance_projection,
    operational_command_run_projection,
    project_application_error_event,
)
from apps.system.queries import (
    diagnostic_detail,
    diagnostic_page,
    maintenance_detail,
    maintenance_page,
    operational_run_page,
)
from apps.system.readiness_services import environment_name, release_identity
from apps.system.services import run_health_check_command


router = Router(tags=["system"])


class HealthComponentSchema(Schema):
    """Output-only bounded result for one health component."""

    component: str
    label: str
    status: str
    message: str
    reason_code: str
    duration_ms: float
    checked_at: datetime | None = None


class HealthProjectionSchema(Schema):
    """Output-only aggregate health result."""

    status: str
    component_count: int
    failed_count: int
    warning_count: int
    components: list[HealthComponentSchema]


PublicServiceStatus = Literal[
    "operational",
    "maintenance_scheduled",
    "maintenance_active",
]


class PublicServiceStatusSchema(Schema):
    """Anonymous, output-only service status projection."""

    status: PublicServiceStatus
    message: str | None = None
    starts_at: datetime | None = None
    ends_at: datetime | None = None


DiagnosticContextValue = str | int | float | bool


class DiagnosticContextValuesSchema(Schema):
    """Output-only allowlist for safe diagnostic context values."""

    service_name: DiagnosticContextValue | None = None
    job_name: DiagnosticContextValue | None = None
    reason_code: DiagnosticContextValue | None = None
    component: DiagnosticContextValue | None = None
    operation: DiagnosticContextValue | None = None
    phase: DiagnosticContextValue | None = None
    dependency: DiagnosticContextValue | None = None
    provider_code: DiagnosticContextValue | None = None
    retryable: DiagnosticContextValue | None = None
    status_code: DiagnosticContextValue | None = None


class DiagnosticContextSchema(Schema):
    state: str
    values: DiagnosticContextValuesSchema


class DiagnosticRemediationSchema(Schema):
    code: str
    hint: str


class ApplicationErrorProjectionSchema(Schema):
    """Output-only redacted application error projection."""

    error_id: str
    created_at: datetime
    request_id: str | None = None
    trace_id: str | None = None
    severity: str
    category: str
    environment: str
    release_version: str | None = None
    build_id: str | None = None
    app_label: str | None = None
    route_name: str | None = None
    view_name: str | None = None
    http_method: str | None = None
    path_template: str | None = None
    status_code: int | None = None
    exception_class: str | None = None
    safe_message: str
    fingerprint_version: str
    fingerprint: str
    diagnostic_context: DiagnosticContextSchema
    remediation: DiagnosticRemediationSchema
    is_resolved: bool
    resolved_at: datetime | None = None


class SystemErrorPageSchema(PageResultSchema):
    items: list[ApplicationErrorProjectionSchema]


class MaintenanceProjectionSchema(Schema):
    """Output-only maintenance-window projection."""

    id: str
    status: str
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    safe_public_message: str
    internal_reason_code: str
    is_expired: bool
    created_at: datetime | None = None
    updated_at: datetime | None = None


class MaintenancePageSchema(PageResultSchema):
    items: list[MaintenanceProjectionSchema]


class OperationalCommandRunProjectionSchema(Schema):
    """Output-only operational history projection."""

    id: str
    command_key: str
    mode: str
    environment: str
    reason_code: str
    configuration_identifier: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    outcome: str
    outcome_reason_code: str | None = None
    release_version: str | None = None
    build_id: str | None = None


class OperationalRunPageSchema(PageResultSchema):
    items: list[OperationalCommandRunProjectionSchema]


class ReleaseIdentitySchema(Schema):
    version: str
    build_id: str
    configured: bool


class ReleaseMetadataSchema(Schema):
    environment: str
    release: ReleaseIdentitySchema


class EnvironmentComponentsSchema(Schema):
    cache_backend: str
    protected_storage_backend: str
    backup_worker_enabled: bool
    notification_worker_enabled: bool


class EnvironmentMaintenanceSchema(Schema):
    active: bool


class EnvironmentSummarySchema(Schema):
    environment: str
    deployment_class: str
    release: ReleaseIdentitySchema
    components: EnvironmentComponentsSchema
    maintenance: EnvironmentMaintenanceSchema


class OperationalCommandSchema(Schema):
    key: str
    label: str
    mode: str


class OperationalCommandCatalogSchema(Schema):
    items: list[OperationalCommandSchema]


class HealthCheckSchema(Schema):
    component: str = "all"


class DiagnosticTransitionSchema(Schema):
    note: str = ""
    expected_updated_at: str | None = None


class MaintenanceScheduleSchema(Schema):
    starts_at: str
    ends_at: str
    public_message: str = ""
    reason_code: str = "scheduled_maintenance"


class MaintenanceTransitionSchema(Schema):
    expected_updated_at: str | None = None
    ends_at: str | None = None
    reason_code: str = "maintenance_operation"


def _actor(request):
    return request.auth.user


def _page(page: PageQuery, page_size: PageSizeQuery):
    try:
        return page_request_from_values(page, page_size)
    except ContractValidationError as exc:
        raise ValidationError() from exc


def _payload(payload):
    return payload.dict() if payload is not None else {}


def _require(can_access, actor):
    if not can_access(actor):
        raise PermissionDeniedError()


def _run(request, operation_id, payload, operation, replay):
    prepared = prepare_api_operation(request, operation_id)
    return run_api_mutation(
        request,
        operation_id,
        payload,
        operation,
        replay,
        prepared_operation=prepared,
    )


def _health_component_projection(value: dict) -> dict:
    """Project the fixed health DTO without provider/configuration details."""
    return {
        "component": str(value.get("component", "unknown"))[:80],
        "label": str(value.get("label", "Operational component"))[:120],
        "status": str(value.get("status", "error"))[:20],
        "message": str(value.get("message", "Health status unavailable."))[:255],
        "reason_code": str(value.get("reason_code", "HEALTH_CHECK_FAILED"))[:100],
        "duration_ms": round(float(value.get("duration_ms", 0) or 0), 2),
        "checked_at": value.get("checked_at"),
    }


def _health_projection(*, component: str = "all") -> dict:
    command = HealthCheckCommand(component=component)
    values = [_health_component_projection(item) for item in run_health_check_command(command)]
    if not values:
        raise ValidationError(field_errors={"component": ["Unknown health component."]})
    failed = sum(item["status"] == "error" for item in values)
    warnings = sum(item["status"] == "warning" for item in values)
    return {
        "status": "error" if failed else ("warning" if warnings else "ok"),
        "component_count": len(values),
        "failed_count": failed,
        "warning_count": warnings,
        "components": values,
    }


def _release_projection() -> dict:
    identity = release_identity()
    return {
        "environment": environment_name(),
        "release": {
            "version": identity["version"],
            "build_id": identity["build_id"],
            "configured": bool(identity["configured"]),
        },
    }


def _environment_projection() -> dict:
    from django.conf import settings
    from apps.system.maintenance_services import get_active_maintenance_window

    cache_backend = str(
        getattr(settings, "CACHES", {}).get("default", {}).get("BACKEND", "")
    ).lower()
    storage_backend = str(getattr(settings, "PROTECTED_STORAGE_BACKEND", "local") or "local").lower()
    return {
        "environment": environment_name(),
        "deployment_class": "deployment" if environment_name() in {"production", "prod", "staging", "stage"} else "non_deployment",
        "release": _release_projection()["release"],
        "components": {
            "cache_backend": "redis" if "redis" in cache_backend else "locmem_or_other",
            "protected_storage_backend": storage_backend if storage_backend in {"local", "s3"} else "other",
            "backup_worker_enabled": bool(getattr(settings, "BACKUP_WORKER_ENABLED", False)),
            "notification_worker_enabled": bool(getattr(settings, "NOTIFICATION_WORKER_ENABLED", False)),
        },
        "maintenance": {
            "active": get_active_maintenance_window() is not None,
        },
    }


def _catalog_projection() -> list[dict]:
    return [
        {
            "key": str(item.get("key", ""))[:100],
            "label": str(item.get("label", ""))[:160],
            "mode": str(item.get("mode", "read-only"))[:30],
        }
        for item in OPERATIONAL_COMMAND_CATALOG
    ]


@router.get("/health/", response=HealthProjectionSchema, exclude_unset=True, operation_id="system_health")
def health(request):
    _require(can_view_system_health, _actor(request))
    prepare_api_operation(request, "system_health")
    return _health_projection()


@router.get(
    "/public-status/",
    auth=None,
    response=PublicServiceStatusSchema,
    operation_id="system_public_status",
)
def public_status(request):
    """Return only the anonymous maintenance/service-status projection."""

    return public_service_status()


@router.post("/health/check/", response=HealthProjectionSchema, exclude_unset=True, operation_id="system_health_check")
def health_check(request, payload: HealthCheckSchema):
    actor = _actor(request)
    _require(can_run_health_checks, actor)
    prepare_api_operation(request, "system_health_check")
    command = HealthCheckCommand(component=payload.component)
    return _health_projection(component=command.component)


@router.get("/errors/", response=SystemErrorPageSchema, exclude_unset=True, operation_id="system_errors_list")
def errors(
    request,
    page: PageQuery,
    page_size: PageSizeQuery,
    unresolved_only: bool = Query(default=False),
    category: str | None = Query(default=None),
):
    _require(can_list_application_error_events, _actor(request))
    prepare_api_operation(request, "system_errors_list")
    category = (category or "").strip() or None
    return diagnostic_page(_actor(request), _page(page, page_size), unresolved_only=unresolved_only, category=category)


@router.get("/errors/{error_id}/", response=ApplicationErrorProjectionSchema, exclude_unset=True, operation_id="system_error_detail")
def error_detail(request, error_id: str):
    _require(lambda actor: can_view_application_error_event(actor, None), _actor(request))
    prepare_api_operation(request, "system_error_detail")
    value = diagnostic_detail(_actor(request), error_id)
    if value is None:
        raise NotFoundError()
    return value


def _error_transition(request, error_id: str, payload: DiagnosticTransitionSchema, operation_id: str, operation):
    actor = _actor(request)
    command = DiagnosticTransitionCommand(
        error_id=error_id,
        note=payload.note,
        expected_updated_at=payload.expected_updated_at,
    )

    def execute():
        event = operation(
            actor=actor,
            error_id=command.error_id,
            note=command.note,
            expected_updated_at=command.expected_updated_at,
        )
        return ApiMutationOutcome(
            value=project_application_error_event(actor, event),
            related_object=event,
            safe_response_path=f"/api/v1/system/errors/{event.error_id}/",
        )

    def replay(key):
        return diagnostic_detail(actor, key.related_object_id or command.error_id)

    return _run(request, operation_id, _payload(payload), execute, replay)


@router.post("/errors/{error_id}/resolve/", response=ApplicationErrorProjectionSchema, exclude_unset=True, operation_id="system_error_resolve")
def resolve_error(request, error_id: str, payload: DiagnosticTransitionSchema):
    return _error_transition(request, error_id, payload, "system_error_resolve", resolve_application_error_by_id)


@router.post("/errors/{error_id}/reopen/", response=ApplicationErrorProjectionSchema, exclude_unset=True, operation_id="system_error_reopen")
def reopen_error(request, error_id: str, payload: DiagnosticTransitionSchema):
    return _error_transition(request, error_id, payload, "system_error_reopen", reopen_application_error_by_id)


@router.get("/maintenance/", response=MaintenancePageSchema, exclude_unset=True, operation_id="system_maintenance_list")
def maintenance(request, page: PageQuery, page_size: PageSizeQuery):
    _require(can_view_maintenance, _actor(request))
    prepare_api_operation(request, "system_maintenance_list")
    return maintenance_page(_actor(request), _page(page, page_size))


@router.get("/maintenance/{window_id}/", response=MaintenanceProjectionSchema, exclude_unset=True, operation_id="system_maintenance_detail")
def maintenance_detail_route(request, window_id: str):
    _require(can_view_maintenance, _actor(request))
    prepare_api_operation(request, "system_maintenance_detail")
    value = maintenance_detail(_actor(request), window_id)
    if not value:
        raise NotFoundError()
    return value


@router.post("/maintenance/", response=MaintenanceProjectionSchema, exclude_unset=True, operation_id="system_maintenance_schedule")
def schedule(request, payload: MaintenanceScheduleSchema):
    actor = _actor(request)
    command = MaintenanceScheduleCommand(**_payload(payload))

    def execute():
        window = schedule_maintenance_command(actor, command)
        return ApiMutationOutcome(
            value=maintenance_projection(window),
            related_object=window,
            safe_response_path=f"/api/v1/system/maintenance/{window.pk}/",
        )

    def replay(key):
        return maintenance_detail(actor, key.related_object_id)

    return _run(request, "system_maintenance_schedule", _payload(payload), execute, replay)


def _maintenance_transition(request, window_id: str, payload: MaintenanceTransitionSchema, operation_id: str, operation):
    actor = _actor(request)
    command = MaintenanceTransitionCommand(window_id=window_id, **_payload(payload))

    def execute():
        window = operation(actor, command)
        return ApiMutationOutcome(
            value=maintenance_projection(window),
            related_object=window,
            safe_response_path=f"/api/v1/system/maintenance/{window.pk}/",
        )

    def replay(key):
        return maintenance_detail(actor, key.related_object_id or window_id)

    return _run(request, operation_id, {"window_id": window_id, **_payload(payload)}, execute, replay)


@router.post("/maintenance/{window_id}/activate/", response=MaintenanceProjectionSchema, exclude_unset=True, operation_id="system_maintenance_activate")
def activate(request, window_id: str, payload: MaintenanceTransitionSchema):
    return _maintenance_transition(request, window_id, payload, "system_maintenance_activate", activate_maintenance_by_id)


@router.post("/maintenance/{window_id}/extend/", response=MaintenanceProjectionSchema, exclude_unset=True, operation_id="system_maintenance_extend")
def extend(request, window_id: str, payload: MaintenanceTransitionSchema):
    return _maintenance_transition(request, window_id, payload, "system_maintenance_extend", extend_maintenance_by_id)


@router.post("/maintenance/{window_id}/complete/", response=MaintenanceProjectionSchema, exclude_unset=True, operation_id="system_maintenance_complete")
def complete(request, window_id: str, payload: MaintenanceTransitionSchema):
    return _maintenance_transition(request, window_id, payload, "system_maintenance_complete", complete_maintenance_by_id)


@router.post("/maintenance/{window_id}/cancel/", response=MaintenanceProjectionSchema, exclude_unset=True, operation_id="system_maintenance_cancel")
def cancel(request, window_id: str, payload: MaintenanceTransitionSchema):
    return _maintenance_transition(request, window_id, payload, "system_maintenance_cancel", cancel_maintenance_by_id)


@router.get("/release/", response=ReleaseMetadataSchema, exclude_unset=True, operation_id="system_release_metadata")
def release(request):
    _require(can_view_release_operations, _actor(request))
    prepare_api_operation(request, "system_release_metadata")
    return _release_projection()


@router.get("/environment/", response=EnvironmentSummarySchema, exclude_unset=True, operation_id="system_environment_summary")
def environment(request):
    _require(can_view_environment_summary, _actor(request))
    prepare_api_operation(request, "system_environment_summary")
    return _environment_projection()


@router.get("/operations/", response=OperationalCommandCatalogSchema, exclude_unset=True, operation_id="system_operations_catalog")
def operations(request):
    _require(can_view_release_operations, _actor(request))
    prepare_api_operation(request, "system_operations_catalog")
    return {"items": _catalog_projection()}


@router.get("/operations/runs/", response=OperationalRunPageSchema, exclude_unset=True, operation_id="system_operations_runs")
def operation_runs(request, page: PageQuery, page_size: PageSizeQuery):
    _require(can_view_operational_history, _actor(request))
    prepare_api_operation(request, "system_operations_runs")
    return operational_run_page(_actor(request), _page(page, page_size))
