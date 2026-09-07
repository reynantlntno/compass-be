"""Projection-only query boundary for system operations."""

from apps.common.contracts import PageRequest, PageResult, page_queryset
from apps.system.models import ApplicationErrorEvent, MaintenanceWindow, OperationalCommandRun
from apps.system.policies import (
    can_list_application_error_events,
    can_view_application_error_event,
    can_view_maintenance,
    can_view_operational_history,
)
from apps.system.projections import (
    maintenance_projection,
    operational_command_run_projection,
    project_application_error_event,
)


def diagnostic_page(actor, page: PageRequest, *, unresolved_only: bool = False, category: str | None = None) -> PageResult:
    if not can_list_application_error_events(actor):
        return PageResult(items=(), page=page.page, page_size=page.page_size, total=0)
    queryset = ApplicationErrorEvent.objects.all().order_by("-created_at", "-pk")
    if unresolved_only:
        queryset = queryset.filter(is_resolved=False)
    if category:
        queryset = queryset.filter(category=category)
    return page_queryset(queryset, page, lambda event: project_application_error_event(actor, event))


def diagnostic_detail(actor, error_id: str) -> dict | None:
    if not can_view_application_error_event(actor, None):
        return None
    event = ApplicationErrorEvent.objects.filter(error_id=error_id).first()
    if event is None or not can_view_application_error_event(actor, event):
        return None
    return project_application_error_event(actor, event)


def maintenance_page(actor, page: PageRequest) -> PageResult:
    if not can_view_maintenance(actor):
        return PageResult(items=(), page=page.page, page_size=page.page_size, total=0)
    queryset = MaintenanceWindow.objects.all().order_by("-starts_at", "-pk")
    return page_queryset(queryset, page, maintenance_projection)


def maintenance_detail(actor, window_id: str) -> dict | None:
    if not can_view_maintenance(actor):
        return None
    value = MaintenanceWindow.objects.filter(pk=window_id).first()
    return maintenance_projection(value) if value is not None else None


def operational_run_page(actor, page: PageRequest) -> PageResult:
    if not can_view_operational_history(actor):
        return PageResult(items=(), page=page.page, page_size=page.page_size, total=0)
    queryset = OperationalCommandRun.objects.all().order_by("-started_at", "-pk")
    return page_queryset(queryset, page, operational_command_run_projection)
