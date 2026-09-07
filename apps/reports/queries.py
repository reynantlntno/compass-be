"""Actor-aware query boundary for the reports domain.

Query functions belong here when the domain receives an API/UI read. They must
compose an existing scoped selector with a fixed projection and never return
HTTP responses or serialize ORM objects directly.
"""

from apps.common.contracts import PageRequest, PageResult
from apps.reports.models import ReportDefinition, ReportRun, ReportExportRequest
from apps.access_control.authority import resolve_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import is_it_admin
from apps.reports.policies import can_view_report_definition, can_view_export_request
from apps.reports.projections import (
    report_definition_projection,
    report_run_projection,
    report_export_projection,
    report_export_technical_projection,
)
from apps.reports.services import list_report_definitions_for_actor
from apps.reports.export_services import list_export_requests_for_actor


def definition_page(actor, page: PageRequest) -> PageResult:
    definitions = list_report_definitions_for_actor(actor).order_by("title", "key")
    total = definitions.count()
    return PageResult(
        items=tuple(
            report_definition_projection(item)
            for item in definitions[page.offset:page.offset + page.page_size]
        ),
        page=page.page,
        page_size=page.page_size,
        total=total,
    )


def definition_detail(actor, key: str) -> dict | None:
    definition = ReportDefinition.objects.filter(key=key, is_active=True).first()
    if definition is None or not can_view_report_definition(actor, definition):
        return None
    return report_definition_projection(definition)


def _visible_run(actor, run_id: str):
    run = ReportRun.objects.select_related("report_definition").filter(id=run_id).first()
    if run is None or not can_view_report_definition(actor, run.report_definition):
        return None
    if run.requested_by_id != getattr(actor, "pk", None) and not resolve_capability(actor, Capability.REPORTS_VIEW_INSTITUTION):
        return None
    return run


def run_page(actor, page: PageRequest) -> PageResult:
    if resolve_capability(actor, Capability.REPORTS_VIEW_INSTITUTION):
        queryset = ReportRun.objects.select_related("report_definition").all()
    else:
        queryset = ReportRun.objects.select_related("report_definition").filter(requested_by=actor)
    queryset = queryset.order_by("-created_at")
    total = queryset.count()
    return PageResult(
        items=tuple(report_run_projection(item) for item in queryset[page.offset:page.offset + page.page_size]),
        page=page.page,
        page_size=page.page_size,
        total=total,
    )


def run_detail(actor, run_id: str) -> dict | None:
    run = _visible_run(actor, run_id)
    return report_run_projection(run) if run is not None else None


def export_page(actor, page: PageRequest) -> PageResult:
    queryset = list_export_requests_for_actor(actor).select_related("report_definition").order_by("-requested_at")
    total = queryset.count()
    return PageResult(
        items=tuple(
            (report_export_technical_projection(item) if is_it_admin(actor) else report_export_projection(item))
            for item in queryset[page.offset:page.offset + page.page_size]
        ),
        page=page.page,
        page_size=page.page_size,
        total=total,
    )


def export_detail(actor, export_id: str) -> dict | None:
    export = ReportExportRequest.objects.select_related("report_definition").filter(id=export_id).first()
    if export is None or not can_view_export_request(actor, export):
        return None
    return report_export_technical_projection(export) if is_it_admin(actor) else report_export_projection(export)


def export_object(actor, export_id: str):
    export = ReportExportRequest.objects.select_related("report_definition").filter(id=export_id).first()
    if export is None or not can_view_export_request(actor, export):
        return None
    return export
