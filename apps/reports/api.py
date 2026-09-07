"""Client-facing Reports API with governed aggregate execution and exports."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from uuid import UUID

from django.http import HttpResponse
from ninja import Router, Schema

from apps.common.api.idempotency import ApiMutationOutcome, run_api_mutation
from apps.common.api.operations import prepare_api_operation
from apps.common.api.pagination import PageQuery, PageSizeQuery, page_request_from_values
from apps.common.api.response_docs import binary_response_openapi
from apps.common.api.schemas import PageResultSchema
from apps.common.contracts import ContractValidationError, to_json_object
from apps.common.exceptions import NotFoundError, ValidationError
from apps.reports import queries
from apps.reports.commands import ReportExportCommand, ReportExportLifecycleCommand, ReportRunCommand
from apps.reports.export_services import (
    archive_report_export,
    cancel_report_export,
    download_report_export,
    expire_report_export,
    generate_report_export,
)
from apps.reports.projections import aggregate_result_projection, report_export_projection, report_run_projection
from apps.reports.services import report_execution_controls, request_export_command, run_report_command


router = Router(tags=["reports"])


ReportFilterValue = str | int | float | bool | None


class ReportFilterSummarySchema(Schema):
    """Output-only allowlist for the redacted report filter summary."""

    campus: ReportFilterValue = None
    college: ReportFilterValue = None
    department: ReportFilterValue = None
    program: ReportFilterValue = None
    year_level: ReportFilterValue = None
    academic_year: ReportFilterValue = None
    service_category: ReportFilterValue = None
    client_type: ReportFilterValue = None
    form_collection: ReportFilterValue = None
    form_revision: ReportFilterValue = None
    employment_status: ReportFilterValue = None
    graduation_year: ReportFilterValue = None
    assigned_counselor: ReportFilterValue = None
    status: ReportFilterValue = None


class ReportDefinitionSchema(Schema):
    """Output-only report definition projection."""

    id: str
    key: str
    title: str
    description: str
    family: str
    sensitivity_level: str
    is_active: bool
    activated_at: datetime | None = None
    updated_at: datetime | None = None


class ReportDefinitionPageSchema(PageResultSchema):
    items: list[ReportDefinitionSchema]


class ReportRunProjectionSchema(Schema):
    """Output-only report run metadata projection."""

    id: str
    report_key: str
    status: str
    filter_hash: str
    filter_summary: ReportFilterSummarySchema
    aggregate_count: int | None = None
    cell_count: int | None = None
    suppression_applied: bool
    suppressed_cell_count: int
    started_at: datetime | None = None
    completed_at: datetime | None = None
    failed_at: datetime | None = None
    expires_at: datetime | None = None
    execution_mode: str
    estimated_work_units: int | None = None
    actual_work_units: int | None = None
    error_code: str | None = None
    suppression_policy_id: str | None = None


class ReportRunPageSchema(PageResultSchema):
    items: list[ReportRunProjectionSchema]


class ReportRunResponseSchema(ReportRunProjectionSchema):
    """Output-only response for a synchronous report execution."""

    result_available: bool
    work_units: int
    output_size_bytes: int | None = None
    result: dict[str, object] | None


class ReportExportProjectionSchema(Schema):
    """Output-only export projection with an explicit actor-safe superset."""

    id: str
    status: str
    export_format: str
    export_type: str
    requested_at: datetime | None = None
    generated_at: datetime | None = None
    expires_at: datetime | None = None
    generation_state: str | None = None
    output_classification: str | None = None

    # Regular report viewers receive these fields. IT maintenance views omit
    # them through the technical projection and route-level exclude_unset.
    report_key: str | None = None
    filter_hash: str | None = None
    filter_summary: ReportFilterSummarySchema | None = None
    includes_sensitive_data: bool | None = None
    includes_identifiable_data: bool | None = None
    suppression_applied: bool | None = None
    suppressed_cell_count: int | None = None
    suppression_policy_id: str | None = None
    suppression_policy_effective_from: datetime | None = None
    suppression_policy_effective_until: datetime | None = None
    download_available: bool | None = None

    # IT maintenance views receive this bounded technical flag instead.
    protected_file_available: bool | None = None


class ReportExportPageSchema(PageResultSchema):
    items: list[ReportExportProjectionSchema]


class ReportRunSchema(Schema):
    report_key: str
    filters: dict[str, str | int | bool] = {}
    expected_definition_updated_at: datetime | None = None


class ReportExportSchema(Schema):
    report_key: str
    export_format: str = "csv"
    filters: dict[str, str | int | bool] = {}
    purpose: str = ""
    expected_definition_updated_at: datetime | None = None


class ReportLifecycleSchema(Schema):
    expected_status: str = ""
    reason: str = ""


def _actor(request):
    return request.auth.user


def _page(page: PageQuery, page_size: PageSizeQuery):
    try:
        return page_request_from_values(page, page_size)
    except ContractValidationError as exc:
        raise ValidationError() from exc


def _fingerprint(command, **extra):
    return to_json_object({**extra, "command": asdict(command)})


def _run_mutation(request, operation_id, payload, operation, replay):
    prepared = prepare_api_operation(request, operation_id)
    return run_api_mutation(
        request,
        operation_id,
        payload,
        operation,
        replay,
        prepared_operation=prepared,
    )


def _run_response(run, dataset=None):
    metadata = dict(run.metadata_json or {})
    execution_mode = metadata.get("execution_mode", "SYNC")
    estimated_work_units = metadata.get("estimated_work_units")
    actual_work_units = metadata.get("actual_work_units")
    if run.status != "COMPLETED" or dataset is None:
        response = report_run_projection(run)
        response.update({
            "execution_mode": execution_mode,
            "result_available": False,
            "estimated_work_units": estimated_work_units,
            "work_units": actual_work_units or estimated_work_units or 0,
            "result": None,
        })
        return response
    controls = report_execution_controls()
    result = aggregate_result_projection(dataset)
    output_size = len(json.dumps(result, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))
    work_units = actual_work_units or max(1, output_size // 256)
    inline = output_size <= controls["max_output_bytes"] and work_units <= controls["max_work_units"]
    response = report_run_projection(run)
    response.update({
        "execution_mode": "INLINE" if inline else "EXPORT_REQUIRED",
        "result_available": inline,
        "estimated_work_units": estimated_work_units,
        "work_units": work_units,
        "output_size_bytes": output_size,
        "result": result if inline else None,
    })
    return response


@router.get("/definitions/", response=ReportDefinitionPageSchema, operation_id="reports_definitions")
def definitions(request, page: PageQuery, page_size: PageSizeQuery):
    prepare_api_operation(request, "reports_definitions")
    return queries.definition_page(_actor(request), _page(page, page_size)).as_dict()


@router.get("/definitions/{key}/", response=ReportDefinitionSchema, operation_id="reports_definition_detail")
def definition_detail(request, key: str):
    prepare_api_operation(request, "reports_definition_detail")
    value = queries.definition_detail(_actor(request), key)
    if value is None:
        raise NotFoundError()
    return value


@router.get("/runs/", response=ReportRunPageSchema, exclude_unset=True, operation_id="reports_runs")
def runs(request, page: PageQuery, page_size: PageSizeQuery):
    prepare_api_operation(request, "reports_runs")
    return queries.run_page(_actor(request), _page(page, page_size)).as_dict()


@router.get("/runs/{run_id}/", response=ReportRunProjectionSchema, exclude_unset=True, operation_id="reports_run_detail")
def run_detail(request, run_id: UUID):
    prepare_api_operation(request, "reports_run_detail")
    value = queries.run_detail(_actor(request), str(run_id))
    if value is None:
        raise NotFoundError()
    return value


@router.post("/runs/", response=ReportRunResponseSchema, exclude_unset=True, operation_id="reports_run")
def run(request, payload: ReportRunSchema):
    command = ReportRunCommand(
        report_key=payload.report_key,
        filters=payload.filters,
        expected_definition_updated_at=payload.expected_definition_updated_at,
    )

    def execute():
        report_run, dataset = run_report_command(_actor(request), command)
        return ApiMutationOutcome(
            value=_run_response(report_run, dataset),
            related_object=report_run,
            safe_response_path=f"/api/v1/reports/runs/{report_run.id}/",
        )

    def replay(stored):
        run_object = queries._visible_run(_actor(request), stored.related_object_id) if stored.related_object_id else None
        if run_object is None:
            raise NotFoundError()
        return _run_response(run_object)

    return _run_mutation(request, "reports_run", _fingerprint(command), execute, replay)


@router.get("/exports/", response=ReportExportPageSchema, exclude_unset=True, operation_id="reports_exports")
def exports(request, page: PageQuery, page_size: PageSizeQuery):
    prepare_api_operation(request, "reports_exports")
    return queries.export_page(_actor(request), _page(page, page_size)).as_dict()


@router.get("/exports/{export_id}/", response=ReportExportProjectionSchema, exclude_unset=True, operation_id="reports_export_detail")
def export_detail(request, export_id: UUID):
    prepare_api_operation(request, "reports_export_detail")
    value = queries.export_detail(_actor(request), str(export_id))
    if value is None:
        raise NotFoundError()
    return value


@router.post("/exports/", response=ReportExportProjectionSchema, exclude_unset=True, operation_id="reports_export_create")
def create_export(request, payload: ReportExportSchema):
    command = ReportExportCommand(
        report_key=payload.report_key,
        export_format=payload.export_format,
        filters=payload.filters,
        purpose=payload.purpose,
        expected_definition_updated_at=payload.expected_definition_updated_at,
    )

    def execute():
        export_request = request_export_command(_actor(request), command)
        return ApiMutationOutcome(
            value=report_export_projection(export_request),
            related_object=export_request,
            safe_response_path=f"/api/v1/reports/exports/{export_request.id}/",
        )

    def replay(stored):
        value = queries.export_detail(_actor(request), stored.related_object_id)
        if value is None:
            raise NotFoundError()
        return value

    return _run_mutation(request, "reports_export_create", _fingerprint(command), execute, replay)


@router.post("/exports/{export_id}/generate/", response=ReportExportProjectionSchema, exclude_unset=True, operation_id="reports_export_generate")
def generate_export(request, export_id: UUID):
    export_id = str(export_id)
    export_request = queries.export_object(_actor(request), export_id)
    if export_request is None:
        raise NotFoundError()
    command = ReportExportLifecycleCommand(export_id=export_id, expected_status=export_request.status)

    def execute():
        updated = generate_report_export(_actor(request), export_id, command)
        return ApiMutationOutcome(
            value=report_export_projection(updated),
            related_object=updated,
            safe_response_path=f"/api/v1/reports/exports/{updated.id}/",
        )

    def replay(stored):
        value = queries.export_detail(_actor(request), stored.related_object_id)
        if value is None:
            raise NotFoundError()
        return value

    return _run_mutation(request, "reports_export_generate", _fingerprint(command, export_id=export_id), execute, replay)


@router.get(
    "/exports/{export_id}/download/",
    response=None,
    openapi_extra=binary_response_openapi(
        "application/pdf",
        "text/csv",
        description="Generated report export",
    ),
    operation_id="reports_export_download",
)
def download_export(request, export_id: UUID):
    export_id = str(export_id)
    prepare_api_operation(request, "reports_export_download")
    export_request = queries.export_object(_actor(request), export_id)
    if export_request is None:
        raise NotFoundError()
    download = download_report_export(_actor(request), export_id)
    content_type = "application/pdf" if download.export_format == "pdf" else "text/csv"
    response = HttpResponse(download.content, content_type=content_type)
    response["Content-Disposition"] = f'attachment; filename="report-export-{export_id}.{download.export_format}"'
    response["Cache-Control"] = "no-store, private"
    return response


@router.post("/exports/{export_id}/cancel/", response=ReportExportProjectionSchema, exclude_unset=True, operation_id="reports_export_cancel")
def cancel_export(request, export_id: UUID, payload: ReportLifecycleSchema = ReportLifecycleSchema()):
    return _lifecycle_mutation(request, "reports_export_cancel", export_id, payload, cancel_report_export)


@router.post("/exports/{export_id}/archive/", response=ReportExportProjectionSchema, exclude_unset=True, operation_id="reports_export_archive")
def archive_export(request, export_id: UUID, payload: ReportLifecycleSchema = ReportLifecycleSchema()):
    return _lifecycle_mutation(request, "reports_export_archive", export_id, payload, archive_report_export)


@router.post("/exports/{export_id}/expire/", response=ReportExportProjectionSchema, exclude_unset=True, operation_id="reports_export_expire")
def expire_export(request, export_id: UUID, payload: ReportLifecycleSchema = ReportLifecycleSchema()):
    return _lifecycle_mutation(request, "reports_export_expire", export_id, payload, expire_report_export)


def _lifecycle_mutation(request, operation_id, export_id, payload, service):
    export_id = str(export_id)
    export_request = queries.export_object(_actor(request), export_id)
    if export_request is None:
        raise NotFoundError()
    command = ReportExportLifecycleCommand(
        export_id=export_id,
        expected_status=payload.expected_status or export_request.status,
        reason=payload.reason,
    )

    def execute():
        updated = service(_actor(request), export_id, command)
        return ApiMutationOutcome(
            value=report_export_projection(updated),
            related_object=updated,
            safe_response_path=f"/api/v1/reports/exports/{updated.id}/",
        )

    def replay(stored):
        value = queries.export_detail(_actor(request), stored.related_object_id)
        if value is None:
            raise NotFoundError()
        return value

    return _run_mutation(request, operation_id, _fingerprint(command, export_id=export_id), execute, replay)
