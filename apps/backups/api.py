"""Django Ninja API for safe IT backup and restore operations."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from ninja import Router, Schema

from apps.backups.commands import (
    BackupLifecycleCommand,
    BackupRequestCommand,
    RestoreAuthorizationCommand,
    RestoreDryRunCommand,
    RestoreRequestCommand,
    RestoreTransitionCommand,
)
from apps.backups.policies import (
    can_view_backup_dashboard,
    can_view_restore_metadata,
)
from apps.backups.projections import (
    backup_artifact_projection,
    backup_dashboard_projection,
    backup_job_projection,
    restore_dashboard_projection,
    restore_request_projection,
)
from apps.backups.queries import (
    backup_artifact_page,
    backup_job_detail,
    backup_job_page,
    restore_request_detail,
    restore_request_page,
)
from apps.backups.selectors import build_backup_dashboard_dto, build_restore_dashboard_dto
from apps.backups.services import (
    authorize_restore_by_id,
    cancel_backup_by_id,
    cancel_restore_by_id,
    dry_run_restore_by_id,
    queue_backup_by_id,
    request_backup_command,
    request_restore_command,
    verify_backup_by_id,
)
from apps.common.api.idempotency import ApiMutationOutcome, run_api_mutation
from apps.common.api.operations import prepare_api_operation
from apps.common.api.pagination import PageQuery, PageSizeQuery, page_request_from_values
from apps.common.api.schemas import PageResultSchema
from apps.common.contracts import ContractValidationError
from apps.common.exceptions import NotFoundError, PermissionDeniedError, ValidationError


router = Router(tags=["backups"])


class BackupArtifactProjectionSchema(Schema):
    """Output-only safe metadata for one recorded backup artifact."""

    id: str
    backup_job_id: str
    artifact_type: str
    size_bytes: int
    encryption_status: str
    created_at: datetime | None = None


class BackupJobProjectionSchema(Schema):
    """Output-only safe metadata for one backup job."""

    id: str
    scope: str
    status: str
    environment: str
    includes_database: bool
    includes_media: bool
    includes_protected_files: bool
    includes_manifest: bool
    encrypted_at_rest: bool
    storage_target_type: str
    retention_class: str
    artifact_count: int
    total_size_bytes: int
    safe_failure_reason_code: str | None = None
    requested_at: datetime | None = None
    queued_at: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    failed_at: datetime | None = None
    cancelled_at: datetime | None = None
    verified_at: datetime | None = None
    expires_at: datetime | None = None
    resource_version: datetime | None = None


class RestoreChecklistProjectionSchema(Schema):
    """Output-only safe checklist item for a restore request."""

    id: str
    step_key: str
    status: str
    safe_message_code: str | None = None
    recorded_at: datetime | None = None


class RestoreRequestProjectionSchema(Schema):
    """Output-only safe metadata for one restore request."""

    id: str
    target_backup_job_id: str
    restore_scope: str
    status: str
    safe_reason_code: str
    dry_run_result_code: str | None = None
    institutional_authorization_type: str
    authorization_recorded_at: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    failed_at: datetime | None = None
    cancelled_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    checklist: list[RestoreChecklistProjectionSchema]


class BackupJobPageSchema(PageResultSchema):
    items: list[BackupJobProjectionSchema]


class BackupArtifactPageSchema(PageResultSchema):
    items: list[BackupArtifactProjectionSchema]


class RestoreRequestPageSchema(PageResultSchema):
    items: list[RestoreRequestProjectionSchema]


class BackupDashboardSummarySchema(Schema):
    total_jobs: int
    queued_or_running_count: int
    archive_count: int
    verified_archive_count: int
    failed_count: int
    latest_job: BackupJobProjectionSchema | None = None


class RestoreDashboardSummarySchema(Schema):
    total_requests: int
    completed_count: int
    active_count: int
    latest_request: RestoreRequestProjectionSchema | None = None


class BackupDashboardSchema(Schema):
    backups: BackupDashboardSummarySchema
    restores: RestoreDashboardSummarySchema | None = None


class BackupRequestSchema(Schema):
    scope: str
    reason: str = "scheduled_backup"


class LifecycleSchema(Schema):
    expected_updated_at: str | None = None
    reason: str = ""


class RestoreRequestSchema(Schema):
    backup_job_id: UUID
    restore_scope: str
    reason: str


class RestoreAuthorizationSchema(Schema):
    authorization_type: str
    authorization_reference: str
    expected_updated_at: str | None = None


class RestoreDryRunSchema(Schema):
    expected_updated_at: str | None = None


class RestoreTransitionSchema(Schema):
    reason: str
    confirmation_phrase: str = ""
    expected_updated_at: str | None = None


def _actor(request):
    return request.auth.user


def _page(page: PageQuery, page_size: PageSizeQuery):
    try:
        return page_request_from_values(page, page_size)
    except ContractValidationError as exc:
        raise ValidationError() from exc


def _payload(payload):
    return payload.dict() if payload is not None else {}


def _require_view(actor):
    if not can_view_backup_dashboard(actor):
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


def _job_outcome(job):
    return ApiMutationOutcome(
        value=backup_job_projection(job),
        related_object=job,
        safe_response_path=f"/api/v1/backups/jobs/{job.pk}/",
    )


def _restore_outcome(restore_request):
    return ApiMutationOutcome(
        value=restore_request_projection(restore_request),
        related_object=restore_request,
        safe_response_path=f"/api/v1/backups/restores/{restore_request.pk}/",
    )


@router.get("/", response=BackupDashboardSchema, exclude_unset=True, operation_id="backups_dashboard")
def dashboard(request):
    actor = _actor(request)
    _require_view(actor)
    restore_summary = None
    if can_view_restore_metadata(actor):
        restore_summary = restore_dashboard_projection(build_restore_dashboard_dto(actor))
    return {
        "backups": backup_dashboard_projection(build_backup_dashboard_dto(actor)),
        "restores": restore_summary,
    }


@router.get("/jobs/", response=BackupJobPageSchema, operation_id="backups_jobs_list")
def list_jobs(request, page: PageQuery, page_size: PageSizeQuery):
    _require_view(_actor(request))
    return backup_job_page(_actor(request), _page(page, page_size))


@router.get("/jobs/{job_id}/", response=BackupJobProjectionSchema, exclude_unset=True, operation_id="backups_job_detail")
def job_detail(request, job_id: UUID):
    job_id = str(job_id)
    _require_view(_actor(request))
    value = backup_job_detail(_actor(request), job_id)
    if value is None:
        raise NotFoundError()
    return value


@router.get("/jobs/{job_id}/artifacts/", response=BackupArtifactPageSchema, operation_id="backups_artifacts_list")
def list_artifacts(request, job_id: UUID, page: PageQuery, page_size: PageSizeQuery):
    job_id = str(job_id)
    _require_view(_actor(request))
    if backup_job_detail(_actor(request), job_id) is None:
        raise NotFoundError()
    return backup_artifact_page(_actor(request), job_id, _page(page, page_size))


@router.post("/jobs/", response=BackupJobProjectionSchema, exclude_unset=True, operation_id="backups_job_request")
def request_job(request, payload: BackupRequestSchema):
    actor = _actor(request)
    command = BackupRequestCommand(scope=payload.scope, reason=payload.reason)
    return _run(
        request,
        "backups_job_request",
        _payload(payload),
        lambda: _job_outcome(request_backup_command(actor, command)),
        lambda key: backup_job_detail(actor, key.related_object_id),
    )


@router.post("/jobs/{job_id}/queue/", response=BackupJobProjectionSchema, exclude_unset=True, operation_id="backups_job_queue")
def queue_job(request, job_id: UUID, payload: LifecycleSchema):
    job_id = str(job_id)
    actor = _actor(request)
    command = BackupLifecycleCommand(
        expected_updated_at=payload.expected_updated_at,
        reason=payload.reason,
    )
    return _run(
        request,
        "backups_job_queue",
        {"job_id": job_id, **_payload(payload)},
        lambda: _job_outcome(queue_backup_by_id(actor, job_id, command)),
        lambda key: backup_job_detail(actor, key.related_object_id or job_id),
    )


@router.post("/jobs/{job_id}/verify/", response=BackupJobProjectionSchema, exclude_unset=True, operation_id="backups_job_verify")
def verify_job(request, job_id: UUID, payload: LifecycleSchema):
    job_id = str(job_id)
    actor = _actor(request)
    command = BackupLifecycleCommand(
        expected_updated_at=payload.expected_updated_at,
        reason=payload.reason,
    )
    return _run(
        request,
        "backups_job_verify",
        {"job_id": job_id, **_payload(payload)},
        lambda: _job_outcome(verify_backup_by_id(actor, job_id, command)),
        lambda key: backup_job_detail(actor, key.related_object_id or job_id),
    )


@router.post("/jobs/{job_id}/cancel/", response=BackupJobProjectionSchema, exclude_unset=True, operation_id="backups_job_cancel")
def cancel_job(request, job_id: UUID, payload: LifecycleSchema):
    job_id = str(job_id)
    actor = _actor(request)
    command = BackupLifecycleCommand(
        expected_updated_at=payload.expected_updated_at,
        reason=payload.reason,
    )
    return _run(
        request,
        "backups_job_cancel",
        {"job_id": job_id, **_payload(payload)},
        lambda: _job_outcome(cancel_backup_by_id(actor, job_id, command)),
        lambda key: backup_job_detail(actor, key.related_object_id or job_id),
    )


@router.get("/restores/", response=RestoreRequestPageSchema, operation_id="backups_restores_list")
def list_restores(request, page: PageQuery, page_size: PageSizeQuery):
    if not can_view_restore_metadata(_actor(request)):
        raise PermissionDeniedError()
    return restore_request_page(_actor(request), _page(page, page_size))


@router.get("/restores/{request_id}/", response=RestoreRequestProjectionSchema, exclude_unset=True, operation_id="backups_restore_detail")
def restore_detail(request, request_id: UUID):
    request_id = str(request_id)
    if not can_view_restore_metadata(_actor(request)):
        raise PermissionDeniedError()
    value = restore_request_detail(_actor(request), request_id)
    if value is None:
        raise NotFoundError()
    return value


@router.post("/restores/", response=RestoreRequestProjectionSchema, exclude_unset=True, operation_id="backups_restore_request")
def create_restore(request, payload: RestoreRequestSchema):
    actor = _actor(request)
    command = RestoreRequestCommand(
        backup_job_id=str(payload.backup_job_id),
        restore_scope=payload.restore_scope,
        reason=payload.reason,
    )
    return _run(
        request,
        "backups_restore_request",
        _payload(payload),
        lambda: _restore_outcome(request_restore_command(actor, command)),
        lambda key: restore_request_detail(actor, key.related_object_id),
    )


@router.post("/restores/{request_id}/authorize/", response=RestoreRequestProjectionSchema, exclude_unset=True, operation_id="backups_restore_authorize")
def authorize_restore(request, request_id: UUID, payload: RestoreAuthorizationSchema):
    request_id = str(request_id)
    actor = _actor(request)
    command = RestoreAuthorizationCommand(
        authorization_type=payload.authorization_type,
        authorization_reference=payload.authorization_reference,
        expected_updated_at=payload.expected_updated_at,
    )
    return _run(
        request,
        "backups_restore_authorize",
        {"request_id": request_id, **_payload(payload)},
        lambda: _restore_outcome(authorize_restore_by_id(actor, request_id, command)),
        lambda key: restore_request_detail(actor, key.related_object_id or request_id),
    )


@router.post("/restores/{request_id}/dry-run/", response=RestoreRequestProjectionSchema, exclude_unset=True, operation_id="backups_restore_dry_run")
def dry_run_restore(request, request_id: UUID, payload: RestoreDryRunSchema):
    request_id = str(request_id)
    actor = _actor(request)
    command = RestoreDryRunCommand(expected_updated_at=payload.expected_updated_at)
    return _run(
        request,
        "backups_restore_dry_run",
        {"request_id": request_id, **_payload(payload)},
        lambda: _restore_outcome(dry_run_restore_by_id(actor, request_id, command)),
        lambda key: restore_request_detail(actor, key.related_object_id or request_id),
    )


def _restore_transition(request, request_id: UUID | str, payload, operation_id, operation):
    request_id = str(request_id)
    actor = _actor(request)
    command = RestoreTransitionCommand(
        reason=payload.reason,
        confirmation_phrase=payload.confirmation_phrase,
        expected_updated_at=payload.expected_updated_at,
    )
    return _run(
        request,
        operation_id,
        {"request_id": request_id, "reason": command.reason, "expected_updated_at": command.expected_updated_at},
        lambda: _restore_outcome(operation(actor, request_id, command)),
        lambda key: restore_request_detail(actor, key.related_object_id or request_id),
    )


@router.post("/restores/{request_id}/cancel/", response=RestoreRequestProjectionSchema, exclude_unset=True, operation_id="backups_restore_cancel")
def cancel_restore(request, request_id: UUID, payload: RestoreTransitionSchema):
    return _restore_transition(request, request_id, payload, "backups_restore_cancel", cancel_restore_by_id)
