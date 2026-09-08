"""Django Ninja API for the governed student onboarding workflow."""

from __future__ import annotations

import hashlib
from datetime import datetime

from ninja import File, Form, Query, Router, Schema, UploadedFile

from apps.common.api.idempotency import ApiMutationOutcome, run_api_mutation
from apps.common.api.operations import prepare_api_operation
from apps.common.api.pagination import PageQuery, PageSizeQuery, page_request_from_values
from apps.common.api.schemas import PageResultSchema
from apps.common.contracts import ContractValidationError
from apps.common.exceptions import NotFoundError, PermissionDeniedError, ValidationError
from apps.common.request_dedup import hash_request_key
from apps.imports import queries
from apps.imports.commands import (
    ActivationInvitationIssueCommand,
    ActivationInvitationReissueCommand,
    ActivationInvitationRevokeCommand,
    ImportBatchCreateCommand,
    ImportBatchExecuteCommand,
    ImportBatchLifecycleCommand,
    ImportBatchReplacementCommand,
    ImportRowCorrectionCommand,
    ImportRowDecisionCommand,
    ImportRowReconciliationCommand,
)
from apps.imports.onboarding import (
    acknowledge_unlinked_boundary_by_id,
    approve_onboarding_batch_by_id,
    correct_onboarding_row_by_id,
    execute_onboarding_batch_by_id,
    exclude_onboarding_row_by_id,
    issue_onboarding_invitations_by_batch_id,
    _max_upload_bytes,
    reconcile_onboarding_row_by_id,
    replace_onboarding_batch_by_id,
    stage_onboarding_batch,
    validate_onboarding_batch_by_id,
)
from apps.imports.policies import (
    can_edit_student_onboarding,
    can_operate_activation_delivery,
    can_view_student_onboarding,
)
from apps.imports.projections import batch_projection, row_editor_projection, row_projection
from apps.student_activation.services import revoke_activation_invitation_by_id
from apps.orchestration.commands import StudentActivationInvitationReissueCommand
from apps.orchestration.use_cases import reissue_student_activation_invitation_for_import
from apps.student_activation.models import StudentActivationInvitation


router = Router(tags=["student onboarding"])


class ImportExecutionSummarySchema(Schema):
    """Output-only bounded counts from one onboarding execution."""

    success: int | None = None
    reconciled: int | None = None
    excluded: int | None = None
    total: int | None = None


class ImportBatchSchema(Schema):
    """Output-only import batch projection."""

    id: str
    source_name: str
    academic_year: str
    status: str
    template_version: str
    catalog_version: str
    content_present: bool
    row_count: int
    validation_revision: int
    validated_at: datetime | None
    approved_at: datetime | None
    approval_revoked_at: datetime | None
    executed_at: datetime | None
    execution_summary: ImportExecutionSummarySchema


class ImportBatchPageSchema(PageResultSchema):
    items: list[ImportBatchSchema]


class ImportCatalogPlacementSchema(Schema):
    """Output-only approved or demo catalog placement."""

    program_code: str
    campus: str
    college: str
    department: str
    program: str
    max_year_level: int


class ImportCatalogPageSchema(PageResultSchema):
    items: list[ImportCatalogPlacementSchema]
    version: str
    demo_only: bool


class ImportRowPlacementSchema(Schema):
    campus: str
    college: str
    department: str
    program: str
    program_code: str
    year_level: int | None


class ImportRowEditableFieldsSchema(Schema):
    """Existing allowlisted correction fields exposed only to authorized editors."""

    student_number: str
    control_number: str
    email: str
    first_name: str
    last_name: str
    program_code: str
    campus: str
    college: str
    department: str
    program: str
    year_level: int | None
    lifecycle_status: str


class ImportRowSchema(Schema):
    """Output-only redacted row projection with an optional editor view."""

    id: str
    row_number: int
    status: str
    error_code: str
    error: str
    masked_email: str
    has_student_number: bool
    has_control_number: bool
    initials: str
    placement: ImportRowPlacementSchema
    correction_revision: int
    reviewed_at: datetime | None
    editable_fields: ImportRowEditableFieldsSchema | None = None


class ImportRowPageSchema(PageResultSchema):
    items: list[ImportRowSchema]


class ImportInvitationSchema(Schema):
    """Output-only activation invitation projection without the token."""

    id: str
    status: str
    expires_at: datetime
    used_at: datetime | None
    revoked_at: datetime | None
    delivery_state: str


class ImportInvitationPageSchema(PageResultSchema):
    items: list[ImportInvitationSchema]


class ImportBatchExecutionResponseSchema(ImportBatchSchema):
    """Batch execution response; replay may omit the execution counts."""

    execution_result: ImportExecutionSummarySchema | None = None


class ImportInvitationIssueResponseSchema(Schema):
    """Explicit superset for issuance counts and the existing replay receipt."""

    issued: int | None = None
    skipped: int | None = None
    eligible: int | None = None
    status: str | None = None
    batch_id: str | None = None


class LifecycleSchema(Schema):
    expected_updated_at: str | None = None
    reason: str = ""


class RowCorrectionSchema(Schema):
    student_number: str | None = None
    control_number: str | None = None
    email: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    program_code: str | None = None
    campus: str | None = None
    college: str | None = None
    department: str | None = None
    program: str | None = None
    year_level: int | None = None
    lifecycle_status: str | None = None
    expected_updated_at: str | None = None


class ReconciliationSchema(Schema):
    student_profile_id: int
    reason: str = ""
    expected_updated_at: str | None = None


class ExecuteSchema(Schema):
    expected_updated_at: str | None = None


class InvitationReasonSchema(Schema):
    reason: str = "manual_reissue"
    expected_updated_at: str | None = None


def _actor(request):
    return request.auth.user


def _page(page: PageQuery, page_size: PageSizeQuery):
    try:
        return page_request_from_values(page, page_size)
    except ContractValidationError as exc:
        raise ValidationError() from exc


def _run(request, operation_id, payload, operation, replay, *, prepared=None):
    prepared = prepared or prepare_api_operation(request, operation_id)
    return run_api_mutation(
        request,
        operation_id,
        payload,
        operation,
        replay,
        prepared_operation=prepared,
    )


def _batch_response(batch):
    return batch_projection(batch)


def _row_response(row, *, editor=False):
    return row_editor_projection(row) if editor else row_projection(row)


@router.get("/", response=ImportBatchPageSchema, exclude_unset=True, operation_id="imports_list")
def list_batches(request, page: PageQuery, page_size: PageSizeQuery):
    return queries.batch_page(_actor(request), _page(page, page_size))


@router.get("/catalog/", response=ImportCatalogPageSchema, exclude_unset=True, operation_id="imports_catalog")
def catalog(request, page: PageQuery, page_size: PageSizeQuery):
    if not can_view_student_onboarding(_actor(request)):
        raise PermissionDeniedError()
    return queries.catalog_page(_page(page, page_size))


@router.get(
    "/invitations/{invitation_id}/",
    response=ImportInvitationSchema,
    exclude_unset=True,
    operation_id="imports_invitation_detail",
)
def invitation_detail(request, invitation_id: int):
    value = queries.invitation_detail(_actor(request), invitation_id)
    if value is None:
        raise NotFoundError()
    return value


@router.post(
    "/invitations/{invitation_id}/reissue/",
    response=ImportInvitationSchema,
    exclude_unset=True,
    operation_id="imports_invitation_reissue",
)
def reissue_invitation(request, invitation_id: int, payload: InvitationReasonSchema):
    actor = _actor(request)
    if not can_operate_activation_delivery(actor):
        raise PermissionDeniedError()
    if not queries.onboarding_invitation_exists(invitation_id):
        raise NotFoundError()
    command = ActivationInvitationReissueCommand(
        reason=payload.reason,
        expected_updated_at=payload.expected_updated_at,
    )
    return _run(
        request,
        "imports_invitation_reissue",
        {"invitation_id": invitation_id, "reason": command.reason, "expected_updated_at": command.expected_updated_at},
        lambda: _invitation_mutation_outcome(
            actor,
            invitation_id,
            reissue_student_activation_invitation_for_import(
                actor,
                StudentActivationInvitationReissueCommand(
                    invitation_id=invitation_id,
                    reason=command.reason,
                    expected_updated_at=command.expected_updated_at,
                ),
            ),
        ),
        lambda key: queries.invitation_detail(actor, key.related_object_id or invitation_id),
    )


@router.post(
    "/invitations/{invitation_id}/revoke/",
    response=ImportInvitationSchema,
    exclude_unset=True,
    operation_id="imports_invitation_revoke",
)
def revoke_invitation(request, invitation_id: int, payload: InvitationReasonSchema):
    actor = _actor(request)
    if not can_operate_activation_delivery(actor):
        raise PermissionDeniedError()
    if not queries.onboarding_invitation_exists(invitation_id):
        raise NotFoundError()
    command = ActivationInvitationRevokeCommand(
        reason=payload.reason,
        expected_updated_at=payload.expected_updated_at,
    )
    return _run(
        request,
        "imports_invitation_revoke",
        {"invitation_id": invitation_id, "reason": command.reason, "expected_updated_at": command.expected_updated_at},
        lambda: _invitation_mutation_outcome(
            actor,
            invitation_id,
            revoke_activation_invitation_by_id(
                invitation_id,
                actor_user=actor,
                reason=command.reason,
                expected_updated_at=command.expected_updated_at,
            ),
        ),
        lambda key: queries.invitation_detail(actor, key.related_object_id or invitation_id),
    )


@router.post("/", response=ImportBatchSchema, exclude_unset=True, operation_id="imports_create")
def create_batch(
    request,
    file: UploadedFile = File(...),
    source_name: str = Form(...),
    academic_year: str = Form(...),
):
    actor = _actor(request)
    prepared = prepare_api_operation(request, "imports_create")
    upload = file
    if int(getattr(upload, "size", 0) or 0) > _max_upload_bytes():
        raise ValidationError("Upload exceeds the permitted size.")
    raw = upload.read()
    command = ImportBatchCreateCommand(
        source_name=source_name,
        academic_year=academic_year,
        filename=str(getattr(upload, "name", "") or ""),
        content_type=str(getattr(upload, "content_type", "") or ""),
    )
    digest = hashlib.sha256(raw).hexdigest()
    return _run(
        request,
        "imports_create",
        {"source_name": command.source_name, "academic_year": command.academic_year, "content_digest": digest},
        lambda: _create_batch_outcome(actor, command, raw),
        lambda key: queries.batch_detail(actor, key.related_object_id) if key.related_object_id else None,
        prepared=prepared,
    )


def _create_batch_outcome(actor, command, raw):
    batch = stage_onboarding_batch(actor_user=actor, command=command, upload=raw)
    return ApiMutationOutcome(
        value=_batch_response(batch),
        related_object=batch,
        safe_response_path=f"/api/v1/imports/{batch.pk}/",
    )


@router.get("/{batch_id}/", response=ImportBatchSchema, exclude_unset=True, operation_id="imports_detail")
def batch_detail(request, batch_id: int):
    value = queries.batch_detail(_actor(request), batch_id)
    if value is None:
        raise NotFoundError()
    return value


@router.get("/{batch_id}/preview/", response=ImportRowPageSchema, exclude_unset=True, operation_id="imports_preview")
def preview(
    request,
    batch_id: int,
    page: PageQuery,
    page_size: PageSizeQuery,
    editor: bool = Query(default=False),
):
    actor = _actor(request)
    if editor and not can_edit_student_onboarding(actor):
        raise PermissionDeniedError()
    return queries.row_page(actor, batch_id, _page(page, page_size), editor=editor)


@router.get(
    "/{batch_id}/invitations/",
    response=ImportInvitationPageSchema,
    exclude_unset=True,
    operation_id="imports_invitation_list",
)
def invitations(request, batch_id: int, page: PageQuery, page_size: PageSizeQuery):
    return queries.invitation_page(_actor(request), batch_id, _page(page, page_size))


@router.post("/{batch_id}/validate/", response=ImportBatchSchema, exclude_unset=True, operation_id="imports_validate")
def validate_batch(request, batch_id: int, payload: LifecycleSchema):
    actor = _actor(request)
    command = ImportBatchLifecycleCommand(
        expected_updated_at=payload.expected_updated_at,
        reason=payload.reason,
    )
    return _run(
        request,
        "imports_validate",
        {"batch_id": batch_id, "expected_updated_at": command.expected_updated_at},
        lambda: _batch_mutation_outcome(validate_onboarding_batch_by_id(actor_user=actor, batch_id=batch_id, command=command)),
        lambda key: queries.batch_detail(actor, key.related_object_id),
    )


def _batch_mutation_outcome(batch):
    return ApiMutationOutcome(value=_batch_response(batch), related_object=batch, safe_response_path=f"/api/v1/imports/{batch.pk}/")


def _invitation_mutation_outcome(actor, invitation_id, receipt):
    invitation = StudentActivationInvitation.objects.filter(pk=receipt.invitation_id).first()
    if invitation is None:
        raise NotFoundError()
    return ApiMutationOutcome(
        value=queries.invitation_detail(actor, str(invitation.pk)),
        related_object=invitation,
        safe_response_path=f"/api/v1/imports/invitations/{invitation.pk}/",
    )


def _row_mutation_outcome(actor, batch_id, row_id, operation, *, editor=False):
    row = operation()
    return ApiMutationOutcome(
        value=_row_response(row, editor=editor),
        related_object=row,
        safe_response_path=f"/api/v1/imports/{batch_id}/preview/",
    )


@router.post("/{batch_id}/replace/", response=ImportBatchSchema, exclude_unset=True, operation_id="imports_replace")
def replace_batch(
    request,
    batch_id: int,
    file: UploadedFile = File(...),
    source_name: str = Form(...),
    academic_year: str = Form(...),
    expected_updated_at: str | None = Form(default=None),
):
    actor = _actor(request)
    prepared = prepare_api_operation(request, "imports_replace")
    upload = file
    if int(getattr(upload, "size", 0) or 0) > _max_upload_bytes():
        raise ValidationError("Upload exceeds the permitted size.")
    raw = upload.read()
    command = ImportBatchReplacementCommand(
        source_name=source_name,
        academic_year=academic_year,
        filename=str(getattr(upload, "name", "") or ""),
        content_type=str(getattr(upload, "content_type", "") or ""),
        expected_updated_at=expected_updated_at or None,
    )
    return _run(
        request,
        "imports_replace",
        {"batch_id": batch_id, "academic_year": command.academic_year, "content_digest": hashlib.sha256(raw).hexdigest()},
        lambda: _batch_mutation_outcome(replace_onboarding_batch_by_id(actor_user=actor, batch_id=batch_id, command=command, upload=raw)),
        lambda key: queries.batch_detail(actor, key.related_object_id),
        prepared=prepared,
    )


@router.post("/{batch_id}/approve/", response=ImportBatchSchema, exclude_unset=True, operation_id="imports_approve")
def approve_batch(request, batch_id: int, payload: LifecycleSchema):
    actor = _actor(request)
    command = ImportBatchLifecycleCommand(expected_updated_at=payload.expected_updated_at, reason=payload.reason)
    return _run(
        request,
        "imports_approve",
        {"batch_id": batch_id, "expected_updated_at": command.expected_updated_at},
        lambda: _batch_mutation_outcome(approve_onboarding_batch_by_id(actor_user=actor, batch_id=batch_id, command=command)),
        lambda key: queries.batch_detail(actor, key.related_object_id),
    )


@router.post(
    "/{batch_id}/execute/",
    response=ImportBatchExecutionResponseSchema,
    exclude_unset=True,
    operation_id="imports_execute",
)
def execute_batch(request, batch_id: int, payload: ExecuteSchema):
    actor = _actor(request)
    prepared = prepare_api_operation(request, "imports_execute")
    digest = hash_request_key(prepared.idempotency_key or "", purpose="imports.batch.execute")
    command = ImportBatchExecuteCommand(expected_updated_at=payload.expected_updated_at, request_key_digest=digest)

    def execute():
        batch = execute_onboarding_batch_by_id(actor_user=actor, batch_id=batch_id, command=command)
        current = queries.batch_object(batch_id)
        if current is None:
            raise NotFoundError()
        value = _batch_response(current)
        value["execution_result"] = {key: int(batch.get(key, 0) or 0) for key in ("success", "reconciled", "excluded", "total") if key in batch}
        return ApiMutationOutcome(value=value, related_object=current, safe_response_path=f"/api/v1/imports/{batch_id}/")

    def replay(key):
        value = queries.batch_detail(actor, key.related_object_id or batch_id)
        return value

    return _run(
        request,
        "imports_execute",
        {"batch_id": batch_id, "expected_updated_at": command.expected_updated_at},
        execute,
        replay,
        prepared=prepared,
    )


@router.post(
    "/{batch_id}/rows/{row_id}/correct/",
    response=ImportRowSchema,
    exclude_unset=True,
    operation_id="imports_row_correct",
)
def correct_row(request, batch_id: int, row_id: int, payload: RowCorrectionSchema):
    data = payload.dict(exclude_unset=True)
    command = ImportRowCorrectionCommand(**data)
    actor = _actor(request)
    return _run(
        request,
        "imports_row_correct",
        {"batch_id": batch_id, "row_id": row_id, "expected_updated_at": command.expected_updated_at, "correction_revision": len(data)},
        lambda: _row_mutation_outcome(actor, batch_id, row_id, lambda: correct_onboarding_row_by_id(actor_user=actor, row_id=row_id, command=command), editor=True),
        lambda key: queries.row_detail(actor, batch_id, key.related_object_id, editor=True),
    )


@router.post(
    "/{batch_id}/rows/{row_id}/reconcile/",
    response=ImportRowSchema,
    exclude_unset=True,
    operation_id="imports_row_reconcile",
)
def reconcile_row(request, batch_id: int, row_id: int, payload: ReconciliationSchema):
    actor = _actor(request)
    command = ImportRowReconciliationCommand(
        student_profile_id=payload.student_profile_id,
        reason=payload.reason,
        expected_updated_at=payload.expected_updated_at,
    )
    return _run(request, "imports_row_reconcile", {"batch_id": batch_id, "row_id": row_id, "student_profile_id": command.student_profile_id}, lambda: _row_mutation_outcome(actor, batch_id, row_id, lambda: reconcile_onboarding_row_by_id(actor_user=actor, row_id=row_id, command=command), editor=False), lambda key: queries.row_detail(actor, batch_id, key.related_object_id, editor=False))


@router.post(
    "/{batch_id}/rows/{row_id}/exclude/",
    response=ImportRowSchema,
    exclude_unset=True,
    operation_id="imports_row_exclude",
)
def exclude_row(request, batch_id: int, row_id: int, payload: LifecycleSchema):
    actor = _actor(request)
    command = ImportRowDecisionCommand(reason=payload.reason, expected_updated_at=payload.expected_updated_at)
    return _run(request, "imports_row_exclude", {"batch_id": batch_id, "row_id": row_id, "expected_updated_at": command.expected_updated_at}, lambda: _row_mutation_outcome(actor, batch_id, row_id, lambda: exclude_onboarding_row_by_id(actor_user=actor, row_id=row_id, command=command), editor=False), lambda key: queries.row_detail(actor, batch_id, key.related_object_id, editor=False))


@router.post(
    "/{batch_id}/rows/{row_id}/acknowledge-boundary/",
    response=ImportRowSchema,
    exclude_unset=True,
    operation_id="imports_row_acknowledge_boundary",
)
def acknowledge_boundary(request, batch_id: int, row_id: int, payload: LifecycleSchema):
    actor = _actor(request)
    command = ImportRowDecisionCommand(reason=payload.reason, expected_updated_at=payload.expected_updated_at)
    return _run(request, "imports_row_acknowledge_boundary", {"batch_id": batch_id, "row_id": row_id, "expected_updated_at": command.expected_updated_at}, lambda: _row_mutation_outcome(actor, batch_id, row_id, lambda: acknowledge_unlinked_boundary_by_id(actor_user=actor, row_id=row_id, command=command), editor=False), lambda key: queries.row_detail(actor, batch_id, key.related_object_id, editor=False))


@router.post(
    "/{batch_id}/invitations/issue/",
    response=ImportInvitationIssueResponseSchema,
    exclude_unset=True,
    operation_id="imports_invitation_issue",
)
def issue_invitations(request, batch_id: int, payload: LifecycleSchema):
    actor = _actor(request)
    command = ActivationInvitationIssueCommand(expected_updated_at=payload.expected_updated_at)
    result = _run(
        request,
        "imports_invitation_issue",
        {"batch_id": batch_id, "expected_updated_at": payload.expected_updated_at},
        lambda: ApiMutationOutcome(value=issue_onboarding_invitations_by_batch_id(actor_user=actor, batch_id=batch_id, command=command), related_object=queries.batch_object(batch_id), safe_response_path=f"/api/v1/imports/{batch_id}/"),
        lambda _key: {"status": "completed", "batch_id": batch_id},
    )
    return result
