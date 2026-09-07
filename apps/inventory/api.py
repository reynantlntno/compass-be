"""Client-facing Individual Inventory API.

Every route uses the shared operation preparation (no-store, correlation
headers, central rate limits) and, for state-changing operations, the shared
idempotency adapter.  Domain services receive actor + stable snapshot ID +
typed command only; the only flexible JSON at this boundary is the validated
Inventory answer object.
"""

from datetime import datetime as datetime_type

from ninja import Router, Schema

from apps.common.api.idempotency import ApiMutationOutcome, run_api_mutation
from apps.common.api.operations import prepare_api_operation
from apps.common.api.pagination import PageQuery, PageSizeQuery, page_request_from_values
from apps.common.api.schemas import PageResultSchema
from apps.common.contracts import ContractValidationError, to_json_object
from apps.common.exceptions import NotFoundError, ValidationError
from apps.inventory import queries as inventory_queries
from apps.inventory.commands import (
    InventoryDraftCommand,
    InventoryDraftCreateCommand,
    InventoryReopenCommand,
    InventorySubmitCommand,
)
from apps.inventory.services import (
    get_or_create_current_inventory_draft,
    reopen_inventory_for_correction,
    save_inventory_draft,
)
from apps.documents.workflow_api import (
    GeneratedDocumentMetadataSchema,
    download as workflow_document_download,
    generate as workflow_document_generate,
    preview as workflow_document_preview,
    workflow_download_openapi,
    workflow_preview_openapi,
)


router = Router(tags=["inventory"])


class InventorySnapshotSchema(Schema):
    """Output-only snapshot projection for owner and authorized staff views."""

    snapshot_id: str
    academic_year: str
    schema_version: str
    status: str
    schema_key: str | None = None
    submitted_at: datetime_type | None = None
    reopened_at: datetime_type | None = None
    updated_at: datetime_type | None = None
    student_profile_id: int | None = None
    answers: dict[str, object] | None = None


class InventoryPageResultSchema(PageResultSchema):
    items: list[InventorySnapshotSchema]


class InventoryHistoryEventSchema(Schema):
    """Output-only status/provenance history row."""

    history_id: str
    status_from: str
    status_to: str
    transitioned_at: datetime_type
    submission_sequence: int | None = None
    is_baseline: bool
    schema_version: str


class InventoryHistoryPageResultSchema(PageResultSchema):
    items: list[InventoryHistoryEventSchema]


class InventoryMutationResponseSchema(Schema):
    snapshot_id: str
    academic_year: str
    status: str


class DraftCreateSchema(Schema):
    academic_year: str


class DraftSaveSchema(Schema):
    answers: dict
    expected_updated_at: str | None = None


class SubmitSchema(Schema):
    privacy_acknowledged: bool
    expected_updated_at: str | None = None


class ReopenSchema(Schema):
    reason: str
    expected_state_token: str = ""


def _actor(request):
    return request.auth.user


def _page(page: PageQuery, page_size: PageSizeQuery):
    try:
        return page_request_from_values(page, page_size)
    except ContractValidationError as error:
        raise ValidationError() from error


def _run(request, operation_id, payload, operation):
    prepared = prepare_api_operation(request, operation_id)
    return run_api_mutation(
        request,
        operation_id,
        payload,
        operation,
        _replay,
        prepared_operation=prepared,
    )


def _replay(key):
    object_id = getattr(key, "related_object_id", None)
    if not object_id:
        return None
    return inventory_queries.replay_snapshot(object_id)


@router.get("/", response=InventoryPageResultSchema, operation_id="inventory_list")
def list_inventory(request, page: PageQuery, page_size: PageSizeQuery):
    prepare_api_operation(request, "inventory_list")
    return inventory_queries.scoped_snapshot_page(_actor(request), _page(page, page_size))


@router.get("/{snapshot_id}/history/", response=InventoryHistoryPageResultSchema, operation_id="inventory_history")
def inventory_history(request, snapshot_id: int, page: PageQuery, page_size: PageSizeQuery):
    prepare_api_operation(request, "inventory_history")
    history = inventory_queries.history_page(_actor(request), snapshot_id, _page(page, page_size))
    if history is None:
        raise NotFoundError()
    return history


@router.get(
    "/{snapshot_id}/document/preview/",
    response=None,
    openapi_extra=workflow_preview_openapi(),
    operation_id="inventory_document_preview",
)
def document_preview(request, snapshot_id: int):
    return workflow_document_preview(
        request, operation_id="inventory_document_preview", domain="inventory",
        stable_key="student_inventory", target_reference=snapshot_id,
    )


class DocumentGenerateSchema(Schema):
    expected_updated_at: str = ""


@router.post("/{snapshot_id}/document/generate/", response=GeneratedDocumentMetadataSchema, operation_id="inventory_document_generate")
def document_generate(request, snapshot_id: int, payload: DocumentGenerateSchema):
    return workflow_document_generate(
        request, operation_id="inventory_document_generate", domain="inventory",
        stable_key="student_inventory", target_reference=snapshot_id,
        expected_updated_at=payload.expected_updated_at,
    )


@router.get(
    "/{snapshot_id}/document/download/",
    response=None,
    openapi_extra=workflow_download_openapi(),
    operation_id="inventory_document_download",
)
def document_download(request, snapshot_id: int):
    return workflow_document_download(
        request, operation_id="inventory_document_download", domain="inventory",
        stable_key="student_inventory", target_reference=snapshot_id,
    )


@router.post("/drafts/", response=InventoryMutationResponseSchema, operation_id="inventory_draft_create")
def create_draft(request, payload: DraftCreateSchema):
    actor = _actor(request)
    command = InventoryDraftCreateCommand(academic_year=payload.academic_year)
    body = {"academic_year": payload.academic_year}

    def _operation():
        snapshot = get_or_create_current_inventory_draft(actor, command)
        return ApiMutationOutcome(
            value=inventory_queries.replay_snapshot(snapshot.pk),
            related_object=snapshot,
            safe_response_path=f"/api/v1/inventory/{snapshot.pk}/",
        )

    return _run(request, "inventory_draft_create", body, _operation)


# Register the static draft path before the generic snapshot path. Django
# resolves Ninja patterns in registration order, so this prevents ``drafts``
# from being captured as a snapshot reference and returning a method error.
@router.get("/{snapshot_id}/", response=InventorySnapshotSchema, operation_id="inventory_detail")
def inventory_detail(request, snapshot_id: int):
    prepare_api_operation(request, "inventory_detail")
    detail = inventory_queries.snapshot_detail(_actor(request), snapshot_id)
    if detail is None:
        raise NotFoundError()
    return detail


def _save_draft(request, snapshot_id: int, payload: DraftSaveSchema, operation_id: str):
    actor = _actor(request)
    try:
        answers = to_json_object(payload.answers)
    except (TypeError, ValueError) as error:
        raise ValidationError() from error
    command = InventoryDraftCommand(
        answers=answers,
        expected_updated_at=payload.expected_updated_at,
    )
    from apps.common.request_dedup import build_command_fingerprint

    body = {
        "snapshot_id": snapshot_id,
        "answers_fingerprint": build_command_fingerprint({"answers": answers}),
        "expected_updated_at": payload.expected_updated_at or "",
    }

    def _operation():
        snapshot = save_inventory_draft(actor, snapshot_id, command)
        return ApiMutationOutcome(
            value=inventory_queries.replay_snapshot(snapshot.pk),
            related_object=snapshot,
            safe_response_path=f"/api/v1/inventory/{snapshot.pk}/",
        )

    return _run(request, operation_id, body, _operation)


@router.put("/{snapshot_id}/", response=InventoryMutationResponseSchema, operation_id="inventory_draft_save")
def save_draft(request, snapshot_id: int, payload: DraftSaveSchema):
    return _save_draft(request, snapshot_id, payload, "inventory_draft_save")


@router.patch("/{snapshot_id}/", response=InventoryMutationResponseSchema, operation_id="inventory_draft_save_patch")
def patch_draft(request, snapshot_id: int, payload: DraftSaveSchema):
    return _save_draft(request, snapshot_id, payload, "inventory_draft_save_patch")


@router.post("/{snapshot_id}/submit/", response=InventoryMutationResponseSchema, operation_id="inventory_submit")
def submit_inventory(request, snapshot_id: int, payload: SubmitSchema):
    actor = _actor(request)
    command = InventorySubmitCommand(
        privacy_acknowledged=payload.privacy_acknowledged,
        expected_updated_at=payload.expected_updated_at,
    )
    body = {
        "snapshot_id": snapshot_id,
        "privacy_acknowledged": payload.privacy_acknowledged,
        "expected_updated_at": payload.expected_updated_at or "",
    }

    def _operation():
        from apps.orchestration.commands import InventorySubmitWorkflowCommand
        from apps.orchestration.use_cases import submit_inventory_workflow

        snapshot = submit_inventory_workflow(
            actor,
            InventorySubmitWorkflowCommand(
                snapshot_id,
                command.privacy_acknowledged,
                command.expected_updated_at,
            ),
        )
        return ApiMutationOutcome(
            value=inventory_queries.replay_snapshot(snapshot.pk),
            related_object=snapshot,
            safe_response_path=f"/api/v1/inventory/{snapshot.pk}/",
        )

    return _run(request, "inventory_submit", body, _operation)


@router.post("/{snapshot_id}/reopen/", response=InventoryMutationResponseSchema, operation_id="inventory_reopen")
def reopen_inventory(request, snapshot_id: int, payload: ReopenSchema):
    actor = _actor(request)
    command = InventoryReopenCommand(
        reason=payload.reason,
        expected_state_token=payload.expected_state_token,
    )
    from apps.common.request_dedup import build_command_fingerprint

    body = {
        "snapshot_id": snapshot_id,
        "reason_fingerprint": build_command_fingerprint({"reason": command.reason}),
        "expected_state_token": payload.expected_state_token,
    }

    def _operation():
        from apps.orchestration.commands import InventoryReopenWorkflowCommand
        from apps.orchestration.use_cases import reopen_inventory_workflow

        # The bounded reason is intentionally excluded from idempotency
        # metadata; it is stored only in the encrypted history row.
        snapshot = reopen_inventory_workflow(
            actor,
            InventoryReopenWorkflowCommand(
                snapshot_id=snapshot_id,
                reason=command.reason,
                expected_state_token=command.expected_state_token,
            ),
        )
        return ApiMutationOutcome(
            value=inventory_queries.replay_snapshot(snapshot.pk),
            related_object=snapshot,
            safe_response_path=f"/api/v1/inventory/{snapshot.pk}/",
        )

    return _run(request, "inventory_reopen", body, _operation)
