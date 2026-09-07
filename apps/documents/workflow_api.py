"""HTTP adapter helpers for workflow-owned document output routes."""

from __future__ import annotations

from datetime import datetime as datetime_type

from ninja import Schema

from apps.common.api.idempotency import ApiMutationOutcome, run_api_mutation
from apps.common.api.operations import prepare_api_operation
from apps.common.api.response_docs import binary_response_openapi
from apps.common.contracts import to_json_object
from apps.common.exceptions import ValidationError
from apps.documents.commands import WorkflowDocumentGenerateCommand, WorkflowDocumentPreviewCommand
from apps.documents.response_adapters import response_for_artifact
from apps.documents.workflow_output import (
    download_workflow_document,
    generate_workflow_document,
    preview_workflow_document,
    replay_generated_document,
    _metadata,
)
from apps.security.downloads import protected_file_download_openapi


class GeneratedDocumentMetadataSchema(Schema):
    """Output-only metadata returned after official document generation."""

    reference_code: str
    document_status: str
    template_key: str
    template_version: str
    output_format: str
    content_type: str
    generated_at: datetime_type | None = None
    released_at: datetime_type | None = None


def workflow_preview_openapi() -> dict:
    """Document the renderer outputs used by workflow previews."""

    return binary_response_openapi(
        "application/pdf",
        "text/html",
        description="Rendered workflow preview",
    )


def workflow_download_openapi() -> dict:
    """Document workflow downloads delegated to protected storage."""

    return protected_file_download_openapi()


def actor_for(request):
    return getattr(getattr(request, "auth", None), "user", None)


def _safe_document_path(domain: str, target_reference: str) -> str:
    prefix = {
        "call_slips": "call-slips",
        "referrals": "referrals",
        "routine_interviews": "counseling/routine-interviews",
        "inventory": "inventory",
        "exit_interviews": "exit-interviews",
        "graduate_tracer": "graduate-tracer",
    }.get(domain)
    if not prefix:
        raise ValidationError("The document workflow is invalid.")
    return f"/api/v1/{prefix}/{target_reference}/document/"


def preview(request, *, operation_id: str, domain: str, stable_key: str, target_reference: str):
    prepare_api_operation(request, operation_id)
    command = WorkflowDocumentPreviewCommand(target_reference=target_reference, stable_key=stable_key)
    return response_for_artifact(preview_workflow_document(actor_for(request), domain, command))


def generate(
    request,
    *,
    operation_id: str,
    domain: str,
    stable_key: str,
    target_reference: str,
    expected_updated_at: str = "",
):
    actor = actor_for(request)
    command = WorkflowDocumentGenerateCommand(
        target_reference=target_reference,
        stable_key=stable_key,
        expected_updated_at=expected_updated_at,
    )
    prepared = prepare_api_operation(request, operation_id)
    payload = to_json_object({
        "target_reference": target_reference,
        "stable_key": stable_key,
        "expected_updated_at": expected_updated_at,
    })

    def _operation():
        document = generate_workflow_document(actor, domain, command)
        return ApiMutationOutcome(
            value=_metadata(document),
            related_object=document,
            safe_response_path=_safe_document_path(domain, target_reference),
        )

    def _replay(key):
        return replay_generated_document(actor, domain, getattr(key, "related_object_id", None))

    return run_api_mutation(
        request,
        operation_id,
        payload,
        _operation,
        _replay,
        prepared_operation=prepared,
    )


def download(request, *, operation_id: str, domain: str, stable_key: str, target_reference: str):
    prepare_api_operation(request, operation_id)
    from apps.documents.commands import WorkflowDocumentDownloadCommand

    command = WorkflowDocumentDownloadCommand(target_reference=target_reference, stable_key=stable_key)
    return download_workflow_document(actor_for(request), domain, command)
