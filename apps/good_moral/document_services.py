# Project: COMPASS
# File: apps/good_moral/document_services.py
# Module: apps.good_moral
# Purpose: Bridge GoodMoralRequest with the document generation engine
# Domain boundary and service policy.

import logging
from django.db import transaction
from django.utils import timezone

from apps.documents.models import (
    DocumentStatusChoices,
    DocumentTemplateVersion,
    GeneratedDocument,
    OutputFormatChoices,
    RendererBackendChoices,
    TemplateStatusChoices,
)
from apps.documents.services import DocumentServiceError
from apps.orchestration.commands import DocumentRenderCommand
from apps.orchestration.use_cases import render_document_for_composition
from apps.good_moral.models import GoodMoralRequest, GoodMoralStatusChoices, RequestTypeChoices
from apps.organizations.models import GovernanceStatusChoices
from apps.good_moral.template_context import (
    build_student_gmc_context,
    build_graduate_gmc_context,
)
from apps.good_moral.policies import can_generate_request_document
from apps.audit.services import audit_log
from apps.common.exceptions import DependencyFailureError, NotFoundError, PermissionDeniedError, ValidationError

logger = logging.getLogger(__name__)


class GoodMoralGenerationError(DependencyFailureError):
    """Raised when Good Moral document generation fails."""
    pass


def _is_official_pdf_document(document) -> bool:
    protected_file = getattr(document, "protected_file", None)
    template_version = getattr(document, "template_version", None)
    snapshot = (getattr(document, "generation_context_snapshot_json", {}) or {}) if document else {}
    control = snapshot.get("document_control") if isinstance(snapshot, dict) else None
    return bool(
        document
        and protected_file
        and protected_file.content_type == "application/pdf"
        and template_version
        and template_version.output_format == OutputFormatChoices.PDF
        and template_version.renderer_backend == RendererBackendChoices.PLAYWRIGHT_PDF
        and isinstance(control, dict)
        and control.get("readiness") == "OFFICIAL"
        and document.document_status in (
            DocumentStatusChoices.GENERATED,
            DocumentStatusChoices.RELEASED,
        )
    )


def _find_existing_official_pdf(request: GoodMoralRequest):
    if _is_official_pdf_document(request.generated_document):
        return request.generated_document
    return (
        GeneratedDocument.objects
        .filter(
            owning_app_label="good_moral",
            owning_model_name="GoodMoralRequest",
            owning_object_id=str(request.pk),
            protected_file__content_type="application/pdf",
            template_version__output_format=OutputFormatChoices.PDF,
            template_version__renderer_backend=RendererBackendChoices.PLAYWRIGHT_PDF,
            document_status__in=(
                DocumentStatusChoices.GENERATED,
                DocumentStatusChoices.RELEASED,
            ),
        )
        .select_related("template_version", "protected_file")
        .order_by("-generated_at", "-created_at")
        .first()
    )


def _enforce_generation_prerequisite(request):
    from apps.good_moral.exit_prerequisite import enforce_exit_prerequisite, ExitPrerequisiteError

    try:
        enforce_exit_prerequisite(request, gate="generation")
    except ExitPrerequisiteError as exc:
        raise GoodMoralGenerationError(str(exc)) from exc


def _good_moral_template_key(request: GoodMoralRequest) -> str:
    from apps.good_moral.lifecycle import GoodMoralVariantError, validate_request_variant

    try:
        request_type = validate_request_variant(request)
    except GoodMoralVariantError as exc:
        raise GoodMoralGenerationError(str(exc)) from exc
    if request_type == RequestTypeChoices.STUDENT:
        return "good_moral_student"
    if request_type == RequestTypeChoices.GRADUATE:
        return "good_moral_graduate"
    raise GoodMoralGenerationError(f"Unknown request type '{request.request_type}'.")


def resolve_good_moral_template_version(request: GoodMoralRequest):
    """Resolve the governed active PDF template for a Good Moral variant."""
    template_key = _good_moral_template_key(request)
    version = (
        DocumentTemplateVersion.objects.filter(
            template__stable_key=template_key,
            template__status=TemplateStatusChoices.ACTIVE,
            status=TemplateStatusChoices.ACTIVE,
        )
        .select_related(
            "template",
            "template__related_form_family",
            "related_form_revision",
            "related_form_revision__form_family",
        )
        .first()
    )
    if not version:
        raise GoodMoralGenerationError(
            f"No active template version found for '{template_key}'."
        )
    if (
        version.output_format != OutputFormatChoices.PDF
        or version.renderer_backend != RendererBackendChoices.PLAYWRIGHT_PDF
    ):
        raise GoodMoralGenerationError(
            "Official Good Moral certificate output requires an active PDF template version."
        )

    form_revision = version.related_form_revision
    form_snapshot = version.form_revision_snapshot or {}
    if (
        not form_revision
        or form_revision.status != GovernanceStatusChoices.ACTIVE
        or form_revision.form_family.current_active_revision_id != form_revision.pk
        or not form_snapshot.get("official_form_code")
        or not form_snapshot.get("official_revision")
        or form_snapshot.get("official_form_code") != form_revision.official_form_code
        or form_snapshot.get("official_revision") != form_revision.official_revision
    ):
        raise GoodMoralGenerationError(
            "Active Good Moral template version must be linked to the current governed form revision snapshot."
        )
    return version


def _generate_good_moral_document(user, request: GoodMoralRequest) -> GoodMoralRequest:
    """Generate and store the official PDF certificate for an approved request.

    HTML templates remain the source of truth, but official output must be a
    protected PDF generated through the shared document service.
    """
    if request.status not in (
        GoodMoralStatusChoices.APPROVED_FOR_GENERATION,
        GoodMoralStatusChoices.FAILED,
    ):
        raise GoodMoralGenerationError(
            f"Cannot generate document for request in status '{request.status}'."
        )

    if not can_generate_request_document(user, request):
        raise GoodMoralGenerationError("Permission denied: cannot generate request document.")
    if (
        not request.approved_by_id
        or not request.approved_at
        or not request.approval_signatory_name
        or not request.approval_signatory_title
    ):
        raise GoodMoralGenerationError("Human approval metadata is required before generation.")

    # 1. Resolve the governed active PDF template version.
    version = resolve_good_moral_template_version(request)
    from apps.good_moral.lifecycle import GoodMoralVariantError, validate_request_variant
    try:
        request_type = validate_request_variant(request)
    except GoodMoralVariantError as exc:
        raise GoodMoralGenerationError(str(exc)) from exc
    context_fn = (
        build_graduate_gmc_context
        if request_type == RequestTypeChoices.GRADUATE
        else build_student_gmc_context
    )

    existing_doc = _find_existing_official_pdf(request)
    if existing_doc:
        with transaction.atomic():
            request = GoodMoralRequest.objects.select_for_update().get(pk=request.pk)
            _enforce_generation_prerequisite(request)
            request.generated_document = existing_doc
            if request.status in (
                GoodMoralStatusChoices.APPROVED_FOR_GENERATION,
                GoodMoralStatusChoices.FAILED,
            ):
                request.status = GoodMoralStatusChoices.GENERATED
                request.generation_failure_code = ""
            request.save()
        return request

    # 3. Build render context
    try:
        render_context = context_fn(request)
    except Exception as exc:
        raise GoodMoralGenerationError(f"Failed to build render context: {exc}") from exc

    # 4. Generate the document via render_and_store_document
    try:
        with transaction.atomic():
            # Re-check under the request lock. The pre-lock reuse check is only
            # a fast path; this prevents two concurrent callers from creating
            # two official PDFs for the same request.
            request = GoodMoralRequest.objects.select_for_update().get(pk=request.pk)
            _enforce_generation_prerequisite(request)
            existing_doc = _find_existing_official_pdf(request)
            if existing_doc:
                request.generated_document = existing_doc
                request.status = GoodMoralStatusChoices.GENERATED
                request.generation_failure_code = ""
                request.save(update_fields=["generated_document", "status", "generation_failure_code", "updated_at"])
                return request
            if request.status not in (
                GoodMoralStatusChoices.APPROVED_FOR_GENERATION,
                GoodMoralStatusChoices.FAILED,
            ):
                raise GoodMoralGenerationError(
                    f"Cannot generate document for request in status '{request.status}'."
                )
            if not can_generate_request_document(user, request):
                raise GoodMoralGenerationError("Permission denied: cannot generate request document.")
            if (
                not request.approved_by_id
                or not request.approved_at
                or not request.approval_signatory_name
                or not request.approval_signatory_title
            ):
                raise GoodMoralGenerationError("Human approval metadata is required before generation.")

            # Update status to GENERATING as a lock/in-progress marker.
            request.status = GoodMoralStatusChoices.GENERATING
            request.save()

            doc = render_document_for_composition(
                user,
                DocumentRenderCommand(
                    template_version_id=str(version.pk),
                    render_context=render_context,
                    academic_year=request.applicant_academic_year,
                    form_revision_id=(
                        str(version.related_form_revision_id)
                        if version.related_form_revision_id is not None
                        else None
                    ),
                    owning_app_label="good_moral",
                    owning_model_name="GoodMoralRequest",
                    owning_object_id=str(request.pk),
                    access_policy_key="good_moral_request",
                    output_intent="OFFICIAL",
                    generated_for_user_id=str(request.requester_user_id),
                    system_context=True,
                ),
            )

            # Update request to GENERATED
            request.generated_document = doc
            request.generated_by = user
            request.generated_at = timezone.now()
            request.generation_failure_code = ""
            request.status = GoodMoralStatusChoices.GENERATED
            request.save()

            from apps.good_moral.notification_services import enqueue_good_moral_event
            enqueue_good_moral_event("generated", request)

    except GoodMoralGenerationError:
        raise
    except DocumentServiceError as exc:
        # Fallback to FAILED status and log the error code
        with transaction.atomic():
            request = GoodMoralRequest.objects.select_for_update().get(pk=request.pk)
            request.status = GoodMoralStatusChoices.FAILED
            request.generation_failure_code = getattr(exc, "error_code", "GENERATION_SERVICE_ERROR")
            request.save()
        raise GoodMoralGenerationError(f"Document generation engine failed: {exc}") from exc
    except Exception as exc:
        with transaction.atomic():
            request = GoodMoralRequest.objects.select_for_update().get(pk=request.pk)
            request.status = GoodMoralStatusChoices.FAILED
            request.generation_failure_code = "UNKNOWN_FAILURE"
            request.save()
        raise GoodMoralGenerationError(f"Unexpected generation failure: {exc}") from exc

    # Audit success
    audit_log(
        action_type="GOOD_MORAL_DOCUMENT_GENERATED",
        event_category="WORKFLOW",
        target_model="GoodMoralRequest",
        target_object_id=str(request.pk),
        actor_user=user,
        reference_code=request.reference_code,
        source_app="apps.good_moral",
        metadata={
            "model": "GoodMoralRequest",
            "object_id": str(request.pk),
            "reference_code": request.reference_code,
            "status": request.status,
            "generated_document_id": str(doc.pk),
            "reference_code_doc": doc.reference_code,
        },
    )

    return request


def generate_good_moral_document_by_reference(*, actor, reference_code: str) -> GoodMoralRequest:
    """Generate a Good Moral certificate from a stable reference code.

    This is the document boundary used by the Good Moral application service;
    model-oriented rendering remains private to this module.
    """
    from apps.access_control.rules import is_active_nonlegacy_actor

    if not is_active_nonlegacy_actor(actor):
        raise PermissionDeniedError()
    normalized = str(reference_code or "").strip()
    if not normalized or len(normalized) > 30:
        raise ValidationError("reference_code is invalid.")
    with transaction.atomic():
        try:
            request = GoodMoralRequest.objects.select_for_update().get(
                reference_code=normalized,
            )
        except GoodMoralRequest.DoesNotExist as exc:
            raise NotFoundError() from exc
        return _generate_good_moral_document(actor, request)
