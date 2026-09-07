"""Client-facing Graduate Tracer response API."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from ninja import Router, Schema

from apps.common.api.idempotency import ApiMutationOutcome, run_api_mutation
from apps.common.api.operations import prepare_api_operation
from apps.common.api.pagination import PageQuery, PageSizeQuery, page_request_from_values
from apps.common.api.schemas import PageResultSchema
from apps.common.contracts import ContractValidationError, to_json_object
from apps.common.exceptions import NotFoundError, ValidationError
from apps.common.form_values import ValidatedAnswerSet
from apps.common.verified_access import VerifiedFormAccessPrincipal
from apps.graduate_tracer import projections, queries
from apps.graduate_tracer.commands import (
    GraduateTracerDraftCommand,
    GraduateTracerLifecycleCommand,
    GraduateTracerStartCommand,
)
from apps.graduate_tracer.models import GraduateTracerResponse
from apps.form_collection.models import FormInvitation
from apps.form_collection.services import get_verified_invitation_for_destination
from apps.graduate_tracer.services import (
    archive_gts_response,
    reopen_gts_response,
    save_gts_draft,
    start_gts_response,
    submit_gts_response,
    void_gts_response,
)
from apps.documents.workflow_api import (
    GeneratedDocumentMetadataSchema,
    download as workflow_document_download,
    generate as workflow_document_generate,
    preview as workflow_document_preview,
    workflow_download_openapi,
    workflow_preview_openapi,
)


router = Router(tags=["graduate-tracer"])


class GraduateTracerResponseSchema(Schema):
    """Output-only metadata projection for a Graduate Tracer response."""

    id: str
    reference_code: str
    student_id: str | None = None
    lifecycle_snapshot: str
    graduation_year: str
    program_snapshot: str
    college_snapshot: str
    status: str
    form_revision_id: str
    form_collection_id: str | None = None
    employment_status: str
    submitted_at: datetime | None = None
    created_at: datetime


class GraduateTracerDetailSchema(GraduateTracerResponseSchema):
    """Bounded metadata/sensitive superset for actor-dependent details."""

    # The sensitive projection adds versioned form answers. Metadata-only
    # readers leave this field unset.
    answers: dict[str, object] | None = None


class GraduateTracerResponsePageSchema(PageResultSchema):
    items: list[GraduateTracerResponseSchema]


class GraduateTracerStatusSchema(Schema):
    """Output-only student status projection."""

    has_response: bool
    status: str
    reference_code: str | None = None
    submitted_at: datetime | None = None


class StartSchema(Schema):
    student_profile_id: int | None = None
    form_revision_id: int
    form_collection_id: UUID | None = None
    form_invitation_id: UUID | None = None
    unlinked_submission_id: UUID | None = None


class AnswerSchema(Schema):
    form_revision_id: int
    answers: dict
    expected_updated_at: str | None = None


class LifecycleSchema(Schema):
    expected_updated_at: str | None = None
    reason: str = ""


def _actor(request):
    auth = getattr(request, "auth", None)
    return getattr(auth, "user", None)


def _verified_principal(request) -> VerifiedFormAccessPrincipal:
    session = getattr(request, "session", None)
    access_id = session.get("form_collection_verified_access_id") if session is not None else None
    if not access_id:
        raise NotFoundError()
    invitation = FormInvitation.objects.select_related(
        "collection", "linked_student", "unlinked_submission",
    ).filter(pk=access_id).first()
    if invitation is None:
        raise NotFoundError()
    try:
        verified = get_verified_invitation_for_destination(
            session,
            expected_target_form_key="graduate_tracer",
            expected_form_type="graduate_tracer",
        )
    except ValidationError as exc:
        raise NotFoundError() from exc
    return VerifiedFormAccessPrincipal.from_invitation(verified)


def _response_actor(request):
    actor = _actor(request)
    return actor if actor is not None else _verified_principal(request)


def _page(page: PageQuery, page_size: PageSizeQuery):
    try:
        return page_request_from_values(page, page_size)
    except ContractValidationError as exc:
        raise ValidationError() from exc


def _answer_set(payload: AnswerSchema):
    try:
        values = to_json_object(payload.answers)
    except (TypeError, ValueError) as exc:
        raise ValidationError() from exc
    return ValidatedAnswerSet(values=values, form_revision_id=payload.form_revision_id)


def _replay_for(model, projector):
    def replay(key):
        object_id = getattr(key, "related_object_id", None)
        value = model.objects.filter(pk=object_id).first() if object_id else None
        return projector(value) if value is not None else None

    return replay


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


def _outcome(value, projector, path):
    return ApiMutationOutcome(value=projector(value), related_object=value, safe_response_path=path)


@router.get(
    "/",
    response=GraduateTracerResponsePageSchema,
    exclude_unset=True,
    operation_id="graduate_tracer_list",
)
def list_responses(request, page: PageQuery, page_size: PageSizeQuery):
    prepare_api_operation(request, "graduate_tracer_list")
    return queries.response_page(_actor(request), _page(page, page_size)).as_dict()


@router.get(
    "/status/",
    response=GraduateTracerStatusSchema,
    exclude_unset=True,
    operation_id="graduate_tracer_status",
)
def student_status(request):
    prepare_api_operation(request, "graduate_tracer_status")
    value = queries.student_status(_actor(request))
    if value is None:
        raise NotFoundError()
    return value


@router.post(
    "/",
    auth=None,
    response=GraduateTracerResponseSchema,
    exclude_unset=True,
    operation_id="graduate_tracer_start",
)
def start_response(request, payload: StartSchema):
    values = payload.dict(exclude_unset=True)
    for field_name in ("form_collection_id", "form_invitation_id", "unlinked_submission_id"):
        if values.get(field_name) is not None:
            values[field_name] = str(values[field_name])
    actor = _actor(request)
    if values.get("form_invitation_id") or actor is None:
        principal = _verified_principal(request)
        if values.get("form_invitation_id") and values["form_invitation_id"] != principal.invitation_id:
            raise ValidationError()
        values["form_invitation_id"] = principal.invitation_id
        values.setdefault("student_profile_id", principal.student_profile_id)
        values.setdefault("form_revision_id", principal.form_revision_id)
        values.setdefault("unlinked_submission_id", principal.unlinked_submission_id)
        actor = principal
    command = GraduateTracerStartCommand(**values)
    return _run(
        request,
        "graduate_tracer_start",
        {"student_profile_id": command.student_profile_id, "form_revision_id": command.form_revision_id, "form_collection_id": command.form_collection_id, "form_invitation_id": command.form_invitation_id, "unlinked_submission_id": command.unlinked_submission_id},
        lambda: _outcome(
            start_gts_response(actor, command),
            projections.response_metadata,
            "/api/v1/graduate-tracer/",
        ),
        _replay_for(GraduateTracerResponse, projections.response_metadata),
    )


@router.get(
    "/{reference_code}/",
    response=GraduateTracerDetailSchema,
    exclude_unset=True,
    operation_id="graduate_tracer_detail",
)
def response_detail(request, reference_code: str):
    prepare_api_operation(request, "graduate_tracer_detail")
    value = queries.response_detail(_actor(request), reference_code)
    if value is None:
        raise NotFoundError()
    return value


@router.get(
    "/{reference_code}/document/preview/",
    response=None,
    openapi_extra=workflow_preview_openapi(),
    operation_id="graduate_tracer_document_preview",
)
def document_preview(request, reference_code: str):
    return workflow_document_preview(
        request, operation_id="graduate_tracer_document_preview", domain="graduate_tracer",
        stable_key="graduate_tracer_survey", target_reference=reference_code,
    )


class DocumentGenerateSchema(Schema):
    expected_updated_at: str = ""


@router.post(
    "/{reference_code}/document/generate/",
    response=GeneratedDocumentMetadataSchema,
    exclude_unset=True,
    operation_id="graduate_tracer_document_generate",
)
def document_generate(request, reference_code: str, payload: DocumentGenerateSchema):
    return workflow_document_generate(
        request, operation_id="graduate_tracer_document_generate", domain="graduate_tracer",
        stable_key="graduate_tracer_survey", target_reference=reference_code,
        expected_updated_at=payload.expected_updated_at,
    )


@router.get(
    "/{reference_code}/document/download/",
    response=None,
    openapi_extra=workflow_download_openapi(),
    operation_id="graduate_tracer_document_download",
)
def document_download(request, reference_code: str):
    return workflow_document_download(
        request, operation_id="graduate_tracer_document_download", domain="graduate_tracer",
        stable_key="graduate_tracer_survey", target_reference=reference_code,
    )


@router.get(
    "/{reference_code}/sensitive/",
    response=GraduateTracerDetailSchema,
    exclude_unset=True,
    operation_id="graduate_tracer_sensitive_detail",
)
def sensitive_detail(request, reference_code: str):
    prepare_api_operation(request, "graduate_tracer_sensitive_detail")
    value = queries.response_sensitive_detail(_actor(request), reference_code)
    if value is None:
        raise NotFoundError()
    return value


@router.put(
    "/{reference_code}/draft/",
    auth=None,
    response=GraduateTracerResponseSchema,
    exclude_unset=True,
    operation_id="graduate_tracer_draft_save",
)
def save_draft(request, reference_code: str, payload: AnswerSchema):
    answers = _answer_set(payload)
    command = GraduateTracerDraftCommand(answers=answers, expected_updated_at=payload.expected_updated_at)
    from apps.common.request_dedup import build_command_fingerprint

    fingerprint = build_command_fingerprint({"answers": answers.values, "form_revision_id": answers.form_revision_id})
    actor = _response_actor(request)
    return _run(
        request,
        "graduate_tracer_draft_save",
        {"reference_code": reference_code, "answers_fingerprint": fingerprint, "expected_updated_at": command.expected_updated_at},
        lambda: _outcome(
            save_gts_draft(actor, reference_code, command),
            projections.response_metadata,
            f"/api/v1/graduate-tracer/{reference_code}/",
        ),
        _replay_for(GraduateTracerResponse, projections.response_metadata),
    )


@router.post(
    "/{reference_code}/submit/",
    auth=None,
    response=GraduateTracerResponseSchema,
    exclude_unset=True,
    operation_id="graduate_tracer_submit",
)
def submit(request, reference_code: str, payload: LifecycleSchema | None = None):
    command = GraduateTracerLifecycleCommand(**(payload.dict(exclude_unset=True) if payload else {}))
    actor = _response_actor(request)
    return _run(
        request,
        "graduate_tracer_submit",
        {"reference_code": reference_code, "expected_updated_at": command.expected_updated_at},
        lambda: _outcome(
            submit_gts_response(actor, reference_code, command),
            projections.response_metadata,
            f"/api/v1/graduate-tracer/{reference_code}/",
        ),
        _replay_for(GraduateTracerResponse, projections.response_metadata),
    )


def _lifecycle_route(request, reference_code, operation_id, service, payload):
    command = GraduateTracerLifecycleCommand(**(payload.dict(exclude_unset=True) if payload else {}))
    from apps.common.request_dedup import build_command_fingerprint

    return _run(
        request,
        operation_id,
        {
            "reference_code": reference_code,
            "reason_fingerprint": build_command_fingerprint({"reason": command.reason}),
            "expected_updated_at": command.expected_updated_at,
        },
        lambda: _outcome(
            service(_actor(request), reference_code, command),
            projections.response_metadata,
            f"/api/v1/graduate-tracer/{reference_code}/",
        ),
        _replay_for(GraduateTracerResponse, projections.response_metadata),
    )


@router.post(
    "/{reference_code}/reopen/",
    response=GraduateTracerResponseSchema,
    exclude_unset=True,
    operation_id="graduate_tracer_reopen",
)
def reopen(request, reference_code: str, payload: LifecycleSchema | None = None):
    return _lifecycle_route(request, reference_code, "graduate_tracer_reopen", reopen_gts_response, payload)


@router.post(
    "/{reference_code}/void/",
    response=GraduateTracerResponseSchema,
    exclude_unset=True,
    operation_id="graduate_tracer_void",
)
def void(request, reference_code: str, payload: LifecycleSchema | None = None):
    return _lifecycle_route(request, reference_code, "graduate_tracer_void", void_gts_response, payload)


@router.post(
    "/{reference_code}/archive/",
    response=GraduateTracerResponseSchema,
    exclude_unset=True,
    operation_id="graduate_tracer_archive",
)
def archive(request, reference_code: str, payload: LifecycleSchema | None = None):
    return _lifecycle_route(request, reference_code, "graduate_tracer_archive", archive_gts_response, payload)
