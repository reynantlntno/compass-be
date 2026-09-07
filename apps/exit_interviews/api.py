"""Client-facing Exit Interview API.

Exit Interview owns response lifecycle and safe projections.  Form Collection
continues to own invitation verification; cross-domain invitation consumption
is kept behind the existing orchestration hooks in the service layer.
"""

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
from apps.exit_interviews import projections, queries
from apps.exit_interviews.commands import (
    ExitInterviewAcknowledgeCommand,
    ExitInterviewAssignmentCommand,
    ExitInterviewAssignmentReassignCommand,
    ExitInterviewDraftCommand,
    ExitInterviewLifecycleCommand,
    ExitInterviewReasonCommand,
    ExitInterviewStartCommand,
)
from apps.exit_interviews.models import ExitInterviewAssignment, ExitInterviewResponse
from apps.exit_interviews.services import (
    acknowledge_exit_response,
    archive_exit_response,
    create_exit_assignment,
    reassign_exit_assignment,
    reopen_exit_response,
    save_exit_draft,
    start_exit_response,
    submit_exit_response,
    void_exit_response,
)
from apps.form_collection.models import FormInvitation
from apps.form_collection.services import get_verified_invitation_for_destination
from apps.documents.workflow_api import (
    GeneratedDocumentMetadataSchema,
    download as workflow_document_download,
    generate as workflow_document_generate,
    preview as workflow_document_preview,
    workflow_download_openapi,
    workflow_preview_openapi,
)


router = Router(tags=["exit-interviews"])


class ExitInterviewResponseSchema(Schema):
    """Output-only metadata projection for an Exit Interview response."""

    id: str
    reference_code: str
    student_id: str
    lifecycle_snapshot: str
    program_snapshot: str
    college_snapshot: str
    academic_year: str
    graduation_year_snapshot: str
    eligibility_source: str
    status: str
    form_revision_id: str
    form_collection_id: str | None = None
    submitted_at: datetime | None = None
    counselor_acknowledged_at: datetime | None = None
    created_at: datetime


class ExitInterviewDetailSchema(ExitInterviewResponseSchema):
    """Bounded metadata/sensitive superset for actor-dependent details."""

    # The sensitive projection adds versioned form answers only for an
    # authorized counselor. Metadata-only readers leave these fields unset.
    answers: dict[str, object] | None = None
    counselor_acknowledged_by: str | None = None


class ExitInterviewResponsePageSchema(PageResultSchema):
    items: list[ExitInterviewResponseSchema]


class ExitInterviewAssignmentSchema(Schema):
    """Output-only assignment projection."""

    id: str
    student_id: str
    collection_id: str | None = None
    due_at: datetime | None = None
    status: str
    assigned_at: datetime


class ExitInterviewAssignmentPageSchema(PageResultSchema):
    items: list[ExitInterviewAssignmentSchema]


class ExitInterviewStatusSchema(Schema):
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
    academic_year: str | None = None


class AnswerSchema(Schema):
    form_revision_id: int
    answers: dict
    expected_updated_at: str | None = None


class LifecycleSchema(Schema):
    expected_updated_at: str | None = None
    reason: str = ""


class AcknowledgeSchema(Schema):
    expected_updated_at: str | None = None


class AssignmentSchema(Schema):
    student_profile_id: int
    collection_id: UUID | None = None
    due_at: datetime | None = None
    graduation_year: str = ""
    expected_updated_at: str | None = None


class AssignmentReassignSchema(Schema):
    assignment_id: UUID
    student_profile_id: int
    due_at: datetime | None = None
    graduation_year: str = ""
    expected_updated_at: str | None = None


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
            expected_target_form_key="exit_interview",
            expected_form_type="exit_interview",
        )
    except ValidationError as exc:
        raise NotFoundError() from exc
    return VerifiedFormAccessPrincipal.from_invitation(verified)


def _response_actor(request, *, invitation_id: str | None = None):
    actor = _actor(request)
    if invitation_id:
        principal = _verified_principal(request)
        if principal.invitation_id != invitation_id:
            raise ValidationError()
        return principal
    if actor is not None:
        return actor
    return _verified_principal(request)


def _page(page: PageQuery, page_size: PageSizeQuery):
    try:
        return page_request_from_values(page, page_size)
    except ContractValidationError as exc:
        raise ValidationError() from exc


def _answers(payload: AnswerSchema):
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
    response=ExitInterviewResponsePageSchema,
    exclude_unset=True,
    operation_id="exit_interviews_list",
)
def list_responses(request, page: PageQuery, page_size: PageSizeQuery):
    prepare_api_operation(request, "exit_interviews_list")
    return queries.response_page(_actor(request), _page(page, page_size)).as_dict()


@router.get(
    "/status/",
    response=ExitInterviewStatusSchema,
    exclude_unset=True,
    operation_id="exit_interviews_status",
)
def student_status(request):
    prepare_api_operation(request, "exit_interviews_status")
    value = queries.student_status(_actor(request))
    if value is None:
        raise NotFoundError()
    return value


@router.get(
    "/assignments/",
    response=ExitInterviewAssignmentPageSchema,
    exclude_unset=True,
    operation_id="exit_interviews_assignments_list",
)
def list_assignments(request, page: PageQuery, page_size: PageSizeQuery):
    prepare_api_operation(request, "exit_interviews_assignments_list")
    return queries.assignment_page(_actor(request), _page(page, page_size)).as_dict()


@router.post(
    "/assignments/",
    response=ExitInterviewAssignmentSchema,
    exclude_unset=True,
    operation_id="exit_interviews_assignment_create",
)
def create_assignment(request, payload: AssignmentSchema):
    data = payload.dict(exclude_unset=True)
    if data.get("collection_id") is not None:
        data["collection_id"] = str(data["collection_id"])
    due_at = data.get("due_at")
    if due_at is not None and not isinstance(due_at, datetime):
        raise ValidationError()
    command = ExitInterviewAssignmentCommand(**data)
    return _run(
        request,
        "exit_interviews_assignment_create",
        {"student_profile_id": command.student_profile_id, "collection_id": command.collection_id, "due_at": command.due_at, "graduation_year": command.graduation_year},
        lambda: _outcome(
            create_exit_assignment(_actor(request), command),
            projections.assignment,
            "/api/v1/exit-interviews/assignments/",
        ),
        _replay_for(ExitInterviewAssignment, projections.assignment),
    )


@router.post(
    "/assignments/reassign/",
    response=ExitInterviewAssignmentSchema,
    exclude_unset=True,
    operation_id="exit_interviews_assignment_reassign",
)
def reassign_assignment(request, payload: AssignmentReassignSchema):
    data = payload.dict(exclude_unset=True)
    data["assignment_id"] = str(data["assignment_id"])
    command = ExitInterviewAssignmentReassignCommand(**data)
    return _run(
        request,
        "exit_interviews_assignment_reassign",
        {
            "assignment_id": command.assignment_id,
            "student_profile_id": command.student_profile_id,
            "due_at": command.due_at,
            "graduation_year": command.graduation_year,
            "expected_updated_at": command.expected_updated_at,
        },
        lambda: _outcome(
            reassign_exit_assignment(_actor(request), command),
            projections.assignment,
            "/api/v1/exit-interviews/assignments/",
        ),
        _replay_for(ExitInterviewAssignment, projections.assignment),
    )


@router.post(
    "/",
    auth=None,
    response=ExitInterviewResponseSchema,
    exclude_unset=True,
    operation_id="exit_interviews_start",
)
def start_response(request, payload: StartSchema):
    values = payload.dict(exclude_unset=True)
    for field_name in ("form_collection_id", "form_invitation_id"):
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
        actor = principal
    command = ExitInterviewStartCommand(**values)
    return _run(
        request,
        "exit_interviews_start",
        {"student_profile_id": command.student_profile_id, "form_revision_id": command.form_revision_id, "form_collection_id": command.form_collection_id, "form_invitation_id": command.form_invitation_id},
        lambda: _outcome(
            start_exit_response(actor, command),
            projections.response_metadata,
            "/api/v1/exit-interviews/",
        ),
        _replay_for(ExitInterviewResponse, projections.response_metadata),
    )


@router.get(
    "/{reference_code}/",
    response=ExitInterviewDetailSchema,
    exclude_unset=True,
    operation_id="exit_interviews_detail",
)
def response_detail(request, reference_code: str):
    prepare_api_operation(request, "exit_interviews_detail")
    value = queries.response_detail(_actor(request), reference_code)
    if value is None:
        raise NotFoundError()
    return value


@router.get(
    "/{reference_code}/document/preview/",
    response=None,
    openapi_extra=workflow_preview_openapi(),
    operation_id="exit_interviews_document_preview",
)
def document_preview(request, reference_code: str):
    return workflow_document_preview(
        request, operation_id="exit_interviews_document_preview", domain="exit_interviews",
        stable_key="exit_interview", target_reference=reference_code,
    )


class DocumentGenerateSchema(Schema):
    expected_updated_at: str = ""


@router.post(
    "/{reference_code}/document/generate/",
    response=GeneratedDocumentMetadataSchema,
    exclude_unset=True,
    operation_id="exit_interviews_document_generate",
)
def document_generate(request, reference_code: str, payload: DocumentGenerateSchema):
    return workflow_document_generate(
        request, operation_id="exit_interviews_document_generate", domain="exit_interviews",
        stable_key="exit_interview", target_reference=reference_code,
        expected_updated_at=payload.expected_updated_at,
    )


@router.get(
    "/{reference_code}/document/download/",
    response=None,
    openapi_extra=workflow_download_openapi(),
    operation_id="exit_interviews_document_download",
)
def document_download(request, reference_code: str):
    return workflow_document_download(
        request, operation_id="exit_interviews_document_download", domain="exit_interviews",
        stable_key="exit_interview", target_reference=reference_code,
    )


@router.get(
    "/{reference_code}/sensitive/",
    response=ExitInterviewDetailSchema,
    exclude_unset=True,
    operation_id="exit_interviews_sensitive_detail",
)
def sensitive_detail(request, reference_code: str):
    prepare_api_operation(request, "exit_interviews_sensitive_detail")
    value = queries.response_sensitive_detail(_actor(request), reference_code)
    if value is None:
        raise NotFoundError()
    return value


def _answer_route(request, reference_code, payload, operation_id, service):
    answers = _answers(payload)
    command = ExitInterviewDraftCommand(answers=answers, expected_updated_at=payload.expected_updated_at)
    answer_fingerprint = __import__("apps.common.request_dedup", fromlist=["build_command_fingerprint"]).build_command_fingerprint({"answers": answers.values, "form_revision_id": answers.form_revision_id})
    actor = _response_actor(request)
    return _run(
        request,
        operation_id,
        {"reference_code": reference_code, "answers_fingerprint": answer_fingerprint, "expected_updated_at": command.expected_updated_at},
        lambda: _outcome(
            service(actor, reference_code, command),
            projections.response_metadata,
            f"/api/v1/exit-interviews/{reference_code}/",
        ),
        _replay_for(ExitInterviewResponse, projections.response_metadata),
    )


@router.put(
    "/{reference_code}/draft/",
    auth=None,
    response=ExitInterviewResponseSchema,
    exclude_unset=True,
    operation_id="exit_interviews_draft_save",
)
def save_draft(request, reference_code: str, payload: AnswerSchema):
    return _answer_route(request, reference_code, payload, "exit_interviews_draft_save", save_exit_draft)


@router.post(
    "/{reference_code}/submit/",
    auth=None,
    response=ExitInterviewResponseSchema,
    exclude_unset=True,
    operation_id="exit_interviews_submit",
)
def submit(request, reference_code: str, payload: LifecycleSchema | None = None):
    command = ExitInterviewLifecycleCommand(**(payload.dict(exclude_unset=True) if payload else {}))
    actor = _response_actor(request)
    return _run(
        request,
        "exit_interviews_submit",
        {"reference_code": reference_code, "expected_updated_at": command.expected_updated_at},
        lambda: _outcome(
            submit_exit_response(actor, reference_code, command),
            projections.response_metadata,
            f"/api/v1/exit-interviews/{reference_code}/",
        ),
        _replay_for(ExitInterviewResponse, projections.response_metadata),
    )


@router.post(
    "/{reference_code}/acknowledge/",
    response=ExitInterviewResponseSchema,
    exclude_unset=True,
    operation_id="exit_interviews_acknowledge",
)
def acknowledge(request, reference_code: str, payload: AcknowledgeSchema | None = None):
    command = ExitInterviewAcknowledgeCommand(**(payload.dict(exclude_unset=True) if payload else {}))
    return _run(
        request,
        "exit_interviews_acknowledge",
        {"reference_code": reference_code, "expected_updated_at": command.expected_updated_at},
        lambda: _outcome(
            acknowledge_exit_response(_actor(request), reference_code, command),
            projections.response_metadata,
            f"/api/v1/exit-interviews/{reference_code}/",
        ),
        _replay_for(ExitInterviewResponse, projections.response_metadata),
    )


def _lifecycle_route(request, reference_code, operation_id, service, payload):
    command = ExitInterviewReasonCommand(**(payload.dict(exclude_unset=True) if payload else {}))
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
            f"/api/v1/exit-interviews/{reference_code}/",
        ),
        _replay_for(ExitInterviewResponse, projections.response_metadata),
    )


@router.post(
    "/{reference_code}/reopen/",
    response=ExitInterviewResponseSchema,
    exclude_unset=True,
    operation_id="exit_interviews_reopen",
)
def reopen(request, reference_code: str, payload: LifecycleSchema | None = None):
    return _lifecycle_route(request, reference_code, "exit_interviews_reopen", reopen_exit_response, payload)


@router.post(
    "/{reference_code}/void/",
    response=ExitInterviewResponseSchema,
    exclude_unset=True,
    operation_id="exit_interviews_void",
)
def void(request, reference_code: str, payload: LifecycleSchema | None = None):
    return _lifecycle_route(request, reference_code, "exit_interviews_void", void_exit_response, payload)


@router.post(
    "/{reference_code}/archive/",
    response=ExitInterviewResponseSchema,
    exclude_unset=True,
    operation_id="exit_interviews_archive",
)
def archive(request, reference_code: str, payload: LifecycleSchema | None = None):
    return _lifecycle_route(request, reference_code, "exit_interviews_archive", archive_exit_response, payload)
