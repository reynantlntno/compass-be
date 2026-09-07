"""Django Ninja adapter for the Good Moral workflow.

Good Moral owns the client-facing certificate workflow. Document rendering and
protected-file access remain internal document/security boundaries.
"""

from dataclasses import asdict, fields, is_dataclass
from datetime import date, datetime
from decimal import Decimal

from ninja import Router, Schema

from apps.common.api.idempotency import ApiMutationOutcome, run_api_mutation
from apps.common.api.operations import prepare_api_operation
from apps.common.api.pagination import PageQuery, PageSizeQuery, page_request_from_values
from apps.common.api.schemas import PageResultSchema
from apps.common.contracts import ContractValidationError, to_json_object
from apps.common.exceptions import NotFoundError, ValidationError
from apps.good_moral import queries
from apps.good_moral.commands import (
    GoodMoralApprovalCommand,
    GoodMoralArchiveCommand,
    GoodMoralDraftCommand,
    GoodMoralDraftUpdateCommand,
    GoodMoralLifecycleCommand,
    GoodMoralOssdVerificationCommand,
    GoodMoralReasonCommand,
    GoodMoralReceiptEncodeCommand,
    GoodMoralReceiptVerificationCommand,
    GoodMoralReviewerCommand,
    UNSET,
)
from apps.good_moral.projections import mutation_result
from apps.good_moral.selectors import get_visible_request_by_reference
from apps.good_moral.services import (
    approve_request as service_approve_request,
    archive_request as service_archive_request,
    assign_reviewer as service_assign_reviewer,
    cancel_request as service_cancel_request,
    change_ossd_verification as service_change_ossd_verification,
    confirm_dry_seal as service_confirm_dry_seal,
    create_draft as service_create_draft,
    encode_receipt as service_encode_receipt,
    generate_certificate as service_generate_certificate,
    hold_request as service_hold_request,
    mark_printed as service_mark_printed,
    reject_request as service_reject_request,
    release_certificate as service_release_certificate,
    start_review as service_start_review,
    submit_request as service_submit_request,
    supersede_certificate as service_supersede_certificate,
    update_draft as service_update_draft,
    verify_receipt as service_verify_receipt,
    void_request as service_void_request,
)
from apps.security.downloads import protected_file_download_openapi
from apps.documents.workflow_api import GeneratedDocumentMetadataSchema


router = Router(tags=["good-moral"])


class GoodMoralRequestSchema(Schema):
    """Output-only superset of the student and staff request projections."""

    reference_code: str
    request_type: str
    status: str
    applicant_lifecycle_status: str
    applicant_academic_year: str
    applicant_graduation_date: date | None = None
    receipt_status: str
    dry_seal_status: str
    dry_seal_confirmation_method: str | None = None
    generated_document: GeneratedDocumentMetadataSchema | None = None
    created_at: datetime
    updated_at: datetime

    # Student-only projection field.
    purpose_text: str | None = None

    # Staff-only operational projection fields.
    applicant_display_name: str | None = None
    applicant_campus: str | None = None
    applicant_college: str | None = None
    applicant_department: str | None = None
    applicant_program_degree: str | None = None
    applicant_year_level: str | None = None
    ossd_verification_status: str | None = None
    approved_at: datetime | None = None
    generated_at: datetime | None = None
    printed_at: datetime | None = None
    released_at: datetime | None = None


class GoodMoralPageResultSchema(PageResultSchema):
    items: list[GoodMoralRequestSchema]


class GoodMoralMutationResponseSchema(Schema):
    """Bounded mutation projection shared by lifecycle and replay responses."""

    reference_code: str
    status: str
    receipt_status: str
    dry_seal_status: str
    updated_at: datetime


class DraftSchema(Schema):
    requester_user_id: int | None = None
    student_profile_id: int | None = None
    purpose_text: str
    academic_year: str | None = None
    semester: str = ""
    major: str = ""
    graduation_date: date | None = None


class DraftUpdateSchema(Schema):
    purpose_text: str | None = None
    semester: str | None = None
    major: str | None = None
    graduation_date: date | None = None
    expected_updated_at: str | None = None


class ReasonSchema(Schema):
    reason_code: str = ""
    note: str = ""


class ReceiptEncodeSchema(Schema):
    receipt_number: str
    receipt_date: date
    receipt_amount: Decimal


class ReceiptVerificationSchema(Schema):
    approved: bool
    rejection_code: str = ""


class ReviewerSchema(Schema):
    reviewer_user_id: int


class OssdSchema(Schema):
    status: str


class ApprovalSchema(Schema):
    signatory_name: str
    signatory_title: str


def _actor(request):
    return request.auth.user


def _page(page: PageQuery, page_size: PageSizeQuery):
    try:
        return page_request_from_values(page, page_size)
    except ContractValidationError as exc:
        raise ValidationError() from exc


def _command_fingerprint(command, **extra):
    if not is_dataclass(command):
        raise ValidationError()
    values = {}
    for field in fields(command):
        value = getattr(command, field.name)
        if value is not UNSET:
            values[field.name] = value
    return to_json_object({**extra, "command": values})


def _outcome(request):
    return ApiMutationOutcome(
        value=mutation_result(request),
        related_object=request,
        safe_response_path=f"/api/v1/good-moral/{request.reference_code}/",
    )


def _run(request, operation_id, payload, operation):
    prepared = prepare_api_operation(request, operation_id)
    return run_api_mutation(
        request,
        operation_id,
        payload,
        operation,
        queries.replay_by_id,
        prepared_operation=prepared,
    )


def _request_or_404(actor, reference_code):
    request = get_visible_request_by_reference(actor, reference_code)
    if request is None:
        raise NotFoundError()
    return request


@router.get(
    "/",
    response=GoodMoralPageResultSchema,
    exclude_unset=True,
    operation_id="good_moral_list",
)
def list_requests(request, page: PageQuery, page_size: PageSizeQuery):
    prepare_api_operation(request, "good_moral_list")
    return queries.request_page(_actor(request), _page(page, page_size)).as_dict()


@router.get(
    "/{reference_code}/",
    response=GoodMoralRequestSchema,
    exclude_unset=True,
    operation_id="good_moral_detail",
)
def request_detail(request, reference_code: str):
    prepare_api_operation(request, "good_moral_detail")
    value = queries.request_detail(_actor(request), reference_code)
    if value is None:
        raise NotFoundError()
    return value


@router.get(
    "/{reference_code}/document/",
    response=GeneratedDocumentMetadataSchema,
    exclude_unset=True,
    operation_id="good_moral_document_detail",
)
def document_detail(request, reference_code: str):
    prepare_api_operation(request, "good_moral_document_detail")
    value = _request_or_404(_actor(request), reference_code)
    document = getattr(value, "generated_document", None)
    if not document:
        raise NotFoundError()
    from apps.good_moral.projections import document_projection
    return document_projection(document) or {}


@router.get(
    "/{reference_code}/document/download/",
    response=None,
    openapi_extra=protected_file_download_openapi(),
    operation_id="good_moral_document_download",
)
def document_download(request, reference_code: str):
    prepare_api_operation(request, "good_moral_document_download")
    actor = _actor(request)
    value = _request_or_404(actor, reference_code)
    document = getattr(value, "generated_document", None)
    if not document or not document.protected_file_id:
        raise NotFoundError()
    from apps.good_moral.policies import can_read_generated_certificate_content
    if not can_read_generated_certificate_content(actor, value, document):
        raise NotFoundError()
    from apps.security.downloads import ProtectedFileDownloadDenied, build_protected_file_download_response
    try:
        return build_protected_file_download_response(actor, document.protected_file_id)
    except ProtectedFileDownloadDenied as exc:
        raise NotFoundError() from exc


@router.post(
    "/",
    response=GoodMoralMutationResponseSchema,
    exclude_unset=True,
    operation_id="good_moral_create",
)
def create_request(request, payload: DraftSchema):
    actor = _actor(request)
    data = payload.dict(exclude_unset=True)
    data.setdefault("requester_user_id", actor.pk)
    if data.get("student_profile_id") is None and hasattr(actor, "student_profile"):
        data["student_profile_id"] = actor.student_profile.pk
    command = GoodMoralDraftCommand(**data)
    return _run(
        request,
        "good_moral_create",
        _command_fingerprint(command),
        lambda: _outcome(service_create_draft(actor=actor, command=command)),
    )


@router.put(
    "/{reference_code}/",
    response=GoodMoralMutationResponseSchema,
    exclude_unset=True,
    operation_id="good_moral_draft_update",
)
def update_request(request, reference_code: str, payload: DraftUpdateSchema):
    command = GoodMoralDraftUpdateCommand(**payload.dict(exclude_unset=True))
    return _run(
        request,
        "good_moral_draft_update",
        _command_fingerprint(command, reference_code=reference_code),
        lambda: _outcome(service_update_draft(actor=_actor(request), reference_code=reference_code, command=command)),
    )


def _reason(payload):
    return GoodMoralReasonCommand(**payload.dict(exclude_unset=True))


@router.post(
    "/{reference_code}/submit/",
    response=GoodMoralMutationResponseSchema,
    exclude_unset=True,
    operation_id="good_moral_submit",
)
def submit_request(request, reference_code: str):
    command = GoodMoralLifecycleCommand()
    return _run(request, "good_moral_submit", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(service_submit_request(actor=_actor(request), reference_code=reference_code, command=command)))


@router.post(
    "/{reference_code}/cancel/",
    response=GoodMoralMutationResponseSchema,
    exclude_unset=True,
    operation_id="good_moral_cancel",
)
def cancel_request(request, reference_code: str, payload: ReasonSchema):
    command = _reason(payload)
    return _run(request, "good_moral_cancel", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(service_cancel_request(actor=_actor(request), reference_code=reference_code, command=command)))


@router.post(
    "/{reference_code}/receipt/encode/",
    response=GoodMoralMutationResponseSchema,
    exclude_unset=True,
    operation_id="good_moral_receipt_encode",
)
def encode_receipt(request, reference_code: str, payload: ReceiptEncodeSchema):
    command = GoodMoralReceiptEncodeCommand(**payload.dict())
    return _run(request, "good_moral_receipt_encode", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(service_encode_receipt(actor=_actor(request), reference_code=reference_code, command=command)))


@router.post(
    "/{reference_code}/receipt/verify/",
    response=GoodMoralMutationResponseSchema,
    exclude_unset=True,
    operation_id="good_moral_receipt_verify",
)
def verify_receipt(request, reference_code: str, payload: ReceiptVerificationSchema):
    command = GoodMoralReceiptVerificationCommand(**payload.dict())
    return _run(request, "good_moral_receipt_verify", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(service_verify_receipt(actor=_actor(request), reference_code=reference_code, command=command)))


@router.post(
    "/{reference_code}/review/start/",
    response=GoodMoralMutationResponseSchema,
    exclude_unset=True,
    operation_id="good_moral_review_start",
)
def start_review(request, reference_code: str):
    command = GoodMoralLifecycleCommand()
    return _run(request, "good_moral_review_start", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(service_start_review(actor=_actor(request), reference_code=reference_code, command=command)))


@router.post(
    "/{reference_code}/reviewer/",
    response=GoodMoralMutationResponseSchema,
    exclude_unset=True,
    operation_id="good_moral_reviewer_assign",
)
def assign_reviewer(request, reference_code: str, payload: ReviewerSchema):
    command = GoodMoralReviewerCommand(**payload.dict())
    return _run(request, "good_moral_reviewer_assign", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(service_assign_reviewer(actor=_actor(request), reference_code=reference_code, command=command)))


@router.post(
    "/{reference_code}/ossd/",
    response=GoodMoralMutationResponseSchema,
    exclude_unset=True,
    operation_id="good_moral_ossd_verification",
)
def change_ossd(request, reference_code: str, payload: OssdSchema):
    command = GoodMoralOssdVerificationCommand(**payload.dict())
    return _run(request, "good_moral_ossd_verification", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(service_change_ossd_verification(actor=_actor(request), reference_code=reference_code, command=command)))


@router.post(
    "/{reference_code}/hold/",
    response=GoodMoralMutationResponseSchema,
    exclude_unset=True,
    operation_id="good_moral_hold",
)
def hold_request(request, reference_code: str, payload: ReasonSchema):
    command = _reason(payload)
    return _run(request, "good_moral_hold", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(service_hold_request(actor=_actor(request), reference_code=reference_code, command=command)))


@router.post(
    "/{reference_code}/approve/",
    response=GoodMoralMutationResponseSchema,
    exclude_unset=True,
    operation_id="good_moral_approve",
)
def approve_request(request, reference_code: str, payload: ApprovalSchema):
    command = GoodMoralApprovalCommand(**payload.dict())
    return _run(request, "good_moral_approve", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(service_approve_request(actor=_actor(request), reference_code=reference_code, command=command)))


@router.post(
    "/{reference_code}/reject/",
    response=GoodMoralMutationResponseSchema,
    exclude_unset=True,
    operation_id="good_moral_reject",
)
def reject_request(request, reference_code: str, payload: ReasonSchema):
    command = _reason(payload)
    return _run(request, "good_moral_reject", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(service_reject_request(actor=_actor(request), reference_code=reference_code, command=command)))


@router.post(
    "/{reference_code}/generate/",
    response=GoodMoralMutationResponseSchema,
    exclude_unset=True,
    operation_id="good_moral_generate",
)
def generate_certificate(request, reference_code: str):
    command = GoodMoralLifecycleCommand()
    return _run(request, "good_moral_generate", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(service_generate_certificate(actor=_actor(request), reference_code=reference_code, command=command)))


@router.post(
    "/{reference_code}/print/",
    response=GoodMoralMutationResponseSchema,
    exclude_unset=True,
    operation_id="good_moral_print",
)
def mark_printed(request, reference_code: str):
    command = GoodMoralLifecycleCommand()
    return _run(request, "good_moral_print", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(service_mark_printed(actor=_actor(request), reference_code=reference_code, command=command)))


@router.post(
    "/{reference_code}/release/",
    response=GoodMoralMutationResponseSchema,
    exclude_unset=True,
    operation_id="good_moral_release",
)
def release_certificate(request, reference_code: str):
    command = GoodMoralLifecycleCommand()
    return _run(request, "good_moral_release", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(service_release_certificate(actor=_actor(request), reference_code=reference_code, command=command)))


@router.post(
    "/{reference_code}/dry-seal/confirm/",
    response=GoodMoralMutationResponseSchema,
    exclude_unset=True,
    operation_id="good_moral_dry_seal_confirm",
)
def confirm_dry_seal(request, reference_code: str):
    command = GoodMoralLifecycleCommand()
    return _run(request, "good_moral_dry_seal_confirm", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(service_confirm_dry_seal(actor=_actor(request), reference_code=reference_code, command=command)))


@router.post(
    "/{reference_code}/void/",
    response=GoodMoralMutationResponseSchema,
    exclude_unset=True,
    operation_id="good_moral_void",
)
def void_request(request, reference_code: str, payload: ReasonSchema):
    command = _reason(payload)
    return _run(request, "good_moral_void", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(service_void_request(actor=_actor(request), reference_code=reference_code, command=command)))


@router.post(
    "/{reference_code}/supersede/",
    response=GoodMoralMutationResponseSchema,
    exclude_unset=True,
    operation_id="good_moral_supersede",
)
def supersede_certificate(request, reference_code: str):
    command = GoodMoralLifecycleCommand()
    return _run(request, "good_moral_supersede", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(service_supersede_certificate(actor=_actor(request), reference_code=reference_code, command=command)))


@router.post(
    "/{reference_code}/archive/",
    response=GoodMoralMutationResponseSchema,
    exclude_unset=True,
    operation_id="good_moral_archive",
)
def archive_request(request, reference_code: str, payload: ReasonSchema):
    command = GoodMoralArchiveCommand(reason_code=payload.reason_code)
    return _run(request, "good_moral_archive", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(service_archive_request(actor=_actor(request), reference_code=reference_code, command=command)))
