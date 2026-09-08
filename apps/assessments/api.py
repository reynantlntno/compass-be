"""Django Ninja adapter for the scoped assessments workflow."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime

from ninja import File, Query, Router, Schema, UploadedFile

from apps.assessments.choices import AssessmentInterpretationVisibility
from apps.assessments.commands import (
    AssessmentArchiveCommand,
    AssessmentCreateCommand,
    AssessmentFileUploadReceipt,
    AssessmentRecordCommand,
    AssessmentReleaseCommand,
    AssessmentReviewCommand,
    AssessmentSubmitReviewCommand,
    AssessmentSupersedeCommand,
    AssessmentUpdateCommand,
    AssessmentVoidCommand,
)
from apps.assessments import queries
from apps.assessments.projections import (
    assessment_sensitive_projection,
    assessment_staff_projection,
    instrument_projection,
    protected_file_metadata_projection,
)
from apps.assessments.services import (
    archive_assessment_record,
    assessment_sensitive_projection_for_actor,
    attach_protected_assessment_file,
    authorized_assessment_file_id,
    create_assessment_record,
    release_assessment_to_student,
    record_assessment_result,
    review_assessment_record,
    submit_assessment_for_review,
    supersede_assessment_record,
    update_assessment_record,
    void_assessment_record,
)
from apps.common.api.idempotency import ApiMutationOutcome, run_api_mutation
from apps.common.api.operations import prepare_api_operation
from apps.common.api.pagination import PageQuery, PageSizeQuery, page_request_from_values
from apps.common.api.schemas import PageResultSchema
from apps.common.contracts import ContractValidationError, to_json_object
from apps.common.exceptions import DependencyFailureError, NotFoundError, ValidationError
from apps.common.request_dedup import build_command_fingerprint
from apps.security.downloads import (
    ProtectedFileDownloadDenied,
    build_protected_file_download_response,
    protected_file_download_openapi,
)
from apps.security.exceptions import PolicyValidationError, SecurityError, StorageError
from apps.security.file_services import store_protected_file_stream, validate_assessment_upload
from apps.security.models import ClassificationChoices, PurposeChoices
from apps.security.storage_adapters import get_storage_adapter


router = Router(tags=["assessments"])


class AssessmentInstrumentSchema(Schema):
    id: int
    key: str
    title: str
    category: str
    allows_scores: bool
    allows_interpretation: bool
    active: bool


class AssessmentInstrumentPageSchema(PageResultSchema):
    items: list[AssessmentInstrumentSchema]


class AssessmentStudentSummaryInstrumentSchema(Schema):
    key: str
    title: str
    category: str


class AssessmentStudentSummarySchema(Schema):
    id: int
    instrument: AssessmentStudentSummaryInstrumentSchema
    status: str
    administered_at: datetime | None
    released_at: datetime | None
    safe_summary: str


class AssessmentStudentSummaryPageSchema(PageResultSchema):
    items: list[AssessmentStudentSummarySchema]


class AssessmentStaffProjectionSchema(Schema):
    id: int
    student_reference: str
    instrument: AssessmentInstrumentSchema
    status: str
    administered_at: datetime | None
    reviewed_at: datetime | None
    released_to_student: bool
    released_at: datetime | None
    interpretation_visibility: str
    has_protected_file: bool


class AssessmentSensitiveProjectionSchema(AssessmentStaffProjectionSchema):
    raw_score: str | None
    scaled_score: str | None
    score_label: str | None
    interpretation: str


class AssessmentPageSchema(PageResultSchema):
    items: list[AssessmentStaffProjectionSchema]


class AssessmentFileMetadataSchema(Schema):
    id: str
    filename: str | None
    content_type: str
    size_bytes: int
    classification: str
    purpose: str
    status: str


class CreateSchema(Schema):
    student_profile_id: int
    instrument_id: int
    administered_at: datetime | None = None
    source_form_reference: str | None = None
    expected_instrument_updated_at: datetime | None = None


class UpdateSchema(Schema):
    administered_at: datetime | None = None
    source_form_reference: str | None = None
    raw_score: str | None = None
    scaled_score: str | None = None
    score_label: str | None = None
    interpretation_text: str | None = None
    interpretation_visibility: str | None = None
    expected_updated_at: datetime | None = None


class RecordSchema(Schema):
    raw_score: str | None = None
    scaled_score: str | None = None
    score_label: str | None = None
    interpretation_text: str | None = None
    interpretation_visibility: str | None = None
    expected_updated_at: datetime | None = None


class ExpectedStateSchema(Schema):
    expected_updated_at: datetime | None = None


class ReviewSchema(Schema):
    notes: str | None = None
    expected_updated_at: datetime | None = None


class ReasonSchema(Schema):
    reason_code: str | None = None
    expected_updated_at: datetime | None = None


class SupersedeSchema(Schema):
    replacement_record_id: int
    reason_code: str | None = None
    expected_updated_at: datetime | None = None


def _actor(request):
    return request.auth.user


def _page(page: PageQuery, page_size: PageSizeQuery):
    try:
        return page_request_from_values(page, page_size)
    except ContractValidationError as exc:
        raise ValidationError() from exc


def _enum(value: str | None):
    if value is None:
        return None
    try:
        return AssessmentInterpretationVisibility(value)
    except ValueError as exc:
        raise ValidationError() from exc


def _fields(payload, allowed: tuple[str, ...]) -> tuple[str, ...]:
    supplied = getattr(payload, "model_fields_set", None)
    if supplied is None:
        supplied = getattr(payload, "__fields_set__", set())
    return tuple(field for field in allowed if field in supplied)


def _safe_fingerprint(command, **extra):
    values = asdict(command)
    for field in ("raw_score", "scaled_score", "score_label", "interpretation_text", "notes"):
        if field in values and values[field] is not None:
            values[field] = build_command_fingerprint({"value": values[field]})
    return to_json_object({**extra, "command": values})


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


def _replay(actor, stored):
    value = queries.assessment_detail(actor, stored.related_object_id)
    if value is None:
        raise NotFoundError()
    return value


@router.get("/instruments/", response=AssessmentInstrumentPageSchema, operation_id="assessments_instruments")
def instruments(request, page: PageQuery, page_size: PageSizeQuery):
    prepare_api_operation(request, "assessments_instruments")
    return queries.instrument_page(_actor(request), _page(page, page_size))


@router.get("/student/summaries/", response=AssessmentStudentSummaryPageSchema, operation_id="assessments_student_summaries")
def student_summaries(request, page: PageQuery, page_size: PageSizeQuery):
    prepare_api_operation(request, "assessments_student_summaries")
    return queries.student_summary_page(_actor(request), _page(page, page_size))


@router.get("/student/summaries/{record_id}/", response=AssessmentStudentSummarySchema, operation_id="assessments_student_summary_detail")
def student_summary_detail(request, record_id: int):
    prepare_api_operation(request, "assessments_student_summary_detail")
    value = queries.student_summary_detail(_actor(request), record_id)
    if value is None:
        raise NotFoundError()
    return value


@router.get("/", response=AssessmentPageSchema, operation_id="assessments_list")
def list_assessments(
    request,
    page: PageQuery,
    page_size: PageSizeQuery,
    status: str = Query(default=""),
    category: str = Query(default=""),
):
    prepare_api_operation(request, "assessments_list")
    return queries.assessment_page(
        _actor(request),
        _page(page, page_size),
        status=status or "",
        category=category or "",
    )


@router.get("/{record_id}/", response=AssessmentStaffProjectionSchema, operation_id="assessments_detail")
def detail(request, record_id: int):
    prepare_api_operation(request, "assessments_detail")
    value = queries.assessment_detail(_actor(request), record_id)
    if value is None:
        raise NotFoundError()
    return value


@router.get("/{record_id}/interpretation/", response=AssessmentSensitiveProjectionSchema, operation_id="assessments_interpretation")
def interpretation(request, record_id: int):
    prepare_api_operation(request, "assessments_interpretation")
    return assessment_sensitive_projection_for_actor(_actor(request), record_id)


@router.get("/{record_id}/file/metadata/", response=AssessmentFileMetadataSchema, operation_id="assessments_file_metadata")
def file_metadata(request, record_id: int):
    prepare_api_operation(request, "assessments_file_metadata")
    from apps.assessments.selectors import get_assessment_record_for_file_metadata

    record = get_assessment_record_for_file_metadata(_actor(request), record_id)
    if record is None:
        raise NotFoundError()
    from apps.assessments.selectors import get_assessment_file_metadata_for_actor

    value = get_assessment_file_metadata_for_actor(_actor(request), record)
    if value is None:
        raise NotFoundError()
    return protected_file_metadata_projection(value)


@router.get(
    "/{record_id}/file/download/",
    response=None,
    openapi_extra=protected_file_download_openapi(),
    operation_id="assessments_file_download",
)
def file_download(request, record_id: int):
    prepare_api_operation(request, "assessments_file_download")
    file_id = authorized_assessment_file_id(_actor(request), record_id)
    try:
        return build_protected_file_download_response(_actor(request), file_id)
    except ProtectedFileDownloadDenied as exc:
        raise NotFoundError() from exc


@router.post("/", response=AssessmentStaffProjectionSchema, operation_id="assessments_create")
def create(request, payload: CreateSchema):
    command = AssessmentCreateCommand(
        student_profile_id=payload.student_profile_id,
        instrument_id=payload.instrument_id,
        administered_at=payload.administered_at,
        source_form_reference=payload.source_form_reference,
        expected_instrument_updated_at=payload.expected_instrument_updated_at,
    )

    def execute():
        record = create_assessment_record(_actor(request), command)
        return ApiMutationOutcome(
            value=assessment_staff_projection(record),
            related_object=record,
            safe_response_path=f"/api/v1/assessments/{record.pk}/",
        )

    return _run(request, "assessments_create", _safe_fingerprint(command), execute, lambda key: _replay(_actor(request), key))


@router.post("/{record_id}/update/", response=AssessmentStaffProjectionSchema, operation_id="assessments_update")
def update(request, record_id: int, payload: UpdateSchema):
    fields = _fields(payload, (
        "administered_at", "source_form_reference", "raw_score", "scaled_score",
        "score_label", "interpretation_text", "interpretation_visibility",
    ))
    command = AssessmentUpdateCommand(
        fields=fields,
        administered_at=payload.administered_at,
        source_form_reference=payload.source_form_reference,
        raw_score=payload.raw_score,
        scaled_score=payload.scaled_score,
        score_label=payload.score_label,
        interpretation_text=payload.interpretation_text,
        interpretation_visibility=_enum(payload.interpretation_visibility),
        expected_updated_at=payload.expected_updated_at,
    )
    if not fields:
        raise ValidationError()

    def execute():
        record = update_assessment_record(_actor(request), record_id, command)
        return ApiMutationOutcome(value=assessment_staff_projection(record), related_object=record)

    return _run(request, "assessments_update", _safe_fingerprint(command, record_id=record_id), execute, lambda key: _replay(_actor(request), key))


@router.post("/{record_id}/record/", response=AssessmentStaffProjectionSchema, operation_id="assessments_record")
def record(request, record_id: int, payload: RecordSchema):
    fields = _fields(payload, ("raw_score", "scaled_score", "score_label", "interpretation_text", "interpretation_visibility"))
    command = AssessmentRecordCommand(
        fields=fields,
        raw_score=payload.raw_score,
        scaled_score=payload.scaled_score,
        score_label=payload.score_label,
        interpretation_text=payload.interpretation_text,
        interpretation_visibility=_enum(payload.interpretation_visibility),
        expected_updated_at=payload.expected_updated_at,
    )

    def execute():
        record = record_assessment_result(_actor(request), record_id, command)
        return ApiMutationOutcome(value=assessment_staff_projection(record), related_object=record)

    return _run(request, "assessments_record", _safe_fingerprint(command, record_id=record_id), execute, lambda key: _replay(_actor(request), key))


@router.post("/{record_id}/submit-review/", response=AssessmentStaffProjectionSchema, operation_id="assessments_submit_review")
def submit_review(request, record_id: int, payload: ExpectedStateSchema = ExpectedStateSchema()):
    command = AssessmentSubmitReviewCommand(expected_updated_at=payload.expected_updated_at)

    def execute():
        record = submit_assessment_for_review(_actor(request), record_id, command)
        return ApiMutationOutcome(value=assessment_staff_projection(record), related_object=record)

    return _run(request, "assessments_submit_review", _safe_fingerprint(command, record_id=record_id), execute, lambda key: _replay(_actor(request), key))


@router.post("/{record_id}/review/", response=AssessmentStaffProjectionSchema, operation_id="assessments_review")
def review(request, record_id: int, payload: ReviewSchema = ReviewSchema()):
    command = AssessmentReviewCommand(notes=payload.notes, expected_updated_at=payload.expected_updated_at)

    def execute():
        record = review_assessment_record(_actor(request), record_id, command)
        return ApiMutationOutcome(value=assessment_staff_projection(record), related_object=record)

    return _run(request, "assessments_review", _safe_fingerprint(command, record_id=record_id), execute, lambda key: _replay(_actor(request), key))


@router.post("/{record_id}/release/", response=AssessmentStaffProjectionSchema, operation_id="assessments_release")
def release(request, record_id: int, payload: ExpectedStateSchema = ExpectedStateSchema()):
    command = AssessmentReleaseCommand(expected_updated_at=payload.expected_updated_at)

    def execute():
        record = release_assessment_to_student(_actor(request), record_id, command)
        return ApiMutationOutcome(value=assessment_staff_projection(record), related_object=record)

    return _run(request, "assessments_release", _safe_fingerprint(command, record_id=record_id), execute, lambda key: _replay(_actor(request), key))


def _reason_mutation(request, operation_id, record_id, payload, command, service):
    def execute():
        record = service(_actor(request), record_id, command)
        return ApiMutationOutcome(value=assessment_staff_projection(record), related_object=record)

    return _run(request, operation_id, _safe_fingerprint(command, record_id=record_id), execute, lambda key: _replay(_actor(request), key))


@router.post("/{record_id}/void/", response=AssessmentStaffProjectionSchema, operation_id="assessments_void")
def void(request, record_id: int, payload: ReasonSchema = ReasonSchema()):
    return _reason_mutation(request, "assessments_void", record_id, payload, AssessmentVoidCommand(payload.reason_code, payload.expected_updated_at), void_assessment_record)


@router.post("/{record_id}/supersede/", response=AssessmentStaffProjectionSchema, operation_id="assessments_supersede")
def supersede(request, record_id: int, payload: SupersedeSchema):
    command = AssessmentSupersedeCommand(payload.replacement_record_id, payload.reason_code, payload.expected_updated_at)
    return _reason_mutation(request, "assessments_supersede", record_id, payload, command, supersede_assessment_record)


@router.post("/{record_id}/archive/", response=AssessmentStaffProjectionSchema, operation_id="assessments_archive")
def archive(request, record_id: int, payload: ReasonSchema = ReasonSchema()):
    return _reason_mutation(request, "assessments_archive", record_id, payload, AssessmentArchiveCommand(payload.reason_code, payload.expected_updated_at), archive_assessment_record)


@router.post("/{record_id}/file/attach/", response=AssessmentStaffProjectionSchema, operation_id="assessments_file_attach")
def attach_file(request, record_id: int, file: UploadedFile = File(...)):
    prepared = prepare_api_operation(request, "assessments_file_attach")
    upload = file
    try:
        validate_assessment_upload(upload)
    except SecurityError as exc:
        raise ValidationError() from exc
    actor = _actor(request)

    def execute():
        protected_file = None
        try:
            protected_file = store_protected_file_stream(
                user=actor,
                uploaded_file=upload,
                purpose=PurposeChoices.ASSESSMENT_RESULT_FILE,
                classification=ClassificationChoices.CONFIDENTIAL,
                app_label="assessments",
                model_name="StudentAssessmentRecord",
                object_id=str(record_id),
                access_policy_key="assessment_result_file",
            )
            record = attach_protected_assessment_file(
                actor,
                record_id,
                AssessmentFileUploadReceipt(protected_file_id=protected_file.pk),
            )
            return ApiMutationOutcome(value=assessment_staff_projection(record), related_object=record)
        except (StorageError, PolicyValidationError) as exc:
            if protected_file is not None:
                try:
                    get_storage_adapter().delete(protected_file.object_key)
                    protected_file.delete()
                except Exception:
                    pass
            raise DependencyFailureError() from exc
        except SecurityError as exc:
            if protected_file is not None:
                try:
                    get_storage_adapter().delete(protected_file.object_key)
                    protected_file.delete()
                except Exception:
                    pass
            raise ValidationError() from exc

    return _run(
        request,
        "assessments_file_attach",
        {"record_id": record_id, "attachment": True},
        execute,
        lambda key: _replay(actor, key),
        prepared=prepared,
    )
