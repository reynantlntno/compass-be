"""Django Ninja adapter for Call Slip workflows."""

from dataclasses import fields, is_dataclass
from datetime import date, datetime

from ninja import Router, Schema

from apps.call_slips import queries
from apps.call_slips import queue as call_slips_queue
from apps.call_slips.commands import (
    CallSlipAssignmentCommand,
    CallSlipAttendanceCommand,
    CallSlipDecisionCommand,
    CallSlipDraftCommand,
    CallSlipDraftUpdateCommand,
    CallSlipIssueCommand,
    CallSlipReasonCommand,
    CallSlipRescheduleCommand,
    UNSET,
)
from apps.call_slips.services import (
    acknowledge_call_slip,
    assign_call_slip,
    cancel_call_slip,
    create_call_slip_draft,
    decide_call_slip_reschedule,
    expire_call_slip,
    issue_call_slip,
    mark_call_slip_no_show,
    record_call_slip_attendance,
    reassign_call_slip,
    request_call_slip_reschedule,
    update_call_slip_draft,
)
from apps.common.api.idempotency import ApiMutationOutcome, run_api_mutation
from apps.common.api.operations import prepare_api_operation
from apps.common.api.pagination import PageQuery, PageSizeQuery, page_request_from_values
from apps.common.api.schemas import PageResultSchema
from apps.common.contracts import ContractValidationError, to_json_object
from apps.common.exceptions import NotFoundError, ValidationError
from apps.orchestration.commands import ReferralCallSlipCommand
from apps.orchestration.use_cases import create_call_slip_from_referral_workflow
from apps.documents.workflow_api import (
    GeneratedDocumentMetadataSchema,
    download as workflow_document_download,
    generate as workflow_document_generate,
    preview as workflow_document_preview,
    workflow_download_openapi,
    workflow_preview_openapi,
)


router = Router(tags=["call-slips"])


class CallSlipQueueItemSchema(Schema):
    """Output-only queue projection for a scoped Call Slip list."""

    reference_code: str
    status_code: str
    status_label: str
    schedule_bucket: str
    assignment_state: str
    updated_at: datetime


class CallSlipPageResultSchema(PageResultSchema):
    items: list[CallSlipQueueItemSchema]


class CallSlipStaffQueueItemSchema(Schema):
    """Staff queue projection for the Call Slips workspace.

    Row scope and sensitive-field access remain owned by the existing Call Slip
    selectors and policies; this schema is an explicit allowlist only.
    """

    reference_code: str
    student_display_name: str
    student_number: str | None = None
    source_type: str
    source_type_label: str
    purpose_code: str
    purpose_label: str
    mode_code: str
    mode_label: str
    destination_code: str
    destination_label: str
    status: str
    status_label: str
    assignment_state: str
    schedule_bucket: str
    scheduled_start_at: datetime | None = None
    scheduled_end_at: datetime | None = None
    referral_reference: str | None = None
    appointment_reference: str | None = None
    issued_at: datetime | None = None
    acknowledged_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class CallSlipStaffQueuePageResultSchema(PageResultSchema):
    items: list[CallSlipStaffQueueItemSchema]


class CallSlipCounselorOptionSchema(Schema):
    """Staff assign target represented by a short-lived opaque selector."""

    selection_token: str
    display_name: str


class CallSlipCounselorOptionPageSchema(PageResultSchema):
    items: list[CallSlipCounselorOptionSchema]


class CallSlipDetailSchema(Schema):
    """Superset contract for the role-dependent Call Slip detail route."""

    reference_code: str
    scheduled_start_at: datetime | None
    scheduled_end_at: datetime | None
    expected_duration_minutes: int
    mode_label: str
    purpose_label: str
    student_safe_instructions: str
    status_label: str

    # Operational-only fields are omitted from the student projection.
    status_code: str | None = None
    student_label: str | None = None
    source_type_label: str | None = None
    assignment_state: str | None = None
    destination_label: str | None = None
    report_to_destination: str | None = None
    student_safe_location: str | None = None
    office_only_remarks: str | None = None
    has_referral_link: bool | None = None
    referral_reference: str | None = None
    has_appointment_link: bool | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    source_form_code: str | None = None
    source_form_revision: int | None = None
    is_printable: bool | None = None

    # Student-only fields are omitted from the operational projection.
    issued_date: date | None = None
    safe_destination: str | None = None
    can_acknowledge: bool | None = None
    can_reschedule: bool | None = None


class StudentCallSlipDetailSchema(Schema):
    """Output-only student Call Slip projection."""

    reference_code: str
    issued_date: date | None
    scheduled_start_at: datetime | None
    scheduled_end_at: datetime | None
    expected_duration_minutes: int
    mode_label: str
    safe_destination: str
    purpose_label: str
    student_safe_instructions: str
    status_label: str
    can_acknowledge: bool
    can_reschedule: bool


class PrintableCallSlipSchema(Schema):
    """Output-only printable Call Slip projection."""

    reference_code: str
    issued_date: date
    scheduled_start_at: datetime | None
    scheduled_end_at: datetime | None
    expected_duration_minutes: int
    mode_label: str
    safe_destination: str
    purpose_label: str
    student_safe_instructions: str
    status_label: str
    source_form_code: str
    source_form_revision: int
    source_form_family: str


class CallSlipRescheduleRequestDetailSchema(Schema):
    """Output-only reschedule request projection."""

    id: int
    reference_code: str
    status: str
    previous_start_at: datetime
    previous_end_at: datetime
    proposed_start_at: datetime
    proposed_end_at: datetime
    student_reason: str
    decision_code: str
    decision_detail: str


class CallSlipMutationResponseSchema(Schema):
    """Output-only response shared by Call Slip mutations and replays."""

    reference_code: str
    status: str


class CallSlipDraftSchema(Schema):
    student_id: int | None = None
    student_selection_token: str | None = None
    source_type: str
    purpose_code: str
    destination_code: str
    referral_reference: str | None = None
    appointment_reference: str | None = None
    reissued_from_reference: str | None = None
    reissue_reason_code: str = ""
    assigned_counselor_id: int | None = None
    report_to_destination: str = ""
    mode: str = "ONSITE"
    student_safe_location: str = ""
    student_safe_instructions: str = ""
    office_only_remarks: str = ""


class CallSlipFromReferralSchema(Schema):
    referral_reference: str
    reissued_from_reference: str | None = None
    reissue_reason_code: str = ""
    destination_code: str = "GUIDANCE_OFFICE"
    report_to_destination: str = ""
    mode: str = "ONSITE"
    student_safe_location: str = ""
    student_safe_instructions: str = ""
    office_only_remarks: str = ""


class CallSlipDraftUpdateSchema(Schema):
    source_type: str | None = None
    purpose_code: str | None = None
    destination_code: str | None = None
    assigned_counselor_id: int | None = None
    report_to_destination: str | None = None
    mode: str | None = None
    student_safe_location: str | None = None
    student_safe_instructions: str | None = None
    office_only_remarks: str | None = None


class CallSlipIssueSchema(Schema):
    scheduled_start_at: str
    scheduled_end_at: str
    expected_duration_minutes: int = 60
    assigned_counselor_id: int | None = None
    mode: str | None = None
    report_to_destination: str | None = None
    student_safe_location: str | None = None
    student_safe_instructions: str | None = None


class CallSlipRescheduleSchema(Schema):
    proposed_start_at: str
    proposed_end_at: str
    proposed_expected_duration_minutes: int
    student_reason: str


class CallSlipDecisionSchema(Schema):
    decision: str
    decision_code: str
    decision_detail: str = ""


class CallSlipAttendanceSchema(Schema):
    reported_at: str | None = None
    interview_ended_at: str | None = None


class CallSlipReasonSchema(Schema):
    reason_code: str
    detail: str = ""


class CallSlipAssignmentSchema(Schema):
    target_counselor_id: int | None = None
    counselor_selection_token: str | None = None
    reason_code: str


def _actor(request):
    return request.auth.user


def _page(page: PageQuery, page_size: PageSizeQuery):
    try:
        return page_request_from_values(page, page_size)
    except ContractValidationError as exc:
        raise ValidationError() from exc


def _data(payload):
    return payload.dict(exclude_unset=True) if payload is not None else {}


def _resolve_student_id(actor, data: dict) -> int:
    legacy_id = data.pop("student_id", None)
    selection_token = data.pop("student_selection_token", None)
    if legacy_id is not None and selection_token:
        raise ValidationError()
    if selection_token:
        from apps.access_control.student_selectors import resolve_student_selection_token

        profile = resolve_student_selection_token(actor, "call_slip", selection_token)
        if profile is None:
            raise ValidationError()
        return profile.user_id
    if isinstance(legacy_id, bool) or not isinstance(legacy_id, int) or legacy_id <= 0:
        raise ValidationError()
    return legacy_id


def _resolve_counselor_assignment(actor, reference_code: str, data: dict) -> dict:
    legacy_id = data.pop("target_counselor_id", None)
    selection_token = data.pop("counselor_selection_token", None)
    if legacy_id is not None and selection_token:
        raise ValidationError()
    if selection_token:
        from apps.access_control.selection_tokens import resolve_counselor_selection_token

        counselor = resolve_counselor_selection_token(
            actor, "call_slip", reference_code, selection_token,
        )
        if counselor is None:
            raise ValidationError()
        data["target_counselor_id"] = counselor.pk
    elif legacy_id is not None:
        data["target_counselor_id"] = legacy_id
    else:
        raise ValidationError()
    return data


def _dt(value):
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError() from exc


def _command_fingerprint(command, **extra):
    if not is_dataclass(command):
        raise ValidationError()
    values = {
        field.name: value
        for field in fields(command)
        if (value := getattr(command, field.name)) is not UNSET
    }
    return to_json_object({**extra, "command": values})


def _outcome(slip):
    return ApiMutationOutcome(
        value={"reference_code": slip.reference_code, "status": slip.status},
        related_object=slip,
        safe_response_path=f"/api/v1/call-slips/{slip.reference_code}/",
    )


def _replay(key):
    object_id = getattr(key, "related_object_id", None)
    if not object_id:
        return None
    return queries.replay_by_id(object_id)


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


@router.get("/", response=CallSlipPageResultSchema, operation_id="call_slips_list")
def list_call_slips(request, page: PageQuery, page_size: PageSizeQuery):
    prepare_api_operation(request, "call_slips_list")
    return queries.scoped_call_slip_page(_actor(request), _page(page, page_size)).as_dict()


@router.get("/queue/", response=CallSlipStaffQueuePageResultSchema, operation_id="call_slips_queue_list")
def list_call_slip_queue(
    request,
    page: PageQuery,
    page_size: PageSizeQuery,
    q: str = "",
    status: str = "",
    academic_year: str = "",
    assignment: str = "all",
    purpose: str = "",
    mode: str = "",
    destination: str = "",
    order: str = "recent",
):
    """Staff-facing Call Slips queue with bounded filters and an allowlist row."""
    prepare_api_operation(request, "call_slips_queue_list")
    return call_slips_queue.queue_page(
        _actor(request),
        _page(page, page_size),
        query=q,
        statuses=status,
        academic_year=academic_year,
        assignment=assignment,
        purpose_codes=purpose,
        mode_codes=mode,
        destination_codes=destination,
        order=order,
    )


@router.get(
    "/{reference_code}/counselor-options/",
    response=CallSlipCounselorOptionPageSchema,
    operation_id="call_slips_counselor_options",
)
def call_slip_counselor_options(
    request,
    reference_code: str,
    page: PageQuery,
    page_size: PageSizeQuery,
    q: str = "",
):
    prepare_api_operation(request, "call_slips_counselor_options")
    from apps.call_slips.models import CallSlip
    from apps.call_slips.selectors import (
        get_call_slip_counselor_options,
        get_operational_call_slip_sensitive_detail,
    )

    # The scoped sensitive-detail selector both authorizes the reader and
    # confirms the reference without exposing existence to unauthorized callers.
    if get_operational_call_slip_sensitive_detail(_actor(request), reference_code) is None:
        raise NotFoundError()
    slip = CallSlip.objects.filter(reference_code=str(reference_code or "").strip()).first()
    if slip is None:
        raise NotFoundError()
    return get_call_slip_counselor_options(
        _actor(request), slip, q=q, page=_page(page, page_size),
    ).as_dict()


@router.get(
    "/{reference_code}/document/preview/",
    response=None,
    openapi_extra=workflow_preview_openapi(),
    operation_id="call_slips_document_preview",
)
def document_preview(request, reference_code: str):
    return workflow_document_preview(
        request, operation_id="call_slips_document_preview", domain="call_slips",
        stable_key="call_slip", target_reference=reference_code,
    )


class DocumentGenerateSchema(Schema):
    expected_updated_at: str = ""


@router.post(
    "/{reference_code}/document/generate/",
    response=GeneratedDocumentMetadataSchema,
    operation_id="call_slips_document_generate",
)
def document_generate(request, reference_code: str, payload: DocumentGenerateSchema):
    return workflow_document_generate(
        request, operation_id="call_slips_document_generate", domain="call_slips",
        stable_key="call_slip", target_reference=reference_code,
        expected_updated_at=payload.expected_updated_at,
    )


@router.get(
    "/{reference_code}/document/download/",
    response=None,
    openapi_extra=workflow_download_openapi(),
    operation_id="call_slips_document_download",
)
def document_download(request, reference_code: str):
    return workflow_document_download(
        request, operation_id="call_slips_document_download", domain="call_slips",
        stable_key="call_slip", target_reference=reference_code,
    )


@router.get(
    "/{reference_code}/",
    response=CallSlipDetailSchema,
    exclude_unset=True,
    operation_id="call_slips_detail",
)
def call_slip_detail(request, reference_code: str):
    prepare_api_operation(request, "call_slips_detail")
    value = queries.call_slip_detail(_actor(request), reference_code)
    if value is None:
        raise NotFoundError()
    return value


@router.get(
    "/{reference_code}/student-detail/",
    response=StudentCallSlipDetailSchema,
    operation_id="call_slips_student_detail",
)
def student_detail(request, reference_code: str):
    prepare_api_operation(request, "call_slips_student_detail")
    value = queries.student_call_slip_detail(_actor(request), reference_code)
    if value is None:
        raise NotFoundError()
    return value


@router.get(
    "/{reference_code}/printable/",
    response=PrintableCallSlipSchema,
    operation_id="call_slips_printable",
)
def printable(request, reference_code: str):
    prepare_api_operation(request, "call_slips_printable")
    value = queries.printable_call_slip(_actor(request), reference_code)
    if value is None:
        raise NotFoundError()
    return value


@router.get(
    "/reschedule/{request_id}/",
    response=CallSlipRescheduleRequestDetailSchema,
    operation_id="call_slips_reschedule_detail",
)
def reschedule_detail(request, request_id: int):
    prepare_api_operation(request, "call_slips_reschedule_detail")
    value = queries.reschedule_request_detail(_actor(request), request_id)
    if value is None:
        raise NotFoundError()
    return value


@router.post("/", response=CallSlipMutationResponseSchema, operation_id="call_slips_create")
def create(request, payload: CallSlipDraftSchema):
    data = _data(payload)
    data["student_id"] = _resolve_student_id(_actor(request), data)
    if data.get("referral_reference"):
        raise ValidationError("Referral-linked Call Slips must use the referral orchestration route.")
    command = CallSlipDraftCommand(**data)
    prepared = prepare_api_operation(request, "call_slips_create")
    return run_api_mutation(
        request,
        "call_slips_create",
        _command_fingerprint(command),
        lambda: _outcome(create_call_slip_draft(_actor(request), command, prepared.idempotency_key)),
        _replay,
        prepared_operation=prepared,
    )


@router.post("/from-referral/", response=CallSlipMutationResponseSchema, operation_id="call_slips_from_referral")
def from_referral(request, payload: CallSlipFromReferralSchema):
    command = ReferralCallSlipCommand(**_data(payload))
    prepared = prepare_api_operation(request, "call_slips_from_referral")
    return run_api_mutation(
        request,
        "call_slips_from_referral",
        _command_fingerprint(command),
        lambda: _outcome(create_call_slip_from_referral_workflow(
            _actor(request), command, prepared.idempotency_key,
        )),
        _replay,
        prepared_operation=prepared,
    )


@router.post("/{reference_code}/assign/", response=CallSlipMutationResponseSchema, operation_id="call_slips_assign")
def assign(request, reference_code: str, payload: CallSlipAssignmentSchema):
    data = _resolve_counselor_assignment(_actor(request), reference_code, _data(payload))
    command = CallSlipAssignmentCommand(**data)
    return _run(request, "call_slips_assign", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(assign_call_slip(_actor(request), reference_code, command)))


@router.post("/{reference_code}/reassign/", response=CallSlipMutationResponseSchema, operation_id="call_slips_reassign")
def reassign(request, reference_code: str, payload: CallSlipAssignmentSchema):
    data = _resolve_counselor_assignment(_actor(request), reference_code, _data(payload))
    command = CallSlipAssignmentCommand(**data)
    return _run(request, "call_slips_reassign", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(reassign_call_slip(_actor(request), reference_code, command)))


@router.post("/{reference_code}/", response=CallSlipMutationResponseSchema, operation_id="call_slips_update")
def update(request, reference_code: str, payload: CallSlipDraftUpdateSchema):
    command = CallSlipDraftUpdateCommand(**_data(payload))
    return _run(request, "call_slips_update", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(update_call_slip_draft(_actor(request), reference_code, command)))


@router.post("/{reference_code}/issue/", response=CallSlipMutationResponseSchema, operation_id="call_slips_issue")
def issue(request, reference_code: str, payload: CallSlipIssueSchema):
    data = _data(payload)
    command = CallSlipIssueCommand(
        scheduled_start_at=_dt(data["scheduled_start_at"]),
        scheduled_end_at=_dt(data["scheduled_end_at"]),
        expected_duration_minutes=data.get("expected_duration_minutes", 60),
        assigned_counselor_id=data.get("assigned_counselor_id", UNSET),
        mode=data.get("mode", UNSET),
        report_to_destination=data.get("report_to_destination", UNSET),
        student_safe_location=data.get("student_safe_location", UNSET),
        student_safe_instructions=data.get("student_safe_instructions", UNSET),
    )
    return _run(request, "call_slips_issue", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(issue_call_slip(_actor(request), reference_code, command)))


@router.post("/{reference_code}/acknowledge/", response=CallSlipMutationResponseSchema, operation_id="call_slips_acknowledge")
def acknowledge(request, reference_code: str):
    return _run(request, "call_slips_acknowledge", {"reference_code": reference_code}, lambda: _outcome(acknowledge_call_slip(_actor(request), reference_code)))


@router.post("/{reference_code}/reschedule/", response=CallSlipMutationResponseSchema, operation_id="call_slips_reschedule_request")
def request_reschedule(request, reference_code: str, payload: CallSlipRescheduleSchema):
    data = _data(payload)
    command = CallSlipRescheduleCommand(
        proposed_start_at=_dt(data["proposed_start_at"]),
        proposed_end_at=_dt(data["proposed_end_at"]),
        proposed_expected_duration_minutes=data["proposed_expected_duration_minutes"],
        student_reason=data["student_reason"],
    )
    prepared = prepare_api_operation(request, "call_slips_reschedule_request")
    return run_api_mutation(
        request,
        "call_slips_reschedule_request",
        _command_fingerprint(command, reference_code=reference_code),
        lambda: _outcome(request_call_slip_reschedule(_actor(request), reference_code, command, prepared.idempotency_key).call_slip),
        _replay,
        prepared_operation=prepared,
    )


@router.post("/reschedule/{request_id}/decision/", response=CallSlipMutationResponseSchema, operation_id="call_slips_reschedule_decision")
def decide_reschedule(request, request_id: int, payload: CallSlipDecisionSchema):
    command = CallSlipDecisionCommand(**_data(payload))
    return _run(request, "call_slips_reschedule_decision", _command_fingerprint(command, request_id=request_id), lambda: _outcome(decide_call_slip_reschedule(_actor(request), request_id, command).call_slip))


@router.post("/{reference_code}/attendance/", response=CallSlipMutationResponseSchema, operation_id="call_slips_attendance")
def attendance(request, reference_code: str, payload: CallSlipAttendanceSchema | None = None):
    data = _data(payload)
    command = CallSlipAttendanceCommand(
        reported_at=_dt(data.get("reported_at")),
        interview_ended_at=_dt(data.get("interview_ended_at")),
    )
    return _run(request, "call_slips_attendance", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(record_call_slip_attendance(_actor(request), reference_code, command)))


@router.post("/{reference_code}/no-show/", response=CallSlipMutationResponseSchema, operation_id="call_slips_no_show")
def no_show(request, reference_code: str, payload: CallSlipReasonSchema):
    command = CallSlipReasonCommand(**_data(payload))
    return _run(request, "call_slips_no_show", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(mark_call_slip_no_show(_actor(request), reference_code, command)))


@router.post("/{reference_code}/expire/", response=CallSlipMutationResponseSchema, operation_id="call_slips_expire")
def expire(request, reference_code: str, payload: CallSlipReasonSchema):
    command = CallSlipReasonCommand(**_data(payload))
    return _run(request, "call_slips_expire", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(expire_call_slip(_actor(request), reference_code, command)))


@router.post("/{reference_code}/cancel/", response=CallSlipMutationResponseSchema, operation_id="call_slips_cancel")
def cancel(request, reference_code: str, payload: CallSlipReasonSchema):
    command = CallSlipReasonCommand(**_data(payload))
    return _run(request, "call_slips_cancel", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(cancel_call_slip(_actor(request), reference_code, command)))
