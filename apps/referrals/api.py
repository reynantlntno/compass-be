"""Django Ninja adapter for the Referral workflow."""

from dataclasses import asdict, fields, is_dataclass
from datetime import date, datetime

from ninja import Router, Schema

from apps.common.api.idempotency import ApiMutationOutcome, run_api_mutation
from apps.common.api.operations import prepare_api_operation
from apps.common.api.pagination import PageQuery, PageSizeQuery, page_request_from_values
from apps.common.api.schemas import PageResultSchema
from apps.common.contracts import ContractValidationError, to_json_object
from apps.common.exceptions import NotFoundError, ValidationError
from apps.referrals import queries
from apps.referrals.commands import (
    ReferralActionCommand,
    ReferralAssignmentCommand,
    ReferralDraftCommand,
    ReferralReassignmentDecisionCommand,
    ReferralReassignmentRequestCommand,
    ReferralSubmitCommand,
    ReferralTransitionCommand,
    UNSET,
)
from apps.referrals.services import (
    add_referral_action,
    assign_referral_counselor,
    begin_referral_review,
    cancel_referral,
    close_referral,
    decide_referral_reassignment,
    escalate_referral_for_head_review,
    receive_referral,
    reassign_referral_counselor,
    reopen_referral,
    request_referral_reassignment,
    set_referral_action_required,
    submit_referral,
    create_referral_draft,
)
from apps.documents.workflow_api import (
    GeneratedDocumentMetadataSchema,
    download as workflow_document_download,
    generate as workflow_document_generate,
    preview as workflow_document_preview,
    workflow_download_openapi,
    workflow_preview_openapi,
)


router = Router(tags=["referrals"])


class ReferralQueueItemSchema(Schema):
    """Output-only queue projection for a scoped Referral list."""

    reference_code: str
    status_code: str
    status_label: str
    age_bucket: str
    assignment_state: str
    updated_at: datetime


class ReferralPageResultSchema(PageResultSchema):
    items: list[ReferralQueueItemSchema]


class ReferralActionOutputSchema(Schema):
    """Output-only action entry nested in Referral details."""

    action_code: str
    outcome_code: str
    remarks: str
    performed_at: datetime


class ReferralLinkedCallSlipPermissionSchema(Schema):
    update: bool
    issue: bool
    attendance: bool
    no_show: bool
    expire: bool
    cancel: bool
    reissue: bool
    print: bool


class ReferralLinkedCallSlipSchema(Schema):
    """Output-only linked Call Slip entry in a Referral detail."""

    reference_code: str
    status_code: str
    status_label: str
    scheduled_start_at: datetime | None
    scheduled_end_at: datetime | None
    issued_at: datetime | None
    acknowledged_at: datetime | None
    is_issued: bool
    is_acknowledged: bool
    is_terminal: bool
    reissued_from_reference: str
    successor_reference: str
    permissions: ReferralLinkedCallSlipPermissionSchema
    has_successor: bool


class ReferralDetailSchema(Schema):
    """Output-only Referral detail projection with bounded role variants."""

    reference_code: str
    status: str
    student_label: str
    source_type: str
    reason_text: str
    reason_category: str
    course_snapshot: str
    year_level_snapshot: str
    block_snapshot: str
    occurred_at: datetime | None
    source_signed_on: date | None
    assignment_state: str
    actions: list[ReferralActionOutputSchema]
    linked_call_slips: list[ReferralLinkedCallSlipSchema]
    field_group_codes: list[str]
    referrer_display_snapshot: str | None = None


class ReferralReassignmentDetailSchema(Schema):
    """Output-only reassignment request projection."""

    id: int
    reference_code: str
    status: str
    request_reason_code: str
    has_proposed_counselor: bool
    created_at: datetime


class ReferralMutationResponseSchema(Schema):
    """Output-only response shared by Referral mutations and replays."""

    reference_code: str
    status: str


class ReferralDraftSchema(Schema):
    student_id: int
    source_type: str
    reason_category_code: str = "UNCATEGORIZED"
    reason_text: str = ""
    referred_by_user_id: int | None = None
    referrer_display_snapshot: str = ""
    occurred_at: str | None = None
    source_signed_on: str | None = None
    course_snapshot: str = ""
    year_level_snapshot: str = ""
    block_snapshot: str = ""


class ReferralSubmitSchema(Schema):
    reason_category_code: str | None = None
    reason_text: str | None = None
    referrer_display_snapshot: str | None = None
    course_snapshot: str | None = None
    year_level_snapshot: str | None = None
    block_snapshot: str | None = None
    occurred_at: str | None = None
    source_signed_on: str | None = None


class ReferralTransitionSchema(Schema):
    reason_code: str
    reason_detail: str = ""


class ReferralActionSchema(Schema):
    action_code: str
    outcome_code: str = ""
    remarks: str = ""


class ReferralAssignmentSchema(Schema):
    counselor_id: int
    reason_code: str


class ReferralReassignmentSchema(Schema):
    proposed_counselor_id: int | None = None
    request_reason_code: str
    request_detail: str = ""


class ReferralDecisionSchema(Schema):
    decision: str
    decision_code: str
    decision_detail: str = ""


class ReferralCallSlipSchema(Schema):
    reissued_from_reference: str | None = None
    reissue_reason_code: str = ""
    destination_code: str = "GUIDANCE_OFFICE"
    report_to_destination: str = ""
    mode: str = "ONSITE"
    student_safe_location: str = ""
    student_safe_instructions: str = ""
    office_only_remarks: str = ""


def _actor(request):
    return request.auth.user


def _page(page: PageQuery, page_size: PageSizeQuery):
    try:
        return page_request_from_values(page, page_size)
    except ContractValidationError as exc:
        raise ValidationError() from exc


def _parse_date(value):
    if value in (None, ""):
        return None
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError() from exc


def _parse_datetime(value):
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError() from exc


def _data(payload):
    return payload.dict(exclude_unset=True) if payload is not None else {}


def _command_fingerprint(command, **extra):
    if not is_dataclass(command):
        raise ValidationError()
    values = {
        field.name: value
        for field in fields(command)
        if (value := getattr(command, field.name)) is not UNSET
    }
    return to_json_object({**extra, "command": values})


def _outcome(result):
    referral = result if hasattr(result, "reference_code") else getattr(result, "referral", None)
    if referral is None:
        raise ValidationError()
    return ApiMutationOutcome(
        value={"reference_code": referral.reference_code, "status": referral.status},
        related_object=referral,
        safe_response_path=f"/api/v1/referrals/{referral.reference_code}/",
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


@router.get("/", response=ReferralPageResultSchema, operation_id="referrals_list")
def list_referrals(request, page: PageQuery, page_size: PageSizeQuery):
    prepare_api_operation(request, "referrals_list")
    return queries.scoped_referral_page(_actor(request), _page(page, page_size)).as_dict()


@router.get(
    "/{reference_code}/document/preview/",
    response=None,
    openapi_extra=workflow_preview_openapi(),
    operation_id="referrals_document_preview",
)
def document_preview(request, reference_code: str):
    return workflow_document_preview(
        request, operation_id="referrals_document_preview", domain="referrals",
        stable_key="referral_slip", target_reference=reference_code,
    )


class DocumentGenerateSchema(Schema):
    expected_updated_at: str = ""


@router.post(
    "/{reference_code}/document/generate/",
    response=GeneratedDocumentMetadataSchema,
    operation_id="referrals_document_generate",
)
def document_generate(request, reference_code: str, payload: DocumentGenerateSchema):
    return workflow_document_generate(
        request, operation_id="referrals_document_generate", domain="referrals",
        stable_key="referral_slip", target_reference=reference_code,
        expected_updated_at=payload.expected_updated_at,
    )


@router.get(
    "/{reference_code}/document/download/",
    response=None,
    openapi_extra=workflow_download_openapi(),
    operation_id="referrals_document_download",
)
def document_download(request, reference_code: str):
    return workflow_document_download(
        request, operation_id="referrals_document_download", domain="referrals",
        stable_key="referral_slip", target_reference=reference_code,
    )


@router.get(
    "/{reference_code}/",
    response=ReferralDetailSchema,
    exclude_unset=True,
    operation_id="referrals_detail",
)
def referral_detail(request, reference_code: str):
    prepare_api_operation(request, "referrals_detail")
    value = queries.referral_detail(_actor(request), reference_code)
    if value is None:
        raise NotFoundError()
    return value


@router.get(
    "/reassignment/{request_id}/",
    response=ReferralReassignmentDetailSchema,
    operation_id="referrals_reassignment_detail",
)
def reassignment_detail(request, request_id: int):
    prepare_api_operation(request, "referrals_reassignment_detail")
    value = queries.reassignment_request_detail(_actor(request), request_id)
    if value is None:
        raise NotFoundError()
    return value


@router.post("/", response=ReferralMutationResponseSchema, operation_id="referrals_create")
def create(request, payload: ReferralDraftSchema):
    data = _data(payload)
    command = ReferralDraftCommand(
        source_type=data["source_type"],
        reason_category_code=data.get("reason_category_code", "UNCATEGORIZED"),
        reason_text=data.get("reason_text", ""),
        referred_by_user_id=data.get("referred_by_user_id"),
        referrer_display_snapshot=data.get("referrer_display_snapshot", ""),
        occurred_at=_parse_datetime(data.get("occurred_at")),
        source_signed_on=_parse_date(data.get("source_signed_on")),
        course_snapshot=data.get("course_snapshot", ""),
        year_level_snapshot=data.get("year_level_snapshot", ""),
        block_snapshot=data.get("block_snapshot", ""),
    )
    prepared = prepare_api_operation(request, "referrals_create")
    return run_api_mutation(
        request,
        "referrals_create",
        _command_fingerprint(command, student_id=data["student_id"]),
        lambda: _outcome(create_referral_draft(
            _actor(request), data["student_id"], command, prepared.idempotency_key,
        )),
        _replay,
        prepared_operation=prepared,
    )


def _transition_route(request, reference_code, operation_id, transition, service):
    command = ReferralTransitionCommand(
        reason_code=transition.reason_code,
        reason_detail=transition.reason_detail,
    )
    return _run(
        request,
        operation_id,
        _command_fingerprint(command, reference_code=reference_code),
        lambda: _outcome(service(_actor(request), reference_code, command)),
    )


@router.post("/{reference_code}/submit/", response=ReferralMutationResponseSchema, operation_id="referrals_submit")
def submit(request, reference_code: str, payload: ReferralSubmitSchema | None = None):
    data = _data(payload)
    for field_name in ("occurred_at", "source_signed_on"):
        if field_name in data:
            data[field_name] = _parse_datetime(data[field_name]) if field_name == "occurred_at" else _parse_date(data[field_name])
    command = ReferralSubmitCommand(**data)
    return _run(request, "referrals_submit", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(submit_referral(_actor(request), reference_code, command)))


@router.post("/{reference_code}/receive/", response=ReferralMutationResponseSchema, operation_id="referrals_receive")
def receive(request, reference_code: str, payload: ReferralTransitionSchema):
    return _transition_route(request, reference_code, "referrals_receive", payload, receive_referral)


@router.post("/{reference_code}/review/", response=ReferralMutationResponseSchema, operation_id="referrals_review")
def review(request, reference_code: str, payload: ReferralTransitionSchema):
    return _transition_route(request, reference_code, "referrals_review", payload, begin_referral_review)


@router.post("/{reference_code}/actions/", response=ReferralMutationResponseSchema, operation_id="referrals_action")
def action(request, reference_code: str, payload: ReferralActionSchema):
    command = ReferralActionCommand(**_data(payload))
    prepared = prepare_api_operation(request, "referrals_action")
    return run_api_mutation(request, "referrals_action", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(add_referral_action(_actor(request), reference_code, command, prepared.idempotency_key)), _replay, prepared_operation=prepared)


@router.post("/{reference_code}/action-required/", response=ReferralMutationResponseSchema, operation_id="referrals_action_required")
def action_required(request, reference_code: str, payload: ReferralTransitionSchema):
    return _transition_route(request, reference_code, "referrals_action_required", payload, set_referral_action_required)


@router.post("/{reference_code}/reassignment/", response=ReferralMutationResponseSchema, operation_id="referrals_reassignment_request")
def request_reassignment(request, reference_code: str, payload: ReferralReassignmentSchema):
    command = ReferralReassignmentRequestCommand(**_data(payload))
    prepared = prepare_api_operation(request, "referrals_reassignment_request")
    return run_api_mutation(request, "referrals_reassignment_request", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(request_referral_reassignment(_actor(request), reference_code, command, prepared.idempotency_key)), _replay, prepared_operation=prepared)


@router.post("/{reference_code}/assign/", response=ReferralMutationResponseSchema, operation_id="referrals_assign")
def assign(request, reference_code: str, payload: ReferralAssignmentSchema):
    command = ReferralAssignmentCommand(**_data(payload))
    return _run(request, "referrals_assign", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(assign_referral_counselor(_actor(request), reference_code, command)))


@router.post("/{reference_code}/reassign/", response=ReferralMutationResponseSchema, operation_id="referrals_reassign")
def reassign(request, reference_code: str, payload: ReferralAssignmentSchema):
    command = ReferralAssignmentCommand(**_data(payload))
    return _run(request, "referrals_reassign", _command_fingerprint(command, reference_code=reference_code), lambda: _outcome(reassign_referral_counselor(_actor(request), reference_code, command)))


@router.post("/{reference_code}/reassignment/{request_id}/decision/", response=ReferralMutationResponseSchema, operation_id="referrals_reassignment_decision")
def reassignment_decision(request, reference_code: str, request_id: int, payload: ReferralDecisionSchema):
    command = ReferralReassignmentDecisionCommand(**_data(payload))
    return _run(request, "referrals_reassignment_decision", _command_fingerprint(command, reference_code=reference_code, request_id=request_id), lambda: _outcome(decide_referral_reassignment(_actor(request), request_id, command)))


@router.post("/{reference_code}/escalate/", response=ReferralMutationResponseSchema, operation_id="referrals_escalate")
def escalate(request, reference_code: str, payload: ReferralTransitionSchema):
    return _transition_route(request, reference_code, "referrals_escalate", payload, escalate_referral_for_head_review)


@router.post("/{reference_code}/close/", response=ReferralMutationResponseSchema, operation_id="referrals_close")
def close(request, reference_code: str, payload: ReferralTransitionSchema):
    return _transition_route(request, reference_code, "referrals_close", payload, close_referral)


@router.post("/{reference_code}/cancel/", response=ReferralMutationResponseSchema, operation_id="referrals_cancel")
def cancel(request, reference_code: str, payload: ReferralTransitionSchema):
    return _transition_route(request, reference_code, "referrals_cancel", payload, cancel_referral)


@router.post("/{reference_code}/reopen/", response=ReferralMutationResponseSchema, operation_id="referrals_reopen")
def reopen(request, reference_code: str, payload: ReferralTransitionSchema):
    return _transition_route(request, reference_code, "referrals_reopen", payload, reopen_referral)
