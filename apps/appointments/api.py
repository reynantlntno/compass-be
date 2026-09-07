"""Client-facing Appointments API.

Every route uses the shared operation preparation (no-store, correlation
headers, central rate limits) and, for state-changing operations, the shared
idempotency adapter. Domain services receive actor + stable reference +
typed command only; no request dictionaries cross that boundary.
"""

from dataclasses import asdict, is_dataclass
from datetime import date as date_type
from datetime import datetime as datetime_type
from datetime import time as time_type

from ninja import Router, Schema

from apps.appointments import queries as appointments_queries
from apps.appointments.commands import (
    AppointmentAssignmentCommand,
    AppointmentCancellationCommand,
    AppointmentCompletionCommand,
    AppointmentNoShowCommand,
    AppointmentRequestCommand,
    AppointmentReviewCommand,
    AppointmentScheduleCommand,
    LateCancellationDecisionCommand,
    LateCancellationRequestCommand,
)
from apps.appointments.services import (
    assign_counselor,
    complete_appointment,
    create_appointment_request,
    decide_appointment_review,
    review_late_cancellation,
    reassign_counselor,
    request_late_cancellation,
    review_and_schedule_appointment,
    schedule_appointment,
    submit_appointment_request,
)
from apps.common.api.idempotency import ApiMutationOutcome, run_api_mutation
from apps.common.api.operations import prepare_api_operation
from apps.common.api.pagination import PageQuery, PageSizeQuery, page_request_from_values
from apps.common.api.schemas import PageResultSchema
from apps.common.contracts import ContractValidationError, to_json_object
from apps.common.exceptions import NotFoundError, ValidationError


router = Router(tags=["appointments"])


class AppointmentProjectionSchema(Schema):
    """Actor-scoped appointment output.

    Role-specific fields are optional because the projection deliberately
    omits them for actors who are not allowed to see them.  This schema is an
    output contract only; request payloads use the command schemas below.
    """

    reference_code: str
    appointment_type: str
    appointment_mode: str
    status: str
    requested_date: date_type | None = None
    requested_start_time: time_type | None = None
    confirmed_date: date_type | None = None
    confirmed_start_time: time_type | None = None
    confirmed_end_time: time_type | None = None
    reason: str | None = None
    cancellation_reason: str | None = None
    internal_notes: str | None = None
    assigned_counselor_id: int | None = None
    preferred_counselor_id: int | None = None
    reviewed_by_id: int | None = None


class AppointmentPageResultSchema(PageResultSchema):
    items: list[AppointmentProjectionSchema]


class AvailableSlotSchema(Schema):
    start: datetime_type
    end: datetime_type
    max_appointments_per_slot: int


class AvailableSlotPageResultSchema(PageResultSchema):
    items: list[AvailableSlotSchema]


class OfficeClosureSchema(Schema):
    public_reference: str
    date: date_type
    start_time: time_type | None = None
    end_time: time_type | None = None
    is_all_day: bool


class OfficeClosurePageResultSchema(PageResultSchema):
    items: list[OfficeClosureSchema]


class AppointmentMutationResponseSchema(Schema):
    reference_code: str
    status: str


class ScheduleChangeResponseSchema(Schema):
    kind: str
    public_reference: str
    is_active: bool


class AppointmentRequestSchema(Schema):
    appointment_type: str
    appointment_mode: str
    preferred_counselor: str | None = None
    requested_date: date_type | None = None
    requested_start_time: str | None = None
    reason: str


class ReviewDecisionSchema(Schema):
    action: str
    assigned_counselor: str | None = None
    confirmed_date: date_type | None = None
    confirmed_start_time: str | None = None
    confirmed_end_time: str | None = None
    decline_reason: str = ""
    internal_notes: str = ""
    reason: str = ""


class ScheduleSchema(Schema):
    confirmed_date: date_type
    confirmed_start_time: str
    confirmed_end_time: str
    internal_notes: str = ""


class ReasonSchema(Schema):
    reason: str


class DecisionSchema(Schema):
    decision: str
    notes: str = ""


class CompletionSchema(Schema):
    actual_start_time: str | None = None
    actual_end_time: str | None = None


class AssignmentSchema(Schema):
    counselor: str
    reason: str = ""

def _actor(request):
    return request.auth.user


def _page(page: PageQuery, page_size: PageSizeQuery):
    try:
        return page_request_from_values(page, page_size)
    except ContractValidationError as error:
        raise ValidationError() from error


def _payload(payload):
    data = payload.dict(exclude_unset=True)
    for field_name in (
        "requested_start_time",
        "confirmed_start_time",
        "confirmed_end_time",
    ):
        if isinstance(data.get(field_name), str):
            try:
                data[field_name] = time_type.fromisoformat(data[field_name])
            except ValueError as error:
                raise ValidationError() from error
    for field_name in ("actual_start_time", "actual_end_time"):
        if isinstance(data.get(field_name), str):
            try:
                data[field_name] = datetime_type.fromisoformat(data[field_name])
            except ValueError as error:
                raise ValidationError() from error
    return data


def _outcome(appointment):
    return ApiMutationOutcome(
        value={
            "reference_code": appointment.reference_code,
            "status": appointment.status,
        },
        related_object=appointment,
        safe_response_path=f"/api/v1/appointments/{appointment.reference_code}/",
    )


def _appointment_id(reference_code):
    """Resolve the public reference to the stable orchestration target ID."""
    from apps.appointments.models import Appointment

    appointment_id = (
        Appointment.objects.filter(
            reference_code=str(reference_code or "").strip(),
        )
        .values_list("pk", flat=True)
        .first()
    )
    if appointment_id is None:
        raise NotFoundError()
    return str(appointment_id)


def _fingerprint_payload(*, reference_code=None, command=None, **extra):
    payload = dict(extra)
    if reference_code is not None:
        payload["reference_code"] = str(reference_code)
    if command is not None:
        if not is_dataclass(command):
            raise ValidationError()
        payload["command"] = asdict(command)
    return to_json_object(payload)


def _replay(key):
    object_id = getattr(key, "related_object_id", None)
    if not object_id:
        return None
    if str(getattr(key, "action_scope", "")).startswith("appointments_") and str(
        getattr(key, "related_object_type", "")
    ) in {"AvailabilityRule", "UnavailableBlock", "OfficeClosure"}:
        return appointments_queries.replay_schedule_change_by_id(
            object_id,
            getattr(key, "related_object_type", ""),
        )
    return appointments_queries.replay_by_id(object_id)


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


@router.get("/", response=AppointmentPageResultSchema, operation_id="appointments_list")
def list_appointments(request, page: PageQuery, page_size: PageSizeQuery):
    prepare_api_operation(request, "appointments_list")
    return appointments_queries.scoped_appointment_page(
        _actor(request),
        _page(page, page_size),
    ).as_dict()


@router.get("/slots/", response=AvailableSlotPageResultSchema, operation_id="appointments_available_slots")
def list_available_slots(request, counselor: int, date: date_type, mode: str = "ONSITE", page: PageQuery = 1, page_size: PageSizeQuery = 25):
    prepare_api_operation(request, "appointments_available_slots")
    return appointments_queries.available_slots_page(
        _actor(request),
        counselor,
        date,
        mode,
        _page(page, page_size),
    ).as_dict()


@router.post("/", response=AppointmentMutationResponseSchema, operation_id="appointments_create")
def create_request(request, payload: AppointmentRequestSchema):
    actor = _actor(request)
    data = _payload(payload)
    command = AppointmentRequestCommand(
        appointment_type=data["appointment_type"],
        appointment_mode=data["appointment_mode"],
        preferred_counselor_id=data.get("preferred_counselor"),
        requested_date=data.get("requested_date"),
        requested_start_time=data.get("requested_start_time"),
        reason=data["reason"],
    )
    return _run(
        request,
        "appointments_create",
        _fingerprint_payload(command=command),
        lambda: _outcome(create_appointment_request(actor, command)),
    )

@router.post("/{reference_code}/submit/", response=AppointmentMutationResponseSchema, operation_id="appointments_submit")
def submit_request(request, reference_code: str):
    actor = _actor(request)
    return _run(
        request,
        "appointments_submit",
        _fingerprint_payload(reference_code=reference_code),
        lambda: _outcome(submit_appointment_request(actor, reference_code)),
    )


@router.post("/{reference_code}/review/", response=AppointmentMutationResponseSchema, operation_id="appointments_review_decision")
def review_decision(request, reference_code: str, payload: ReviewDecisionSchema):
    actor = _actor(request)
    data = _payload(payload)
    command = AppointmentReviewCommand(
        action=data["action"],
        assigned_counselor_id=data.get("assigned_counselor"),
        confirmed_date=data.get("confirmed_date"),
        confirmed_start_time=data.get("confirmed_start_time"),
        confirmed_end_time=data.get("confirmed_end_time"),
        decline_reason=data.get("decline_reason", ""),
        internal_notes=data.get("internal_notes", ""),
        reason=data.get("reason", ""),
    )
    return _run(
        request,
        "appointments_review_decision",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _outcome(decide_appointment_review(actor, reference_code, command)),
    )


@router.post("/{reference_code}/schedule/", response=AppointmentMutationResponseSchema, operation_id="appointments_schedule")
def schedule(request, reference_code: str, payload: ScheduleSchema):
    actor = _actor(request)
    command = AppointmentScheduleCommand(**_payload(payload))
    return _run(
        request,
        "appointments_schedule",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _outcome(schedule_appointment(actor, reference_code, command)),
    )


@router.post("/{reference_code}/review-and-schedule/", response=AppointmentMutationResponseSchema, operation_id="appointments_review_and_schedule")
def review_and_schedule(request, reference_code: str, payload: ReviewDecisionSchema):
    actor = _actor(request)
    data = _payload(payload)
    command = AppointmentReviewCommand(
        action=data["action"],
        assigned_counselor_id=data.get("assigned_counselor"),
        confirmed_date=data.get("confirmed_date"),
        confirmed_start_time=data.get("confirmed_start_time"),
        confirmed_end_time=data.get("confirmed_end_time"),
        decline_reason=data.get("decline_reason", ""),
        internal_notes=data.get("internal_notes", ""),
        reason=data.get("reason", ""),
    )
    return _run(
        request,
        "appointments_review_and_schedule",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _outcome(review_and_schedule_appointment(actor, reference_code, command)),
    )


@router.post("/{reference_code}/assign-counselor/", response=AppointmentMutationResponseSchema, operation_id="appointments_assign_counselor")
def assign(request, reference_code: str, payload: AssignmentSchema):
    actor = _actor(request)
    command = AppointmentAssignmentCommand(
        counselor_id=payload.counselor,
        reason=payload.reason,
    )
    return _run(
        request,
        "appointments_assign_counselor",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _outcome(assign_counselor(actor, reference_code, command)),
    )


@router.post("/{reference_code}/reassign-counselor/", response=AppointmentMutationResponseSchema, operation_id="appointments_reassign_counselor")
def reassign(request, reference_code: str, payload: AssignmentSchema):
    actor = _actor(request)
    command = AppointmentAssignmentCommand(
        counselor_id=payload.counselor,
        reason=payload.reason,
    )
    return _run(
        request,
        "appointments_reassign_counselor",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _outcome(reassign_counselor(actor, reference_code, command)),
    )

@router.post("/{reference_code}/cancel/", response=AppointmentMutationResponseSchema, operation_id="appointments_cancel")
def cancel(request, reference_code: str, payload: ReasonSchema):
    from apps.orchestration.commands import LinkedAppointmentCommand
    from apps.orchestration.use_cases import cancel_appointment_with_linked_session

    actor = _actor(request)
    command = AppointmentCancellationCommand(**_payload(payload))
    linked_command = LinkedAppointmentCommand(
        appointment_id=_appointment_id(reference_code),
        reason=command.reason,
    )
    return _run(
        request,
        "appointments_cancel",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _outcome(cancel_appointment_with_linked_session(actor, linked_command)),
    )


@router.post("/{reference_code}/late-cancellation/", response=AppointmentMutationResponseSchema, operation_id="appointments_late_cancellation_request")
def request_late_cancellation_route(request, reference_code: str, payload: ReasonSchema):
    actor = _actor(request)
    command = LateCancellationRequestCommand(**_payload(payload))
    return _run(
        request,
        "appointments_late_cancellation_request",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _outcome(request_late_cancellation(actor, reference_code, command)),
    )


@router.post("/{reference_code}/late-cancellation/decision/", response=AppointmentMutationResponseSchema, operation_id="appointments_late_cancellation_decision")
def decide_late_cancellation_route(request, reference_code: str, payload: DecisionSchema):
    actor = _actor(request)
    command = LateCancellationDecisionCommand(**_payload(payload))
    action = lambda: _outcome(review_late_cancellation(actor, reference_code, command))
    return _run(
        request,
        "appointments_late_cancellation_decision",
        _fingerprint_payload(reference_code=reference_code, command=command),
        action,
    )


@router.post("/{reference_code}/complete/", response=AppointmentMutationResponseSchema, operation_id="appointments_complete")
def complete(request, reference_code: str, payload: CompletionSchema | None = None):
    actor = _actor(request)
    data = _payload(payload) if payload is not None else {}
    command = AppointmentCompletionCommand(**data)
    return _run(
        request,
        "appointments_complete",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _outcome(complete_appointment(actor, reference_code, command)),
    )


@router.post("/{reference_code}/no-show/", response=AppointmentMutationResponseSchema, operation_id="appointments_no_show")
def no_show(request, reference_code: str):
    from apps.orchestration.commands import LinkedAppointmentCommand
    from apps.orchestration.use_cases import mark_appointment_no_show_with_linked_session

    actor = _actor(request)
    command = AppointmentNoShowCommand()
    return _run(
        request,
        "appointments_no_show",
        _fingerprint_payload(reference_code=reference_code, command=command),
        lambda: _outcome(
            mark_appointment_no_show_with_linked_session(
                actor,
                LinkedAppointmentCommand(appointment_id=_appointment_id(reference_code)),
            )
        ),
    )

class ScheduleChangeSchema(Schema):
    kind: str
    operation: str = "create"
    target_reference: str | None = None
    counselor: str | None = None
    day_of_week: int | None = None
    start_time: str | None = None
    end_time: str | None = None
    mode: str = ""
    location: str = ""
    slot_duration_minutes: int | None = None
    max_appointments_per_slot: int | None = None
    block_date: date_type | None = None
    is_all_day: bool = False
    scope_reason: str = ""
    effective_from: date_type | None = None
    effective_until: date_type | None = None
    reason: str
    request_key: str
    expected_fingerprint: str = ""
    confirm: bool = False
    handoff_action: str = ""


def _schedule_payload(payload):
    data = payload.dict(exclude_unset=True)
    for field_name in ("start_time", "end_time"):
        if isinstance(data.get(field_name), str):
            try:
                data[field_name] = time_type.fromisoformat(data[field_name])
            except ValueError as error:
                raise ValidationError() from error
    return data


def _schedule_projection(record):
    return {
        "kind": type(record).__name__,
        "public_reference": str(getattr(record, "public_reference", "") or ""),
        "is_active": getattr(record, "is_active", True),
    }


def _schedule_command(
    payload,
    *,
    allowed_kinds=None,
    operation=None,
    target_reference=None,
):
    from apps.appointments.commands import ScheduleChangeCommand

    data = _schedule_payload(payload)
    if allowed_kinds is not None and data.get("kind") not in allowed_kinds:
        raise ValidationError()
    if operation is not None:
        data["operation"] = operation
    if target_reference is not None:
        data["target_reference"] = target_reference
    counselor_id = data.pop("counselor", None)
    return ScheduleChangeCommand(counselor_id=counselor_id, **data)


def _schedule_change_outcome(actor, command, safe_response_path):
    from apps.appointments.availability_services import apply_schedule_change_for_command

    record = apply_schedule_change_for_command(actor, command)
    return ApiMutationOutcome(
        value=_schedule_projection(record),
        related_object=record,
        safe_response_path=safe_response_path,
    )


@router.post("/schedule-changes/", response=ScheduleChangeResponseSchema, operation_id="appointments_schedule_change")
def schedule_change(request, payload: ScheduleChangeSchema):
    actor = _actor(request)
    command = _schedule_command(payload)
    return _run(
        request,
        "appointments_schedule_change",
        _fingerprint_payload(command=command),
        lambda: _schedule_change_outcome(
            actor,
            command,
            "/api/v1/appointments/schedule-changes/",
        ),
    )


@router.post("/availability/", response=ScheduleChangeResponseSchema, operation_id="appointments_availability_create")
def create_availability(request, payload: ScheduleChangeSchema):
    actor = _actor(request)
    command = _schedule_command(
        payload,
        allowed_kinds={"availability_rule", "unavailable_block"},
        operation="create",
    )
    return _run(
        request,
        "appointments_availability_create",
        _fingerprint_payload(command=command),
        lambda: _schedule_change_outcome(actor, command, "/api/v1/appointments/availability/"),
    )


@router.put("/availability/{public_reference}/", response=ScheduleChangeResponseSchema, operation_id="appointments_availability_update")
def update_availability(request, public_reference: str, payload: ScheduleChangeSchema):
    actor = _actor(request)
    command = _schedule_command(
        payload,
        allowed_kinds={"availability_rule", "unavailable_block"},
        operation="update",
        target_reference=public_reference,
    )
    return _run(
        request,
        "appointments_availability_update",
        _fingerprint_payload(reference_code=public_reference, command=command),
        lambda: _schedule_change_outcome(
            actor,
            command,
            f"/api/v1/appointments/availability/{public_reference}/",
        ),
    )


@router.post("/availability/{public_reference}/deactivate/", response=ScheduleChangeResponseSchema, operation_id="appointments_availability_deactivate")
def deactivate_availability(request, public_reference: str, payload: ScheduleChangeSchema):
    actor = _actor(request)
    command = _schedule_command(
        payload,
        allowed_kinds={"availability_rule", "unavailable_block"},
        operation="void",
        target_reference=public_reference,
    )
    return _run(
        request,
        "appointments_availability_deactivate",
        _fingerprint_payload(reference_code=public_reference, command=command),
        lambda: _schedule_change_outcome(
            actor,
            command,
            f"/api/v1/appointments/availability/{public_reference}/",
        ),
    )


@router.get("/office-closures/", response=OfficeClosurePageResultSchema, operation_id="appointments_office_closures")
def office_closures(request, page: PageQuery, page_size: PageSizeQuery):
    prepare_api_operation(request, "appointments_office_closures")
    return appointments_queries.active_office_closure_page(
        _actor(request),
        _page(page, page_size),
    ).as_dict()


@router.post("/office-closures/", response=ScheduleChangeResponseSchema, operation_id="appointments_office_closure_create")
def create_office_closure(request, payload: ScheduleChangeSchema):
    actor = _actor(request)
    command = _schedule_command(
        payload,
        allowed_kinds={"office_closure"},
        operation="create",
    )
    return _run(
        request,
        "appointments_office_closure_create",
        _fingerprint_payload(command=command),
        lambda: _schedule_change_outcome(actor, command, "/api/v1/appointments/office-closures/"),
    )


@router.put("/office-closures/{public_reference}/", response=ScheduleChangeResponseSchema, operation_id="appointments_office_closure_update")
def update_office_closure(request, public_reference: str, payload: ScheduleChangeSchema):
    actor = _actor(request)
    command = _schedule_command(
        payload,
        allowed_kinds={"office_closure"},
        operation="update",
        target_reference=public_reference,
    )
    return _run(
        request,
        "appointments_office_closure_update",
        _fingerprint_payload(reference_code=public_reference, command=command),
        lambda: _schedule_change_outcome(
            actor,
            command,
            f"/api/v1/appointments/office-closures/{public_reference}/",
        ),
    )


@router.post("/office-closures/{public_reference}/deactivate/", response=ScheduleChangeResponseSchema, operation_id="appointments_office_closure_deactivate")
def deactivate_office_closure(request, public_reference: str, payload: ScheduleChangeSchema):
    actor = _actor(request)
    command = _schedule_command(
        payload,
        allowed_kinds={"office_closure"},
        operation="void",
        target_reference=public_reference,
    )
    return _run(
        request,
        "appointments_office_closure_deactivate",
        _fingerprint_payload(reference_code=public_reference, command=command),
        lambda: _schedule_change_outcome(
            actor,
            command,
            f"/api/v1/appointments/office-closures/{public_reference}/",
        ),
    )


@router.get("/{reference_code}/", response=AppointmentProjectionSchema, operation_id="appointments_detail")
def appointment_detail(request, reference_code: str):
    prepare_api_operation(request, "appointments_detail")
    detail = appointments_queries.appointment_detail(_actor(request), reference_code)
    if detail is None:
        raise NotFoundError()
    return detail
