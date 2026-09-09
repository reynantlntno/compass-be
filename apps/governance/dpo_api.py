"""Governance-owned DPO appointment API."""

from datetime import datetime
from uuid import UUID

from ninja import Router, Schema
from pydantic import Field

from apps.common.api.idempotency import ApiMutationOutcome, run_api_mutation
from apps.common.api.operations import prepare_api_operation
from apps.common.exceptions import NotFoundError
from apps.governance.dpo_commands import DPOAppointmentRequest
from apps.governance.dpo_services import (
    create_dpo_appointment_request,
    is_current_dpo,
    retire_dpo_appointment_by_id,
)
from apps.governance.models import DPOAppointment
from apps.governance.projections import project_dpo_appointment
from apps.governance.selectors import active_dpo_appointment


router = Router(tags=["policies"])


class DPOAppointmentCreateSchema(Schema):
    holder_id: int
    valid_from: datetime
    valid_until: datetime | None = None
    appointment_reference: str
    contact_email: str


class DPOAppointmentSchema(Schema):
    id: str
    holder_id: int
    valid_from: str
    valid_until: str | None = None
    appointment_reference: str
    contact_email: str
    status: str
    appointed_at: str
    retired_at: str | None = None


class CurrentDPOAppointmentSchema(Schema):
    label: str = Field(..., max_length=40)


class GovernanceReasonSchema(Schema):
    reason_code: str = ""


def _actor(request):
    return request.auth.user


def _dpo_governance_actor(actor):
    from apps.access_control.authority import has_fixed_capability
    from apps.access_control.capabilities import Capability
    from apps.access_control.rules import is_head_guidance

    return bool(
        is_current_dpo(actor)
        or (is_head_guidance(actor) and has_fixed_capability(actor, Capability.ORGANIZATION_GOVERNANCE_MANAGE))
    )


def _appointment_replay(key):
    appointment = DPOAppointment.objects.filter(pk=key.related_object_id).first()
    return project_dpo_appointment(appointment)


def _governance_outcome(value, path):
    return ApiMutationOutcome(
        value=project_dpo_appointment(value),
        related_object=value,
        safe_response_path=path,
    )


@router.get(
    "/dpo-appointment/",
    response=DPOAppointmentSchema,
    exclude_unset=True,
    operation_id="policies_dpo_appointment_view",
)
def dpo_appointment_view(request):
    actor = _actor(request)
    if not _dpo_governance_actor(actor):
        raise NotFoundError()
    value = active_dpo_appointment()
    if value is None:
        raise NotFoundError()
    return project_dpo_appointment(value)


@router.get(
    "/dpo-appointment/me/",
    response=CurrentDPOAppointmentSchema,
    exclude_unset=True,
    operation_id="policies_dpo_appointment_me",
)
def dpo_appointment_me(request):
    if not is_current_dpo(_actor(request)):
        raise NotFoundError()
    return {"label": "DPO"}


@router.post(
    "/dpo-appointment/",
    response=DPOAppointmentSchema,
    exclude_unset=True,
    operation_id="policies_dpo_appointment_create",
)
def dpo_appointment_create(request, payload: DPOAppointmentCreateSchema):
    actor = _actor(request)
    command = DPOAppointmentRequest(
        holder_id=payload.holder_id,
        valid_from=payload.valid_from,
        valid_until=payload.valid_until,
        appointment_reference=payload.appointment_reference,
        contact_email=payload.contact_email,
    )
    prepared = prepare_api_operation(request, "policies_dpo_appointment_create")
    return run_api_mutation(
        request,
        "policies_dpo_appointment_create",
        {"holder_id": command.holder_id, "appointment_reference": command.appointment_reference},
        lambda: _governance_outcome(
            create_dpo_appointment_request(actor=actor, request=command),
            "/api/v1/policies/dpo-appointment/",
        ),
        _appointment_replay,
        prepared_operation=prepared,
    )


@router.post(
    "/dpo-appointment/{appointment_id}/retire/",
    response=DPOAppointmentSchema,
    exclude_unset=True,
    operation_id="policies_dpo_appointment_retire",
)
def dpo_appointment_retire(request, appointment_id: UUID, payload: GovernanceReasonSchema | None = None):
    actor = _actor(request)
    reason_code = (payload.reason_code if payload else "DPO_APPOINTMENT_RETIRED")[:80]
    prepared = prepare_api_operation(request, "policies_dpo_appointment_retire")
    return run_api_mutation(
        request,
        "policies_dpo_appointment_retire",
        {"appointment_id": str(appointment_id), "reason_code": reason_code},
        lambda: _governance_outcome(
            retire_dpo_appointment_by_id(actor=actor, appointment_id=appointment_id, reason_code=reason_code),
            "/api/v1/policies/dpo-appointment/",
        ),
        _appointment_replay,
        prepared_operation=prepared,
    )
