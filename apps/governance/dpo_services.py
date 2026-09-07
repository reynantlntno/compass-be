"""Governance-owned DPO appointment and authorization queries."""

from django.core import exceptions as django_exceptions
from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.access_control.authority import has_fixed_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import is_active_nonlegacy_actor, is_head_guidance
from apps.audit.services import audit_log
from apps.common.exceptions import GovernanceError, NotFoundError, PermissionDeniedError, ValidationError
from apps.governance.choices import DPOAppointmentStatus
from apps.governance.dpo_commands import DPOAppointmentRequest
from apps.governance.models import DPOAppointment


def is_current_dpo(actor, *, at=None) -> bool:
    if not is_active_nonlegacy_actor(actor):
        return False
    from apps.governance.selectors import active_dpo_appointment

    appointment = active_dpo_appointment(at=at)
    return bool(appointment and appointment.holder_id == actor.pk)


@transaction.atomic
def create_dpo_appointment(*, actor, holder, valid_from, valid_until, appointment_reference, contact_email, system_context=False):
    if not system_context and not (is_head_guidance(actor) and has_fixed_capability(actor, Capability.ORGANIZATION_GOVERNANCE_MANAGE)):
        raise PermissionDeniedError("DPO appointment requires controlled institutional setup.")
    if actor is not None and getattr(actor, "pk", None) == getattr(holder, "pk", None):
        raise PermissionDeniedError("The appointing actor cannot self-appoint as DPO.")
    if DPOAppointment.objects.select_for_update().filter(status=DPOAppointmentStatus.ACTIVE).exists():
        raise ValidationError("Only one active DPO appointment may exist.")
    appointment = DPOAppointment(
        holder=holder,
        valid_from=valid_from,
        valid_until=valid_until,
        appointment_reference=appointment_reference,
        contact_email=contact_email,
        appointed_by=actor,
    )
    try:
        appointment.full_clean()
    except django_exceptions.ValidationError as exc:
        raise ValidationError() from exc
    try:
        appointment.save()
    except IntegrityError as exc:
        raise ValidationError("Only one active DPO appointment may exist.") from exc
    event = audit_log(
        action_type="DPO_APPOINTMENT_CREATED",
        event_category="GOVERNANCE",
        target_model="governance.DPOAppointment",
        target_object_id=str(appointment.pk),
        actor_user=actor,
        source_app="apps.governance",
        metadata={"holder_id": holder.pk, "appointment_reference": appointment_reference[:120]},
    )
    if event is None:
        raise GovernanceError("DPO appointment audit could not be recorded.")
    return appointment


@transaction.atomic
def create_dpo_appointment_request(*, actor, request: DPOAppointmentRequest, system_context=False):
    from apps.accounts.models import User

    if not request.holder_id or len(request.appointment_reference.strip()) > 255:
        raise ValidationError("DPO appointment evidence is invalid.")
    if len(request.contact_email.strip()) > 254:
        raise ValidationError("DPO contact metadata is invalid.")
    holder = User.objects.select_for_update().filter(pk=request.holder_id).first()
    if holder is None:
        raise ValidationError("The DPO holder does not exist.")
    return create_dpo_appointment(
        actor=actor,
        holder=holder,
        valid_from=request.valid_from,
        valid_until=request.valid_until,
        appointment_reference=request.appointment_reference,
        contact_email=request.contact_email,
        system_context=system_context,
    )


@transaction.atomic
def retire_dpo_appointment(*, actor, appointment, reason_code="DPO_APPOINTMENT_RETIRED"):
    if not (is_head_guidance(actor) and has_fixed_capability(actor, Capability.ORGANIZATION_GOVERNANCE_MANAGE)):
        raise PermissionDeniedError("DPO appointment retirement requires controlled institutional setup.")
    current = DPOAppointment.objects.select_for_update().get(pk=appointment.pk)
    if current.status == DPOAppointmentStatus.RETIRED:
        return current
    current.status = DPOAppointmentStatus.RETIRED
    current.retired_by = actor
    current.retired_at = timezone.now()
    current.save(update_fields=["status", "retired_by", "retired_at", "updated_at"])
    event = audit_log(
        action_type="DPO_APPOINTMENT_RETIRED",
        event_category="GOVERNANCE",
        target_model="governance.DPOAppointment",
        target_object_id=str(current.pk),
        actor_user=actor,
        source_app="apps.governance",
        metadata={"reason_code": reason_code},
    )
    if event is None:
        raise GovernanceError("DPO appointment audit could not be recorded.")
    return current


@transaction.atomic
def retire_dpo_appointment_by_id(*, actor, appointment_id, reason_code="DPO_APPOINTMENT_RETIRED"):
    appointment = DPOAppointment.objects.select_for_update().filter(pk=appointment_id).first()
    if appointment is None:
        raise NotFoundError()
    return retire_dpo_appointment(actor=actor, appointment=appointment, reason_code=reason_code)
