"""Transactional services for counselor availability and office closures."""

from __future__ import annotations

import datetime
import hashlib
import json
import uuid
import copy
from dataclasses import dataclass

from django.core import signing
from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.appointments.config import get_slot_duration_minutes
from apps.appointments.models import (
    ACTIVE_APPOINTMENT_STATUSES,
    Appointment,
    AppointmentStatusChoices,
    AvailabilityRule,
    OfficeClosure,
    ScheduleChangeEvent,
    ScheduleCoordinationLock,
    UnavailableBlock,
)
from apps.appointments.policies import (
    can_manage_availability_for,
    can_manage_office_closure_scope,
)
from apps.audit.services import audit_log
from apps.common.exceptions import ErrorCode, ValidationError
from apps.common.request_dedup import RequestKeyPolicy, validate_and_lock_request_key, normalize_request_key


SCHEDULE_REVIEW_SALT = "compass.appointments.schedule-review.v1"
_SCHEDULE_REQUEST_KEY_POLICY = RequestKeyPolicy("appointments.schedule", max_length=64)
SCHEDULE_REVIEW_MAX_AGE = 15 * 60
PENDING_STATUSES = (
    AppointmentStatusChoices.SUBMITTED,
    AppointmentStatusChoices.PENDING_REVIEW,
    AppointmentStatusChoices.APPROVED,
)
CONFIRMED_STATUSES = (
    AppointmentStatusChoices.SCHEDULED,
    AppointmentStatusChoices.LATE_CANCELLATION_REQUESTED,
    AppointmentStatusChoices.LATE_CANCELLATION_DECLINED,
)


class AvailabilityManagementError(ValidationError):
    """Base class for safe availability-workspace failures."""


class AvailabilityPermissionError(AvailabilityManagementError):
    code = ErrorCode.PERMISSION
    public_message = "You do not have permission to manage this schedule."


class AvailabilityConflictError(AvailabilityManagementError):
    code = ErrorCode.LIFECYCLE_CONFLICT
    public_message = "The schedule cannot be changed in its current state."


class AvailabilityReviewExpired(AvailabilityManagementError):
    code = ErrorCode.STALE_STATE
    public_message = "The schedule review has expired. Refresh and try again."


class AvailabilityHandoffRequired(AvailabilityManagementError):
    def __init__(self, preview):
        super().__init__("Existing appointments require an explicit operational handoff.")
        self.preview = preview


@dataclass(frozen=True)
class AppointmentImpact:
    pending: tuple[Appointment, ...] = ()
    scheduled: tuple[Appointment, ...] = ()

    @property
    def pending_count(self):
        return len(self.pending)

    @property
    def scheduled_count(self):
        return len(self.scheduled)

    @property
    def fingerprint(self):
        values = [
            *(f"pending:{item.pk}" for item in self.pending),
            *(f"scheduled:{item.pk}" for item in self.scheduled),
        ]
        return hashlib.sha256("|".join(values).encode("utf-8")).hexdigest()


def _lock(scope_key: str):
    """Get and lock one coordination row inside the caller's transaction."""
    try:
        lock, _created = ScheduleCoordinationLock.objects.get_or_create(scope_key=scope_key)
    except IntegrityError:
        lock = ScheduleCoordinationLock.objects.get(scope_key=scope_key)
    return ScheduleCoordinationLock.objects.select_for_update().get(pk=lock.pk)


def _lock_for_kind(kind: str, counselor_id: int | None = None):
    """Acquire schedule locks in the shared office -> counselor order."""
    locks = [_lock("office")]
    if kind != "office_closure":
        if counselor_id is None:
            raise AvailabilityManagementError("A counselor is required for this schedule change.")
        locks.append(_lock(f"counselor:{counselor_id}"))
    return locks


def lock_schedule_scope(counselor_id: int | None = None):
    """Acquire the booking/schedule locks in a fixed order."""
    locks = [_lock("office")]
    if counselor_id is not None:
        locks.append(_lock(f"counselor:{counselor_id}"))
    return locks


def _as_date(value):
    if isinstance(value, datetime.date):
        return value
    return datetime.date.fromisoformat(str(value))


def _as_time(value):
    if isinstance(value, datetime.time):
        return value
    return datetime.time.fromisoformat(str(value)) if value else None


def _interval_overlaps(start, end, other_start, other_end):
    return start < other_end and end > other_start


def _mode_intersects(left, right):
    return left == "BOTH" or right == "BOTH" or left == right


def _date_ranges_intersect(left_from, left_until, right_from, right_until):
    left_until = left_until or datetime.date.max
    right_until = right_until or datetime.date.max
    return left_from <= right_until and right_from <= left_until


def _state(record):
    if isinstance(record, AvailabilityRule):
        return {
            "type": "availability_rule",
            "counselor": record.counselor_id,
            "day_of_week": record.day_of_week,
            "start_time": record.start_time.isoformat(),
            "end_time": record.end_time.isoformat(),
            "mode": record.mode,
            "location_set": bool(record.location),
            "slot_duration_minutes": record.slot_duration_minutes,
            "max_appointments_per_slot": record.max_appointments_per_slot,
            "is_active": record.is_active,
            "effective_from": record.effective_from.isoformat(),
            "effective_until": record.effective_until.isoformat() if record.effective_until else None,
        }
    return {
        "type": "unavailable_block" if isinstance(record, UnavailableBlock) else "office_closure",
        "scope": record.counselor_id if isinstance(record, UnavailableBlock) else "office",
        "date": record.date.isoformat(),
        "start_time": record.start_time.isoformat() if record.start_time else None,
        "end_time": record.end_time.isoformat() if record.end_time else None,
        "is_all_day": record.is_all_day,
        "is_active": record.is_active,
        "reason_set": bool(record.reason),
    }


def _record_from_payload(kind, payload, *, counselor=None, instance=None, actor=None):
    data = dict(payload)
    if kind == "availability_rule":
        record = copy.copy(instance) if instance is not None else AvailabilityRule()
        record.counselor = counselor or record.counselor
        record.day_of_week = int(data["day_of_week"])
        record.start_time = _as_time(data["start_time"])
        record.end_time = _as_time(data["end_time"])
        record.mode = data["mode"]
        record.location = data.get("location", "")
        record.slot_duration_minutes = int(data.get("slot_duration_minutes") or get_slot_duration_minutes())
        record.max_appointments_per_slot = int(data.get("max_appointments_per_slot") or 1)
        record.effective_from = _as_date(data["effective_from"])
        record.effective_until = _as_date(data["effective_until"]) if data.get("effective_until") else None
        record.is_active = bool(data.get("is_active", True))
        if actor and not record.created_by_id:
            record.created_by = actor
        return record
    model = UnavailableBlock if kind == "unavailable_block" else OfficeClosure
    record = copy.copy(instance) if instance is not None else model()
    if kind == "unavailable_block":
        record.counselor = counselor or record.counselor
    record.date = _as_date(data["date"])
    record.is_all_day = bool(data.get("is_all_day"))
    start_value = data.get("start_time")
    end_value = data.get("end_time")
    has_start = start_value not in (None, "")
    has_end = end_value not in (None, "")
    if record.is_all_day and (has_start or has_end):
        raise ValidationError("All-day schedule records must have cleared start and end times.")
    if not record.is_all_day and not (has_start and has_end):
        raise ValidationError("Timed schedule records require both start and end times.")
    record.start_time = None if record.is_all_day else _as_time(start_value)
    record.end_time = None if record.is_all_day else _as_time(end_value)
    record.reason = str(data.get("reason", "")).strip()
    record.is_active = bool(data.get("is_active", True))
    if actor and not record.created_by_id:
        record.created_by = actor
    return record


def _validate_reason(reason):
    reason = str(reason or "").strip()
    if not reason:
        raise ValidationError("An operational reason is required.")
    if len(reason) > 200:
        raise ValidationError("The operational reason must be 200 characters or fewer.")
    return reason


def _validate_overlaps(record, *, exclude_pk=None):
    if isinstance(record, AvailabilityRule):
        candidates = AvailabilityRule.objects.filter(
            counselor=record.counselor,
            day_of_week=record.day_of_week,
            is_active=True,
        ).exclude(pk=exclude_pk)
        for other in candidates:
            if not _mode_intersects(record.mode, other.mode):
                continue
            if _date_ranges_intersect(record.effective_from, record.effective_until, other.effective_from, other.effective_until) and _interval_overlaps(record.start_time, record.end_time, other.start_time, other.end_time):
                raise AvailabilityConflictError("This active availability overlaps another rule for the same counselor.")
        return
    if isinstance(record, UnavailableBlock):
        candidates = UnavailableBlock.objects.filter(counselor=record.counselor, date=record.date, is_active=True).exclude(pk=exclude_pk)
    else:
        candidates = OfficeClosure.objects.filter(date=record.date, is_active=True).exclude(pk=exclude_pk)
    for other in candidates:
        if record.is_all_day or other.is_all_day:
            raise AvailabilityConflictError("This active schedule block overlaps another block in the same scope.")
        if _interval_overlaps(record.start_time, record.end_time, other.start_time, other.end_time):
            raise AvailabilityConflictError("This active schedule block overlaps another block in the same scope.")


def _appointment_interval(appointment):
    start = appointment.confirmed_start_time or appointment.requested_start_time
    if not start:
        return None
    end = appointment.confirmed_end_time
    if not end:
        end_dt = datetime.datetime.combine(datetime.date.today(), start) + datetime.timedelta(minutes=get_slot_duration_minutes())
        end = end_dt.time()
    return start, end


def _appointment_affected(appointment, record):
    if isinstance(record, AvailabilityRule):
        if appointment.assigned_counselor_id != record.counselor_id:
            return False
        if record.mode != "BOTH" and appointment.appointment_mode != record.mode:
            return False
        target_date = appointment.confirmed_date or appointment.requested_date
        if not target_date or target_date.weekday() != record.day_of_week:
            return False
        if not (record.effective_from <= target_date and (record.effective_until is None or target_date <= record.effective_until)):
            return False
        interval = _appointment_interval(appointment)
        return bool(interval and _interval_overlaps(interval[0], interval[1], record.start_time, record.end_time))
    target_date = appointment.confirmed_date or appointment.requested_date
    if not target_date or target_date != record.date:
        return False
    if isinstance(record, UnavailableBlock) and appointment.assigned_counselor_id != record.counselor_id:
        return False
    if record.is_all_day:
        return True
    interval = _appointment_interval(appointment)
    return bool(interval and _interval_overlaps(interval[0], interval[1], record.start_time, record.end_time))


def _impact(record):
    queryset = Appointment.objects.filter(status__in=(*PENDING_STATUSES, *CONFIRMED_STATUSES)).select_related("assigned_counselor")
    pending = []
    scheduled = []
    for appointment in queryset:
        if not _appointment_affected(appointment, record):
            continue
        if appointment.status in PENDING_STATUSES:
            pending.append(appointment)
        else:
            scheduled.append(appointment)
    return AppointmentImpact(tuple(pending), tuple(scheduled))


def _preview_payload(kind, record, impact, *, operation, request_key):
    return {
        "kind": kind,
        "operation": operation,
        "record_reference": str(record.public_reference) if getattr(record, "public_reference", None) else "",
        "record_state": _state(record),
        "pending_count": impact.pending_count,
        "scheduled_count": impact.scheduled_count,
        "affected_outcome": "UNCHANGED_HANDOFF_REQUIRED" if (impact.pending_count or impact.scheduled_count) else "NONE",
        "fingerprint": impact.fingerprint,
        "request_key": request_key,
    }


def _json_safe(value):
    if isinstance(value, (datetime.date, datetime.time, datetime.datetime)):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def build_review_token(preview, *, actor, payload=None):
    return signing.dumps(
        {"actor_id": actor.pk, **preview, "payload": _json_safe(payload or {})},
        salt=SCHEDULE_REVIEW_SALT,
    )


def load_review_token(token, *, actor):
    try:
        payload = signing.loads(token, salt=SCHEDULE_REVIEW_SALT, max_age=SCHEDULE_REVIEW_MAX_AGE)
    except (signing.BadSignature, signing.SignatureExpired, TypeError, ValueError):
        raise AvailabilityReviewExpired("This schedule review is no longer current.") from None
    if payload.get("actor_id") != actor.pk:
        raise AvailabilityReviewExpired("This schedule review is no longer current.")
    return payload


def preview_schedule_change(actor, *, kind, payload, operation="create", instance=None, counselor=None, request_key=None):
    if kind in {"availability_rule", "unavailable_block"}:
        target = counselor or (instance.counselor if instance else None)
        if not can_manage_availability_for(actor, target):
            raise AvailabilityPermissionError("You do not have permission to manage this counselor schedule.")
    elif kind == "office_closure":
        if not can_manage_office_closure_scope(actor):
            raise AvailabilityPermissionError("You do not have permission to manage office closures.")
    else:
        raise AvailabilityManagementError("Unknown schedule record type.")
    record = _record_from_payload(kind, payload, counselor=counselor, instance=instance, actor=actor)
    record.full_clean()
    if record.is_active:
        _validate_overlaps(record, exclude_pk=instance.pk if instance else None)
    impact = AppointmentImpact()
    if operation in {"create", "update", "void"}:
        if record.is_active:
            impact = _impact(record)
        if operation == "update" and instance is not None and instance.is_active:
            # An update can remove coverage from appointments affected by the
            # prior state, so the handoff set is the union of both states.
            previous = _impact(instance)
            pending = {item.pk: item for item in (*previous.pending, *impact.pending)}
            scheduled = {item.pk: item for item in (*previous.scheduled, *impact.scheduled)}
            impact = AppointmentImpact(
                tuple(pending[key] for key in sorted(pending)),
                tuple(scheduled[key] for key in sorted(scheduled)),
            )
    request_key = normalize_request_key(request_key or uuid.uuid4().hex, max_length=64)
    return _preview_payload(kind, record, impact, operation=operation, request_key=request_key), record


@transaction.atomic
def apply_schedule_change(
    actor,
    *,
    kind,
    payload,
    reason,
    operation="create",
    instance=None,
    counselor=None,
    request_key,
    expected_fingerprint="",
    confirm=False,
):
    request_key = validate_and_lock_request_key(_SCHEDULE_REQUEST_KEY_POLICY, request_key)
    reason = _validate_reason(reason)
    target = counselor or (instance.counselor if instance else None)
    _lock_for_kind(kind, getattr(target, "pk", None))
    if kind == "office_closure":
        if not can_manage_office_closure_scope(actor):
            raise AvailabilityPermissionError("You do not have permission to manage office closures.")
    elif not can_manage_availability_for(actor, target):
        raise AvailabilityPermissionError("You do not have permission to manage this counselor schedule.")
    existing_event = ScheduleChangeEvent.objects.filter(request_key=request_key).first()
    if existing_event:
        model = {
            "availability_rule": AvailabilityRule,
            "unavailable_block": UnavailableBlock,
            "office_closure": OfficeClosure,
        }[kind]
        return model.objects.filter(pk=existing_event.target_object_id).first() or existing_event
    fresh_instance = instance
    if instance is not None:
        model = AvailabilityRule if kind == "availability_rule" else UnavailableBlock if kind == "unavailable_block" else OfficeClosure
        fresh_instance = model.objects.select_for_update().get(pk=instance.pk)
    preview, record = preview_schedule_change(
        actor,
        kind=kind,
        payload=payload,
        operation=operation,
        instance=fresh_instance,
        counselor=target,
        request_key=request_key,
    )
    impacted = _impact(record) if record.is_active else AppointmentImpact()
    if operation == "update" and fresh_instance is not None and fresh_instance.is_active:
        prior = _impact(fresh_instance)
        impacted = AppointmentImpact(
            tuple({item.pk: item for item in (*prior.pending, *impacted.pending)}.values()),
            tuple({item.pk: item for item in (*prior.scheduled, *impacted.scheduled)}.values()),
        )
    affected_ids = sorted({item.pk for item in (*impacted.pending, *impacted.scheduled)})
    if affected_ids:
        list(
            Appointment.objects.select_for_update()
            .filter(pk__in=affected_ids)
            .order_by("pk")
        )
        # The locks make this the final conflict/handoff calculation.
        preview, record = preview_schedule_change(
            actor,
            kind=kind,
            payload=payload,
            operation=operation,
            instance=fresh_instance,
            counselor=target,
            request_key=request_key,
        )
    if expected_fingerprint and expected_fingerprint != preview["fingerprint"]:
        raise AvailabilityReviewExpired("The affected appointment list changed. Review the schedule change again.")
    if not confirm:
        raise AvailabilityHandoffRequired(preview)
    if preview["pending_count"] or preview["scheduled_count"]:
        if payload.get("handoff_action") != "save_and_handoff":
            raise AvailabilityHandoffRequired(preview)
    before = _state(fresh_instance) if fresh_instance is not None else {}
    if operation == "void":
        record = fresh_instance
        record.is_active = False
        record.save(update_fields=["is_active", "updated_at"])
    else:
        if isinstance(record, AvailabilityRule) and fresh_instance is not None:
            record.created_by = fresh_instance.created_by or actor
        record.save()
    after = _state(record)
    event = ScheduleChangeEvent.objects.create(
        target_type=kind,
        target_object_id=str(record.pk),
        target_public_reference=getattr(record, "public_reference", None),
        action_type=f"{operation.upper()}_{kind.upper()}",
        actor=actor,
        reason=reason,
        prior_state=before,
        resulting_state=after,
        pending_appointment_count=preview["pending_count"],
        scheduled_appointment_count=preview["scheduled_count"],
        affected_appointment_outcome=preview["affected_outcome"],
        request_key=request_key,
    )
    audit_log(
        action_type="SCHEDULE_CHANGE",
        event_category="WORKFLOW",
        target_model=kind,
        target_object_id=str(record.pk),
        actor_user=actor,
        metadata={
            "action": event.action_type,
            "reason": reason,
            "prior_state": before,
            "resulting_state": after,
            "pending_appointment_count": preview["pending_count"],
            "scheduled_appointment_count": preview["scheduled_count"],
            "affected_appointment_outcome": preview["affected_outcome"],
        },
        source_app="appointments",
        source_view="availability_services.apply_schedule_change",
    )
    return record


_MODEL_BY_KIND = {
    "availability_rule": AvailabilityRule,
    "unavailable_block": UnavailableBlock,
    "office_closure": OfficeClosure,
}


def apply_schedule_change_for_command(actor, command) -> object:
    """Typed-command entry point for schedule management mutations.

    The frozen ``ScheduleChangeCommand`` is the only accepted boundary input;
    the legacy keyword form below remains an internal implementation detail.
    """
    from django.contrib.auth import get_user_model

    from apps.appointments.commands import ScheduleChangeCommand
    from apps.common.exceptions import NotFoundError

    if not isinstance(command, ScheduleChangeCommand):
        raise AvailabilityManagementError("Schedule changes require a ScheduleChangeCommand.")

    counselor = None
    if command.counselor_id is not None:
        counselor = (
            get_user_model().objects.filter(pk=command.counselor_id, is_active=True).first()
        )
        if counselor is None:
            raise AvailabilityPermissionError("The selected counselor is not available.")

    instance = None
    if command.operation in {"update", "void"}:
        if not command.target_reference:
            raise ValidationError("A target reference is required for this operation.")
        try:
            reference_uuid = uuid.UUID(str(command.target_reference))
        except ValueError as exc:
            raise NotFoundError("The schedule record was not found.") from exc
        instance = (
            _MODEL_BY_KIND[command.kind]
            .objects.filter(public_reference=reference_uuid)
            .first()
        )
        if instance is None:
            raise NotFoundError("The schedule record was not found.")

    return apply_schedule_change(
        actor,
        kind=command.kind,
        payload=command.payload(),
        reason=command.reason,
        operation=command.operation,
        instance=instance,
        counselor=counselor,
        request_key=command.request_key,
        expected_fingerprint=command.expected_fingerprint,
        confirm=command.confirm,
    )
