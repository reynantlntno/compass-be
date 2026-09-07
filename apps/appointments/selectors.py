# Project: COMPASS
# File: apps/appointments/selectors.py
# Module: apps.appointments
# Purpose: Side-effect-free query selectors for appointment workflows
# Domain boundary and service policy.
# Notes:
#   - All selectors are query-only. No mutations.
#   - Slot validation follows the multi-layer bounded selector algorithm.
#   - PRIVACY: never exposes internal_notes, decline_reason, or raw sensitive fields.

import datetime
from typing import Optional

from django.db import models
from django.utils import timezone

from apps.appointments.config import get_slot_duration_minutes
from apps.access_control.authority import has_capability, has_fixed_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import (
    is_active_nonlegacy_actor,
    is_student,
    is_counselor,
    is_gco_staff,
)
from apps.access_control.scopes import (
    build_geographic_scope_q,
    build_workflow_authority_scope_q,
    get_live_counselor_coverages,
)
from apps.appointments.models import (
    Appointment,
    AppointmentModeChoices,
    AppointmentStatusChoices,
    AvailabilityModeChoices,
    AvailabilityRule,
    UnavailableBlock,
    OfficeClosure,
)
from apps.appointments.policies import (
    can_view_appointment,
    can_view_appointment_private_detail,
    has_active_appointment_request_db,
    _has_counselor_coverage_for_appointment,
    _is_counselor_assigned_to_appointment,
    _is_staff_assigned_to_appointment_scope,
)


APPOINTMENT_SENSITIVE_FIELDS = (
    "reason",
    "cancellation_reason",
    "decline_reason",
    "internal_notes",
)

# ---------------------------------------------------------------------------
# Explicit field allowlists (the OUTPUT boundary).
# NOTE: defer() is retained as a performance hint only and is NOT a security
# control. appointment_view_projection() is the authoritative allowlist and is
# the only entry point read surfaces must use to expose Appointment fields.
# Only fields that actually exist on Appointment are referenced here.
# ---------------------------------------------------------------------------
_STUDENT_FIELDS = frozenset({
    "reference_code",
    "appointment_type",
    "appointment_mode",
    "status",
    "requested_date",
    "requested_start_time",
    "confirmed_date",
    "confirmed_start_time",
    "confirmed_end_time",
})
_COVERAGE_FIELDS = _STUDENT_FIELDS | {"reason"}
_ASSIGNED_FIELDS = _STUDENT_FIELDS | {"reason", "cancellation_reason", "internal_notes"}
_OPERATIONAL_STAFF_FIELDS = _STUDENT_FIELDS | {"reason"}
# Office metadata may identify workflow ownership, but never crosses the
# boundary as a Django relation.  Foreign-key IDs are scalar and are still
# safe for the scoped operational workspace to use for follow-up actions.
_OFFICE_METADATA_FIELDS = _STUDENT_FIELDS | {
    "assigned_counselor_id",
    "preferred_counselor_id",
    "reviewed_by_id",
}
_PRIVATE_ALL_FIELDS = _STUDENT_FIELDS | {
    "reason", "cancellation_reason", "decline_reason", "internal_notes",
}


def _projection_field_set(user, appointment: Appointment) -> frozenset:
    """Return the exact allowlist for the actor per confirmed policy."""
    if is_student(user):
        return _STUDENT_FIELDS
    if can_view_appointment_private_detail(user, appointment):
        if _is_counselor_assigned_to_appointment(user, appointment):
            return _ASSIGNED_FIELDS
        if is_gco_staff(user):
            return _OPERATIONAL_STAFF_FIELDS
        return _COVERAGE_FIELDS
    if is_counselor(user) and _has_counselor_coverage_for_appointment(user, appointment):
        return _COVERAGE_FIELDS
    if is_gco_staff(user) and _is_staff_assigned_to_appointment_scope(user, appointment):
        return _OPERATIONAL_STAFF_FIELDS
    return _OFFICE_METADATA_FIELDS


def appointment_view_projection(user, appointment: Appointment) -> dict | None:
    """Return a plain dict with EXACTLY the allowed fields for the actor.

    This is the single output boundary for appointment read surfaces. It never
    includes fields outside the allowlist for the actor's role/scope. An
    unauthorized actor receives ``None`` rather than a metadata projection.
    """
    if not can_view_appointment(user, appointment):
        return None

    allowed = _projection_field_set(user, appointment)
    payload = {}
    for field in allowed:
        payload[field] = getattr(appointment, field)
    return payload


def assert_fields_visible(projection: dict, *fields) -> None:
    """Raise if a consumer tries to read a field outside the projection."""
    missing = [field for field in fields if field not in projection]
    if missing:
        raise KeyError(
            f"Field(s) not allowed by appointment projection: {', '.join(missing)}"
        )


def get_appointments_visible_to(user) -> models.QuerySet:
    """Return a filtered Appointment queryset visible to the user.

    Rules:
    - Student: own appointments only
    - Head Guidance: all appointments
    - Assigned counselor: appointments assigned to them
    - Counselor with coverage: appointments for students in their scope
    - GCO Staff scoped to appointments queue: all appointments
    """
    if not is_active_nonlegacy_actor(user):
        return Appointment.objects.none()

    if is_student(user):
        return Appointment.objects.filter(student=user)

    # Only code-owned fixed Head authority is office-wide.  An account grant
    # must flow through the target-aware organization/assignment predicate
    # below; resolving it without a target would broaden a scoped GCO grant.
    if has_fixed_capability(user, Capability.APPOINTMENTS_REVIEW):
        return Appointment.objects.all()

    if is_counselor(user):
        coverage_q = build_geographic_scope_q(
            get_live_counselor_coverages(user),
            {
                "campus": "student__student_profile__campus",
                "college": "student__student_profile__college",
                "department": "student__student_profile__department",
                "program": "student__student_profile__program",
            },
        )
        return Appointment.objects.defer(*APPOINTMENT_SENSITIVE_FIELDS).filter(
            models.Q(assigned_counselor=user) | coverage_q,
        ).distinct()

    if is_gco_staff(user):
        scope_q = build_workflow_authority_scope_q(
            user,
            capability=Capability.APPOINTMENTS_REVIEW,
            field_map={
                "campus": "student__student_profile__campus",
                "college": "student__student_profile__college",
                "department": "student__student_profile__department",
                "program": "student__student_profile__program",
            },
            counselor_field="assigned_counselor_id",
        )
        return Appointment.objects.defer(*APPOINTMENT_SENSITIVE_FIELDS).filter(scope_q).distinct()

    return Appointment.objects.none()


def get_student_appointments(user) -> models.QuerySet:
    """Return the student's own appointments."""
    if not is_active_nonlegacy_actor(user):
        return Appointment.objects.none()
    return Appointment.objects.filter(student=user)


def get_counselor_appointment_queue(user) -> models.QuerySet:
    """Return appointments relevant to a counselor's queue.

    Includes:
    - Appointments assigned to this counselor
    - Appointments for students in counselor's coverage scope
    """
    if not is_active_nonlegacy_actor(user):
        return Appointment.objects.none()

    if not is_counselor(user) and not is_gco_staff(user) and not has_fixed_capability(
        user,
        Capability.APPOINTMENTS_REVIEW,
    ):
        return Appointment.objects.none()

    if has_fixed_capability(user, Capability.APPOINTMENTS_REVIEW):
        return Appointment.objects.all()

    return get_appointments_visible_to(user)


def get_pending_review_appointments(user) -> models.QuerySet:
    """Return appointments pending staff review.

    Filters to SUBMITTED and PENDING_REVIEW statuses.
    """
    if not is_active_nonlegacy_actor(user):
        return Appointment.objects.none()

    base_qs = get_appointments_visible_to(user)
    return base_qs.filter(
        status__in=[
            AppointmentStatusChoices.SUBMITTED,
            AppointmentStatusChoices.PENDING_REVIEW,
        ]
    )


def get_available_slots(
    counselor,
    date: datetime.date,
    appointment_mode: Optional[str] = None,
) -> list[dict]:
    """Compute available time slots for a given counselor and date.

    Bounded slot-selection algorithm:
    1. Get active AvailabilityRule rows for counselor/date/weekday.
    2. BOTH availability mode matches either appointment mode.
    3. Subtract counselor UnavailableBlock overlaps.
    4. Subtract OfficeClosure overlaps.
    5. Subtract only SCHEDULED confirmed appointments.
    6. Return remaining slot windows.

    Args:
        counselor: User instance with COUNSELOR role.
        date: The target date for slot computation.
        appointment_mode: Optional mode filter (ONSITE or ONLINE).

    Returns:
        List of dicts with 'start', 'end', and 'duration_minutes' keys.
    """
    weekday = date.weekday()  # 0=Monday

    # Step 1: Get active availability rules for this counselor/weekday
    avail_rules = AvailabilityRule.objects.filter(
        counselor=counselor,
        day_of_week=weekday,
        is_active=True,
        effective_from__lte=date,
    ).filter(
        models.Q(effective_until__isnull=True) | models.Q(effective_until__gte=date),
    )

    if not avail_rules:
        return []

    # Step 2: Build discrete slots from rules
    slots = []
    for rule in avail_rules:
        # Mode matching
        if appointment_mode:
            if rule.mode == AvailabilityModeChoices.ONSITE and appointment_mode != AppointmentModeChoices.ONSITE:
                continue
            if rule.mode == AvailabilityModeChoices.ONLINE and appointment_mode != AppointmentModeChoices.ONLINE:
                continue
            # BOTH matches either

        duration_minutes = rule.slot_duration_minutes or get_slot_duration_minutes()
        slot_start = datetime.datetime.combine(date, rule.start_time)
        rule_end = datetime.datetime.combine(date, rule.end_time)
        while slot_start + datetime.timedelta(minutes=duration_minutes) <= rule_end:
            slot_end = slot_start + datetime.timedelta(minutes=duration_minutes)
            aware_start = timezone.make_aware(slot_start, timezone.get_current_timezone())
            aware_end = timezone.make_aware(slot_end, timezone.get_current_timezone())
            slots.append({
                "start": slot_start,
                "end": slot_end,
                "start_at": aware_start,
                "end_at": aware_end,
                "duration_minutes": duration_minutes,
                "max_appointments_per_slot": rule.max_appointments_per_slot,
            })
            slot_start = slot_end

    if not slots:
        return []

    # Step 3: Subtract counselor UnavailableBlock overlaps
    unavail_blocks = UnavailableBlock.objects.filter(
        counselor=counselor,
        date=date,
        is_active=True,
    )
    for block in unavail_blocks:
        if block.is_all_day:
            slots = []
            break
        if block.start_time and block.end_time:
            block_start = datetime.datetime.combine(date, block.start_time)
            block_end = datetime.datetime.combine(date, block.end_time)
            new_slots = []
            for slot in slots:
                # Check overlap
                if slot["start"] < block_end and slot["end"] > block_start:
                    continue
                else:
                    new_slots.append(slot)
            slots = new_slots

    # Step 4: Subtract OfficeClosure overlaps
    closures = OfficeClosure.objects.filter(date=date, is_active=True)
    for closure in closures:
        if closure.is_all_day:
            slots = []
            break
        if closure.start_time and closure.end_time:
            closure_start = datetime.datetime.combine(date, closure.start_time)
            closure_end = datetime.datetime.combine(date, closure.end_time)
            new_slots = []
            for slot in slots:
                if slot["start"] < closure_end and slot["end"] > closure_start:
                    continue
                else:
                    new_slots.append(slot)
            slots = new_slots

    # Step 5: Subtract reserved appointments. A pending or legacy-declined
    # late-cancellation request does not release the original reservation.
    blocking_appointments = Appointment.objects.filter(
        assigned_counselor=counselor,
        confirmed_date=date,
        status__in=(
            AppointmentStatusChoices.SCHEDULED,
            AppointmentStatusChoices.LATE_CANCELLATION_REQUESTED,
            AppointmentStatusChoices.LATE_CANCELLATION_DECLINED,
        ),
        confirmed_start_time__isnull=False,
        confirmed_end_time__isnull=False,
    )

    # Adapter check: subtract safe Call Slip blocking intervals.
    from apps.call_slips.selectors import get_call_slip_blocking_intervals
    tz = timezone.get_current_timezone()
    call_slip_blocks = get_call_slip_blocking_intervals(counselor, date)

    available_slots = []
    for slot in slots:
        is_hard_blocked = False
        slot_start_aware = timezone.make_aware(slot["start"], tz)
        slot_end_aware = timezone.make_aware(slot["end"], tz)

        for block in call_slip_blocks:
            if slot_start_aware < block["end"] and slot_end_aware > block["start"]:
                is_hard_blocked = True
                break

        if is_hard_blocked:
            continue

        overlap_count = 0
        for apt in blocking_appointments:
            apt_start = datetime.datetime.combine(date, apt.confirmed_start_time)
            apt_end = datetime.datetime.combine(date, apt.confirmed_end_time)
            if slot["start"] < apt_end and slot["end"] > apt_start:
                overlap_count += 1
        if overlap_count < slot["max_appointments_per_slot"]:
            available_slots.append(slot)

    return available_slots


def get_matching_available_slot(
    counselor,
    date: datetime.date,
    start_time: datetime.time,
    end_time: datetime.time,
    appointment_mode: str,
) -> Optional[dict]:
    """Return the exact live slot requested by an operational scheduling POST."""
    for slot in get_available_slots(counselor, date, appointment_mode):
        if slot["start"].time() == start_time and slot["end"].time() == end_time:
            return slot
    return None


def has_active_appointment_request(user) -> bool:
    """Check if the student has any active appointment request.

    Thin wrapper around the policy function for selector consistency.
    """
    return has_active_appointment_request_db(user)
