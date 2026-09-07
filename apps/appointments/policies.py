# Project: COMPASS
# File: apps/appointments/policies.py
# Module: apps.appointments
# Purpose: Scope-aware authorization policies for appointment workflows
# Domain boundary and service policy.
# Notes:
#   - Uses CounselorCoverage and WorkflowAuthorityGrant from apps.access_control.
#   - No new access control models.
#   - No Django framework permission-flag business-role bypass.
#   - Preferred counselor does NOT gain access unless assigned/scoped/head.

import datetime

from django.utils import timezone

from apps.access_control.authority import has_capability, has_fixed_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import (
    is_active_nonlegacy_actor,
    is_counselor,
    is_gco_staff,
    is_student,
    owns_user,
)
from apps.governance.runtime_config import is_policy_active
from apps.access_control.scopes import (
    counselor_has_live_coverage_for_student,
    get_active_workflow_authority_grants,
    get_live_counselor_coverages,
    workflow_authority_authorizes_record,
)
from apps.appointments.config import (
    get_cancellation_cutoff_minutes,
    get_no_show_grace_period_minutes,
)
from apps.appointments.models import (
    ACTIVE_APPOINTMENT_STATUSES,
    Appointment,
    AppointmentStatusChoices,
)
from apps.organizations.academic_year import (
    resolve_current_academic_year,
    AcademicYearConfigurationError,
)
from apps.inventory.models import StudentInventorySnapshot, InventoryStatusChoices

# ---------------------------------------------------------------------------
# Inventory prerequisite helper
# ---------------------------------------------------------------------------


def student_has_current_year_inventory(user) -> bool:
    """Check if the student has a submitted inventory for the current academic year."""
    if not is_active_nonlegacy_actor(user):
        return False
    if not is_student(user):
        return False
    try:
        academic_year = resolve_current_academic_year()
    except AcademicYearConfigurationError:
        return False
    student_profile = getattr(user, "student_profile", None)
    if not student_profile:
        return False
    return StudentInventorySnapshot.objects.filter(
        student_profile=student_profile,
        academic_year=academic_year,
        status=InventoryStatusChoices.SUBMITTED,
    ).exists()


# ---------------------------------------------------------------------------
# Scope helpers
# ---------------------------------------------------------------------------


def _is_counselor_assigned_to_appointment(user, appointment: Appointment) -> bool:
    """Check if the user is the assigned counselor for this appointment."""
    return bool(appointment.assigned_counselor_id and appointment.assigned_counselor_id == user.pk)


def _get_student_profile_for_appointment(appointment: Appointment):
    return getattr(appointment.student, "student_profile", None)


def _has_counselor_coverage_for_appointment(user, appointment: Appointment) -> bool:
    """Check if the counselor coverage exactly matches the appointment student."""
    student_profile = _get_student_profile_for_appointment(appointment)
    return counselor_has_live_coverage_for_student(user, student_profile)


def _is_staff_assigned_to_appointment_scope(user, appointment: Appointment | None = None) -> bool:
    """Check if GCO Staff assignment matches the appointment workflow and student scope."""
    grants = get_active_workflow_authority_grants(user, capability=Capability.APPOINTMENTS_REVIEW)
    if appointment is None:
        return grants.exists()

    student_profile = _get_student_profile_for_appointment(appointment)
    return workflow_authority_authorizes_record(
        user, capability=Capability.APPOINTMENTS_REVIEW,
        student_profile=student_profile,
        assigned_counselor=appointment.assigned_counselor,
    )


def can_view_appointment_queue(user) -> bool:
    """Destination-level gate for the appointment review queue."""
    if not is_active_nonlegacy_actor(user):
        return False
    # A targetless queue check may only represent code-owned office-wide Head
    # authority.  Scoped GCO grants are evaluated by the row-level selector.
    if has_fixed_capability(user, Capability.APPOINTMENTS_REVIEW):
        return True
    if is_counselor(user):
        return bool(
            _is_active_counselor_with_coverage(user)
            or user.assigned_appointments.exists()
        )
    if is_gco_staff(user):
        return _is_staff_assigned_to_appointment_scope(user)
    return False


def _is_active_counselor_with_coverage(user) -> bool:
    return bool(
        is_active_nonlegacy_actor(user)
        and is_counselor(user)
        and get_live_counselor_coverages(user).exists()
    )


def get_confirmed_start_at(appointment: Appointment):
    """Return timezone-aware confirmed start datetime, or None if incomplete."""
    if not appointment.confirmed_date or not appointment.confirmed_start_time:
        return None
    confirmed_start = datetime.datetime.combine(
        appointment.confirmed_date,
        appointment.confirmed_start_time,
    )
    if timezone.is_naive(confirmed_start):
        confirmed_start = timezone.make_aware(confirmed_start, timezone.get_current_timezone())
    return confirmed_start


def is_before_student_cancellation_cutoff(appointment: Appointment, now=None) -> bool:
    confirmed_start = get_confirmed_start_at(appointment)
    if confirmed_start is None:
        return False
    now = now or timezone.now()
    cutoff_at = confirmed_start - datetime.timedelta(minutes=get_cancellation_cutoff_minutes())
    return now < cutoff_at


def is_inside_student_cancellation_cutoff(appointment: Appointment, now=None) -> bool:
    confirmed_start = get_confirmed_start_at(appointment)
    if confirmed_start is None:
        return False
    now = now or timezone.now()
    return now >= confirmed_start - datetime.timedelta(minutes=get_cancellation_cutoff_minutes())


def is_past_no_show_grace_period(appointment: Appointment, now=None) -> bool:
    confirmed_start = get_confirmed_start_at(appointment)
    if confirmed_start is None:
        return False
    now = now or timezone.now()
    grace_elapsed_at = confirmed_start + datetime.timedelta(minutes=get_no_show_grace_period_minutes())
    return now >= grace_elapsed_at


# ---------------------------------------------------------------------------
# Policy functions
# ---------------------------------------------------------------------------


def can_request_appointment(user) -> bool:
    """Check if a student can request a new appointment.

    Prerequisites:
    - Active student account
    - Current-year inventory submitted
    - No existing active appointment request
    """
    if not is_active_nonlegacy_actor(user):
        return False
    if not is_student(user):
        return False
    if not student_has_current_year_inventory(user):
        return False
    if has_active_appointment_request_db(user):
        return False
    return True


def has_active_appointment_request_db(user) -> bool:
    """Check if the student has any active (non-terminal) appointment request.

    Used by can_request_appointment and directly by selectors.
    """
    if not is_active_nonlegacy_actor(user) or not is_student(user):
        return False
    return Appointment.objects.filter(
        student_id=user.pk,
        status__in=ACTIVE_APPOINTMENT_STATUSES,
    ).exists()


def can_view_appointment(user, appointment: Appointment) -> bool:
    """Check if the user can view the given appointment (record-level gate).

    This is a RECORD-VISIBILITY gate only. The DRAFT -> SUBMITTED mutation is
    authorized separately by ``can_submit_appointment()`` (owner-only) and is
    intentionally NOT coupled to this read gate.

    Record-eligibility rules (row-level):
    - Student (own appointment)
    - Assigned counselor
    - Counselor with coverage over the student
    - GCO Staff assigned to appointment queue
    - Head Guidance, when active and non-legacy

    Field-level private detail is decided separately by
    ``can_view_appointment_private_detail()``; Head Guidance office-wide row
    visibility does NOT by itself grant private-detail access.

    Inactive accounts and legacy Django superusers are never eligible for
    appointment row visibility, including their own appointments.
    """
    if not is_active_nonlegacy_actor(user):
        return False

    # Student can view only their own appointment
    if is_student(user):
        return owns_user(user, appointment.student_id)

    # Head Guidance's office supervision is represented by a named fixed
    # review capability, never by a generic designation bypass.
    if has_capability(
        user, Capability.APPOINTMENTS_REVIEW,
        target=_get_student_profile_for_appointment(appointment),
    ):
        return True

    # Assigned counselor
    if _is_counselor_assigned_to_appointment(user, appointment):
        return True

    # Counselor with matching coverage
    if is_counselor(user) and _has_counselor_coverage_for_appointment(user, appointment):
        return True

    # GCO Staff assigned to matching appointment queue scope
    if is_gco_staff(user) and _is_staff_assigned_to_appointment_scope(user, appointment):
        return True

    return False


def can_submit_appointment(user, appointment: Appointment) -> bool:
    """Authorize the DRAFT -> SUBMITTED transition (owner-only).

    Explicit, dedicated submit gate that must NOT be coupled to the read gate.
    Required conditions (all must hold):
      - authenticated
      - active
      - NOT a legacy Django superuser (``is_student()`` alone does not reject
        ``is_superuser``, so the superuser guard is explicit)
      - has the STUDENT role
      - owns the appointment (``appointment.student_id == user.pk``)
      - appointment status is DRAFT

    "Submit on behalf" (staff/counselor/Head) is intentionally NOT granted:
    it would require a separate named capability, scope, and audit event, and is
    outside this workflow boundary.
    """
    if not is_active_nonlegacy_actor(user):
        return False

    if not is_student(user):
        return False

    if not owns_user(user, appointment.student_id):
        return False

    if appointment.status != AppointmentStatusChoices.DRAFT:
        return False

    return True


def can_view_appointment_private_detail(user, appointment: Appointment) -> bool:
    """Authorize access to an appointment's private/sensitive detail fields.

    CONFIRMED POLICY — Head Guidance is a COUNSELOR and is evaluated by the same
    counselor rules in assignment/coverage-first order (never Head-first), so the
    private-field rule is explicit, not implicit:

      * Head Guidance ASSIGNED to the appointment -> full assigned-counselor
        detail (including ``internal_notes``).
      * Head Guidance within an active CounselorCoverage over the student ->
        coverage-counselor detail (``reason`` included; ``internal_notes``
        EXCLUDED by confirmed policy).
      * Head Guidance outside assignment/coverage -> metadata-only; private detail
        is denied outside the normal counselor/staff scope.

    Evaluation order (mirrors the confirmed policy; Head is handled as a COUNSELOR):
    1. Student -> denied (a student never receives raw office notes, even for their
       own appointment).
    2. Assigned counselor (including a Head who is assigned) -> allowed.
    3. Counselor with a live CounselorCoverage over the student (including a Head
       who is covered) -> allowed (field-limited by projection).
    4. Scoped GCO Staff -> allowed (``internal_notes`` stripped at projection).
    5. Otherwise -> denied.
    """
    if not is_active_nonlegacy_actor(user):
        return False

    # 1. Student is never granted private office detail.
    if is_student(user):
        return False

    # 2. Assigned counselor (includes Head-as-assigned).
    if _is_counselor_assigned_to_appointment(user, appointment):
        return True

    # 3. Counselor with live coverage over the student (includes Head-as-covered).
    if is_counselor(user) and _has_counselor_coverage_for_appointment(user, appointment):
        return True

    # 4. Scoped GCO Staff (field-limited at projection).
    if is_gco_staff(user) and _is_staff_assigned_to_appointment_scope(user, appointment):
        return True

    return False


def _counselor_can_process_queue_item(user, appointment: Appointment) -> bool:
    """Return whether a counselor owns or can process this queue item.

    Coverage permits operational handling of an unassigned item (or an item
    already assigned to the actor). It never permits a counselor to mutate an
    appointment assigned to another counselor.
    """
    if not is_counselor(user):
        return False
    if _is_counselor_assigned_to_appointment(user, appointment):
        return True
    return bool(
        appointment.assigned_counselor_id is None
        and _has_counselor_coverage_for_appointment(user, appointment)
    )


def _can_review_action(user, appointment: Appointment) -> bool:
    """Shared scope calculation for review and late-cancellation decisions."""
    if not is_active_nonlegacy_actor(user):
        return False
    if has_capability(
        user, Capability.APPOINTMENTS_REVIEW,
        target=_get_student_profile_for_appointment(appointment),
    ):
        return True
    if _counselor_can_process_queue_item(user, appointment):
        return True
    if is_gco_staff(user) and _is_staff_assigned_to_appointment_scope(user, appointment):
        return True
    return bool(is_gco_staff(user) and workflow_authority_authorizes_record(
        user, capability=Capability.APPOINTMENTS_REVIEW,
        student_profile=_get_student_profile_for_appointment(appointment),
        assigned_counselor=appointment.assigned_counselor,
    ))


def can_review_appointment(user, appointment: Appointment) -> bool:
    """Authorize approve/decline and submitted-to-review processing.

    Assigned counselors and coverage-scoped counselors may process only their
    own or unassigned queue items. Head Guidance follows the same counselor
    scope; outside that scope a named office-wide review capability is needed.
    GCO Staff remain governed by appointment-queue assignments.
    """
    return _can_review_action(user, appointment)


def can_review_late_cancellation(user, appointment: Appointment) -> bool:
    """Authorize approval or decline of a late-cancellation request."""
    return _can_review_action(user, appointment)


def can_assign_appointment(user, appointment: Appointment) -> bool:
    """Authorize assignment/reassignment before target validation.

    A counselor may accept an unassigned in-scope item or manage an item
    already assigned to them, but target validation still limits them to
    self-assignment. Head Guidance needs the explicit office-wide assignment
    capability to operate outside ordinary counselor scope.
    """
    if not is_active_nonlegacy_actor(user):
        return False
    if is_counselor(user) and (
        _is_counselor_assigned_to_appointment(user, appointment)
        or (
            appointment.assigned_counselor_id is None
            and _has_counselor_coverage_for_appointment(user, appointment)
        )
    ):
        return True
    return bool(
        is_counselor(user)
        and has_capability(
            user, Capability.APPOINTMENTS_ASSIGN,
            target=_get_student_profile_for_appointment(appointment),
        )
    )


def can_assign_appointment_to(user, appointment: Appointment, target_counselor) -> bool:
    """Authorize the selected counselor target.

    Ordinary counselor scope permits only self-acceptance. A Head Guidance
    actor outside that scope needs the explicit office-wide assignment
    capability; the designation alone is not enough.
    """
    if not is_active_nonlegacy_actor(user):
        return False

    if not is_active_nonlegacy_actor(target_counselor) or not is_counselor(target_counselor):
        return False

    if is_counselor(user):
        may_accept_self = (
            appointment.assigned_counselor_id in (None, user.pk)
            and target_counselor.pk == user.pk
            and (
                _is_counselor_assigned_to_appointment(user, appointment)
                or _has_counselor_coverage_for_appointment(user, appointment)
            )
        )
        if may_accept_self:
            return True

    return bool(
        is_counselor(user)
        and target_counselor.pk == user.pk
        and has_capability(
            user, Capability.APPOINTMENTS_ASSIGN,
            target=_get_student_profile_for_appointment(appointment),
        )
    )


def can_schedule_appointment(user, appointment: Appointment) -> bool:
    """Authorize the APPROVED -> SCHEDULED mutation."""
    if not is_active_nonlegacy_actor(user):
        return False
    if is_counselor(user) and _is_counselor_assigned_to_appointment(user, appointment):
        return True

    if has_capability(
        user, Capability.APPOINTMENTS_SCHEDULE,
        target=_get_student_profile_for_appointment(appointment),
    ):
        return True
    if is_gco_staff(user) and _is_staff_assigned_to_appointment_scope(user, appointment):
        return True
    return bool(is_gco_staff(user) and workflow_authority_authorizes_record(
        user, capability=Capability.APPOINTMENTS_SCHEDULE,
        student_profile=_get_student_profile_for_appointment(appointment),
        assigned_counselor=appointment.assigned_counselor,
    ))


def can_cancel_appointment(user, appointment: Appointment) -> bool:
    """Check if the user can cancel the appointment.

    Authorized:
    - Student (own appointment, before cutoff)
    - Assigned counselor
    - Scoped GCO Staff
    - Head Guidance only through an explicit office-wide cancel capability
    """
    if not is_active_nonlegacy_actor(user):
        return False

    # Student self-cancellation
    if is_student(user) and owns_user(user, appointment.student_id):
        if appointment.status != AppointmentStatusChoices.SCHEDULED:
            return False
        return is_before_student_cancellation_cutoff(appointment)

    if is_counselor(user) and _is_counselor_assigned_to_appointment(user, appointment):
        return appointment.status == AppointmentStatusChoices.SCHEDULED

    if has_capability(
        user, Capability.APPOINTMENTS_CANCEL,
        target=_get_student_profile_for_appointment(appointment),
    ):
        return appointment.status == AppointmentStatusChoices.SCHEDULED

    if is_gco_staff(user) and _is_staff_assigned_to_appointment_scope(user, appointment):
        return appointment.status == AppointmentStatusChoices.SCHEDULED

    return bool(appointment.status == AppointmentStatusChoices.SCHEDULED and is_gco_staff(user) and workflow_authority_authorizes_record(
        user, capability=Capability.APPOINTMENTS_CANCEL,
        student_profile=_get_student_profile_for_appointment(appointment),
        assigned_counselor=appointment.assigned_counselor,
    ))


def can_request_late_cancellation(user, appointment: Appointment) -> bool:
    """Check if a student can request late cancellation inside the cutoff."""
    if not is_active_nonlegacy_actor(user):
        return False
    if not is_student(user) or not owns_user(user, appointment.student_id):
        return False
    if appointment.status != AppointmentStatusChoices.SCHEDULED:
        return False
    return is_inside_student_cancellation_cutoff(appointment)


def can_complete_appointment(user, appointment: Appointment) -> bool:
    """Check if the user can mark the appointment as completed.

    Authorized:
    - Assigned counselor
    - Head Guidance within normal counselor scope, or through an explicit
      office-wide outcome capability
    Must be in SCHEDULED status.
    """
    if not is_active_nonlegacy_actor(user):
        return False

    if appointment.status != AppointmentStatusChoices.SCHEDULED:
        return False

    if is_counselor(user) and _is_counselor_assigned_to_appointment(user, appointment):
        return True

    if has_capability(
        user, Capability.APPOINTMENTS_OUTCOME_MANAGE,
        target=_get_student_profile_for_appointment(appointment),
    ):
        return True

    return bool(is_gco_staff(user) and workflow_authority_authorizes_record(
        user, capability=Capability.APPOINTMENTS_OUTCOME_MANAGE,
        student_profile=_get_student_profile_for_appointment(appointment),
        assigned_counselor=appointment.assigned_counselor,
    ))


def can_mark_no_show(user, appointment: Appointment) -> bool:
    """Check if the user can mark the appointment as no-show.

    Authorized:
    - Assigned counselor
    - Scoped GCO Staff
    - Head Guidance within normal counselor scope, or through an explicit
      office-wide outcome capability
    Must be in SCHEDULED status past the grace period.
    """
    if not is_active_nonlegacy_actor(user):
        return False

    if appointment.status != AppointmentStatusChoices.SCHEDULED:
        return False

    if not is_past_no_show_grace_period(appointment):
        return False

    if is_counselor(user) and _is_counselor_assigned_to_appointment(user, appointment):
        return True

    if has_capability(
        user, Capability.APPOINTMENTS_OUTCOME_MANAGE,
        target=_get_student_profile_for_appointment(appointment),
    ):
        return True

    if is_gco_staff(user) and _is_staff_assigned_to_appointment_scope(user, appointment):
        return True

    return bool(is_gco_staff(user) and workflow_authority_authorizes_record(
        user, capability=Capability.APPOINTMENTS_OUTCOME_MANAGE,
        student_profile=_get_student_profile_for_appointment(appointment),
        assigned_counselor=appointment.assigned_counselor,
    ))


def can_manage_availability(user) -> bool:
    """Check if the user can manage availability rules.

    Authorized:
    - Counselor (own)
    - Head Guidance (any)
    """
    if not is_active_nonlegacy_actor(user):
        return False

    if has_capability(user, Capability.APPOINTMENTS_AVAILABILITY_MANAGE):
        return True

    if is_counselor(user):
        return True

    return False


def can_manage_availability_for(user, counselor) -> bool:
    """Authorize one counselor's availability/block scope."""
    if not is_active_nonlegacy_actor(user):
        return False
    if not is_active_nonlegacy_actor(counselor) or not is_counselor(counselor):
        return False
    if has_capability(user, Capability.APPOINTMENTS_AVAILABILITY_MANAGE):
        return True
    return is_counselor(user) and counselor.pk == user.pk


def can_manage_office_closure_scope(user) -> bool:
    """Require the named fixed office-closure authority."""
    return bool(is_policy_active("office.closures") and has_capability(user, Capability.OFFICE_CLOSURES_MANAGE))


def can_manage_office_closures(user) -> bool:
    """Check if the user can manage office closures.

    Authorized:
    - Head Guidance (global)
    - GCO Staff with active appointment queue scope
    """
    return can_manage_office_closure_scope(user)
