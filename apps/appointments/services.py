# Project: COMPASS
# File: apps/appointments/services.py
# Module: apps.appointments
# Purpose: Transactional service functions for appointment workflows
# Domain boundary and service policy.
# Notes:
#   - Each mutation service receives actor + stable reference + typed command.
#   - The target is locked and reloaded inside the service; callers never pass
#     model instances across the mutation boundary.
#   - All mutation services use @transaction.atomic and write status/assignment
#     history plus audit records atomically with the domain change.
#   - Services call policy guards before mutating.
#   - Notifications are queued through the outbox after commit.
#   - PRIVACY: No raw sensitive data in audit metadata.

from typing import Optional

from apps.common.exceptions import (
    NotFoundError,
    PermissionDeniedError,
    StaleStateError,
    ValidationError,
    WorkflowError,
)
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.appointments.models import (
    Appointment,
    AppointmentStatusChoices,
    AppointmentStatusHistory,
    AssignmentHistory,
)
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
from apps.appointments.policies import (
    can_request_appointment,
    can_submit_appointment,
    can_review_appointment,
    can_assign_appointment,
    can_assign_appointment_to,
    can_cancel_appointment,
    can_request_late_cancellation,
    can_review_late_cancellation,
    can_schedule_appointment,
    can_complete_appointment,
    can_mark_no_show,
)
from apps.appointments.reference_codes import generate_appointment_reference_code
from apps.appointments.availability_services import lock_schedule_scope
from apps.access_control.rules import is_active_nonlegacy_actor, is_counselor, is_gco_staff
from apps.audit.services import audit_status_transition, audit_assignment_change


class AppointmentTransitionError(WorkflowError):
    """Raised when an invalid status transition is attempted."""
    pass


class AppointmentPermissionError(PermissionDeniedError):
    """Raised when the user is not authorized to perform the action."""
    pass

_VALID_TRANSITIONS = {
    AppointmentStatusChoices.DRAFT: [AppointmentStatusChoices.SUBMITTED],
    AppointmentStatusChoices.SUBMITTED: [AppointmentStatusChoices.PENDING_REVIEW],
    AppointmentStatusChoices.PENDING_REVIEW: [
        AppointmentStatusChoices.APPROVED,
        AppointmentStatusChoices.DECLINED,
    ],
    AppointmentStatusChoices.APPROVED: [AppointmentStatusChoices.SCHEDULED],
    AppointmentStatusChoices.SCHEDULED: [
        AppointmentStatusChoices.COMPLETED,
        AppointmentStatusChoices.NO_SHOW,
        AppointmentStatusChoices.CANCELLED_BY_STUDENT,
        AppointmentStatusChoices.CANCELLED_BY_OFFICE,
        AppointmentStatusChoices.LATE_CANCELLATION_REQUESTED,
    ],
    AppointmentStatusChoices.LATE_CANCELLATION_REQUESTED: [
        AppointmentStatusChoices.LATE_CANCELLATION_APPROVED,
        AppointmentStatusChoices.SCHEDULED,
    ],
    # Terminal states — no outgoing transitions
    AppointmentStatusChoices.DECLINED: [],
    AppointmentStatusChoices.CANCELLED_BY_STUDENT: [],
    AppointmentStatusChoices.CANCELLED_BY_OFFICE: [],
    AppointmentStatusChoices.LATE_CANCELLATION_APPROVED: [],
    AppointmentStatusChoices.LATE_CANCELLATION_DECLINED: [],
    AppointmentStatusChoices.COMPLETED: [],
    AppointmentStatusChoices.NO_SHOW: [],
}


def _validate_transition(appointment: Appointment, new_status: str):
    """Validate that the status transition is allowed."""
    valid_next = _VALID_TRANSITIONS.get(appointment.status, [])
    if new_status not in valid_next:
        raise AppointmentTransitionError(
            f"Cannot transition from {appointment.status} to {new_status}."
        )


def _create_status_history(
    appointment: Appointment,
    new_status: str,
    changed_by,
    reason: str = "",
    *,
    from_status: Optional[str] = None,
):
    """Create an AppointmentStatusHistory entry for the transition."""
    AppointmentStatusHistory.objects.create(
        appointment=appointment,
        from_status=appointment.status if from_status is None else from_status,
        to_status=new_status,
        changed_by=changed_by,
        reason=reason,
    )


def _create_assignment_history(
    appointment: Appointment,
    from_counselor,
    to_counselor,
    assigned_by,
    reason: str = "",
):
    """Record a real assignment change."""
    AssignmentHistory.objects.create(
        appointment=appointment,
        from_counselor=from_counselor,
        to_counselor=to_counselor,
        assigned_by=assigned_by,
        reason=reason,
    )

def _validate_confirmed_schedule(confirmed_date, confirmed_start_time, confirmed_end_time):
    """Require complete, ordered confirmed schedule fields."""
    if not confirmed_date:
        raise AppointmentTransitionError("Confirmed date is required before scheduling.")
    if not confirmed_start_time:
        raise AppointmentTransitionError("Confirmed start time is required before scheduling.")
    if not confirmed_end_time:
        raise AppointmentTransitionError("Confirmed end time is required before scheduling.")
    if confirmed_start_time >= confirmed_end_time:
        raise AppointmentTransitionError("Confirmed start time must be before confirmed end time.")


def _load_appointment(reference_code) -> Appointment:
    """Resolve a stable reference into a row-locked, freshly reloaded target."""
    # Every appointment mutation acquires the shared office/schedule lock
    # before the appointment row. Linked counseling workflows use the same
    # order, preventing an appointment-first path from deadlocking with a
    # schedule or counseling transition.
    lock_schedule_scope()
    if not isinstance(reference_code, str):
        raise ValidationError("An appointment reference is required.")
    normalized = reference_code.strip()
    if not normalized:
        raise ValidationError("An appointment reference is required.")
    appointment = (
        Appointment.objects.select_for_update(of=("self",))
        .select_related(
            "student",
            "student__student_profile",
            "assigned_counselor",
            "preferred_counselor",
            "reviewed_by",
        )
        .filter(reference_code=normalized)
        .first()
    )
    if appointment is None:
        raise NotFoundError("The appointment was not found.")
    return appointment


def _check_not_stale(appointment: Appointment, expected_updated_at) -> None:
    """Validate optimistic concurrency when an expected timestamp is supplied."""
    if expected_updated_at is None:
        return
    current = appointment.updated_at
    if current is None:
        return
    if hasattr(expected_updated_at, "tzinfo"):
        if expected_updated_at != current:
            raise StaleStateError()
    elif str(expected_updated_at) != current.isoformat():
        raise StaleStateError()


def _notify(event: str, appointment: Appointment, *, actor=None) -> None:
    from apps.appointments.notification_services import enqueue_appointment_event

    enqueue_appointment_event(event, appointment, actor=actor)


def _ensure_linked_session_is_unstarted(appointment: Appointment) -> None:
    """Validate (never mutate) the linked counseling session lifecycle.

    Locking follows the shared appointment → counseling session order.
    """
    from apps.counseling.models import CounselingSession, SessionStatusChoices

    session_status = (
        CounselingSession.objects.select_for_update()
        .filter(appointment=appointment)
        .values_list("status", flat=True)
        .first()
    )
    if session_status and session_status != SessionStatusChoices.SCHEDULED:
        raise AppointmentTransitionError(
            "This action is unavailable because the linked counseling session has "
            "already started or ended."
        )


def _ensure_linked_session_completed_before_appointment_completion(
    appointment: Appointment,
) -> None:
    """Prevent a direct appointment completion from orphaning a live session.

    A linked counseling session must be completed through the orchestration
    completion use case first. Terminal counseling outcomes are safe to pair
    with the appointment completion transition.
    """
    from apps.counseling.models import CounselingSession, SessionStatusChoices

    terminal_statuses = {
        SessionStatusChoices.COMPLETED,
        SessionStatusChoices.FINALIZED,
        SessionStatusChoices.LOCKED,
        SessionStatusChoices.CANCELLED,
        SessionStatusChoices.NO_SHOW,
    }
    session_status = (
        CounselingSession.objects.select_for_update()
        .filter(appointment=appointment)
        .values_list("status", flat=True)
        .first()
    )
    if session_status and session_status not in terminal_statuses:
        raise AppointmentTransitionError(
            "Complete the linked counseling session through its coordinated workflow first."
        )


def _resolve_active_user(user_id, label: str = "counselor"):
    """Resolve a stable user id into a locked, active account."""
    User = get_user_model()
    resolved = User.objects.select_for_update().filter(pk=user_id, is_active=True).first()
    if resolved is None:
        raise ValidationError(f"The selected {label} is not available.")
    return resolved


# ---------------------------------------------------------------------------
# Service functions
# ---------------------------------------------------------------------------

@transaction.atomic
def create_appointment_request(user, command: AppointmentRequestCommand) -> Appointment:
    """Create a new appointment in DRAFT status with a generated reference code."""
    User = get_user_model()
    if not isinstance(command, AppointmentRequestCommand):
        raise ValidationError("Appointment creation requires an AppointmentRequestCommand.")
    locked_user = User.objects.select_for_update().get(pk=user.pk)
    if not can_request_appointment(locked_user):
        raise AppointmentPermissionError("You are not eligible to request an appointment.")

    preferred_counselor = None
    if command.preferred_counselor_id:
        preferred_counselor = (
            User.objects.filter(pk=command.preferred_counselor_id, is_active=True).first()
        )
        if preferred_counselor is None or not is_active_nonlegacy_actor(preferred_counselor) or not is_counselor(preferred_counselor):
            raise ValidationError("The preferred counselor is not available.")

    reference_code = generate_appointment_reference_code()

    try:
        appointment = Appointment.objects.create(
            reference_code=reference_code,
            student=locked_user,
            appointment_type=command.appointment_type,
            appointment_mode=command.appointment_mode,
            preferred_counselor=preferred_counselor,
            requested_date=command.requested_date,
            requested_start_time=command.requested_start_time,
            reason=command.reason,
            status=AppointmentStatusChoices.DRAFT,
        )
    except IntegrityError as exc:
        raise AppointmentPermissionError(
            "You already have an active appointment request."
        ) from exc

    _create_status_history(
        appointment,
        AppointmentStatusChoices.DRAFT,
        locked_user,
        "Appointment created",
        from_status="",
    )

    audit_status_transition(
        actor_user=locked_user,
        target_model="Appointment",
        target_object_id=str(appointment.pk),
        reference_code=appointment.reference_code,
        metadata={
            "action": "create_appointment_request",
            "from_status": "",
            "to_status": AppointmentStatusChoices.DRAFT,
        },
    )

    return appointment


def _submit(appointment: Appointment, user) -> Appointment:
    """Shared DRAFT → SUBMITTED transition on an already-locked row."""
    _validate_transition(appointment, AppointmentStatusChoices.SUBMITTED)
    from_status = appointment.status
    appointment.status = AppointmentStatusChoices.SUBMITTED
    appointment.submitted_at = timezone.now()
    appointment.save(update_fields=["status", "submitted_at", "updated_at"])
    _create_status_history(
        appointment,
        AppointmentStatusChoices.SUBMITTED,
        user,
        from_status=from_status,
    )
    audit_status_transition(
        actor_user=user,
        target_model="Appointment",
        target_object_id=str(appointment.pk),
        reference_code=appointment.reference_code,
        metadata={
            "action": "submit_appointment_request",
            "from_status": from_status,
            "to_status": AppointmentStatusChoices.SUBMITTED,
        },
    )
    return appointment


@transaction.atomic
def submit_appointment_request(
    user,
    reference_code: str,
    *,
    expected_updated_at=None,
) -> Appointment:
    """Transition DRAFT → SUBMITTED."""
    appointment = _load_appointment(reference_code)
    _check_not_stale(appointment, expected_updated_at)
    if not can_submit_appointment(user, appointment):
        raise AppointmentPermissionError("You do not have permission to submit this appointment.")
    return _submit(appointment, user)


@transaction.atomic
def move_to_pending_review(user, reference_code: str) -> Appointment:
    """Transition SUBMITTED → PENDING_REVIEW."""
    appointment = _load_appointment(reference_code)
    if not can_review_appointment(user, appointment):
        raise AppointmentPermissionError("You do not have permission to review this appointment.")

    _validate_transition(appointment, AppointmentStatusChoices.PENDING_REVIEW)

    from_status = appointment.status
    appointment.status = AppointmentStatusChoices.PENDING_REVIEW
    appointment.save(update_fields=["status", "updated_at"])

    _create_status_history(
        appointment,
        AppointmentStatusChoices.PENDING_REVIEW,
        user,
        from_status=from_status,
    )

    audit_status_transition(
        actor_user=user,
        target_model="Appointment",
        target_object_id=str(appointment.pk),
        reference_code=appointment.reference_code,
        metadata={
            "action": "move_to_pending_review",
            "from_status": from_status,
            "to_status": AppointmentStatusChoices.PENDING_REVIEW,
        },
    )

    return appointment

@transaction.atomic
def decide_appointment_review(
    user,
    reference_code: str,
    command: AppointmentReviewCommand,
    *,
    expected_updated_at=None,
) -> Appointment:
    """Transition PENDING_REVIEW → APPROVED or PENDING_REVIEW → DECLINED."""
    if not isinstance(command, AppointmentReviewCommand):
        raise ValidationError("Appointment review requires an AppointmentReviewCommand.")
    appointment = _load_appointment(reference_code)
    _check_not_stale(appointment, expected_updated_at)
    if not can_review_appointment(user, appointment):
        raise AppointmentPermissionError("You do not have permission to review this appointment.")

    action = command.action
    new_status = (
        AppointmentStatusChoices.APPROVED
        if action == "approve"
        else AppointmentStatusChoices.DECLINED
    )

    _validate_transition(appointment, new_status)

    from_status = appointment.status
    old_counselor = appointment.assigned_counselor

    if action == "approve":
        _validate_confirmed_schedule(
            command.confirmed_date,
            command.confirmed_start_time,
            command.confirmed_end_time,
        )
        new_counselor_id = command.assigned_counselor_id or appointment.assigned_counselor_id
        new_counselor = _resolve_active_user(new_counselor_id) if new_counselor_id else None
        if new_counselor != old_counselor:
            if not can_assign_appointment_to(user, appointment, new_counselor):
                raise AppointmentPermissionError(
                    "You do not have permission to assign this counselor."
                )
            _create_assignment_history(
                appointment,
                old_counselor,
                new_counselor,
                user,
                "Assigned during appointment review",
            )
        appointment.assigned_counselor = new_counselor
        appointment.confirmed_date = command.confirmed_date
        appointment.confirmed_start_time = command.confirmed_start_time
        appointment.confirmed_end_time = command.confirmed_end_time
        appointment.internal_notes = command.internal_notes
    else:
        appointment.decline_reason = command.decline_reason
    appointment.reviewed_by = user
    appointment.reviewed_at = timezone.now()
    appointment.status = new_status
    appointment.save()

    _create_status_history(
        appointment,
        new_status,
        user,
        command.reason,
        from_status=from_status,
    )

    audit_status_transition(
        actor_user=user,
        target_model="Appointment",
        target_object_id=str(appointment.pk),
        reference_code=appointment.reference_code,
        metadata={
            "action": f"decide_appointment_review_{command.action}",
            "from_status": from_status,
            "to_status": new_status,
        },
    )

    if action == "approve" and old_counselor != appointment.assigned_counselor:
        _notify("counselor_assigned", appointment, actor=user)

    return appointment


@transaction.atomic
def schedule_appointment(
    user,
    reference_code: str,
    command: AppointmentScheduleCommand,
    *,
    expected_updated_at=None,
) -> Appointment:
    """Transition APPROVED → SCHEDULED with the confirmed datetime."""
    if not isinstance(command, AppointmentScheduleCommand):
        raise ValidationError("Appointment scheduling requires an AppointmentScheduleCommand.")
    # Read only the counselor identifier needed to establish the lock order;
    # the authoritative appointment is still locked and reloaded below.
    lock_schedule_scope()
    counselor_id = (
        Appointment.objects.filter(reference_code=str(reference_code or "").strip())
        .values_list("assigned_counselor_id", flat=True)
        .first()
    )
    lock_schedule_scope(counselor_id)
    appointment = _load_appointment(reference_code)
    # Booking shares the schedule-management lock order: office, counselor,
    # then appointment. This closes the race where a block/closure is created
    # after availability is checked but before the appointment is committed.
    _check_not_stale(appointment, expected_updated_at)
    if not can_schedule_appointment(user, appointment):
        raise AppointmentPermissionError(
            "You do not have permission to schedule this appointment."
        )

    confirmed_date = command.confirmed_date or appointment.confirmed_date
    confirmed_start_time = command.confirmed_start_time or appointment.confirmed_start_time
    confirmed_end_time = command.confirmed_end_time or appointment.confirmed_end_time
    _validate_confirmed_schedule(confirmed_date, confirmed_start_time, confirmed_end_time)
    if appointment.assigned_counselor_id is None:
        raise AppointmentTransitionError(
            "Assign an active counselor before scheduling this appointment."
        )

    counselor = _resolve_active_user(appointment.assigned_counselor_id)
    from apps.appointments.selectors import get_matching_available_slot

    if get_matching_available_slot(
        counselor,
        confirmed_date,
        confirmed_start_time,
        confirmed_end_time,
        appointment.appointment_mode,
    ) is None:
        raise AppointmentTransitionError(
            "That time is no longer available. Check the counselor's available times "
            "and choose another slot."
        )

    _validate_transition(appointment, AppointmentStatusChoices.SCHEDULED)

    from_status = appointment.status
    appointment.confirmed_date = confirmed_date
    appointment.confirmed_start_time = confirmed_start_time
    appointment.confirmed_end_time = confirmed_end_time
    if command.internal_notes:
        appointment.internal_notes = command.internal_notes
    appointment.status = AppointmentStatusChoices.SCHEDULED
    appointment.save()

    _create_status_history(
        appointment,
        AppointmentStatusChoices.SCHEDULED,
        user,
        from_status=from_status,
    )

    audit_status_transition(
        actor_user=user,
        target_model="Appointment",
        target_object_id=str(appointment.pk),
        reference_code=appointment.reference_code,
        metadata={
            "action": "schedule_appointment",
            "from_status": from_status,
            "to_status": AppointmentStatusChoices.SCHEDULED,
        },
    )

    return appointment

@transaction.atomic
def review_and_schedule_appointment(
    user,
    reference_code: str,
    command: AppointmentReviewCommand,
) -> Appointment:
    """Review a request and, when approved, reserve the exact live slot atomically."""
    if not isinstance(command, AppointmentReviewCommand):
        raise ValidationError("Review and scheduling requires an AppointmentReviewCommand.")
    decision = command.action
    assigned_counselor_id = command.assigned_counselor_id
    confirmed_date = command.confirmed_date
    confirmed_start_time = command.confirmed_start_time
    confirmed_end_time = command.confirmed_end_time
    decline_reason = command.decline_reason
    internal_notes = command.internal_notes
    lock_schedule_scope()
    existing_counselor_id = (
        Appointment.objects.filter(reference_code=str(reference_code or "").strip())
        .values_list("assigned_counselor_id", flat=True)
        .first()
    )
    candidate_counselor_id = assigned_counselor_id or existing_counselor_id
    if candidate_counselor_id is None and is_counselor(user):
        candidate_counselor_id = user.pk
    if decision == "approve":
        lock_schedule_scope(candidate_counselor_id)
    appointment = _load_appointment(reference_code)
    if candidate_counselor_id is None:
        candidate_counselor_id = appointment.assigned_counselor_id
    if not can_review_appointment(user, appointment):
        raise AppointmentPermissionError("You do not have permission to review this appointment.")

    if decision == "decline":
        if appointment.status == AppointmentStatusChoices.SUBMITTED:
            _submit(appointment, user)
        if appointment.status != AppointmentStatusChoices.PENDING_REVIEW:
            raise AppointmentTransitionError("Only a pending request can be declined.")
        appointment = decide_appointment_review(
            user,
            reference_code,
            AppointmentReviewCommand(
                action="decline",
                decline_reason=decline_reason,
            ),
        )
        _notify("declined", appointment, actor=user)
        return appointment

    if decision != "approve":
        raise AppointmentTransitionError("Select a valid appointment decision.")

    if is_counselor(user):
        target_counselor_id = (
            assigned_counselor_id
            or appointment.assigned_counselor_id
            or user.pk
        )
    elif is_gco_staff(user):
        target_counselor_id = appointment.assigned_counselor_id
        if assigned_counselor_id and str(assigned_counselor_id) != str(target_counselor_id):
            raise AppointmentPermissionError("GCO Staff cannot change the assigned counselor.")
    else:
        raise AppointmentPermissionError("You do not have permission to schedule appointments.")

    if target_counselor_id is None:
        raise AppointmentTransitionError(
            "Assign an active counselor before scheduling this appointment."
        )

    target_counselor = _resolve_active_user(target_counselor_id)
    if not can_assign_appointment_to(user, appointment, target_counselor):
        if not (
            is_gco_staff(user)
            and appointment.assigned_counselor_id == target_counselor.pk
        ):
            raise AppointmentPermissionError("You cannot assign the selected counselor.")

    _validate_confirmed_schedule(confirmed_date, confirmed_start_time, confirmed_end_time)

    from apps.appointments.selectors import get_matching_available_slot

    matching_slot = get_matching_available_slot(
        target_counselor,
        confirmed_date,
        confirmed_start_time,
        confirmed_end_time,
        appointment.appointment_mode,
    )
    if matching_slot is None:
        raise AppointmentTransitionError(
            "That time is no longer available. Check the counselor's available times "
            "and choose another slot."
        )

    if appointment.status == AppointmentStatusChoices.SUBMITTED:
        _submit(appointment, user)
    if appointment.status == AppointmentStatusChoices.PENDING_REVIEW:
        appointment = decide_appointment_review(
            user,
            reference_code,
            AppointmentReviewCommand(
                action="approve",
                assigned_counselor_id=str(target_counselor.pk),
                confirmed_date=confirmed_date,
                confirmed_start_time=confirmed_start_time,
                confirmed_end_time=confirmed_end_time,
                internal_notes=internal_notes,
            ),
        )
    elif appointment.status != AppointmentStatusChoices.APPROVED:
        raise AppointmentTransitionError(
            "Only a submitted, pending, or approved appointment can be scheduled."
        )

    appointment = schedule_appointment(
        user,
        reference_code,
        AppointmentScheduleCommand(
            confirmed_date=confirmed_date,
            confirmed_start_time=confirmed_start_time,
            confirmed_end_time=confirmed_end_time,
        ),
    )
    _notify("scheduled", appointment, actor=user)
    return appointment

@transaction.atomic
def cancel_appointment(
    user,
    reference_code: str,
    command: AppointmentCancellationCommand,
    *,
    expected_updated_at=None,
) -> Appointment:
    """Cancel the appointment.

    Determines cancellation type based on actor role:
    - Student → CANCELLED_BY_STUDENT
    - Staff/counselor/head → CANCELLED_BY_OFFICE
    """
    if not isinstance(command, AppointmentCancellationCommand):
        raise ValidationError(
            "Appointment cancellation requires an AppointmentCancellationCommand."
        )
    appointment = _load_appointment(reference_code)
    _check_not_stale(appointment, expected_updated_at)
    reason = command.reason
    if not can_cancel_appointment(user, appointment):
        raise AppointmentPermissionError("You do not have permission to cancel this appointment.")
    _ensure_linked_session_is_unstarted(appointment)

    from apps.access_control.rules import is_student

    new_status = (
        AppointmentStatusChoices.CANCELLED_BY_STUDENT
        if is_student(user)
        else AppointmentStatusChoices.CANCELLED_BY_OFFICE
    )

    _validate_transition(appointment, new_status)

    from_status = appointment.status
    appointment.cancellation_reason = reason
    appointment.status = new_status
    appointment.save()

    _create_status_history(appointment, new_status, user, reason, from_status=from_status)
    audit_status_transition(
        actor_user=user,
        target_model="Appointment",
        target_object_id=str(appointment.pk),
        reference_code=appointment.reference_code,
        metadata={
            "action": "cancel_appointment",
            "from_status": from_status,
            "to_status": new_status,
        },
    )

    _notify(
        "cancelled_by_student"
        if new_status == AppointmentStatusChoices.CANCELLED_BY_STUDENT
        else "cancelled_by_office",
        appointment,
        actor=user,
    )
    return appointment


@transaction.atomic
def request_late_cancellation(
    user,
    reference_code: str,
    command: LateCancellationRequestCommand,
    *,
    expected_updated_at=None,
) -> Appointment:
    """Transition SCHEDULED → LATE_CANCELLATION_REQUESTED."""
    if not isinstance(command, LateCancellationRequestCommand):
        raise ValidationError(
            "A late cancellation request requires a LateCancellationRequestCommand."
        )
    appointment = _load_appointment(reference_code)
    _check_not_stale(appointment, expected_updated_at)
    reason = command.reason
    if not can_request_late_cancellation(user, appointment):
        raise AppointmentPermissionError(
            "This appointment is not eligible for a late cancellation request."
        )
    _ensure_linked_session_is_unstarted(appointment)

    _validate_transition(appointment, AppointmentStatusChoices.LATE_CANCELLATION_REQUESTED)

    from_status = appointment.status
    appointment.status = AppointmentStatusChoices.LATE_CANCELLATION_REQUESTED
    appointment.cancellation_reason = reason
    appointment.save()

    _create_status_history(
        appointment,
        AppointmentStatusChoices.LATE_CANCELLATION_REQUESTED,
        user,
        reason,
        from_status=from_status,
    )

    audit_status_transition(
        actor_user=user,
        target_model="Appointment",
        target_object_id=str(appointment.pk),
        reference_code=appointment.reference_code,
        metadata={
            "action": "request_late_cancellation",
            "from_status": from_status,
            "to_status": AppointmentStatusChoices.LATE_CANCELLATION_REQUESTED,
        },
    )

    _notify("late_cancellation_requested", appointment, actor=user)
    return appointment

@transaction.atomic
def review_late_cancellation(
    user,
    reference_code: str,
    command: LateCancellationDecisionCommand,
) -> Appointment:
    """Approve or decline a pending late-cancellation request."""
    if not isinstance(command, LateCancellationDecisionCommand):
        raise ValidationError(
            "A late cancellation decision requires a LateCancellationDecisionCommand."
        )
    if command.decision == "approve":
        return approve_late_cancellation(user, reference_code)
    return decline_late_cancellation(user, reference_code)


@transaction.atomic
def approve_late_cancellation(user, reference_code: str) -> Appointment:
    """Transition LATE_CANCELLATION_REQUESTED → LATE_CANCELLATION_APPROVED.

    This is a single-domain transition. Cancelling the linked counseling
    session belongs to the orchestration use case.
    """
    appointment = _load_appointment(reference_code)
    if not can_review_late_cancellation(user, appointment):
        raise AppointmentPermissionError(
            "You do not have permission to approve late cancellations."
        )

    _validate_transition(appointment, AppointmentStatusChoices.LATE_CANCELLATION_APPROVED)

    from_status = appointment.status
    appointment.status = AppointmentStatusChoices.LATE_CANCELLATION_APPROVED
    appointment.save()

    _create_status_history(
        appointment,
        AppointmentStatusChoices.LATE_CANCELLATION_APPROVED,
        user,
        "Late cancellation approved",
        from_status=from_status,
    )
    _ensure_linked_session_is_unstarted(appointment)

    audit_status_transition(
        actor_user=user,
        target_model="Appointment",
        target_object_id=str(appointment.pk),
        reference_code=appointment.reference_code,
        metadata={
            "action": "approve_late_cancellation",
            "from_status": from_status,
            "to_status": AppointmentStatusChoices.LATE_CANCELLATION_APPROVED,
        },
    )

    _notify("late_cancellation_approved", appointment, actor=user)
    return appointment


@transaction.atomic
def decline_late_cancellation(user, reference_code: str) -> Appointment:
    """Decline a late cancellation while preserving the scheduled reservation."""
    appointment = _load_appointment(reference_code)
    if not can_review_late_cancellation(user, appointment):
        raise AppointmentPermissionError(
            "You do not have permission to decline late cancellations."
        )

    from_status = appointment.status
    if from_status != AppointmentStatusChoices.LATE_CANCELLATION_REQUESTED:
        raise AppointmentTransitionError("Only a pending late cancellation can be declined.")
    appointment.status = AppointmentStatusChoices.SCHEDULED
    appointment.save()

    _create_status_history(
        appointment,
        AppointmentStatusChoices.SCHEDULED,
        user,
        "Late cancellation declined; appointment remains scheduled",
        from_status=from_status,
    )

    audit_status_transition(
        actor_user=user,
        target_model="Appointment",
        target_object_id=str(appointment.pk),
        reference_code=appointment.reference_code,
        metadata={
            "action": "decline_late_cancellation",
            "from_status": from_status,
            "to_status": AppointmentStatusChoices.SCHEDULED,
        },
    )

    _notify("late_cancellation_declined", appointment, actor=user)
    return appointment

@transaction.atomic
def complete_appointment(
    user,
    reference_code: str,
    command: AppointmentCompletionCommand | None = None,
) -> Appointment:
    """Transition SCHEDULED → COMPLETED with actual start/end times."""
    if command is None:
        command = AppointmentCompletionCommand()
    if not isinstance(command, AppointmentCompletionCommand):
        raise ValidationError("Appointment completion requires an AppointmentCompletionCommand.")
    appointment = _load_appointment(reference_code)
    if not can_complete_appointment(user, appointment):
        raise AppointmentPermissionError(
            "You do not have permission to complete this appointment."
        )
    _ensure_linked_session_completed_before_appointment_completion(appointment)
    if appointment.status == AppointmentStatusChoices.COMPLETED:
        return appointment

    _validate_transition(appointment, AppointmentStatusChoices.COMPLETED)

    from_status = appointment.status
    if command.actual_start_time is not None:
        appointment.actual_start_time = command.actual_start_time
    if command.actual_end_time is not None:
        appointment.actual_end_time = command.actual_end_time
    appointment.completed_at = timezone.now()
    appointment.status = AppointmentStatusChoices.COMPLETED
    appointment.save()

    _create_status_history(
        appointment,
        AppointmentStatusChoices.COMPLETED,
        user,
        "Appointment completed",
        from_status=from_status,
    )

    audit_status_transition(
        actor_user=user,
        target_model="Appointment",
        target_object_id=str(appointment.pk),
        reference_code=appointment.reference_code,
        metadata={
            "action": "complete_appointment",
            "from_status": from_status,
            "to_status": AppointmentStatusChoices.COMPLETED,
        },
    )

    _notify("completed", appointment, actor=user)
    return appointment


@transaction.atomic
def mark_no_show(
    user,
    reference_code: str,
    command: AppointmentNoShowCommand | None = None,
) -> Appointment:
    """Transition SCHEDULED → NO_SHOW."""
    if command is None:
        command = AppointmentNoShowCommand()
    if not isinstance(command, AppointmentNoShowCommand):
        raise ValidationError("Appointment no-show requires an AppointmentNoShowCommand.")
    appointment = _load_appointment(reference_code)
    if not can_mark_no_show(user, appointment):
        raise AppointmentPermissionError(
            "You do not have permission to mark this appointment as no-show."
        )
    if appointment.status == AppointmentStatusChoices.NO_SHOW:
        return appointment
    _ensure_linked_session_is_unstarted(appointment)

    _validate_transition(appointment, AppointmentStatusChoices.NO_SHOW)

    from_status = appointment.status
    appointment.status = AppointmentStatusChoices.NO_SHOW
    appointment.save()

    _create_status_history(
        appointment,
        AppointmentStatusChoices.NO_SHOW,
        user,
        "Student did not attend",
        from_status=from_status,
    )

    audit_status_transition(
        actor_user=user,
        target_model="Appointment",
        target_object_id=str(appointment.pk),
        reference_code=appointment.reference_code,
        metadata={
            "action": "mark_no_show",
            "from_status": from_status,
            "to_status": AppointmentStatusChoices.NO_SHOW,
        },
    )

    _notify("no_show", appointment, actor=user)
    return appointment

@transaction.atomic
def assign_counselor(
    user,
    reference_code: str,
    command: AppointmentAssignmentCommand,
) -> Appointment:
    """Assign a counselor to an appointment (initial assignment)."""
    if not isinstance(command, AppointmentAssignmentCommand):
        raise ValidationError("Counselor assignment requires an AppointmentAssignmentCommand.")
    appointment = _load_appointment(reference_code)
    if not can_assign_appointment(user, appointment):
        raise AppointmentPermissionError("You do not have permission to assign counselors.")

    from_counselor = appointment.assigned_counselor
    counselor = _resolve_active_user(command.counselor_id)
    if not can_assign_appointment_to(user, appointment, counselor):
        raise AppointmentPermissionError("You do not have permission to assign this counselor.")
    if from_counselor == counselor:
        return appointment

    _create_assignment_history(
        appointment=appointment,
        from_counselor=from_counselor,
        to_counselor=counselor,
        assigned_by=user,
        reason=command.reason or "Initial assignment",
    )

    appointment.assigned_counselor = counselor
    appointment.save(update_fields=["assigned_counselor", "updated_at"])

    audit_assignment_change(
        actor_user=user,
        target_model="Appointment",
        target_object_id=str(appointment.pk),
        reference_code=appointment.reference_code,
        metadata={
            "action": "assign_counselor",
            "from_counselor_id": str(from_counselor.pk) if from_counselor else None,
            "to_counselor_id": str(counselor.pk),
        },
    )

    _notify("counselor_assigned", appointment, actor=user)

    return appointment


@transaction.atomic
def reassign_counselor(
    user,
    reference_code: str,
    command: AppointmentAssignmentCommand,
) -> Appointment:
    """Reassign an appointment to a different counselor."""
    if not isinstance(command, AppointmentAssignmentCommand):
        raise ValidationError(
            "Counselor reassignment requires an AppointmentAssignmentCommand."
        )
    appointment = _load_appointment(reference_code)
    if not can_assign_appointment(user, appointment):
        raise AppointmentPermissionError("You do not have permission to reassign counselors.")

    from_counselor = appointment.assigned_counselor
    counselor = _resolve_active_user(command.counselor_id)
    if not can_assign_appointment_to(user, appointment, counselor):
        raise AppointmentPermissionError("You do not have permission to assign this counselor.")
    if from_counselor == counselor:
        return appointment

    _create_assignment_history(
        appointment=appointment,
        from_counselor=from_counselor,
        to_counselor=counselor,
        assigned_by=user,
        reason=command.reason,
    )

    appointment.assigned_counselor = counselor
    appointment.save(update_fields=["assigned_counselor", "updated_at"])

    audit_assignment_change(
        actor_user=user,
        target_model="Appointment",
        target_object_id=str(appointment.pk),
        reference_code=appointment.reference_code,
        metadata={
            "action": "reassign_counselor",
            "from_counselor_id": str(from_counselor.pk) if from_counselor else None,
            "to_counselor_id": str(counselor.pk),
            "reason_set": bool(command.reason),
        },
    )

    _notify("counselor_assigned", appointment, actor=user)

    return appointment
