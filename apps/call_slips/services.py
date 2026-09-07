# Project: COMPASS
# File: apps/call_slips/services.py
# Module: apps.call_slips
# Purpose: Scoped, transactional, and audited call slip workflow services.
# Domain boundary and service policy.

import datetime
from apps.common.exceptions import PermissionDeniedError, ValidationError, NotFoundError, WorkflowError
from django.apps import apps as django_apps
from django.contrib.auth import get_user_model
from django.db import transaction, IntegrityError
from django.utils import timezone

from apps.accounts.models import RoleChoices
from apps.access_control.authority import has_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import is_counselor, is_student, owns_user
from apps.audit.services import (
    audit_log,
    audit_status_transition,
    audit_assignment_change,
)
from apps.call_slips.models import (
    CallSlip,
    CallSlipStatusChoices,
    CallSlipStatusHistory,
    CallSlipAssignmentHistory,
    CallSlipScheduleHistory,
    CallSlipRescheduleRequest,
    CallSlipWorkflowReasonChoices,
    CallSlipRescheduleRequestStatusChoices,
    CallSlipAssignmentChangeTypeChoices,
    CallSlipScheduleChangeTypeChoices,
    CallSlipModeChoices,
    CallSlipSourceTypeChoices,
    CallSlipPurposeCodeChoices,
    CallSlipReissueReasonChoices,
    COUNSELOR_TIME_PURPOSES,
    EVER_ISSUED_STATUSES,
    TERMINAL_STATUSES,
)
from apps.call_slips.commands import (
    CallSlipAttendanceCommand,
    CallSlipAssignmentCommand,
    CallSlipDecisionCommand,
    CallSlipDraftCommand,
    CallSlipReasonCommand,
    CallSlipCreateFromReferralCommand,
    CallSlipDraftUpdateCommand,
    CallSlipIssueCommand,
    CallSlipRescheduleCommand,
)
from apps.call_slips.reference_codes import generate_call_slip_reference_code
from apps.call_slips.encryption import (
    CALL_SLIP_CONFIDENTIAL_FIELDS,
    RESCHEDULE_CONFIDENTIAL_FIELDS,
    CS_ASSIGNMENT,
    CS_CANCELLATION,
    CS_INSTRUCTIONS,
    CS_NO_SHOW,
    CS_OFFICE_REMARKS,
    CS_RESCHEDULE_DECISION,
    CS_RESCHEDULE_REQUEST,
    CallSlipEncryptionError,
    initialize_group,
    prepare_group_write,
    read_group,
    read_owned_request_for_retry,
)
from apps.common.request_dedup import RequestKeyPolicy, validate_and_lock_request_key


def _locked_slip(reference_code):
    return (
        CallSlip.objects.select_for_update(of=("self",))
        .defer(*CALL_SLIP_CONFIDENTIAL_FIELDS)
        .select_related("student", "student__student_profile", "assigned_counselor")
        .get(reference_code=str(reference_code or "").strip())
    )


def _get_slip(reference_code):
    try:
        return _locked_slip(reference_code)
    except CallSlip.DoesNotExist as exc:
        raise NotFoundError() from exc


def _get_user(user_id, *, required=True):
    if user_id in (None, ""):
        if required:
            raise ValidationError("The account reference is required.")
        return None
    try:
        return get_user_model().objects.get(pk=str(user_id))
    except get_user_model().DoesNotExist as exc:
        raise NotFoundError() from exc


def _user_pk(user_id):
    if user_id in (None, ""):
        return None
    try:
        return int(str(user_id))
    except (TypeError, ValueError):
        return str(user_id)


def _reference_pk(label, reference_code):
    if reference_code in (None, ""):
        return None
    app_label, model_name = label.split(".", 1)
    model = django_apps.get_model(app_label, model_name)
    return model.objects.filter(reference_code=str(reference_code).strip()).values_list("pk", flat=True).first()


def _assignment_history(**kwargs):
    history = CallSlipAssignmentHistory(detail="", **kwargs)
    initialize_group(history, CS_ASSIGNMENT, "")
    history.save(force_insert=True)
    return history


def _audit_event(event_code, actor, slip, metadata=None):
    safe_metadata = {
        "event_code": event_code,
        "reference_code": slip.reference_code,
        **(metadata or {}),
    }
    return audit_log(
        action_type=event_code,
        event_category="WORKFLOW",
        target_model="call_slips.CallSlip",
        target_object_id=str(slip.pk),
        actor_user=actor,
        reference_code=slip.reference_code,
        source_app="call_slips",
        metadata=safe_metadata,
    )


def _validate_assignment_payload(actor, command, slip=None):
    if not command.has("assigned_counselor_id"):
        return None
    target = _get_user(command.assigned_counselor_id, required=False)
    current_id = getattr(slip, "assigned_counselor_id", None)
    if target is None and current_id is None:
        return None
    if target is not None and target.pk == current_id:
        return target
    if current_id is None and target is not None and target.pk == actor.pk and is_counselor(actor):
        return target
    if not has_capability(actor, Capability.CALL_SLIPS_ASSIGN, target=slip):
        raise PermissionDeniedError("Call-slip assignment authority is required.")
    if target is not None and (not target.is_active or target.role != RoleChoices.COUNSELOR):
        raise ValidationError("The selected counselor is not available.")
    return target


def _get_coarse_schedule_bucket(scheduled_start_at):
    if not scheduled_start_at:
        return "Unscheduled"
    today = timezone.localdate()
    scheduled_date = timezone.localtime(scheduled_start_at).date()
    if scheduled_date == today:
        return "Today"
    elif scheduled_date == today + datetime.timedelta(days=1):
        return "Tomorrow"
    elif scheduled_date < today:
        return "Past"
    else:
        return "Future"


def check_counselor_conflicts(counselor, start_at, end_at, exclude_slip=None):
    from apps.appointments.models import Appointment, AppointmentStatusChoices

    # 1. Overlap with scheduled appointments
    local_start = timezone.localtime(start_at)
    local_end = timezone.localtime(end_at)

    dates = []
    curr = local_start.date()
    while curr <= local_end.date():
        dates.append(curr)
        curr += datetime.timedelta(days=1)

    appts = Appointment.objects.select_for_update().filter(
        assigned_counselor=counselor,
        status=AppointmentStatusChoices.SCHEDULED,
        confirmed_date__in=dates,
        confirmed_start_time__isnull=False,
        confirmed_end_time__isnull=False,
    )
    for app in appts:
        tz = timezone.get_current_timezone()
        app_start = timezone.make_aware(datetime.datetime.combine(app.confirmed_date, app.confirmed_start_time), tz)
        app_end = timezone.make_aware(datetime.datetime.combine(app.confirmed_date, app.confirmed_end_time), tz)

        # Half-open overlap rule
        if start_at < app_end and end_at > app_start:
            linked_exact_reservation = bool(
                exclude_slip
                and exclude_slip.appointment_id == app.pk
                and app.student_id == exclude_slip.student_id
                and app.assigned_counselor_id == counselor.pk
                and app_start == start_at
                and app_end == end_at
            )
            if linked_exact_reservation:
                continue
            raise ValidationError("Schedule conflict: counselor has a scheduled appointment during this interval.")

    # 2. Overlap with other Call Slips
    slips = CallSlip.objects.select_for_update().filter(
        assigned_counselor=counselor,
        status__in=[
            CallSlipStatusChoices.ISSUED,
            CallSlipStatusChoices.ACKNOWLEDGED,
            CallSlipStatusChoices.RESCHEDULE_REQUESTED,
        ],
        scheduled_start_at__isnull=False,
        scheduled_end_at__isnull=False,
        purpose_code__in=COUNSELOR_TIME_PURPOSES,
    )
    if exclude_slip:
        slips = slips.exclude(pk=exclude_slip.pk)

    for cs in slips:
        if start_at < cs.scheduled_end_at and end_at > cs.scheduled_start_at:
            raise ValidationError("Schedule conflict: counselor has another issued Call Slip during this interval.")


class ActiveReferralCallSlipConflict(WorkflowError):
    pass


_DERIVED_COUNSELOR_UNSET = object()


def _creation_payload_matches(existing, actor, student, command: CallSlipDraftCommand):
    """Compare an idempotent create retry without reading unrelated secrets."""
    if not (
        existing.created_by_id == actor.pk
        and existing.student_id == student.pk
        and existing.referral_id == _reference_pk("referrals.Referral", command.referral_reference)
        and existing.appointment_id == _reference_pk("appointments.Appointment", command.appointment_reference)
        and existing.source_type == command.source_type
        and existing.purpose_code == command.purpose_code
        and existing.destination_code == command.destination_code
        and existing.report_to_destination == command.report_to_destination
        and existing.mode == (command.mode or CallSlipModeChoices.ONSITE)
        and existing.student_safe_location == command.student_safe_location
        and existing.assigned_counselor_id == _user_pk(command.assigned_counselor_id)
        and existing.reissued_from_id == _reference_pk("call_slips.CallSlip", command.reissued_from_reference)
        and existing.reissue_reason_code == command.reissue_reason_code
    ):
        return False
    try:
        return (
            read_group(actor, existing, CS_INSTRUCTIONS)
            == command.student_safe_instructions
            and read_group(actor, existing, CS_OFFICE_REMARKS)
            == command.office_only_remarks
        )
    except CallSlipEncryptionError:
        return False


def _create_call_slip_draft_record(
    actor, student, command: CallSlipDraftCommand, request_key, *, derived_counselor=_DERIVED_COUNSELOR_UNSET,
    referral=None, appointment=None, reissued_from=None,
) -> CallSlip:
    request_key = validate_and_lock_request_key(RequestKeyPolicy("call_slips.create", max_length=100), request_key)

    # Idempotence check
    existing = CallSlip.objects.defer(*CALL_SLIP_CONFIDENTIAL_FIELDS).filter(creation_request_key=request_key).first()
    if existing:
        if _creation_payload_matches(existing, actor, student, command):
            return existing
        raise ValidationError("This request key is already in use.")

    target_counselor = (
        derived_counselor
        if derived_counselor is not _DERIVED_COUNSELOR_UNSET
        else _validate_assignment_payload(actor, command)
    )

    ref = generate_call_slip_reference_code()

    # Frozen snapshot fields
    course_snap = student.student_profile.program if hasattr(student, "student_profile") else ""
    year_snap = str(student.student_profile.year_level) if hasattr(student, "student_profile") and student.student_profile.year_level else ""

    slip = CallSlip(
        reference_code=ref,
        student=student,
        referral=referral,
        appointment=appointment,
        reissued_from=reissued_from,
        reissue_reason_code=command.reissue_reason_code,
        source_type=command.source_type,
        purpose_code=command.purpose_code,
        assigned_counselor=target_counselor,
        destination_code=command.destination_code,
        report_to_destination=command.report_to_destination,
        mode=command.mode or CallSlipModeChoices.ONSITE,
        student_safe_location=command.student_safe_location,
        student_safe_instructions=command.student_safe_instructions,
        office_only_remarks=command.office_only_remarks,
        course_snapshot=course_snap,
        year_level_snapshot=year_snap,
        created_by=actor,
        updated_by=actor,
        creation_request_key=request_key,
        status=CallSlipStatusChoices.DRAFT,
    )
    initialize_group(slip, CS_INSTRUCTIONS, command.student_safe_instructions)
    initialize_group(slip, CS_OFFICE_REMARKS, command.office_only_remarks)
    slip.full_clean()
    slip.save(force_insert=True)

    # Initial history
    CallSlipStatusHistory.objects.create(
        call_slip=slip,
        from_status="",
        to_status=CallSlipStatusChoices.DRAFT,
        actor=actor,
        reason_code=CallSlipWorkflowReasonChoices.WORKFLOW_PROGRESSION,
        transitioned_at=timezone.now(),
        request_key=request_key,
    )

    if slip.assigned_counselor:
        _assignment_history(
            call_slip=slip,
            from_counselor=None,
            to_counselor=slip.assigned_counselor,
            changed_by=actor,
            reason_code=CallSlipWorkflowReasonChoices.WORKFLOW_PROGRESSION,
            change_type=CallSlipAssignmentChangeTypeChoices.INITIAL_ASSIGNMENT,
            changed_at=timezone.now(),
        )

    # Audit
    _audit_event("CALL_SLIP_CREATE_DRAFT", actor, slip, {
        "status": slip.status,
        "purpose": slip.purpose_code,
        "mode": slip.mode,
    })

    return slip


@transaction.atomic
def create_call_slip_draft(actor, command: CallSlipDraftCommand, request_key) -> CallSlip:
    if not isinstance(command, CallSlipDraftCommand):
        raise ValidationError("Call Slip creation requires a CallSlipDraftCommand.")
    if command.referral_reference:
        raise ValidationError("Referral-linked Call Slips must use the orchestration boundary.")
    student = _get_user(command.student_id)
    from apps.call_slips.policies import can_create_call_slip_draft
    if not can_create_call_slip_draft(actor, student):
        raise PermissionDeniedError("You do not have permission to create a call slip draft for this student.")
    appointment = None
    if command.appointment_reference:
        from apps.appointments.models import Appointment
        appointment = Appointment.objects.select_for_update().filter(reference_code=command.appointment_reference).first()
        if appointment is None:
            raise NotFoundError()
        if appointment.student_id != student.pk:
            raise ValidationError("The linked appointment belongs to another student.")
    reissued_from = None
    if command.reissued_from_reference:
        reissued_from = CallSlip.objects.select_for_update().filter(reference_code=command.reissued_from_reference).first()
        if reissued_from is None:
            raise NotFoundError()
    return _create_call_slip_draft_record(
        actor, student, command, request_key, appointment=appointment, reissued_from=reissued_from,
    )


def _locked_referral(reference_code):
    from apps.referrals.encryption import REFERRAL_CONFIDENTIAL_FIELDS
    from apps.referrals.models import Referral

    return (
        Referral.objects.select_for_update(of=("self",))
        .defer(*REFERRAL_CONFIDENTIAL_FIELDS)
        .select_related("student", "student__student_profile", "assigned_counselor")
        .get(reference_code=str(reference_code or "").strip())
    )


@transaction.atomic
def create_call_slip_from_referral(
    actor, command: CallSlipCreateFromReferralCommand, request_key
) -> CallSlip:
    if not isinstance(command, CallSlipCreateFromReferralCommand):
        raise ValidationError("Referral-linked Call Slip creation requires a CallSlipCreateFromReferralCommand.")
    from apps.call_slips.policies import (
        can_create_call_slip_from_referral,
        can_reissue_referral_call_slip,
    )

    referral = _locked_referral(command.referral_reference)
    if not can_create_call_slip_from_referral(actor, referral):
        raise PermissionDeniedError("You do not have permission to create a Call Slip from this Referral.")

    linked = list(
        CallSlip.objects.select_for_update(of=("self",))
        .defer(*CALL_SLIP_CONFIDENTIAL_FIELDS)
        .filter(referral=referral)
        .select_related("referral", "student", "student__student_profile", "assigned_counselor")
        .order_by("created_at", "pk")
    )

    initial_counselor = referral.assigned_counselor
    if initial_counselor is None and is_counselor(actor):
        initial_counselor = actor

    forced_command = CallSlipDraftCommand(
        student_id=str(referral.student_id),
        referral_reference=referral.reference_code,
        source_type=CallSlipSourceTypeChoices.REFERRAL,
        purpose_code=CallSlipPurposeCodeChoices.GUIDANCE_INTERVIEW,
        destination_code=command.destination_code,
        assigned_counselor_id=str(initial_counselor.pk) if initial_counselor else None,
        report_to_destination=command.report_to_destination,
        mode=command.mode,
        student_safe_location=command.student_safe_location,
        student_safe_instructions=command.student_safe_instructions,
        office_only_remarks=command.office_only_remarks,
        reissued_from_reference=command.reissued_from_reference,
        reissue_reason_code=command.reissue_reason_code,
    )
    request_key = validate_and_lock_request_key(RequestKeyPolicy("call_slips.create", max_length=100), request_key)
    existing_retry = next((slip for slip in linked if slip.creation_request_key == request_key), None)
    if existing_retry is not None:
        if _creation_payload_matches(existing_retry, actor, referral.student, forced_command):
            return existing_retry
        raise ValidationError("This request key is already in use.")

    active = next(
        (
            slip for slip in linked
            if slip.status in {
                CallSlipStatusChoices.DRAFT,
                CallSlipStatusChoices.ISSUED,
                CallSlipStatusChoices.ACKNOWLEDGED,
                CallSlipStatusChoices.RESCHEDULE_REQUESTED,
            }
        ),
        None,
    )
    if active is not None:
        raise ActiveReferralCallSlipConflict(
            f"Referral already has active Call Slip {active.reference_code}."
        )

    reissued_from = None
    if command.reissued_from_reference:
        reissued_from = next((slip for slip in linked if slip.reference_code == command.reissued_from_reference), None)
        predecessor = next(
            (slip for slip in linked if reissued_from is not None and slip.pk == reissued_from.pk), None
        )
        latest = linked[-1] if linked else None
        if predecessor is None or latest is None or predecessor.pk != latest.pk:
            raise ActiveReferralCallSlipConflict("Only the latest linked Call Slip may be reissued.")
        if not can_reissue_referral_call_slip(actor, predecessor):
            raise PermissionDeniedError("You do not have permission to reissue this Call Slip.")
        expected_reason = {
            CallSlipStatusChoices.NO_SHOW: CallSlipReissueReasonChoices.AFTER_NO_SHOW,
            CallSlipStatusChoices.EXPIRED: CallSlipReissueReasonChoices.AFTER_EXPIRY,
            CallSlipStatusChoices.CANCELLED: CallSlipReissueReasonChoices.AFTER_CANCELLATION,
        }.get(predecessor.status)
        if not expected_reason or command.reissue_reason_code != expected_reason:
            raise ValidationError("Reissue reason does not match the previous Call Slip state.")
        if hasattr(predecessor, "reissued_as"):
            raise ActiveReferralCallSlipConflict("This Call Slip has already been reissued.")
    elif linked:
        raise ActiveReferralCallSlipConflict(
            "A prior Call Slip exists. Use the approved reissue action when eligible."
        )

    try:
        slip = _create_call_slip_draft_record(
            actor,
            referral.student,
            forced_command,
            request_key,
            derived_counselor=initial_counselor,
            referral=referral,
            reissued_from=predecessor if command.reissued_from_reference else None,
        )
    except IntegrityError as exc:
        raise ActiveReferralCallSlipConflict(
            "Another active Call Slip was created for this Referral."
        ) from exc

    audit_entry = _audit_event("CALL_SLIP_CREATE_FROM_REFERRAL", actor, slip, {
        "status": slip.status,
        "referral_reference_code": referral.reference_code,
        "reissued": bool(command.reissued_from_reference),
        "reissue_reason_code": command.reissue_reason_code,
        **(
            {"previous_call_slip_reference_code": reissued_from.reference_code}
            if reissued_from is not None else {}
        ),
    })
    if audit_entry is None:
        # Referral-linked creation is a consequential relationship change;
        # do not commit the draft when its required audit evidence cannot be
        # persisted.  The surrounding atomic transaction rolls back the
        # Call Slip, histories, and any confidential field writes.
        raise ValidationError("The linked Call Slip draft could not be audited.")
    return slip


@transaction.atomic
def update_call_slip_draft(actor, reference_code, command: CallSlipDraftUpdateCommand) -> CallSlip:
    if not isinstance(command, CallSlipDraftUpdateCommand):
        raise ValidationError("Call Slip updates require a CallSlipDraftUpdateCommand.")
    # Row lock
    slip = _get_slip(reference_code)

    from apps.call_slips.policies import can_update_call_slip_draft
    if not can_update_call_slip_draft(actor, slip):
        raise PermissionDeniedError("You do not have permission to update this call slip draft.")

    if slip.status != CallSlipStatusChoices.DRAFT:
        raise ValidationError("Only drafts can be updated.")

    old_counselor = slip.assigned_counselor

    # Update allowed fields
    update_fields = []
    if command.has("source_type"):
        slip.source_type = command.source_type
        update_fields.append("source_type")
    if command.has("purpose_code"):
        slip.purpose_code = command.purpose_code
        update_fields.append("purpose_code")
    if command.has("assigned_counselor_id"):
        slip.assigned_counselor = _validate_assignment_payload(actor, command, slip)
        update_fields.append("assigned_counselor")
    if command.has("destination_code"):
        slip.destination_code = command.destination_code
        update_fields.append("destination_code")
    if command.has("report_to_destination"):
        slip.report_to_destination = command.report_to_destination
        update_fields.append("report_to_destination")
    if command.has("mode"):
        slip.mode = command.mode
        update_fields.append("mode")
    if command.has("student_safe_location"):
        slip.student_safe_location = command.student_safe_location
        update_fields.append("student_safe_location")
    if command.has("student_safe_instructions"):
        update_fields.extend(prepare_group_write(slip, CS_INSTRUCTIONS, command.student_safe_instructions))
    if command.has("office_only_remarks"):
        update_fields.extend(prepare_group_write(slip, CS_OFFICE_REMARKS, command.office_only_remarks))

    slip.updated_by = actor
    update_fields.append("updated_by")
    slip.full_clean()
    slip.save(update_fields=[*dict.fromkeys(update_fields), "updated_at"])

    # Assignment change check
    if old_counselor != slip.assigned_counselor:
        _assignment_history(
            call_slip=slip,
            from_counselor=old_counselor,
            to_counselor=slip.assigned_counselor,
            changed_by=actor,
            reason_code=CallSlipWorkflowReasonChoices.ASSIGNMENT_CHANGE,
            change_type=CallSlipAssignmentChangeTypeChoices.INITIAL_ASSIGNMENT if not old_counselor else CallSlipAssignmentChangeTypeChoices.REASSIGNMENT,
            changed_at=timezone.now(),
        )

    # Audit
    _audit_event("CALL_SLIP_UPDATE_DRAFT", actor, slip, {
        "status": slip.status,
        "purpose": slip.purpose_code,
        "mode": slip.mode,
    })

    return slip


@transaction.atomic
def assign_call_slip(actor, reference_code, command: CallSlipAssignmentCommand) -> CallSlip:
    if not isinstance(command, CallSlipAssignmentCommand):
        raise ValidationError("Call Slip assignment requires a typed counselor assignment command.")
    # Row lock
    slip = _get_slip(reference_code)
    target = _get_user(command.target_counselor_id)

    from apps.call_slips.policies import can_assign_call_slip
    if not can_assign_call_slip(actor, slip, target):
        raise PermissionDeniedError("You do not have permission to assign this counselor.")

    if slip.assigned_counselor == target:
        return slip  # No-op

    # Availability check if already issued
    if slip.status in EVER_ISSUED_STATUSES and target:
        # Check conflicts for target counselor
        check_counselor_conflicts(target, slip.scheduled_start_at, slip.scheduled_end_at, exclude_slip=slip)

    old_counselor = slip.assigned_counselor
    slip.assigned_counselor = target
    slip.updated_by = actor

    # Clear acknowledgement if already issued
    ack_invalidated = False
    if slip.status == CallSlipStatusChoices.ACKNOWLEDGED:
        slip.status = CallSlipStatusChoices.ISSUED
        slip.acknowledged_at = None
        slip.acknowledged_by = None
        ack_invalidated = True

    slip.full_clean()
    assignment_update_fields = ["assigned_counselor", "updated_by"]
    if ack_invalidated:
        assignment_update_fields.extend(["status", "acknowledged_at", "acknowledged_by"])
    slip.save(update_fields=[*assignment_update_fields, "updated_at"])

    # Assignment history
    change_type = CallSlipAssignmentChangeTypeChoices.INITIAL_ASSIGNMENT if not old_counselor else CallSlipAssignmentChangeTypeChoices.REASSIGNMENT
    _assignment_history(
        call_slip=slip,
        from_counselor=old_counselor,
        to_counselor=target,
        changed_by=actor,
        reason_code=command.reason_code,
        change_type=change_type,
        changed_at=timezone.now(),
    )

    # Schedule history for reassignment if ever issued
    if slip.status in EVER_ISSUED_STATUSES:
        CallSlipScheduleHistory.objects.create(
            call_slip=slip,
            change_type=CallSlipScheduleChangeTypeChoices.ASSIGNMENT_REEVALUATION,
            previous_start_at=slip.scheduled_start_at,
            previous_end_at=slip.scheduled_end_at,
            previous_expected_duration_minutes=slip.expected_duration_minutes,
            new_start_at=slip.scheduled_start_at,
            new_end_at=slip.scheduled_end_at,
            new_expected_duration_minutes=slip.expected_duration_minutes,
            previous_counselor=old_counselor,
            new_counselor=target,
            actor=actor,
            reason_code=command.reason_code,
            changed_at=timezone.now(),
            availability_blocking_before=bool(old_counselor and slip.purpose_code in COUNSELOR_TIME_PURPOSES),
            availability_blocking_after=bool(target and slip.purpose_code in COUNSELOR_TIME_PURPOSES),
        )

    if ack_invalidated:
        CallSlipStatusHistory.objects.create(
            call_slip=slip,
            from_status=CallSlipStatusChoices.ACKNOWLEDGED,
            to_status=CallSlipStatusChoices.ISSUED,
            actor=actor,
            reason_code=command.reason_code,
            transitioned_at=timezone.now(),
        )

    # Audit
    assignment_event = "CALL_SLIP_ASSIGN" if old_counselor is None else "CALL_SLIP_REASSIGN"
    _audit_event(assignment_event, actor, slip, {
        "status": slip.status,
        "assignment_changed": True,
        "acknowledgement_invalidated": ack_invalidated,
    })
    if slip.status in EVER_ISSUED_STATUSES:
        _audit_event("CALL_SLIP_SCHEDULE_CHANGE", actor, slip, {
            "status": slip.status,
            "assignment_changed": True,
            "schedule_changed": False,
        })

    return slip


@transaction.atomic
def reassign_call_slip(actor, reference_code, command: CallSlipAssignmentCommand) -> CallSlip:
    return assign_call_slip(actor, reference_code, command)


@transaction.atomic
def issue_call_slip(actor, reference_code, command: CallSlipIssueCommand) -> CallSlip:
    if not isinstance(command, CallSlipIssueCommand):
        raise ValidationError("Call Slip issuance requires a CallSlipIssueCommand.")
    # Row lock
    slip = _get_slip(reference_code)

    from apps.call_slips.policies import can_issue_call_slip
    if not can_issue_call_slip(actor, slip):
        raise PermissionDeniedError("You do not have permission to issue this call slip.")

    if slip.status != CallSlipStatusChoices.DRAFT:
        raise ValidationError("Cannot issue call slip from current state.")

    start_at = command.scheduled_start_at
    end_at = command.scheduled_end_at
    duration = command.expected_duration_minutes

    # Check conflicts for counselor
    if slip.purpose_code in COUNSELOR_TIME_PURPOSES:
        counselor = _validate_assignment_payload(actor, command, slip) if command.has("assigned_counselor_id") else slip.assigned_counselor
        if not counselor:
            raise ValidationError("Counselor-time purposes require an assigned counselor.")
        check_counselor_conflicts(counselor, start_at, end_at, exclude_slip=slip)

    old_status = slip.status
    old_start = slip.scheduled_start_at
    old_end = slip.scheduled_end_at
    old_duration = slip.expected_duration_minutes
    old_counselor = slip.assigned_counselor

    # Update schedule and parameters
    slip.scheduled_start_at = start_at
    slip.scheduled_end_at = end_at
    slip.expected_duration_minutes = duration

    if command.has("assigned_counselor_id"):
        slip.assigned_counselor = _validate_assignment_payload(actor, command, slip)
    if command.has("mode"):
        slip.mode = command.mode
    if command.has("report_to_destination"):
        slip.report_to_destination = command.report_to_destination
    if command.has("student_safe_location"):
        slip.student_safe_location = command.student_safe_location
    if command.has("student_safe_instructions"):
        confidential_fields = prepare_group_write(slip, CS_INSTRUCTIONS, command.student_safe_instructions)
    else:
        confidential_fields = ()

    slip.status = CallSlipStatusChoices.ISSUED
    slip.acknowledged_at = None
    slip.acknowledged_by = None
    slip.updated_by = actor

    # Fresh issue vs reissue markers
    is_initial = (old_status == CallSlipStatusChoices.DRAFT)
    if is_initial:
        slip.issued_at = timezone.now()
        slip.issued_by = actor
        # Freeze snapshots
        slip.course_snapshot = slip.student.student_profile.program if hasattr(slip.student, "student_profile") else ""
        slip.year_level_snapshot = str(slip.student.student_profile.year_level) if hasattr(slip.student, "student_profile") and slip.student.student_profile.year_level else ""

    slip.full_clean()
    issue_update_fields = [
        "scheduled_start_at", "scheduled_end_at", "expected_duration_minutes",
        "status", "acknowledged_at", "acknowledged_by", "updated_by",
        *confidential_fields,
    ]
    for field in ("assigned_counselor", "mode", "report_to_destination", "student_safe_location"):
        if command.has(field):
            issue_update_fields.append(field)
    if is_initial:
        issue_update_fields.extend(["issued_at", "issued_by", "course_snapshot", "year_level_snapshot"])
    slip.save(update_fields=[*dict.fromkeys(issue_update_fields), "updated_at"])

    # Status history
    if old_status != CallSlipStatusChoices.ISSUED:
        CallSlipStatusHistory.objects.create(
            call_slip=slip,
            from_status=old_status,
            to_status=CallSlipStatusChoices.ISSUED,
            actor=actor,
            reason_code=CallSlipWorkflowReasonChoices.WORKFLOW_PROGRESSION,
            transitioned_at=timezone.now(),
        )

    # Counselor change history if updated during issue
    if old_counselor != slip.assigned_counselor:
        _assignment_history(
            call_slip=slip,
            from_counselor=old_counselor,
            to_counselor=slip.assigned_counselor,
            changed_by=actor,
            reason_code=CallSlipWorkflowReasonChoices.ASSIGNMENT_CHANGE,
            change_type=CallSlipAssignmentChangeTypeChoices.INITIAL_ASSIGNMENT if not old_counselor else CallSlipAssignmentChangeTypeChoices.REASSIGNMENT,
            changed_at=timezone.now(),
        )

    # Schedule history
    change_type = CallSlipScheduleChangeTypeChoices.INITIAL_ISSUE if is_initial else CallSlipScheduleChangeTypeChoices.REISSUE
    CallSlipScheduleHistory.objects.create(
        call_slip=slip,
        change_type=change_type,
        previous_start_at=old_start,
        previous_end_at=old_end,
        previous_expected_duration_minutes=old_duration,
        new_start_at=start_at,
        new_end_at=end_at,
        new_expected_duration_minutes=duration,
        previous_counselor=old_counselor,
        new_counselor=slip.assigned_counselor,
        actor=actor,
        reason_code=CallSlipWorkflowReasonChoices.WORKFLOW_PROGRESSION,
        changed_at=timezone.now(),
        availability_blocking_before=bool(not is_initial and old_counselor and slip.purpose_code in COUNSELOR_TIME_PURPOSES),
        availability_blocking_after=bool(slip.assigned_counselor and slip.purpose_code in COUNSELOR_TIME_PURPOSES),
    )

    # Audit
    _audit_event("CALL_SLIP_ISSUE", actor, slip, {
        "status": slip.status,
        "schedule_changed": True,
        "from_coarse_schedule": _get_coarse_schedule_bucket(old_start),
        "to_coarse_schedule": _get_coarse_schedule_bucket(start_at),
    })
    _audit_event("CALL_SLIP_SCHEDULE_CHANGE", actor, slip, {
        "status": slip.status,
        "schedule_changed": True,
        "from_coarse_schedule": _get_coarse_schedule_bucket(old_start),
        "to_coarse_schedule": _get_coarse_schedule_bucket(start_at),
    })

    from apps.call_slips.notification_services import enqueue_call_slip_event
    enqueue_call_slip_event("issued", slip)

    return slip


@transaction.atomic
def acknowledge_call_slip(student, reference_code) -> CallSlip:
    # Row lock
    slip = _get_slip(reference_code)

    if slip.status == CallSlipStatusChoices.ACKNOWLEDGED:
        if is_student(student) and owns_user(student, slip.student_id):
            return slip
        raise PermissionDeniedError("You do not have permission to acknowledge this call slip.")

    from apps.call_slips.policies import can_acknowledge_call_slip
    if not can_acknowledge_call_slip(student, slip):
        raise PermissionDeniedError("You do not have permission to acknowledge this call slip.")

    slip.status = CallSlipStatusChoices.ACKNOWLEDGED
    slip.acknowledged_at = timezone.now()
    slip.acknowledged_by = student
    slip.full_clean()
    slip.save(update_fields=["status", "acknowledged_at", "acknowledged_by", "updated_at"])

    CallSlipStatusHistory.objects.create(
        call_slip=slip,
        from_status=CallSlipStatusChoices.ISSUED,
        to_status=CallSlipStatusChoices.ACKNOWLEDGED,
        actor=student,
        reason_code=CallSlipWorkflowReasonChoices.WORKFLOW_PROGRESSION,
        transitioned_at=timezone.now(),
    )

    # Audit
    _audit_event("CALL_SLIP_ACKNOWLEDGE", student, slip, {
        "status": slip.status,
        "own_record": True,
    })

    return slip


@transaction.atomic
def request_call_slip_reschedule(student, reference_code, command: CallSlipRescheduleCommand, request_key) -> CallSlipRescheduleRequest:
    if not isinstance(command, CallSlipRescheduleCommand):
        raise ValidationError("Reschedule requests require a CallSlipRescheduleCommand.")
    request_key = validate_and_lock_request_key(RequestKeyPolicy("call_slips.reschedule", max_length=100), request_key)
    # Row lock CallSlip
    slip = _get_slip(reference_code)

    # Same-key retries must remain reachable after the first request changes the
    # parent status. Authorize exact ownership before any confidential compare.
    existing = CallSlipRescheduleRequest.objects.defer(*RESCHEDULE_CONFIDENTIAL_FIELDS).filter(
        call_slip=slip, request_key=request_key
    ).first()
    if existing:
        owns_request = bool(
            is_student(student)
            and owns_user(student, slip.student_id)
            and owns_user(student, existing.student_id)
        )
        if not owns_request:
            raise PermissionDeniedError("You do not have permission to request a reschedule for this call slip.")
        try:
            stored_reason = read_owned_request_for_retry(student, existing)
        except CallSlipEncryptionError:
            stored_reason = None
        same_payload = (
            existing.proposed_start_at == command.proposed_start_at
            and existing.proposed_end_at == command.proposed_end_at
            and existing.proposed_expected_duration_minutes == command.proposed_expected_duration_minutes
            and stored_reason == command.student_reason
        )
        if same_payload:
            return existing
        raise ValidationError("This request key is already in use.")

    from apps.call_slips.policies import can_request_reschedule
    if not can_request_reschedule(student, slip):
        raise PermissionDeniedError("You do not have permission to request a reschedule for this call slip.")

    # Conditional unique check for PENDING requests
    has_pending = CallSlipRescheduleRequest.objects.filter(call_slip=slip, status=CallSlipRescheduleRequestStatusChoices.PENDING).exists()
    if has_pending:
        raise ValidationError("There is already a pending reschedule request for this call slip.")

    old_status = slip.status

    req = CallSlipRescheduleRequest(
        call_slip=slip,
        student=student,
        previous_status_snapshot=old_status,
        previous_start_at=slip.scheduled_start_at,
        previous_end_at=slip.scheduled_end_at,
        previous_expected_duration_minutes=slip.expected_duration_minutes,
        proposed_start_at=command.proposed_start_at,
        proposed_end_at=command.proposed_end_at,
        proposed_expected_duration_minutes=command.proposed_expected_duration_minutes,
        student_reason=command.student_reason,
        request_key=request_key,
        status=CallSlipRescheduleRequestStatusChoices.PENDING,
    )
    initialize_group(req, CS_RESCHEDULE_REQUEST, command.student_reason)
    req.full_clean()
    req.save(force_insert=True)

    # Update slip status
    slip.status = CallSlipStatusChoices.RESCHEDULE_REQUESTED
    slip.full_clean()
    slip.save(update_fields=["status", "updated_at"])

    # Status history
    CallSlipStatusHistory.objects.create(
        call_slip=slip,
        from_status=old_status,
        to_status=CallSlipStatusChoices.RESCHEDULE_REQUESTED,
        actor=student,
        reason_code=CallSlipWorkflowReasonChoices.SCHEDULE_CHANGE,
        transitioned_at=timezone.now(),
        request_key=request_key,
    )

    # Audit
    _audit_event("CALL_SLIP_RESCHEDULE_REQUEST", student, slip, {
        "status": slip.status,
        "own_record": True,
        "from_coarse_schedule": _get_coarse_schedule_bucket(slip.scheduled_start_at),
        "to_coarse_schedule": _get_coarse_schedule_bucket(req.proposed_start_at),
    })

    return req


@transaction.atomic
def decide_call_slip_reschedule(actor, request_id, command: CallSlipDecisionCommand) -> CallSlipRescheduleRequest:
    if not isinstance(command, CallSlipDecisionCommand):
        raise ValidationError("Reschedule decisions require a CallSlipDecisionCommand.")
    # Global lock order: parent CallSlip, then the exact request.
    request_snapshot = CallSlipRescheduleRequest.objects.only("call_slip_id").filter(pk=str(request_id)).first()
    if request_snapshot is None:
        raise NotFoundError()
    parent = CallSlip.objects.filter(pk=request_snapshot.call_slip_id).values_list("reference_code", flat=True).first()
    if not parent:
        raise NotFoundError()
    slip = _get_slip(parent)
    request = (
        CallSlipRescheduleRequest.objects.select_for_update()
        .defer(*RESCHEDULE_CONFIDENTIAL_FIELDS)
        .get(pk=str(request_id), call_slip_id=slip.pk)
    )
    request.call_slip = slip

    from apps.call_slips.policies import can_decide_reschedule
    if not can_decide_reschedule(actor, request):
        raise PermissionDeniedError("You do not have permission to decide on this reschedule request.")

    if request.status != CallSlipRescheduleRequestStatusChoices.PENDING:
        raise ValidationError("This reschedule request is already decided.")

    snapshot_matches = (
        slip.status == CallSlipStatusChoices.RESCHEDULE_REQUESTED
        and slip.scheduled_start_at == request.previous_start_at
        and slip.scheduled_end_at == request.previous_end_at
        and slip.expected_duration_minutes == request.previous_expected_duration_minutes
    )
    if not snapshot_matches:
        raise ValidationError("This reschedule request is stale.")

    status_choice = command.decision
    decision_code = command.decision_code
    decision_detail = command.decision_detail

    old_status = slip.status
    old_start = slip.scheduled_start_at
    old_end = slip.scheduled_end_at
    old_duration = slip.expected_duration_minutes

    if status_choice == CallSlipRescheduleRequestStatusChoices.APPROVED:
        # Re-check availability conflicts before commit
        if slip.purpose_code in COUNSELOR_TIME_PURPOSES and slip.assigned_counselor:
            check_counselor_conflicts(
                slip.assigned_counselor,
                request.proposed_start_at,
                request.proposed_end_at,
                exclude_slip=slip
            )

    request.status = status_choice
    request.decider = actor
    request.decided_at = timezone.now()
    request.decision_code = decision_code
    confidential_fields = prepare_group_write(request, CS_RESCHEDULE_DECISION, decision_detail)
    request.full_clean()
    request.save(update_fields=[
        "status", "decider", "decided_at", "decision_code",
        *confidential_fields, "updated_at",
    ])

    if status_choice == CallSlipRescheduleRequestStatusChoices.APPROVED:
        slip.scheduled_start_at = request.proposed_start_at
        slip.scheduled_end_at = request.proposed_end_at
        slip.expected_duration_minutes = request.proposed_expected_duration_minutes
        slip.status = CallSlipStatusChoices.ISSUED
        slip.acknowledged_at = None
        slip.acknowledged_by = None
        slip.updated_by = actor
        slip.full_clean()
        slip.save(update_fields=[
            "scheduled_start_at", "scheduled_end_at", "expected_duration_minutes",
            "status", "acknowledged_at", "acknowledged_by", "updated_by", "updated_at",
        ])

        # Status history
        CallSlipStatusHistory.objects.create(
            call_slip=slip,
            from_status=old_status,
            to_status=CallSlipStatusChoices.ISSUED,
            actor=actor,
            reason_code=decision_code,
            transitioned_at=timezone.now(),
        )

        # Schedule history
        CallSlipScheduleHistory.objects.create(
            call_slip=slip,
            change_type=CallSlipScheduleChangeTypeChoices.RESCHEDULE_APPROVED,
            previous_start_at=old_start,
            previous_end_at=old_end,
            previous_expected_duration_minutes=old_duration,
            new_start_at=slip.scheduled_start_at,
            new_end_at=slip.scheduled_end_at,
            new_expected_duration_minutes=slip.expected_duration_minutes,
            previous_counselor=slip.assigned_counselor,
            new_counselor=slip.assigned_counselor,
            actor=actor,
            reason_code=decision_code,
            changed_at=timezone.now(),
            availability_blocking_before=bool(slip.assigned_counselor and slip.purpose_code in COUNSELOR_TIME_PURPOSES),
            availability_blocking_after=bool(slip.assigned_counselor and slip.purpose_code in COUNSELOR_TIME_PURPOSES),
        )

    else:  # DECLINED
        slip.status = request.previous_status_snapshot
        slip.updated_by = actor
        slip.full_clean()
        slip.save(update_fields=["status", "updated_by", "updated_at"])

        # Status history
        CallSlipStatusHistory.objects.create(
            call_slip=slip,
            from_status=old_status,
            to_status=slip.status,
            actor=actor,
            reason_code=decision_code,
            transitioned_at=timezone.now(),
        )

    # Audit
    _audit_event("CALL_SLIP_RESCHEDULE_DECISION", actor, slip, {
        "status": slip.status,
        "decision": status_choice,
        "decision_code": decision_code,
    })
    if status_choice == CallSlipRescheduleRequestStatusChoices.APPROVED:
        _audit_event("CALL_SLIP_SCHEDULE_CHANGE", actor, slip, {
            "status": slip.status,
            "schedule_changed": True,
            "from_coarse_schedule": _get_coarse_schedule_bucket(old_start),
            "to_coarse_schedule": _get_coarse_schedule_bucket(slip.scheduled_start_at),
        })

    from apps.call_slips.notification_services import enqueue_call_slip_event
    enqueue_call_slip_event("rescheduled", slip)

    return request


@transaction.atomic
def record_call_slip_attendance(actor, reference_code, command: CallSlipAttendanceCommand) -> CallSlip:
    if not isinstance(command, CallSlipAttendanceCommand):
        raise ValidationError("Attendance recording requires a CallSlipAttendanceCommand.")
    # Row lock
    slip = _get_slip(reference_code)

    from apps.call_slips.policies import can_record_attendance
    if not can_record_attendance(actor, slip):
        raise PermissionDeniedError("You do not have permission to record attendance for this call slip.")

    # Reschedule request pending validation
    has_pending = CallSlipRescheduleRequest.objects.filter(call_slip=slip, status=CallSlipRescheduleRequestStatusChoices.PENDING).exists()
    if has_pending:
        raise ValidationError("Cannot record attendance while a reschedule request is pending.")

    # Time validation: Cannot attend before scheduled start
    now = timezone.now()
    if slip.scheduled_start_at and now < slip.scheduled_start_at:
        raise ValidationError("Cannot record attendance before the scheduled start time.")

    old_status = slip.status

    slip.status = CallSlipStatusChoices.ATTENDED
    slip.reported_at = command.reported_at if command.has("reported_at") else now
    slip.attendance_recorded_at = now
    slip.attendance_recorded_by = actor
    slip.interview_ended_at = command.interview_ended_at if command.has("interview_ended_at") else None
    slip.full_clean()
    slip.save(update_fields=[
        "status", "reported_at", "attendance_recorded_at",
        "attendance_recorded_by", "interview_ended_at", "updated_at",
    ])

    CallSlipStatusHistory.objects.create(
        call_slip=slip,
        from_status=old_status,
        to_status=CallSlipStatusChoices.ATTENDED,
        actor=actor,
        reason_code=CallSlipWorkflowReasonChoices.WORKFLOW_PROGRESSION,
        transitioned_at=now,
    )

    # Audit
    _audit_event("CALL_SLIP_ATTENDANCE", actor, slip, {"status": slip.status})

    from apps.orchestration.commands import FeedbackInvitationCommand
    from apps.orchestration.use_cases import issue_feedback_invitation_for_completed_source

    issue_feedback_invitation_for_completed_source(
        actor,
        FeedbackInvitationCommand("call_slip", str(slip.pk))
    )
    from apps.call_slips.notification_services import enqueue_call_slip_event
    enqueue_call_slip_event("completed", slip)
    return slip


@transaction.atomic
def mark_call_slip_no_show(actor, reference_code, command: CallSlipReasonCommand) -> CallSlip:
    if not isinstance(command, CallSlipReasonCommand):
        raise ValidationError("No-show requires a CallSlipReasonCommand.")
    # Row lock
    slip = _get_slip(reference_code)

    from apps.call_slips.policies import can_mark_no_show
    if not can_mark_no_show(actor, slip):
        raise PermissionDeniedError("You do not have permission to mark this call slip as no-show.")

    # Reschedule request pending validation
    has_pending = CallSlipRescheduleRequest.objects.filter(call_slip=slip, status=CallSlipRescheduleRequestStatusChoices.PENDING).exists()
    if has_pending:
        raise ValidationError("Cannot mark no-show while a reschedule request is pending.")

    # Time validation: grace period checks (15 minutes by default)
    # The start time must have passed
    now = timezone.now()
    if slip.scheduled_start_at and now < slip.scheduled_start_at + datetime.timedelta(minutes=15):
        raise ValidationError("Cannot record no-show before the 15-minute grace period has elapsed.")

    old_status = slip.status

    slip.status = CallSlipStatusChoices.NO_SHOW
    slip.no_show_at = now
    slip.no_show_by = actor
    slip.no_show_reason_code = command.reason_code
    confidential_fields = prepare_group_write(slip, CS_NO_SHOW, command.detail)
    slip.full_clean()
    slip.save(update_fields=[
        "status", "no_show_at", "no_show_by", "no_show_reason_code",
        *confidential_fields, "updated_at",
    ])

    CallSlipStatusHistory.objects.create(
        call_slip=slip,
        from_status=old_status,
        to_status=CallSlipStatusChoices.NO_SHOW,
        actor=actor,
        reason_code=command.reason_code,
        transitioned_at=now,
    )

    # Audit
    _audit_event("CALL_SLIP_NO_SHOW", actor, slip, {
        "status": slip.status,
        "reason_code": command.reason_code,
    })

    from apps.call_slips.notification_services import enqueue_call_slip_event
    enqueue_call_slip_event("no_show", slip)

    return slip


@transaction.atomic
def expire_call_slip(actor, reference_code, command: CallSlipReasonCommand) -> CallSlip:
    if not isinstance(command, CallSlipReasonCommand):
        raise ValidationError("Expiry requires a CallSlipReasonCommand.")
    # Row lock
    slip = _get_slip(reference_code)

    from apps.call_slips.policies import can_expire_call_slip
    if not can_expire_call_slip(actor, slip):
        raise PermissionDeniedError("You do not have permission to expire this call slip.")

    # Reschedule request pending validation
    has_pending = CallSlipRescheduleRequest.objects.filter(call_slip=slip, status=CallSlipRescheduleRequestStatusChoices.PENDING).exists()
    if has_pending:
        raise ValidationError("Cannot expire call slip while a reschedule request is pending.")

    # Time validation: scheduled end must have passed
    now = timezone.now()
    if slip.scheduled_end_at and now < slip.scheduled_end_at:
        raise ValidationError("Cannot expire call slip before the scheduled end time.")

    old_status = slip.status

    slip.status = CallSlipStatusChoices.EXPIRED
    slip.expired_at = now
    slip.expired_by = actor
    slip.expiry_reason_code = command.reason_code
    slip.full_clean()
    slip.save(update_fields=["status", "expired_at", "expired_by", "expiry_reason_code", "updated_at"])

    CallSlipStatusHistory.objects.create(
        call_slip=slip,
        from_status=old_status,
        to_status=CallSlipStatusChoices.EXPIRED,
        actor=actor,
        reason_code=command.reason_code,
        transitioned_at=now,
    )

    # Audit
    _audit_event("CALL_SLIP_EXPIRE", actor, slip, {
        "status": slip.status,
        "reason_code": command.reason_code,
    })

    from apps.call_slips.notification_services import enqueue_call_slip_event
    enqueue_call_slip_event("expired", slip)

    return slip


@transaction.atomic
def cancel_call_slip(actor, reference_code, command: CallSlipReasonCommand) -> CallSlip:
    if not isinstance(command, CallSlipReasonCommand):
        raise ValidationError("Cancellation requires a CallSlipReasonCommand.")
    # Row lock
    slip = _get_slip(reference_code)

    from apps.call_slips.policies import can_cancel_call_slip
    if not can_cancel_call_slip(actor, slip):
        raise PermissionDeniedError("You do not have permission to cancel this call slip.")

    # If there's a pending reschedule request, decline it atomically
    pending_request = CallSlipRescheduleRequest.objects.select_for_update().defer(*RESCHEDULE_CONFIDENTIAL_FIELDS).filter(
        call_slip=slip,
        status=CallSlipRescheduleRequestStatusChoices.PENDING,
    ).first()
    if pending_request:
        if not can_cancel_call_slip(actor, slip):
            raise PermissionDeniedError("You do not have permission to cancel this call slip.")
        snapshot_matches = (
            slip.status == CallSlipStatusChoices.RESCHEDULE_REQUESTED
            and slip.scheduled_start_at == pending_request.previous_start_at
            and slip.scheduled_end_at == pending_request.previous_end_at
            and slip.expected_duration_minutes == pending_request.previous_expected_duration_minutes
        )
        if not snapshot_matches:
            raise ValidationError("The pending reschedule request is stale.")
        pending_request.status = CallSlipRescheduleRequestStatusChoices.DECLINED
        pending_request.decider = actor
        pending_request.decided_at = timezone.now()
        pending_request.decision_code = CallSlipWorkflowReasonChoices.STUDENT_REQUEST_DECLINED
        decision_fields = prepare_group_write(
            pending_request,
            CS_RESCHEDULE_DECISION,
            "Decline due to call slip cancellation.",
        )
        pending_request.full_clean()
        pending_request.save(update_fields=[
            "status", "decider", "decided_at", "decision_code",
            *decision_fields, "updated_at",
        ])

    old_status = slip.status
    old_start = slip.scheduled_start_at
    old_end = slip.scheduled_end_at
    old_duration = slip.expected_duration_minutes
    old_counselor = slip.assigned_counselor

    slip.status = CallSlipStatusChoices.CANCELLED
    slip.cancelled_at = timezone.now()
    slip.cancelled_by = actor
    slip.cancel_reason_code = command.reason_code
    confidential_fields = prepare_group_write(slip, CS_CANCELLATION, command.detail)
    slip.full_clean()
    slip.save(update_fields=[
        "status", "cancelled_at", "cancelled_by", "cancel_reason_code",
        *confidential_fields, "updated_at",
    ])

    # Status history
    CallSlipStatusHistory.objects.create(
        call_slip=slip,
        from_status=old_status,
        to_status=CallSlipStatusChoices.CANCELLED,
        actor=actor,
        reason_code=command.reason_code,
        transitioned_at=timezone.now(),
    )

    # Schedule history for cancellation if ever issued to release the block
    if old_status in EVER_ISSUED_STATUSES:
        CallSlipScheduleHistory.objects.create(
            call_slip=slip,
            change_type=CallSlipScheduleChangeTypeChoices.CANCELLATION,
            previous_start_at=old_start,
            previous_end_at=old_end,
            previous_expected_duration_minutes=old_duration,
            new_start_at=None,
            new_end_at=None,
            new_expected_duration_minutes=None,
            previous_counselor=old_counselor,
            new_counselor=None,
            actor=actor,
            reason_code=command.reason_code,
            changed_at=timezone.now(),
            availability_blocking_before=bool(old_counselor and slip.purpose_code in COUNSELOR_TIME_PURPOSES),
            availability_blocking_after=False,
        )

    # Audit
    _audit_event("CALL_SLIP_CANCEL", actor, slip, {
        "status": slip.status,
        "reason_code": command.reason_code,
    })
    if old_status in EVER_ISSUED_STATUSES:
        _audit_event("CALL_SLIP_SCHEDULE_CHANGE", actor, slip, {
            "status": slip.status,
            "schedule_changed": False,
            "availability_blocking": False,
        })

    from apps.call_slips.notification_services import enqueue_call_slip_event
    enqueue_call_slip_event("cancelled", slip)

    return slip
