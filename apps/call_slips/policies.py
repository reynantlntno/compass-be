# Project: COMPASS
# File: apps/call_slips/policies.py
# Module: apps.call_slips
# Purpose: Deny-by-default target-aware call slip authorization policies.
# Domain boundary and service policy.

from apps.access_control.authority import has_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import (
    is_active_nonlegacy_actor,
    is_counselor,
    is_gco_staff,
    is_student,
    owns_user,
)
from apps.access_control.scopes import (
    counselor_has_live_coverage_for_student,
    get_active_workflow_authority_grants,
    get_live_counselor_coverages,
    workflow_authority_authorizes_record,
)
from apps.call_slips.models import CallSlipStatusChoices, EVER_ISSUED_STATUSES, TERMINAL_STATUSES


REFERRAL_CALL_SLIP_ELIGIBLE_STATUSES = {
    "SUBMITTED", "RECEIVED", "UNDER_REVIEW", "ACTION_REQUIRED", "ESCALATED",
}
REFERRAL_CALL_SLIP_REISSUE_STATUSES = {
    CallSlipStatusChoices.NO_SHOW,
    CallSlipStatusChoices.EXPIRED,
    CallSlipStatusChoices.CANCELLED,
}


def _active(user):
    return is_active_nonlegacy_actor(user)


def _valid_student(student):
    return bool(_active(student) and is_student(student) and hasattr(student, "student_profile"))


def _active_counselor(user):
    return bool(_active(user) and is_counselor(user))


def has_counselor_coverage_for_student(user, student):
    if not _active_counselor(user) or not _valid_student(student):
        return False
    return counselor_has_live_coverage_for_student(user, student.student_profile)


def _workflow_grant_matches(user, student, assigned_counselor=None):
    if not _active(user) or not is_gco_staff(user) or not _valid_student(student):
        return False
    return workflow_authority_authorizes_record(
        user, capability=Capability.CALL_SLIPS_PREPARE,
        student_profile=student.student_profile,
        assigned_counselor=assigned_counselor,
    )


def can_view_call_slip_queue(user):
    if not _active(user):
        return False
    if has_capability(user, Capability.CALL_SLIPS_PREPARE):
        return True
    if is_counselor(user):
        has_live_coverage = get_live_counselor_coverages(user).exists()
        return has_live_coverage or user.assigned_call_slips.exists()
    if is_gco_staff(user):
        return get_active_workflow_authority_grants(user, capability=Capability.CALL_SLIPS_PREPARE).exists()
    return False

def can_create_call_slip_draft(user, target_student):
    if not _active(user) or not _valid_student(target_student):
        return False
    if has_capability(user, Capability.CALL_SLIPS_PREPARE, target=target_student.student_profile):
        return True
    if is_counselor(user):
        return has_counselor_coverage_for_student(user, target_student)
    if is_gco_staff(user):
        return _workflow_grant_matches(user, target_student)
    return False


def can_create_call_slip_from_referral(user, referral):
    if not _active(user) or not referral or referral.status not in REFERRAL_CALL_SLIP_ELIGIBLE_STATUSES:
        return False
    # Head Guidance may create the linked draft for every eligible Referral;
    # the action marker is operational evidence for scoped staff/counselor
    # workflows, not a reason to exclude Head Guidance.
    if has_capability(user, Capability.CALL_SLIPS_PREPARE, target=referral.student.student_profile):
        return True
    if is_counselor(user):
        if referral.assigned_counselor_id:
            return referral.assigned_counselor_id == getattr(user, "pk", None)
        return has_counselor_coverage_for_student(user, referral.student)
    if is_gco_staff(user):
        # Staff must hold both workflow scopes: the Referral policy check
        # proves Referral Processing assignment, while this check proves
        # Call Slip Preparation assignment.
        from apps.referrals.policies import can_view_referral_safe_metadata
        if not can_view_referral_safe_metadata(user, referral):
            return False
        return _workflow_grant_matches(
            user, referral.student, referral.assigned_counselor
        )
    return False


def can_reissue_referral_call_slip(user, call_slip):
    return bool(
        call_slip
        and call_slip.referral_id
        and call_slip.status in REFERRAL_CALL_SLIP_REISSUE_STATUSES
        and can_create_call_slip_from_referral(user, call_slip.referral)
        and can_view_call_slip_sensitive_detail(user, call_slip)
    )


def can_view_call_slip_sensitive_detail(user, call_slip):
    student = getattr(call_slip, "student", None) if call_slip is not None else None
    if not _active(user) or not _valid_student(student):
        return False
    # If the user is the student owner: they do NOT have sensitive operational access
    if is_student(user):
        return False
    if has_capability(user, Capability.CALL_SLIPS_PREPARE, target=student.student_profile):
        return True
    if is_counselor(user):
        # Assigned counselor gets access
        if call_slip.assigned_counselor_id == user.pk:
            return True
        # If explicitly assigned to another counselor, other counselors have NO coverage access
        if call_slip.assigned_counselor_id and call_slip.assigned_counselor_id != user.pk:
            return False
        # If unassigned, coverage counselor has access
        return has_counselor_coverage_for_student(user, student)
    if is_gco_staff(user):
        return _workflow_grant_matches(user, student, call_slip.assigned_counselor)
    return False


def can_update_call_slip_draft(user, call_slip):
    if call_slip.status != CallSlipStatusChoices.DRAFT:
        return False
    if not _active(user):
        return False
    if has_capability(user, Capability.CALL_SLIPS_PREPARE, target=call_slip.student.student_profile):
        return True
    if is_counselor(user):
        if call_slip.assigned_counselor_id:
            return call_slip.assigned_counselor_id == user.pk
        return has_counselor_coverage_for_student(user, call_slip.student)
    if is_gco_staff(user):
        return _workflow_grant_matches(user, call_slip.student, call_slip.assigned_counselor)
    return False


def can_assign_call_slip(user, call_slip, target=None):
    if call_slip.status in TERMINAL_STATUSES:
        return False
    if not _active(user):
        return False
    # Staff cannot assign or reassign
    if is_gco_staff(user):
        return False
    if not has_capability(user, Capability.CALL_SLIPS_ASSIGN, target=call_slip):
        return False
    if target is None:
        return True
    return _active_counselor(target)


def can_reassign_call_slip(user, call_slip, target=None):
    return can_assign_call_slip(user, call_slip, target)


def can_issue_call_slip(user, call_slip):
    if call_slip.status != CallSlipStatusChoices.DRAFT:
        return False
    if not _active(user):
        return False
    if has_capability(user, Capability.CALL_SLIPS_ISSUE, target=call_slip.student.student_profile):
        return True
    if is_counselor(user):
        if call_slip.assigned_counselor_id:
            return call_slip.assigned_counselor_id == user.pk
        return has_counselor_coverage_for_student(user, call_slip.student)
    if is_gco_staff(user):
        return _workflow_grant_matches(user, call_slip.student, call_slip.assigned_counselor)
    return False


def can_student_view_call_slip(user, call_slip):
    if not _active(user) or not is_student(user):
        return False
    if not owns_user(user, call_slip.student_id):
        return False
    if call_slip.status in EVER_ISSUED_STATUSES:
        return True
    if call_slip.status == CallSlipStatusChoices.CANCELLED:
        return bool(call_slip.issued_at)
    return False


def can_acknowledge_call_slip(user, call_slip):
    if not _active(user) or not is_student(user):
        return False
    if not owns_user(user, call_slip.student_id):
        return False
    return call_slip.status == CallSlipStatusChoices.ISSUED


def can_request_reschedule(user, call_slip):
    if not _active(user) or not is_student(user):
        return False
    if not owns_user(user, call_slip.student_id):
        return False
    return call_slip.status in (CallSlipStatusChoices.ISSUED, CallSlipStatusChoices.ACKNOWLEDGED)


def can_decide_reschedule(user, request):
    if request.status != "PENDING":
        return False
    if request.call_slip.status != CallSlipStatusChoices.RESCHEDULE_REQUESTED:
        return False
    if not _active(user):
        return False
    if has_capability(user, Capability.CALL_SLIPS_RESCHEDULE_DECIDE, target=request.call_slip.student.student_profile):
        return True
    if is_counselor(user):
        return request.call_slip.assigned_counselor_id == user.pk
    if is_gco_staff(user):
        # Staff may process only when matching CALL_SLIP_PREPARATION and current assignment/schedule policy
        return _workflow_grant_matches(user, request.call_slip.student, request.call_slip.assigned_counselor)
    return False


def can_record_attendance(user, call_slip):
    if call_slip.status not in (CallSlipStatusChoices.ISSUED, CallSlipStatusChoices.ACKNOWLEDGED):
        return False
    if not _active(user):
        return False
    if has_capability(user, Capability.CALL_SLIPS_ATTENDANCE_RECORD, target=call_slip.student.student_profile):
        return True
    if is_counselor(user):
        return call_slip.assigned_counselor_id == user.pk
    if is_gco_staff(user):
        return _workflow_grant_matches(user, call_slip.student, call_slip.assigned_counselor)
    return False


def can_mark_no_show(user, call_slip):
    return can_record_attendance(user, call_slip)


def can_expire_call_slip(user, call_slip):
    return can_record_attendance(user, call_slip)


def can_cancel_call_slip(user, call_slip):
    if call_slip.status in TERMINAL_STATUSES:
        return False
    if not _active(user):
        return False
    if has_capability(user, Capability.CALL_SLIPS_CANCEL, target=call_slip.student.student_profile):
        return True
    if is_counselor(user):
        if call_slip.assigned_counselor_id:
            return call_slip.assigned_counselor_id == user.pk
        return has_counselor_coverage_for_student(user, call_slip.student)
    if is_gco_staff(user):
        # Staff can cancel only draft or issued/acknowledged slips they match
        return _workflow_grant_matches(user, call_slip.student, call_slip.assigned_counselor)
    return False
