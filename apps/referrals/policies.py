# Project: COMPASS
# File: apps/referrals/policies.py
# Module: apps.referrals
# Purpose: Deny-by-default target-aware referral authorization policies.
# Domain boundary and service policy.

from apps.access_control.authority import has_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import is_active_nonlegacy_actor, is_counselor, is_gco_staff
from apps.access_control.scopes import (
    counselor_has_live_coverage_for_student,
    get_active_workflow_authority_grants,
    get_live_counselor_coverages,
    workflow_authority_authorizes_record,
)
from apps.accounts.models import RoleChoices
from apps.referrals.models import ReferralActionCodeChoices, ReferralStatusChoices


STAFF_ACTION_CODES = {
    ReferralActionCodeChoices.PARENT_CONTACT_ATTEMPTED,
    ReferralActionCodeChoices.PARENT_NOTIFICATION_RECORDED,
    ReferralActionCodeChoices.CALL_SLIP_NEEDED,
    ReferralActionCodeChoices.INTERVIEW_SCHEDULING_NEEDED,
    ReferralActionCodeChoices.MONITORING_RECORDED,
    ReferralActionCodeChoices.HEAD_REVIEW_REQUESTED,
}
COUNSELOR_ACTION_CODES = set(ReferralActionCodeChoices.values)
STAFF_INTAKE_STATUSES = {
    ReferralStatusChoices.DRAFT,
    ReferralStatusChoices.SUBMITTED,
    ReferralStatusChoices.RECEIVED,
}
TERMINAL_STATUSES = {
    ReferralStatusChoices.CLOSED,
    ReferralStatusChoices.CANCELLED,
}


def _active(user):
    return is_active_nonlegacy_actor(user)


def _valid_student(student):
    return bool(_active(student) and student.role == RoleChoices.STUDENT and hasattr(student, "student_profile"))


def _active_counselor(user):
    return bool(_active(user) and is_counselor(user))


def has_counselor_coverage_for_student(user, student):
    if not _active_counselor(user) or not _valid_student(student):
        return False
    return counselor_has_live_coverage_for_student(user, student.student_profile)


def _workflow_grant_matches(user, student, assigned_counselor=None, capability=Capability.REFERRALS_QUEUE_PROCESS):
    if not _active(user) or not is_gco_staff(user) or not _valid_student(student):
        return False
    return workflow_authority_authorizes_record(
        user, capability=capability,
        student_profile=student.student_profile,
        assigned_counselor=assigned_counselor,
    )


def can_create_referral_draft(user, target_student):
    if not _active(user) or not _valid_student(target_student):
        return False
    if has_capability(user, Capability.REFERRALS_INTAKE, target=target_student.student_profile):
        return True
    if is_counselor(user):
        return has_counselor_coverage_for_student(user, target_student)
    if is_gco_staff(user):
        return _workflow_grant_matches(user, target_student, capability=Capability.REFERRALS_INTAKE)
    return False

def can_view_referral_safe_metadata(user, referral):
    if not _active(user) or referral is None or not _valid_student(getattr(referral, "student", None)):
        return False
    if has_capability(user, Capability.REFERRALS_QUEUE_PROCESS, target=referral.student.student_profile):
        return True
    if is_counselor(user):
        if referral.assigned_counselor_id:
            return referral.assigned_counselor_id == user.pk
        return has_counselor_coverage_for_student(user, referral.student)
    if is_gco_staff(user):
        return _workflow_grant_matches(user, referral.student, referral.assigned_counselor)
    return False


def can_view_referral_queue(user):
    if not _active(user):
        return False
    if has_capability(user, Capability.REFERRALS_QUEUE_PROCESS):
        return True
    if is_counselor(user):
        has_live_coverage = get_live_counselor_coverages(user).exists()
        return has_live_coverage or user.assigned_referrals.exists()
    if is_gco_staff(user):
        return get_active_workflow_authority_grants(user, capability=Capability.REFERRALS_QUEUE_PROCESS).exists()
    return False


def can_view_referral_sensitive_detail(user, referral, purpose="detail"):
    if not can_view_referral_safe_metadata(user, referral):
        return False
    if is_gco_staff(user):
        if purpose == "detail":
            return True
        return referral.status in STAFF_INTAKE_STATUSES and purpose in {"intake", "receive", "route"}
    return is_counselor(user)


def can_view_referral_submission_narrative(user, referral):
    """Authorize only the submission narrative, never another referral group."""
    if not can_view_referral_safe_metadata(user, referral):
        return False
    if is_gco_staff(user):
        return referral.status in STAFF_INTAKE_STATUSES
    return bool(is_counselor(user))


def can_view_referral_action_narrative(user, action):
    """Action remarks are counselor/Head content; staff get metadata redaction."""
    referral = getattr(action, "referral", None)
    return bool(
        referral is not None
        and is_counselor(user)
        and can_view_referral_safe_metadata(user, referral)
    )


def can_submit_referral(user, referral):
    return referral.status == ReferralStatusChoices.DRAFT and can_view_referral_safe_metadata(user, referral)


def can_receive_referral(user, referral):
    return referral.status == ReferralStatusChoices.SUBMITTED and can_view_referral_safe_metadata(user, referral)


def can_begin_referral_review(user, referral):
    if not (is_counselor(user) and can_view_referral_safe_metadata(user, referral)):
        return False
    if referral.status == ReferralStatusChoices.ESCALATED:
        return has_capability(user, Capability.REFERRALS_QUEUE_PROCESS, target=referral.student.student_profile)
    return referral.status in {ReferralStatusChoices.RECEIVED, ReferralStatusChoices.ACTION_REQUIRED}


def can_add_referral_action(user, referral, action_code=None):
    if referral.status == ReferralStatusChoices.DRAFT or referral.status in TERMINAL_STATUSES:
        return False
    if not can_view_referral_safe_metadata(user, referral):
        return False
    if is_gco_staff(user):
        return action_code in STAFF_ACTION_CODES and _workflow_grant_matches(
            user, referral.student, referral.assigned_counselor,
            capability=Capability.REFERRALS_ROUTE,
        )
    return bool(is_counselor(user) and action_code in COUNSELOR_ACTION_CODES)


def can_set_referral_action_required(user, referral):
    return bool(is_counselor(user) and can_view_referral_safe_metadata(user, referral) and referral.status in {ReferralStatusChoices.UNDER_REVIEW, ReferralStatusChoices.ACTION_REQUIRED})


def can_request_referral_reassignment(user, referral):
    return bool(
        is_counselor(user)
        and can_view_referral_safe_metadata(user, referral)
        and referral.assigned_counselor_id
        and (
            referral.assigned_counselor_id == user.pk
            or has_capability(user, Capability.REFERRALS_REASSIGN, target=referral.student.student_profile)
        )
        and referral.status not in TERMINAL_STATUSES
    )


def can_decide_referral_reassignment(user, request):
    return bool(
        _active(user)
        and request.status == "PENDING"
        and has_capability(user, Capability.REFERRALS_REASSIGN, target=request.referral.student.student_profile)
    )


def can_assign_referral(user, referral, target=None):
    if not (_active(user) and referral is not None and _valid_student(getattr(referral, "student", None)) and has_capability(user, Capability.REFERRALS_ASSIGN, target=referral.student.student_profile)):
        return False
    if referral.status in TERMINAL_STATUSES:
        return False
    if target is None:
        return True
    return _active_counselor(target)


def can_reassign_referral(user, referral, target=None):
    if referral is None or not _valid_student(getattr(referral, "student", None)) or referral.status in TERMINAL_STATUSES or not _active(user):
        return False
    if not has_capability(user, Capability.REFERRALS_REASSIGN, target=referral.student.student_profile):
        return False
    return target is None or _active_counselor(target)


def can_escalate_referral(user, referral):
    return bool(is_counselor(user) and can_view_referral_safe_metadata(user, referral) and referral.status in {ReferralStatusChoices.UNDER_REVIEW, ReferralStatusChoices.ACTION_REQUIRED})


def can_close_referral(user, referral):
    if not (is_counselor(user) and can_view_referral_safe_metadata(user, referral)):
        return False
    if referral.status == ReferralStatusChoices.ESCALATED:
        return has_capability(user, Capability.REFERRALS_CLOSE, target=referral.student.student_profile)
    if has_capability(user, Capability.REFERRALS_CLOSE, target=referral.student.student_profile):
        return referral.status in {ReferralStatusChoices.UNDER_REVIEW, ReferralStatusChoices.ACTION_REQUIRED}
    return bool(
        referral.assigned_counselor_id == getattr(user, "pk", None)
        and referral.status in {ReferralStatusChoices.UNDER_REVIEW, ReferralStatusChoices.ACTION_REQUIRED}
    )


def can_cancel_referral(user, referral):
    if not can_view_referral_safe_metadata(user, referral) or referral.status == ReferralStatusChoices.CANCELLED:
        return False
    if has_capability(user, Capability.REFERRALS_CANCEL, target=referral.student.student_profile):
        return referral.status != ReferralStatusChoices.CLOSED
    return referral.status in STAFF_INTAKE_STATUSES


def can_reopen_referral(user, referral):
    return bool(
        _active(user)
        and referral.status == ReferralStatusChoices.CLOSED
        and has_capability(user, Capability.REFERRALS_REOPEN, target=referral.student.student_profile)
    )
