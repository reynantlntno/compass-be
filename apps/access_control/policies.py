# Project: COMPASS
# File: apps/access_control/policies.py
# Module: apps.access_control
# Purpose: Access control authorization policies
# Domain boundary and service policy.

from enum import Enum

from apps.access_control.rules import (
    is_active_nonlegacy_actor,
    is_counselor,
    is_gco_staff,
    is_it_admin,
    is_student,
    owns_user,
    owns_student_profile,
)
from apps.access_control.authority import has_capability
from apps.access_control.capabilities import Capability
from apps.access_control.scopes import counselor_has_live_coverage_for_student


class DestinationKey(str, Enum):
    """Stable authorization capability keys shared by API policies and reports."""

    APPOINTMENTS = "appointments"
    REFERRALS = "referrals"
    CALL_SLIPS = "call_slips"
    GOOD_MORAL = "good_moral"
    CONTACT = "contact"
    CONTENT = "content"
    REPORTS = "reports"
    EXIT_INTERVIEWS = "exit_interviews"
    GRADUATE_TRACER = "graduate_tracer"
    ASSESSMENTS = "assessments"
    SUPPORT_NEEDS = "support_needs"
    SYSTEM_OPERATIONS = "system_operations"


def can_access_destination(actor, destination_key: str | DestinationKey) -> bool:
    """Resolve one canonical destination capability and fail closed.

    Static registry audiences, command metadata, and signed/reference URLs do
    not grant access.  The module policy is imported lazily so this API can be
    used by every shell without introducing import cycles.
    """
    try:
        key = DestinationKey(destination_key)
    except (TypeError, ValueError):
        return False
    if not actor or not actor.is_authenticated or not actor.is_active or getattr(actor, "is_superuser", False):
        return False
    if key is DestinationKey.SYSTEM_OPERATIONS:
        return has_capability(actor, Capability.SYSTEM_OPERATIONS_MANAGE)

    predicates = {
        DestinationKey.APPOINTMENTS: ("apps.appointments.policies", "can_view_appointment_queue"),
        DestinationKey.REFERRALS: ("apps.referrals.policies", "can_view_referral_queue"),
        DestinationKey.CALL_SLIPS: ("apps.call_slips.policies", "can_view_call_slip_queue"),
        DestinationKey.GOOD_MORAL: ("apps.good_moral.policies", "can_view_review_queue"),
        DestinationKey.CONTACT: ("apps.content.policies", "can_view_contact_queue"),
        DestinationKey.CONTENT: ("apps.content.policies", "can_view_content_workspace"),
        DestinationKey.REPORTS: ("apps.reports.policies", "can_access_reports_destination"),
        DestinationKey.EXIT_INTERVIEWS: ("apps.exit_interviews.selectors", "can_view_exit_review_queue"),
        DestinationKey.GRADUATE_TRACER: ("apps.graduate_tracer.selectors", "can_view_gts_review_queue"),
        DestinationKey.ASSESSMENTS: ("apps.assessments.policies", "can_view_assessment_destination"),
        DestinationKey.SUPPORT_NEEDS: ("apps.support_needs.policies", "has_support_need_scope"),
    }
    module_name, predicate_name = predicates.get(key, (None, None))
    if not module_name:
        return False
    try:
        from importlib import import_module

        predicate = getattr(import_module(module_name), predicate_name)
        return bool(predicate(actor))
    except (ImportError, AttributeError, TypeError, ValueError):
        return False


def can_view_own_profile(user, profile) -> bool:
    """Authorize a user to view their own profile."""
    return bool(
        is_active_nonlegacy_actor(user)
        and profile is not None
        and owns_user(user, getattr(profile, "user_id", None))
    )


def can_view_student_profile(user, student_profile) -> bool:
    """Authorize access to a specific student profile.
    
    Access is granted to:
    - The student owner themselves.
    - Guidance counselors designated as Head Guidance.
    - Guidance counselors whose live coverage scope matches the student's profile.
    - Denied to all others (including IT Admins).
    """
    if not is_active_nonlegacy_actor(user):
        return False

    # 1. Student self-access
    if is_student(user):
        return owns_student_profile(user, student_profile)

    # 2. Counselor access
    if is_counselor(user):
        if has_capability(user, Capability.STUDENT_RECORDS_VIEW_INSTITUTION):
            return True

        return counselor_has_live_coverage_for_student(user, student_profile)

    # 3. GCO Staff access
    if is_gco_staff(user):
        return False

    return False


def can_manage_student_profile_metadata(user, student_profile) -> bool:
    """Authorize administrative modification of student profile metadata.
    
    Students cannot edit their own official metadata.
    Access is granted only to:
    - Head Guidance.
    - Scoped Counselors matching student campus/college/department/program.
    - GCO Staff members assigned to corresponding campus/college/department.
    """
    if not is_active_nonlegacy_actor(user):
        return False

    # Students cannot manage official metadata fields
    if is_student(user):
        return False

    if is_counselor(user):
        if has_capability(user, Capability.STUDENT_RECORDS_VIEW_INSTITUTION):
            return True

        return counselor_has_live_coverage_for_student(user, student_profile)

    if is_gco_staff(user):
        return False

    return False


def can_manage_counselor_coverage(user) -> bool:
    """Authorize management of counselor coverage rules through fixed Head authority."""
    return has_capability(user, Capability.COUNSELOR_COVERAGE_MANAGE)


def can_manage_workflow_authority(user) -> bool:
    """Authorize creation/revocation of account-level workflow grants."""
    return has_capability(user, Capability.WORKFLOW_AUTHORITY_MANAGE)
