# Project: COMPASS
# File: apps/support_needs/policies.py
# Module: apps.support_needs
# Purpose: Policy check functions to authorize access to student support needs.
# Domain boundary and service policy.

from apps.access_control.authority import has_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import is_counselor, is_active_nonlegacy_actor
from apps.access_control.selectors import get_students_visible_to
from apps.profiles.models import StudentProfile


def _can_access_student(actor, student_profile: StudentProfile) -> bool:
    """Helper to check if the student is within the actor's scope."""
    if not is_active_nonlegacy_actor(actor) or student_profile is None:
        return False
    # Head Guidance has office-wide access
    if has_capability(actor, Capability.STUDENT_RECORDS_VIEW_INSTITUTION):
        return True
    # Other internal actors must have student visible in their coverage/assignment scope
    return get_students_visible_to(actor).filter(id=student_profile.id).exists()


def has_support_need_scope(actor) -> bool:
    """Return whether an active counselor has an approved support scope."""
    if not is_active_nonlegacy_actor(actor):
        return False
    if not is_counselor(actor):
        return False
    if has_capability(actor, Capability.STUDENT_RECORDS_VIEW_INSTITUTION):
        return True
    return get_students_visible_to(actor).exists()


def can_view_support_need(actor, support_need) -> bool:
    """Check if actor can view a specific student support need record."""
    if support_need is None or not _can_access_student(actor, getattr(support_need, "student_profile", None)):
        return False
    # Viewing remains part of scoped counselor direct-care work; optional
    # grants govern verification, dispute, and archival actions below.
    return is_counselor(actor)


def can_create_support_need(actor, student_profile: StudentProfile) -> bool:
    """Check if actor can create a student support need for a student."""
    if not _can_access_student(actor, student_profile):
        return False
    # Only counselors (including Head Guidance) can create student support needs.
    return is_counselor(actor)


def can_update_support_need(actor, support_need) -> bool:
    """Check if actor can update a student support need."""
    if support_need is None or not _can_access_student(actor, getattr(support_need, "student_profile", None)):
        return False
    # Only counselors can update
    return is_counselor(actor)


def can_verify_support_need(actor, support_need) -> bool:
    """Check if actor can verify a student support need."""
    if support_need is None or not _can_access_student(actor, getattr(support_need, "student_profile", None)):
        return False
    return has_capability(actor, Capability.SUPPORT_NEEDS_VERIFY, target=support_need.student_profile)


def can_mark_support_need_needs_review(actor, support_need) -> bool:
    """Check if actor can mark an support_need as needing review."""
    return bool(
        support_need is not None
        and _can_access_student(actor, getattr(support_need, "student_profile", None))
        and has_capability(actor, Capability.SUPPORT_NEEDS_DISPUTE, target=support_need.student_profile)
    )


def can_dispute_support_need(actor, support_need) -> bool:
    """Check if actor can dispute a student support need."""
    return bool(
        support_need is not None
        and _can_access_student(actor, getattr(support_need, "student_profile", None))
        and has_capability(actor, Capability.SUPPORT_NEEDS_DISPUTE, target=support_need.student_profile)
    )


def can_archive_support_need(actor, support_need) -> bool:
    """Check if actor can archive a student support need."""
    if support_need is None or not _can_access_student(actor, getattr(support_need, "student_profile", None)):
        return False
    return has_capability(actor, Capability.SUPPORT_NEEDS_ARCHIVE, target=support_need.student_profile)


def can_view_support_need_aggregate(actor, filters=None) -> bool:
    """Check if actor can view aggregate student support-need reports."""
    # No approved support-support_need workflow scope grants GCO Staff access.
    return has_support_need_scope(actor)
