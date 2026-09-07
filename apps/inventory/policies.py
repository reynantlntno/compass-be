# Project: COMPASS
# File: apps/inventory/policies.py
# Module: apps.inventory
# Purpose: Access policies to control inventory snapshots retrieval and modifications.
# Domain boundary and service policy.

from apps.access_control.rules import (
    is_active_nonlegacy_actor,
    is_student,
    is_it_admin,
    is_counselor,
    is_gco_staff,
    owns_student_profile,
)
from apps.access_control.authority import has_capability
from apps.access_control.capabilities import Capability
from apps.access_control.policies import can_view_student_profile
from apps.inventory.models import InventoryStatusChoices


def can_view_own_draft(user, snapshot) -> bool:
    """Authorize a student to view their own draft inventory snapshot."""
    if not is_active_nonlegacy_actor(user) or snapshot is None:
        return False
    if not is_student(user):
        return False
    return owns_student_profile(user, snapshot.student_profile)


def can_edit_own_draft(user, snapshot) -> bool:
    """Authorize a student to modify their draft or reopened snapshot."""
    if not is_active_nonlegacy_actor(user) or snapshot is None:
        return False
    if not is_student(user):
        return False
    if not owns_student_profile(user, snapshot.student_profile):
        return False
    return snapshot.status in [InventoryStatusChoices.DRAFT, InventoryStatusChoices.REOPENED_FOR_CORRECTION]


def can_view_submitted_inventory(user, snapshot) -> bool:
    """Authorize viewing of a submitted individual inventory snapshot.
    
    Access is granted to:
    - The student owner (read-only view approved in this PR).
    - Counselors with active coverage matching the student.
    - Head Guidance globally.
    
    Access is strictly denied to:
    - IT Admins (including is_it_admin)
    - Django superusers (user.is_superuser)
    - Any out-of-scope internal users.
    """
    if not is_active_nonlegacy_actor(user) or snapshot is None:
        return False

    # IT Admin and Django superusers are strictly blocked
    if is_it_admin(user) or user.is_superuser:
        return False

    # 1. Student self-access (read-only self-view approved)
    if is_student(user):
        return owns_student_profile(user, snapshot.student_profile)

    # 2. Scoped counselor direct-care read access.  Reopening/correction is a
    # separate optional authority and must not be reused as a read gate.
    return bool(can_view_student_profile(user, snapshot.student_profile) and is_counselor(user))


def can_reopen_inventory(user, snapshot) -> bool:
    """Authorize a counselor or Head Guidance to reopen a student's submitted snapshot.
    
    Access is granted to:
    - Counselors with active coverage matching the student.
    - Head Guidance globally.
    
    Access is strictly denied to:
    - The student owner.
    - IT Admins.
    - Django superusers.
    """
    if not is_active_nonlegacy_actor(user) or snapshot is None:
        return False

    if (
        not is_counselor(user)
        or is_student(user)
        or is_gco_staff(user)
        or is_it_admin(user)
        or user.is_superuser
    ):
        return False

    # Must be in submitted status to be reopened
    if snapshot.status != InventoryStatusChoices.SUBMITTED:
        return False

    # Scoped coverage verification
    return bool(
        can_view_student_profile(user, snapshot.student_profile)
        and has_capability(user, Capability.INVENTORY_CORRECTION_REVIEW, target=snapshot.student_profile)
    )


def can_review_inventory_correction(user, snapshot) -> bool:
    """Authorize entering the correction workflow before state validation.

    This deliberately does not require ``SUBMITTED`` so a stale review page
    can return a safe workflow-conflict response instead of turning a valid
    counselor into a generic authorization denial.  The state-changing policy
    above remains the final guard.
    """

    if not is_active_nonlegacy_actor(user) or snapshot is None:
        return False
    if (
        not is_counselor(user)
        or is_student(user)
        or is_gco_staff(user)
        or is_it_admin(user)
        or user.is_superuser
    ):
        return False
    return can_view_student_profile(user, snapshot.student_profile)
