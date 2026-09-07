# Project: COMPASS
# File: apps/access_control/rules.py
# Module: apps.access_control
# Purpose: Basic role helper check predicates
# Domain boundary and service policy.

from apps.accounts.models import RoleChoices


def is_student(user) -> bool:
    """Check if the user is authenticated and holds the STUDENT role."""
    if not is_active_nonlegacy_actor(user):
        return False
    return user.role == RoleChoices.STUDENT


def is_counselor(user) -> bool:
    """Check if the user is authenticated and holds the COUNSELOR role."""
    if not is_active_nonlegacy_actor(user):
        return False
    return user.role == RoleChoices.COUNSELOR


def is_gco_staff(user) -> bool:
    """Check if the user is authenticated and holds the GCO_STAFF role."""
    if not is_active_nonlegacy_actor(user):
        return False
    return user.role == RoleChoices.GCO_STAFF


def is_it_admin(user) -> bool:
    """Check if the user is authenticated and holds the IT_ADMIN role."""
    if not is_active_nonlegacy_actor(user):
        return False
    return user.role == RoleChoices.IT_ADMIN


def is_head_guidance(user) -> bool:
    """Check if the user is a counselor designated as Head Guidance."""
    if not is_counselor(user):
        return False
    # Safe lookup to avoid failures if CounselorProfile doesn't exist
    return hasattr(user, "counselor_profile") and user.counselor_profile.is_head_guidance


def is_active_nonlegacy_actor(user) -> bool:
    """Return whether the actor is an active, non-legacy-superuser account.

    Mirrors the AuthorityContext eligibility rule (access_control.authority):
    an inactive account or a legacy framework superuser never satisfies an
    authorization branch. This is a pure actor predicate, not a permission or
    object-scope decision; domain policies still own record scope, field
    sensitivity, and actions. It is the single source of truth for the
    eligibility check used by domain fail-closed guards.
    """
    return bool(
        user
        and getattr(user, "is_authenticated", False)
        and getattr(user, "is_active", False)
        and not bool(getattr(user, "is_superuser", False))
    )


def owns_user(actor, owner_id) -> bool:
    """Return whether an active actor is exactly the supplied owner.

    Ownership is intentionally narrower than role membership.  Callers must
    still decide whether the resource is a student-owned resource, but they
    can rely on this predicate for the common active/non-legacy/exact-ID
    boundary.
    """
    return bool(
        is_active_nonlegacy_actor(actor)
        and owner_id is not None
        and getattr(actor, "pk", None) == owner_id
    )


def owns_student_profile(actor, student_profile) -> bool:
    """Return whether an active Student owns the concrete profile target."""
    return bool(
        is_student(actor)
        and student_profile is not None
        and owns_user(actor, getattr(student_profile, "user_id", None))
    )
