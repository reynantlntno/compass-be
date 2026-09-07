"""Pure authorization boundary for profile reads and mutations.

The canonical evaluation order is:

    active actor -> OWNER or relationship/grant -> concrete student target
    -> safe read action -> fixed field projection

Head access is honored only through the named fixed safe-metadata capability
(``student_support_needs.view_institution``), never the ``is_head_guidance``
designation alone.  GCO Staff access is honored only through an active
EXPLICIT_ORGANIZATION grant backed by an allowlisted student-facing capability
that matches the student's organization scope.  IT Admins, inactive accounts,
legacy superusers, role-only GCO Staff, and bare linked-counselor relationships
all fail closed.  No Django HTTP types appear in this module.
"""

from apps.access_control.authority import has_fixed_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import (
    is_active_nonlegacy_actor,
    is_counselor,
    is_gco_staff,
    is_head_guidance,
    is_it_admin,
    owns_student_profile,
)
from apps.access_control.scopes import (
    get_live_counselor_coverages,
    scope_matches_student_profile,
)
from apps.profiles.selectors import actor_has_matching_directory_grant


# The single named fixed capability that authorizes Head Guidance support-
# directory metadata access for any concrete student target.
HEAD_SUPPORT_METADATA_CAPABILITY = Capability.STUDENT_RECORDS_VIEW_INSTITUTION


def can_view_own_profile(actor) -> bool:
    """Return whether an active, non-legacy actor may read their own profile."""
    return is_active_nonlegacy_actor(actor)


def _covered_counselor_matches_student(actor, student_profile) -> bool:
    """Return whether live coverage (not a bare counselor link) matches."""
    if not is_counselor(actor) or student_profile is None:
        return False
    return any(
        scope_matches_student_profile(coverage, student_profile)
        for coverage in get_live_counselor_coverages(actor)
    )


def _head_fixed_metadata_access(actor, student_profile) -> bool:
    """Return Head authority strictly via the named fixed capability."""
    if student_profile is None or not is_head_guidance(actor):
        return False
    return bool(has_fixed_capability(actor, HEAD_SUPPORT_METADATA_CAPABILITY))


def can_view_support_directory(actor, student_profile) -> bool:
    """Return whether the actor may view the directory of this concrete student.

    Owner students, counselors with live coverage (or the Head's named fixed
    safe-metadata capability), and GCO Staff with an active allowlisted
    EXPLICIT_ORGANIZATION grant matching the student's organization pass.
    Every other combination fails closed.
    """
    if not is_active_nonlegacy_actor(actor) or student_profile is None:
        return False
    if is_it_admin(actor):
        return False
    if owns_student_profile(actor, student_profile):
        return True
    if _covered_counselor_matches_student(actor, student_profile):
        return True
    if _head_fixed_metadata_access(actor, student_profile):
        return True
    if is_gco_staff(actor) and actor_has_matching_directory_grant(actor, student_profile):
        return True
    return False
