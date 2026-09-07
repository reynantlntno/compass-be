"""Internal scoped profile ORM selectors; never an HTTP response boundary.

Selectors return QuerySets or model instances only.  Authorization predicates
live in ``policies.py`` and JSON-safe composition lives in ``queries.py``.
"""

from django.db.models import Q
from django.utils import timezone

from apps.access_control.models import CounselorCoverage, WorkflowAuthorityGrant
from apps.access_control.scopes import build_scope_match_q
from apps.access_control.capabilities import Capability
from apps.access_control.choices import GrantStatus, ScopeMode
from apps.accounts.models import RoleChoices
from apps.profiles.models import CounselorProfile, GCOStaffProfile, StudentProfile


# Allowlisted student-facing GCO capabilities that may back a support-directory
# grant.  Any other capability — however powerful — never grants directory
# access, and only EXPLICIT_ORGANIZATION scope modes are honored here.
STUDENT_DIRECTORY_GCO_CAPABILITIES = frozenset({
    Capability.APPOINTMENTS_REVIEW.value,
    Capability.CALL_SLIPS_PREPARE.value,
    Capability.GOOD_MORAL_DOCUMENT_GENERATE.value,
    Capability.EXIT_INTERVIEWS_PROCESS.value,
    Capability.GRADUATE_TRACER_PROCESS.value,
    Capability.CONTENT_LOCAL_VIEW.value,
})


def select_own_student_profile(actor):
    """Return the actor's own StudentProfile, or None when absent."""
    if not (actor is not None and getattr(actor, "is_authenticated", False)):
        return None
    return StudentProfile.objects.filter(user=actor).select_related("user").first()


def select_own_counselor_profile(actor):
    """Return the actor's own CounselorProfile, or None when absent."""
    if not (actor is not None and getattr(actor, "is_authenticated", False)):
        return None
    return CounselorProfile.objects.filter(user=actor).select_related("user").first()


def select_own_staff_profile(actor):
    """Return the actor's own GCOStaffProfile, or None when absent."""
    if not (actor is not None and getattr(actor, "is_authenticated", False)):
        return None
    return GCOStaffProfile.objects.filter(user=actor).select_related("user").first()


def select_student_by_id(student_id):
    """Return one concrete student target by stable primary key, or None."""
    if student_id is None:
        return None
    return (
        StudentProfile.objects.filter(
            pk=student_id,
            user__role=RoleChoices.STUDENT,
            user__is_active=True,
            user__is_superuser=False,
        )
        .select_related("user")
        .first()
    )


def _matching_directory_coverage_ids(student_profile):
    """Return a bulk subquery of counselor IDs covering this student."""
    today = timezone.localdate()
    live_coverages = CounselorCoverage.objects.filter(
        counselor__is_active=True,
        counselor__is_superuser=False,
        counselor__role=RoleChoices.COUNSELOR,
        is_active=True,
        starts_at__lte=today,
    ).filter(Q(ends_at__isnull=True) | Q(ends_at__gte=today))
    return live_coverages.filter(build_scope_match_q(student_profile)).values("counselor_id")


def select_covering_counselors(student_profile):
    """Return counselors whose live coverage matches this concrete student."""
    if student_profile is None:
        return CounselorProfile.objects.none()
    return CounselorProfile.objects.filter(
        user_id__in=_matching_directory_coverage_ids(student_profile),
        user__is_active=True,
        user__is_superuser=False,
        user__role=RoleChoices.COUNSELOR,
    ).select_related("user")


def _active_directory_organization_grants(*, grantee_id=None):
    """Return live allowlisted EXPLICIT_ORGANIZATION grants for the directory.

    Office-wide, assigned-record, wrong-capability, expired, and revoked
    grants are structurally excluded by this query; blank scopes cannot exist
    because the grant model validates at least one organization value.
    """
    today = timezone.localdate()
    query = WorkflowAuthorityGrant.objects.filter(
        grantee__role=RoleChoices.GCO_STAFF,
        grantee__is_active=True,
        grantee__is_superuser=False,
        capability__in=STUDENT_DIRECTORY_GCO_CAPABILITIES,
        scope_mode=ScopeMode.EXPLICIT_ORGANIZATION.value,
        status=GrantStatus.ACTIVE,
        valid_from__lte=today,
    ).filter(Q(valid_until__isnull=True) | Q(valid_until__gte=today))
    # Model validation rejects empty explicit scopes, but this is also a
    # runtime boundary: bulk imports or legacy rows must never turn a blank
    # scope into office-wide directory access.
    query = query.filter(build_scope_match_q(None, require_non_empty=True))
    if grantee_id is not None:
        query = query.filter(grantee_id=grantee_id)
    return query


def select_gco_staff_with_matching_grants(student_profile):
    """Return staff holding an in-scope allowlisted grant for this student."""
    if student_profile is None:
        return GCOStaffProfile.objects.none()
    return GCOStaffProfile.objects.filter(
        user_id__in=_active_directory_organization_grants().filter(
            build_scope_match_q(student_profile, require_non_empty=True)
        ).values("grantee_id"),
        user__is_active=True,
        user__is_superuser=False,
        user__role=RoleChoices.GCO_STAFF,
    ).select_related("user")


def actor_has_matching_directory_grant(actor, student_profile) -> bool:
    """Return whether this actor holds a matching allowlisted directory grant."""
    if actor is None or student_profile is None:
        return False
    if not getattr(actor, "is_authenticated", False):
        return False
    return _active_directory_organization_grants(grantee_id=actor.pk).filter(
        build_scope_match_q(student_profile, require_non_empty=True)
    ).exists()
