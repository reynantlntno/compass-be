"""Actor-aware query boundary for the profiles domain.

Query functions belong here when the domain receives an API/UI read. They must
compose an existing scoped selector with a fixed projection and never return
HTTP responses or serialize ORM objects directly.
"""

from django.db.models.functions import Lower

from apps.common.contracts import PageRequest, PageResult, to_json_object
from apps.common.exceptions import NotFoundError, PermissionDeniedError, ValidationError
from apps.access_control.rules import (
    is_active_nonlegacy_actor,
    is_counselor,
    is_gco_staff,
    is_it_admin,
    is_student,
)
from apps.profiles.policies import can_view_support_directory
from apps.profiles.projections import (
    project_base_profile,
    project_counselor_directory_entry,
    project_self_counselor_profile,
    project_self_staff_profile,
    project_self_student_profile,
    project_staff_directory_entry,
)
from apps.profiles.selectors import (
    select_covering_counselors,
    select_gco_staff_with_matching_grants,
    select_own_counselor_profile,
    select_own_staff_profile,
    select_own_student_profile,
    select_student_by_id,
)


def my_profile(actor) -> dict:
    """Return the authenticated actor's safe role-specific profile projection.

    Missing required role profiles fail closed; IT Admins receive only the
    base role-safe projection with no profile details.
    """
    if not is_active_nonlegacy_actor(actor):
        raise PermissionDeniedError()

    if is_it_admin(actor):
        return to_json_object(project_base_profile(actor))

    if is_student(actor):
        profile = select_own_student_profile(actor)
        if profile is None:
            raise PermissionDeniedError()
        return to_json_object(project_self_student_profile(profile))

    if is_counselor(actor):
        profile = select_own_counselor_profile(actor)
        if profile is None:
            raise PermissionDeniedError()
        return to_json_object(project_self_counselor_profile(profile))

    if is_gco_staff(actor):
        profile = select_own_staff_profile(actor)
        if profile is None:
            raise PermissionDeniedError()
        return to_json_object(project_self_staff_profile(profile))

    raise PermissionDeniedError()


def _resolve_directory_target(actor, student_id):
    """Resolve and authorize one concrete student target for the directory."""
    if not is_active_nonlegacy_actor(actor):
        raise PermissionDeniedError()
    if is_it_admin(actor):
        raise PermissionDeniedError()

    if is_student(actor):
        own_profile = select_own_student_profile(actor)
        if own_profile is None:
            raise PermissionDeniedError()
        if student_id is not None and student_id != own_profile.pk:
            # Never confirm that another student target exists.
            raise NotFoundError()
        return own_profile

    if is_counselor(actor) or is_gco_staff(actor):
        if student_id is None:
            raise ValidationError(field_errors={"target": ["A student target is required."]})
        target = select_student_by_id(student_id)
        if target is None or not can_view_support_directory(actor, target):
            # Out-of-scope or unknown targets share one generic response so
            # student existence is never disclosed.
            raise NotFoundError()
        return target

    raise PermissionDeniedError()


def support_directory_page(
    actor, *, student_id=None, page: PageRequest | None = None
) -> dict:
    """Return the paginated support contacts visible for one concrete student."""
    page = page or PageRequest()
    target = _resolve_directory_target(actor, student_id)

    # Keep the two role-specific QuerySets separate, but apply the canonical
    # role ordering before slicing.  This preserves the public projection
    # order without materializing every visible staff member in Python.
    counselor_profiles = select_covering_counselors(target).order_by(
        Lower("user__first_name"), Lower("user__last_name"), "user_id"
    )
    staff_profiles = select_gco_staff_with_matching_grants(target).order_by(
        Lower("user__first_name"), Lower("user__last_name"), "user_id"
    )
    counselor_total = counselor_profiles.count()
    staff_total = staff_profiles.count()
    total = counselor_total + staff_total
    start = page.offset
    stop = start + page.page_size
    entries = []

    if start < counselor_total:
        counselor_stop = min(stop, counselor_total)
        entries.extend(
            project_counselor_directory_entry(profile)
            for profile in counselor_profiles[start:counselor_stop]
        )

    if stop > counselor_total:
        staff_start = max(0, start - counselor_total)
        staff_stop = max(0, stop - counselor_total)
        entries.extend(
            project_staff_directory_entry(profile)
            for profile in staff_profiles[staff_start:staff_stop]
        )

    return PageResult(
        items=tuple(entries),
        page=page.page,
        page_size=page.page_size,
        total=total,
    ).as_dict()
