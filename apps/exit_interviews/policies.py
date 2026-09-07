"""Target-aware access policies for Exit Interview records and queues."""

from apps.access_control.rules import (
    is_active_nonlegacy_actor,
    is_counselor,
    is_gco_staff,
    is_it_admin,
    is_student,
    owns_student_profile,
)
from apps.access_control.authority import has_capability
from apps.access_control.capabilities import Capability
from apps.access_control.scopes import (
    counselor_has_live_coverage_for_student,
    get_live_counselor_coverages,
    workflow_authority_authorizes_record,
)


EXIT_INTERVIEW_PROCESSING_CAPABILITY = Capability.EXIT_INTERVIEWS_PROCESS


def _active(user):
    return is_active_nonlegacy_actor(user)


def _staff_scope_matches(user, response):
    return bool(
        _active(user)
        and is_gco_staff(user)
        and workflow_authority_authorizes_record(
            user, capability=EXIT_INTERVIEW_PROCESSING_CAPABILITY,
            student_profile=response.student,
        )
    )


def _counselor_scope_matches(user, response):
    return bool(
        _active(user)
        and is_counselor(user)
        and counselor_has_live_coverage_for_student(user, response.student)
    )


def can_access_exit_interview(user) -> bool:
    return _active(user) and is_student(user)


def can_start_exit_interview(user, student_profile) -> bool:
    return owns_student_profile(user, student_profile)


def can_submit_exit_interview(user, response) -> bool:
    return bool(_active(user) and owns_student_profile(user, response.student))


def can_view_exit_response(user, response) -> bool:
    """Authorize one response; role membership alone never grants staff access."""
    if not _active(user) or response is None or is_it_admin(user):
        return False
    if is_student(user):
        return owns_student_profile(user, response.student)
    if has_capability(user, Capability.EXIT_INTERVIEWS_PROCESS, target=response.student):
        return True
    return _counselor_scope_matches(user, response) or _staff_scope_matches(user, response)


def can_reopen_exit_interview(user, response=None) -> bool:
    """Authorize lifecycle mutations against the exact response target."""
    if not _active(user) or is_it_admin(user) or is_student(user):
        return False
    if has_capability(
        user, Capability.EXIT_INTERVIEWS_REOPEN,
        target=getattr(response, "student", None) if response is not None else None,
    ):
        return True
    if response is None:
        return is_counselor(user)
    return _counselor_scope_matches(user, response) or _staff_scope_matches(user, response)


def can_manage_exit_assignments(user, student_profile=None) -> bool:
    """Authorize assignment management against the concrete student scope."""
    if not _active(user) or is_it_admin(user) or is_student(user):
        return False
    if has_capability(user, Capability.EXIT_INTERVIEWS_ASSIGN, target=student_profile):
        return True
    if is_counselor(user):
        return bool(student_profile and counselor_has_live_coverage_for_student(user, student_profile))
    if is_gco_staff(user):
        return bool(
            student_profile
            and workflow_authority_authorizes_record(
                user,
                capability=Capability.EXIT_INTERVIEWS_ASSIGN,
                student_profile=student_profile,
            )
        )
    return False


def can_view_exit_free_text(user, response) -> bool:
    """Free-text answers are a separate, narrower permission than metadata."""
    if not _active(user) or response is None or is_it_admin(user) or is_gco_staff(user):
        return False
    if is_student(user):
        return False
    if not can_view_exit_response(user, response):
        return False
    if has_capability(
        user, Capability.EXIT_INTERVIEWS_PROCESS,
        target=response.student,
    ):
        return True
    return _counselor_scope_matches(user, response)


def can_acknowledge_exit_interview(user, response) -> bool:
    """Acknowledge metadata only; GCO operational staff cannot attest."""
    if not _active(user) or is_it_admin(user) or is_gco_staff(user) or is_student(user):
        return False
    if has_capability(user, Capability.EXIT_INTERVIEWS_ACKNOWLEDGE, target=response.student):
        return True
    return _counselor_scope_matches(user, response)
