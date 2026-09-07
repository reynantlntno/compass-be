# Project: COMPASS
# File: apps/graduate_tracer/policies.py
# Module: apps.graduate_tracer
# Purpose: Access control policies for Graduate Tracer Survey (GTS)
# Domain boundary and service policy.

from apps.access_control.authority import has_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import (
    is_active_nonlegacy_actor,
    is_counselor,
    is_gco_staff,
    is_student,
    is_it_admin,
    owns_student_profile,
)
from apps.access_control.scopes import counselor_has_live_coverage_for_student, get_live_counselor_coverages, workflow_authority_authorizes_record
from apps.graduate_tracer.models import GraduateTracerResponse
from apps.profiles.models import StudentLifecycleChoices


def can_access_gts(user) -> bool:
    """Only students/alumni or token verified users can access GTS interfaces."""
    if not is_active_nonlegacy_actor(user):
        return False
    return is_student(user)


def can_start_gts(user, student_profile) -> bool:
    """Only the student himself can start his GTS response."""
    if not is_active_nonlegacy_actor(user):
        return False
    return bool(
        owns_student_profile(user, student_profile)
        and student_profile.lifecycle_status in (StudentLifecycleChoices.GRADUATED, StudentLifecycleChoices.ALUMNI)
    )


def can_submit_gts(user, response: GraduateTracerResponse) -> bool:
    """Check if the actor can submit this GTS response."""
    if not is_active_nonlegacy_actor(user):
        return False
    return bool(response and is_student(user) and response.student and owns_student_profile(user, response.student))


def can_reopen_gts(user, response=None) -> bool:
    """Only Head Guidance or GCO staff can reopen or void GTS responses.

    IT Admin is strictly denied.
    """
    if not is_active_nonlegacy_actor(user):
        return False
    if is_it_admin(user):
        return False
    target = getattr(response, "student", None) if response is not None else None
    return has_capability(user, Capability.GRADUATE_TRACER_REOPEN, target=target)


def can_view_gts_response(user, response: GraduateTracerResponse) -> bool:
    """Check if actor is authorized to view response details."""
    if not is_active_nonlegacy_actor(user) or response is None or getattr(response, "student", None) is None:
        return False

    if has_capability(user, Capability.GRADUATE_TRACER_PROCESS, target=response.student):
        return True

    if is_it_admin(user):
        return False

    if is_counselor(user):
        return counselor_has_live_coverage_for_student(user, response.student)

    if is_gco_staff(user):
        return workflow_authority_authorizes_record(
            user, capability=Capability.GRADUATE_TRACER_PROCESS,
            student_profile=response.student,
        )

    if is_student(user):
        return owns_student_profile(user, response.student)

    return False


def can_manage_gts_collections(user) -> bool:
    """Manage the global tracer collection lifecycle through fixed authority."""
    if not is_active_nonlegacy_actor(user):
        return False
    return has_capability(user, Capability.GRADUATE_TRACER_COLLECTION_MANAGE)


def can_view_gts_free_text(user, response) -> bool:
    """Authorize sensitive GTS answers against the concrete response target."""
    if not is_active_nonlegacy_actor(user) or response is None or is_it_admin(user):
        return False
    if is_student(user):
        return False
    if not can_view_gts_response(user, response):
        return False
    return bool(
        has_capability(user, Capability.GRADUATE_TRACER_PROCESS, target=response.student)
        or (
            is_counselor(user)
            and counselor_has_live_coverage_for_student(user, response.student)
        )
        or (
            is_gco_staff(user)
            and workflow_authority_authorizes_record(
                user,
                capability=Capability.GRADUATE_TRACER_PROCESS,
                student_profile=response.student,
            )
        )
    )
