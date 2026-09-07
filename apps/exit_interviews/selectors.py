"""Scoped ORM selectors for Exit Interview reads."""

from django.db.models import QuerySet, Q

from apps.access_control.authority import has_capability, has_fixed_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import (
    is_active_nonlegacy_actor,
    is_counselor,
    is_gco_staff,
    is_student,
    owns_student_profile,
)
from apps.access_control.scopes import (
    build_geographic_scope_q,
    build_workflow_authority_scope_q,
    get_live_counselor_coverages,
    get_active_workflow_authority_grants,
)
from apps.exit_interviews.models import ExitInterviewAssignment, ExitInterviewResponse, ExitResponseStatus
from apps.exit_interviews.policies import can_view_exit_free_text, can_view_exit_response


EXIT_RESPONSE_SENSITIVE_FIELDS = (
    "response_json",
    "metadata_json",
    "civil_status",
    "program_schedule",
    "suggestions",
    "reopen_reason",
    "void_reason",
)


def _staff_scope_q(actor):
    field_map = {
        "campus": "student__campus",
        "college": "student__college",
        "department": "student__department",
        "program": "student__program",
    }
    if is_counselor(actor):
        return build_geographic_scope_q(get_live_counselor_coverages(actor), field_map)
    if is_gco_staff(actor):
        return build_workflow_authority_scope_q(actor, capability=Capability.EXIT_INTERVIEWS_PROCESS, field_map=field_map)
    return Q(pk__in=[])


def list_exit_responses_for_actor(actor) -> QuerySet[ExitInterviewResponse]:
    if not is_active_nonlegacy_actor(actor):
        return ExitInterviewResponse.objects.none()
    base = ExitInterviewResponse.objects.select_related("student", "form_revision", "form_collection").defer(*EXIT_RESPONSE_SENSITIVE_FIELDS)
    if is_student(actor):
        return base.filter(student__user=actor).order_by("-submitted_at", "-created_at", "-pk")
    if has_fixed_capability(actor, Capability.EXIT_INTERVIEWS_PROCESS):
        return base.order_by("-submitted_at", "-created_at", "-pk")
    if is_counselor(actor) or is_gco_staff(actor):
        return base.filter(_staff_scope_q(actor)).order_by("-submitted_at", "-created_at", "-pk")
    return ExitInterviewResponse.objects.none()


def get_exit_response_for_actor(actor, response_id: str) -> ExitInterviewResponse | None:
    if not is_active_nonlegacy_actor(actor):
        return None
    response = ExitInterviewResponse.objects.select_related("student", "form_revision", "form_collection").defer(*EXIT_RESPONSE_SENSITIVE_FIELDS).filter(pk=response_id).first()
    if response is None or not can_view_exit_response(actor, response):
        return None
    if can_view_exit_free_text(actor, response):
        return ExitInterviewResponse.objects.select_related("student", "form_revision", "form_collection").get(pk=response.pk)
    return response


def get_exit_detail_for_actor_by_reference(actor, reference_code: str) -> ExitInterviewResponse | None:
    if not is_active_nonlegacy_actor(actor):
        return None
    response = ExitInterviewResponse.objects.select_related("student", "form_revision", "form_collection").defer(*EXIT_RESPONSE_SENSITIVE_FIELDS).filter(reference_code=reference_code).first()
    if response is None or not can_view_exit_response(actor, response):
        return None
    if can_view_exit_free_text(actor, response):
        return ExitInterviewResponse.objects.select_related("student", "form_revision", "form_collection").get(pk=response.pk)
    return response


def can_view_exit_review_queue(actor) -> bool:
    if not is_active_nonlegacy_actor(actor):
        return False
    if has_capability(actor, Capability.EXIT_INTERVIEWS_PROCESS):
        return True
    if is_counselor(actor):
        return get_live_counselor_coverages(actor).exists()
    if is_gco_staff(actor):
        return get_active_workflow_authority_grants(actor, capability=Capability.EXIT_INTERVIEWS_PROCESS).exists()
    return False


def list_assignments_for_actor(actor) -> QuerySet[ExitInterviewAssignment]:
    if not is_active_nonlegacy_actor(actor):
        return ExitInterviewAssignment.objects.none()
    if has_fixed_capability(actor, Capability.EXIT_INTERVIEWS_ASSIGN):
        return ExitInterviewAssignment.objects.select_related("student", "collection").order_by("-created_at", "-pk")
    if is_student(actor):
        return ExitInterviewAssignment.objects.filter(student__user=actor).select_related("student", "collection").order_by("-created_at", "-pk")
    if is_counselor(actor) or is_gco_staff(actor):
        field_map = {
            "campus": "student__campus",
            "college": "student__college",
            "department": "student__department",
            "program": "student__program",
        }
        scope = (
            build_geographic_scope_q(get_live_counselor_coverages(actor), field_map)
            if is_counselor(actor)
            else _staff_scope_q_for_assignment(actor)
        )
        return ExitInterviewAssignment.objects.filter(scope).select_related("student", "collection").order_by("-created_at", "-pk")
    return ExitInterviewAssignment.objects.none()


def _staff_scope_q_for_assignment(actor):
    return build_workflow_authority_scope_q(
        actor,
        capability=Capability.EXIT_INTERVIEWS_PROCESS,
        field_map={
            "campus": "student__campus",
            "college": "student__college",
            "department": "student__department",
            "program": "student__program",
        },
    )


def get_student_exit_status(actor) -> dict[str, object] | None:
    if not is_active_nonlegacy_actor(actor) or not is_student(actor):
        return None
    student_profile = getattr(actor, "student_profile", None)
    if not owns_student_profile(actor, student_profile):
        return None
    from apps.organizations.academic_year import resolve_current_academic_year
    try:
        academic_year = resolve_current_academic_year()
    except Exception:
        academic_year = None
    response = ExitInterviewResponse.objects.filter(student=student_profile, academic_year=academic_year).first() if academic_year else None
    if response:
        return {"has_response": True, "status": response.status, "reference_code": response.reference_code, "submitted_at": response.submitted_at}
    return {"has_response": False, "status": "NOT_STARTED", "reference_code": None, "submitted_at": None}
