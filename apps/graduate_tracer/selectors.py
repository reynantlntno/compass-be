"""Scoped ORM selectors for Graduate Tracer reads."""

from django.db.models import QuerySet

from apps.access_control.authority import has_capability, has_fixed_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import (
    is_active_nonlegacy_actor,
    is_counselor,
    is_gco_staff,
    is_it_admin,
    is_student,
    owns_student_profile,
)
from apps.access_control.scopes import (
    build_geographic_scope_q,
    build_workflow_authority_scope_q,
    get_live_counselor_coverages,
)
from apps.graduate_tracer.models import GraduateTracerResponse
from apps.graduate_tracer.policies import can_view_gts_free_text, can_view_gts_response


GTS_SENSITIVE_FIELDS = (
    "response_json",
    "metadata_json",
    "telephone_number",
    "place_of_work",
    "initial_gross_earnings",
    "reopen_reason",
    "void_reason",
)


def _scope_q(actor):
    field_map = {
        "campus": "student__campus",
        "college": "student__college",
        "department": "student__department",
        "program": "student__program",
    }
    if is_counselor(actor):
        return build_geographic_scope_q(get_live_counselor_coverages(actor), field_map)
    if is_gco_staff(actor):
        return build_workflow_authority_scope_q(actor, capability=Capability.GRADUATE_TRACER_PROCESS, field_map=field_map)
    return None


def list_gts_responses_for_actor(actor) -> QuerySet[GraduateTracerResponse]:
    if not is_active_nonlegacy_actor(actor):
        return GraduateTracerResponse.objects.none()
    base = GraduateTracerResponse.objects.select_related("student", "form_revision", "form_collection").defer(*GTS_SENSITIVE_FIELDS)
    if is_student(actor):
        return base.filter(student__user=actor).order_by("-submitted_at", "-created_at", "-pk")
    if has_fixed_capability(actor, Capability.GRADUATE_TRACER_PROCESS):
        return base.order_by("-submitted_at", "-created_at", "-pk")
    scope = _scope_q(actor)
    if scope is not None:
        return base.filter(scope).order_by("-submitted_at", "-created_at", "-pk")
    return GraduateTracerResponse.objects.none()


def get_gts_response_for_actor(actor, response_id: str) -> GraduateTracerResponse | None:
    if not is_active_nonlegacy_actor(actor):
        return None
    response = GraduateTracerResponse.objects.select_related("student", "form_revision", "form_collection").defer(*GTS_SENSITIVE_FIELDS).filter(pk=response_id).first()
    if response is None or not can_view_gts_response(actor, response):
        return None
    if can_view_gts_free_text(actor, response):
        return GraduateTracerResponse.objects.select_related("student", "form_revision", "form_collection").get(pk=response.pk)
    return response


def get_gts_detail_for_actor_by_reference(actor, reference_code: str) -> GraduateTracerResponse | None:
    if not is_active_nonlegacy_actor(actor):
        return None
    response = GraduateTracerResponse.objects.select_related("student", "form_revision", "form_collection").defer(*GTS_SENSITIVE_FIELDS).filter(reference_code=reference_code).first()
    if response is None or not can_view_gts_response(actor, response):
        return None
    if can_view_gts_free_text(actor, response):
        return GraduateTracerResponse.objects.select_related("student", "form_revision", "form_collection").get(pk=response.pk)
    return response


def can_view_gts_review_queue(actor) -> bool:
    if not is_active_nonlegacy_actor(actor) or is_it_admin(actor):
        return False
    if has_fixed_capability(actor, Capability.GRADUATE_TRACER_PROCESS):
        return True
    return bool(_scope_q(actor) is not None)


def get_alumni_gts_status(actor) -> dict[str, object] | None:
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
    response = GraduateTracerResponse.objects.filter(student=student_profile, graduation_year=academic_year).first() if academic_year else None
    if response:
        return {"has_response": True, "status": response.status, "reference_code": response.reference_code, "submitted_at": response.submitted_at}
    return {"has_response": False, "status": "NOT_STARTED", "reference_code": None, "submitted_at": None}
