"""Actor and purpose policies for the Privacy client boundary.

The privacy domain deliberately does not infer authority from a base role. A
student owns only the subject represented by their own HMAC reference, a staff
reviewer needs an explicit dated authorization, and the DPO relationship is
resolved from the active appointment.
"""

from apps.access_control.authority import has_fixed_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import is_active_nonlegacy_actor, is_it_admin, is_student

from .services import hash_safe_reference, has_reviewer_scope


def is_current_dpo(actor) -> bool:
    from apps.governance.dpo_services import is_current_dpo as governance_is_current_dpo

    return governance_is_current_dpo(actor)


def can_create_request(actor, *, target_category: str, staff_assisted: bool = False) -> bool:
    if not is_active_nonlegacy_actor(actor):
        return False
    if staff_assisted:
        return has_reviewer_scope(actor, "request_intake", target_category=target_category)
    return is_student(actor)


def can_view_request(actor, request) -> bool:
    if request is None or not is_active_nonlegacy_actor(actor):
        return False
    if is_student(actor):
        return request.subject_reference_hash == hash_safe_reference(
            f"user:{actor.pk}", namespace="subject:privacy_request"
        )
    return bool(
        is_current_dpo(actor)
        or has_reviewer_scope(actor, "request_review", target_category=request.target_category)
    )


def can_view_request_sensitive(actor, request) -> bool:
    if not can_view_request(actor, request):
        return False
    return bool(
        is_current_dpo(actor)
        or has_reviewer_scope(actor, "request_sensitive", target_category=request.target_category)
    )


def can_assign_request(actor, *, target_category: str) -> bool:
    return bool(
        is_current_dpo(actor)
        or has_reviewer_scope(actor, "request_assign", target_category=target_category)
    )


def can_view_retention(actor) -> bool:
    return bool(is_current_dpo(actor))


def can_evaluate_retention(actor) -> bool:
    return can_view_retention(actor)


def can_manage_legal_hold(actor, *, target_category: str) -> bool:
    return bool(
        is_current_dpo(actor)
        or has_reviewer_scope(actor, "legal_hold", target_category=target_category)
    )


def can_view_incident(actor, *, target_category: str = "") -> bool:
    if not is_active_nonlegacy_actor(actor):
        return False
    # The appointment relationship is an independent privacy authority.  A
    # DPO who also carries the technical base role must retain DPO visibility;
    # IT-only containment remains the fallback for non-DPO IT administrators.
    if is_current_dpo(actor):
        return True
    if is_it_admin(actor):
        return has_fixed_capability(actor, Capability.PRIVACY_INCIDENTS_TECHNICAL_OPERATE)
    return bool(
        has_reviewer_scope(actor, "incident_record", target_category=target_category)
    )


def can_record_incident(actor, *, target_category: str = "") -> bool:
    return can_view_incident(actor, target_category=target_category)


def can_decide_incident(actor, *, target_category: str = "", to_status: str = "") -> bool:
    if is_current_dpo(actor):
        return True
    if is_it_admin(actor):
        return bool(
            to_status == "CONTAINED"
            and has_fixed_capability(actor, Capability.PRIVACY_INCIDENTS_TECHNICAL_OPERATE)
        )
    return bool(
        has_reviewer_scope(actor, "incident_decision", target_category=target_category)
    )


def can_view_acceptance(actor, event) -> bool:
    if event is None or not is_active_nonlegacy_actor(actor):
        return False
    if is_student(actor):
        return event.subject_reference_hash == hash_safe_reference(
            f"user:{actor.pk}", namespace=f"subject:{event.purpose_workflow}"
        )
    return bool(is_current_dpo(actor))
