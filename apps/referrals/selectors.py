# Project: COMPASS
# File: apps/referrals/selectors.py
# Module: apps.referrals
# Purpose: Side-effect-free referral queries and allowlisted DTOs.
# Domain boundary and service policy.

from dataclasses import asdict, dataclass

from django.db.models import Q, QuerySet
from django.utils import timezone

from apps.access_control.authority import has_capability
from apps.access_control.authority import has_fixed_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import is_active_nonlegacy_actor, is_counselor, is_gco_staff
from apps.access_control.scopes import (
    build_geographic_scope_q,
    build_workflow_authority_scope_q,
    get_live_counselor_coverages,
)
from apps.accounts.models import RoleChoices
from apps.access_control.display import office_student_display_label
from apps.referrals.models import (
    Referral,
    ReferralAction,
    ReferralActionCodeChoices,
    ReferralActionOutcomeCodeChoices,
    ReferralReasonCategoryChoices,
    ReferralReassignmentRequest,
    ReferralSourceTypeChoices,
    ReferralStatusChoices,
    ReferralWorkflowReasonCodeChoices,
)
from apps.referrals.encryption import (
    ACTION_CONFIDENTIAL_FIELDS,
    REFERRAL_ACTION,
    REFERRAL_CONFIDENTIAL_FIELDS,
    REFERRAL_SUBMISSION,
    REASSIGNMENT_CONFIDENTIAL_FIELDS,
    read_group,
)
from apps.referrals.policies import (
    can_decide_referral_reassignment,
    can_view_referral_queue,
    can_view_referral_safe_metadata,
    can_view_referral_sensitive_detail,
    has_counselor_coverage_for_student,
)


MAX_ACTIONS_PER_DETAIL = 100


@dataclass(frozen=True)
class ReferralQueueItemDTO:
    reference_code: str
    status: str
    age_bucket: str
    assignment_state: str


def _safe_choice_display(instance, field_name, value, allowed_values):
    if value not in allowed_values:
        return "Unavailable"
    return getattr(instance, f"get_{field_name}_display")()


def _safe_optional_code(value, allowed_values):
    return value if not value or value in allowed_values else ""


def get_referrals_visible_to(user) -> QuerySet:
    if not is_active_nonlegacy_actor(user):
        return Referral.objects.none()
    base = Referral.objects.defer(*REFERRAL_CONFIDENTIAL_FIELDS).filter(
        student__is_active=True,
        student__is_superuser=False,
        student__role=RoleChoices.STUDENT,
    )
    if has_fixed_capability(user, Capability.REFERRALS_QUEUE_PROCESS):
        return base
    if is_counselor(user):
        coverage_q = build_geographic_scope_q(
            get_live_counselor_coverages(user),
            {
                "campus": "student__student_profile__campus",
                "college": "student__student_profile__college",
                "department": "student__student_profile__department",
                "program": "student__student_profile__program",
            },
        )
        return base.filter(
            Q(assigned_counselor_id=user.pk)
            | (Q(assigned_counselor_id__isnull=True) & coverage_q)
        )
    if is_gco_staff(user):
        scope_q = build_workflow_authority_scope_q(
            user,
            capability=Capability.REFERRALS_QUEUE_PROCESS,
            field_map={
                "campus": "student__student_profile__campus",
                "college": "student__student_profile__college",
                "department": "student__student_profile__department",
                "program": "student__student_profile__program",
            },
            counselor_field="assigned_counselor_id",
        )
        return base.filter(scope_q)
    return Referral.objects.none()


def get_head_referral_queue(user):
    return get_referrals_visible_to(user) if has_fixed_capability(user, Capability.REFERRALS_QUEUE_PROCESS) else Referral.objects.none()


def get_assigned_referral_queue(user):
    if not is_active_nonlegacy_actor(user) or not is_counselor(user):
        return Referral.objects.none()
    return get_referrals_visible_to(user).filter(assigned_counselor_id=user.pk)


def get_coverage_referral_queue(user):
    if not is_active_nonlegacy_actor(user) or not is_counselor(user):
        return Referral.objects.none()
    return get_referrals_visible_to(user).filter(assigned_counselor_id__isnull=True)


def get_staff_referral_queue(user):
    if not is_active_nonlegacy_actor(user) or not is_gco_staff(user):
        return Referral.objects.none()
    return get_referrals_visible_to(user)


def get_referral_by_reference_code(user, reference_code):
    return (
        get_referrals_visible_to(user)
        .select_related("student", "student__student_profile", "assigned_counselor")
        .filter(reference_code=str(reference_code or "").strip())
        .first()
    )


def _age_bucket(referral):
    days = max(0, (timezone.now() - referral.created_at).days)
    if days == 0:
        return "Today"
    if days <= 7:
        return "Within 7 days"
    if days <= 30:
        return "Within 30 days"
    return "Older than 30 days"


def get_referral_queue_items(user):
    return [
        asdict(ReferralQueueItemDTO(
            reference_code=referral.reference_code,
            status=_safe_choice_display(referral, "status", referral.status, ReferralStatusChoices.values),
            age_bucket=_age_bucket(referral),
            assignment_state="Assigned" if referral.assigned_counselor_id else "Unassigned",
        ))
        for referral in get_referrals_visible_to(user)
    ]


def get_referral_sensitive_detail(user, reference_code, purpose="detail"):
    referral = get_referral_by_reference_code(user, reference_code)
    if not referral or not can_view_referral_sensitive_detail(user, referral, purpose):
        return None
    staff_intake = is_gco_staff(user) and referral.status in {
        "DRAFT", "SUBMITTED", "RECEIVED",
    }
    counselor_detail = is_counselor(user)
    reason_text = read_group(user, referral, REFERRAL_SUBMISSION) if counselor_detail or staff_intake else ""
    decrypted_groups = [REFERRAL_SUBMISSION] if counselor_detail or staff_intake else []
    detail = {
        "reference_code": referral.reference_code,
        "status": _safe_choice_display(referral, "status", referral.status, ReferralStatusChoices.values),
        "student_label": office_student_display_label(referral.student.student_profile) if counselor_detail or staff_intake else "Restricted after intake",
        "source_type": _safe_choice_display(referral, "source_type", referral.source_type, ReferralSourceTypeChoices.values) if counselor_detail or staff_intake else "Restricted after intake",
        "reason_text": reason_text,
        "reason_category": _safe_choice_display(referral, "reason_category_code", referral.reason_category_code, ReferralReasonCategoryChoices.values) if counselor_detail or staff_intake else "Restricted after intake",
        "course_snapshot": referral.course_snapshot if counselor_detail or staff_intake else "",
        "year_level_snapshot": referral.year_level_snapshot if counselor_detail or staff_intake else "",
        "block_snapshot": referral.block_snapshot if counselor_detail or staff_intake else "",
        "occurred_at": referral.occurred_at if counselor_detail or staff_intake else None,
        "source_signed_on": referral.source_signed_on if counselor_detail or staff_intake else None,
        "assignment_state": "Assigned" if referral.assigned_counselor_id else "Unassigned",
        "actions": [],
        "linked_call_slips": [],
        "field_group_codes": decrypted_groups,
    }
    from apps.call_slips.selectors import get_referral_linked_call_slips
    detail["linked_call_slips"] = get_referral_linked_call_slips(user, referral)
    if counselor_detail:
        detail["referrer_display_snapshot"] = referral.referrer_display_snapshot
        actions = list(
            ReferralAction.objects.defer(*ACTION_CONFIDENTIAL_FIELDS)
            .filter(referral_id=referral.pk)
            .order_by("-performed_at")
            [:MAX_ACTIONS_PER_DETAIL]
        )
        detail["actions"] = [
            {
                "action_code": _safe_choice_display(action, "action_code", action.action_code, ReferralActionCodeChoices.values),
                "outcome_code": _safe_optional_code(action.outcome_code, ReferralActionOutcomeCodeChoices.values),
                "remarks": read_group(user, action, REFERRAL_ACTION),
                "performed_at": action.performed_at,
            }
            for action in actions
        ]
        if actions:
            detail["field_group_codes"].append(REFERRAL_ACTION)
    elif is_gco_staff(user):
        detail["actions"] = [
            {
                "action_code": _safe_choice_display(action, "action_code", action.action_code, ReferralActionCodeChoices.values),
                "outcome_code": _safe_optional_code(action.outcome_code, ReferralActionOutcomeCodeChoices.values),
                "remarks": "",
                "performed_at": action.performed_at,
            }
            for action in ReferralAction.objects.defer(*ACTION_CONFIDENTIAL_FIELDS)
            .filter(referral_id=referral.pk)
            .order_by("-performed_at")
            [:MAX_ACTIONS_PER_DETAIL]
        ]
    return detail


def get_reassignment_request_dto(user, request):
    if not is_active_nonlegacy_actor(user) or not request:
        return None
    student = getattr(getattr(request, "referral", None), "student", None)
    if not _valid_student(student):
        return None
    if not (
        has_capability(user, Capability.REFERRALS_REASSIGN, target=student.student_profile)
        or request.requester_id == getattr(user, "pk", None)
    ):
        return None
    return {
        "id": request.pk,
        "reference_code": request.referral.reference_code,
        "status": request.get_status_display(),
        "request_reason_code": _safe_optional_code(request.request_reason_code, ReferralWorkflowReasonCodeChoices.values),
        "has_proposed_counselor": bool(request.proposed_counselor_id),
        "created_at": request.created_at,
    }


def get_reassignment_request_for_decision(user, request_id):
    if not is_active_nonlegacy_actor(user) or not has_capability(user, Capability.REFERRALS_REASSIGN):
        return None
    try:
        request = ReferralReassignmentRequest.objects.select_related(
            "referral", "requester", "proposed_counselor",
        ).defer(
            *REASSIGNMENT_CONFIDENTIAL_FIELDS,
            *(f"referral__{name}" for name in REFERRAL_CONFIDENTIAL_FIELDS),
        ).get(pk=request_id)
    except ReferralReassignmentRequest.DoesNotExist:
        return None
    return request if can_decide_referral_reassignment(user, request) else None
def get_referral_counselor_options(actor, referral, *, q=None, page=None):
    """Return scoped active counselor options for a Referral assign action.

    Only counselors who are current, policy-eligible assign targets for this
    Referral are disclosed. The returned selector is opaque and bound to the
    requesting actor and this Referral.
    """
    from apps.access_control.display import safe_user_display_label
    from apps.access_control.selection_tokens import issue_counselor_selection_token
    from apps.accounts.models import RoleChoices, User
    from apps.common.contracts import PageRequest, PageResult, page_queryset
    from apps.referrals.policies import (
        can_assign_referral,
        can_reassign_referral,
        can_view_referral_safe_metadata,
    )

    empty = PageResult((), page.page if page else 1, page.page_size if page else 25, 0)
    if not can_view_referral_safe_metadata(actor, referral):
        return empty
    if not (can_assign_referral(actor, referral) or can_reassign_referral(actor, referral)):
        return empty

    queryset = User.objects.filter(
        is_active=True,
        is_superuser=False,
        role=RoleChoices.COUNSELOR,
    ).order_by("last_name", "first_name", "pk")
    search = " ".join(str(q or "").split())[:80]
    if search:
        queryset = queryset.filter(
            Q(first_name__icontains=search) | Q(last_name__icontains=search)
        )
    allowed_ids = [
        counselor.pk
        for counselor in queryset
        if can_assign_referral(actor, referral, counselor)
        or can_reassign_referral(actor, referral, counselor)
    ]
    request = page or PageRequest()
    paged = page_queryset(
        queryset.filter(pk__in=allowed_ids),
        request,
        lambda counselor: {
            "selection_token": issue_counselor_selection_token(
                actor, "referral", referral.reference_code, counselor,
            ),
            "display_name": safe_user_display_label(counselor),
        },
    )
    return PageResult(
        items=tuple(item for item in paged["items"] if item is not None),
        page=paged["page"],
        page_size=paged["page_size"],
        total=paged["total"],
    )
