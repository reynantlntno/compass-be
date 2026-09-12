"""Staff-safe Referral queue queries and projections.

Row scope is owned by the existing Referral selectors and policies; this module
only adds bounded queue filtering and an explicit allowlist projection for the
staff-facing Referrals workspace.
"""

from __future__ import annotations

from django.db.models import Q

from apps.access_control.display import office_student_display_label
from apps.call_slips.models import TERMINAL_STATUSES as CALL_SLIP_TERMINAL_STATUSES
from apps.common.contracts import PageRequest, PageResult, to_json_value
from apps.common.exceptions import ValidationError
from apps.common.references import academic_year_to_segment
from apps.referrals.models import (
    ReferralReasonCategoryChoices,
    ReferralSourceTypeChoices,
    ReferralStatusChoices,
)
from apps.referrals.selectors import _age_bucket, get_referrals_visible_to


QUEUE_STATUSES = frozenset(value for value, _label in ReferralStatusChoices.choices)
SOURCE_TYPES = frozenset(value for value, _label in ReferralSourceTypeChoices.choices)
REASON_CATEGORIES = frozenset(value for value, _label in ReferralReasonCategoryChoices.choices)
QUEUE_ORDERS = frozenset({"recent", "oldest"})
ASSIGNMENT_STATES = frozenset({"all", "mine", "unassigned"})
MAX_QUERY_LENGTH = 120
MAX_FILTER_LENGTH = 100
REFERRAL_PREFIX = "REF"


def _clean(value, *, limit=MAX_FILTER_LENGTH):
    value = " ".join(str(value or "").split()).strip()
    if len(value) > limit:
        raise ValidationError()
    return value


def _statuses(value):
    values = tuple(
        dict.fromkeys(item.strip().upper() for item in str(value or "").split(",") if item.strip())
    )
    if any(item not in QUEUE_STATUSES for item in values):
        raise ValidationError()
    return values


def _codes(value, allowed):
    values = tuple(
        dict.fromkeys(item.strip().upper() for item in str(value or "").split(",") if item.strip())
    )
    if any(item not in allowed for item in values):
        raise ValidationError()
    return values


def _academic_year_segment(value) -> str:
    value = _clean(value)
    if not value:
        return ""
    try:
        return academic_year_to_segment(value)
    except Exception:  # invalid academic-year shapes fail closed with a 422
        raise ValidationError() from None


def _queue_queryset(actor):
    return (
        get_referrals_visible_to(actor)
        .select_related("student", "student__student_profile", "assigned_counselor")
        .prefetch_related("call_slips")
    )


def _active_linked_call_slip(referral):
    if not getattr(referral, "_prefetched_objects_cache", {}).get("call_slips"):
        return None
    return next(
        (slip for slip in referral.call_slips if slip.status not in CALL_SLIP_TERMINAL_STATUSES),
        None,
    )


def _project_row(actor, referral) -> dict:
    from apps.call_slips.policies import can_create_call_slip_from_referral

    student = referral.student
    profile = student.student_profile if hasattr(student, "student_profile") else None
    active_slip = _active_linked_call_slip(referral)
    return {
        "reference_code": referral.reference_code,
        "student_display_name": office_student_display_label(profile) if profile else "Student",
        "student_number": str(profile.student_number).strip()[:50] if profile and profile.student_number else None,
        "student_block_snapshot": str(referral.block_snapshot or "").strip()[:100] or None,
        "source_type": referral.source_type,
        "source_type_label": referral.get_source_type_display(),
        "reason_category": referral.reason_category_code,
        "reason_category_label": referral.get_reason_category_code_display(),
        "status": referral.status,
        "status_label": referral.get_status_display(),
        "assignment_state": "Assigned" if referral.assigned_counselor_id else "Unassigned",
        "age_bucket": _age_bucket(referral),
        "received_at": to_json_value(referral.received_at),
        "created_at": to_json_value(referral.created_at),
        "updated_at": to_json_value(referral.updated_at),
        "has_active_call_slip": active_slip is not None,
        "active_call_slip_reference": active_slip.reference_code if active_slip else None,
        "can_prepare_call_slip": bool(
            active_slip is None and can_create_call_slip_from_referral(actor, referral)
        ),
        "is_terminal": referral.status in {ReferralStatusChoices.CLOSED, ReferralStatusChoices.CANCELLED},
    }
def queue_page(
    actor,
    page: PageRequest,
    *,
    query: str | None = None,
    statuses: str | None = None,
    academic_year: str | None = None,
    assignment: str = "all",
    source_types: str | None = None,
    reason_categories: str | None = None,
    order: str = "recent",
) -> dict[str, object]:
    query = _clean(query, limit=MAX_QUERY_LENGTH)
    assignment = _clean(assignment, limit=20).lower() or "all"
    if assignment not in ASSIGNMENT_STATES:
        raise ValidationError()
    order = _clean(order, limit=20).lower() or "recent"
    if order not in QUEUE_ORDERS:
        raise ValidationError()
    status_values = _statuses(statuses)
    source_values = _codes(source_types, SOURCE_TYPES)
    category_values = _codes(reason_categories, REASON_CATEGORIES)
    ay_segment = _academic_year_segment(academic_year)

    queryset = _queue_queryset(actor)
    if status_values:
        queryset = queryset.filter(status__in=status_values)
    if source_values:
        queryset = queryset.filter(source_type__in=source_values)
    if category_values:
        queryset = queryset.filter(reason_category_code__in=category_values)
    if ay_segment:
        queryset = queryset.filter(reference_code__istartswith=f"{REFERRAL_PREFIX}-{ay_segment}-")
    if assignment == "mine":
        queryset = queryset.filter(assigned_counselor_id=actor.pk)
    elif assignment == "unassigned":
        queryset = queryset.filter(assigned_counselor_id__isnull=True)
    if query:
        queryset = queryset.filter(
            Q(reference_code__icontains=query)
            | Q(student__student_profile__student_number__icontains=query)
            | Q(student__first_name__icontains=query)
            | Q(student__last_name__icontains=query)
        )

    ordering = ("updated_at", "pk") if order == "oldest" else ("-updated_at", "-pk")
    queryset = queryset.order_by(*ordering)
    total = queryset.count()
    rows = queryset[page.offset : page.offset + page.page_size]
    return PageResult(
        items=tuple(_project_row(actor, row) for row in rows),
        page=page.page,
        page_size=page.page_size,
        total=total,
    ).as_dict()