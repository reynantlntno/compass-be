"""Staff-safe Call Slip queue queries and projections.

Row scope is owned by the existing Call Slip selectors and policies; this module
only adds bounded queue filtering and an explicit allowlist projection for the
staff-facing Call Slips workspace.
"""

from __future__ import annotations

from django.db.models import Q

from apps.access_control.authority import has_fixed_capability
from apps.access_control.capabilities import Capability
from apps.access_control.display import office_student_display_label
from apps.access_control.rules import is_counselor, is_gco_staff, is_student
from apps.call_slips.models import (
    CallSlip,
    CallSlipDestinationChoices,
    CallSlipModeChoices,
    CallSlipPurposeCodeChoices,
    CallSlipStatusChoices,
)
from apps.call_slips.selectors import (
    _schedule_bucket,
    get_assigned_call_slip_queue,
    get_coverage_call_slip_queue,
    get_head_call_slip_queue,
    get_staff_call_slip_queue,
)
from apps.common.contracts import PageRequest, PageResult, to_json_value
from apps.common.exceptions import ValidationError
from apps.common.references import academic_year_to_segment


QUEUE_STATUSES = frozenset(value for value, _label in CallSlipStatusChoices.choices)
PURPOSE_CODES = frozenset(value for value, _label in CallSlipPurposeCodeChoices.choices)
MODE_CODES = frozenset(value for value, _label in CallSlipModeChoices.choices)
DESTINATION_CODES = frozenset(value for value, _label in CallSlipDestinationChoices.choices)
QUEUE_ORDERS = frozenset({"recent", "oldest"})
ASSIGNMENT_STATES = frozenset({"all", "mine", "unassigned"})
MAX_QUERY_LENGTH = 120
MAX_FILTER_LENGTH = 100
CALL_SLIP_PREFIX = "CSL"


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


def _code(value, allowed):
    value = _clean(value, limit=30).upper()
    if value and value not in allowed:
        raise ValidationError()
    return value


def _academic_year_segment(value) -> str:
    value = _clean(value)
    if not value:
        return ""
    try:
        return academic_year_to_segment(value)
    except Exception:  # invalid academic-year shapes fail closed with a 422
        raise ValidationError() from None


def _queue_queryset(actor):
    from django.db.models import OuterRef, Subquery

    from apps.appointments.models import Appointment
    from apps.referrals.models import Referral

    if is_student(actor):
        base = CallSlip.objects.none()
    elif has_fixed_capability(actor, Capability.CALL_SLIPS_PREPARE):
        base = get_head_call_slip_queue(actor)
    elif is_counselor(actor):
        base = get_assigned_call_slip_queue(actor) | get_coverage_call_slip_queue(actor)
    elif is_gco_staff(actor):
        base = get_staff_call_slip_queue(actor)
    else:
        base = get_head_call_slip_queue(actor)

    # Resolve related references with plain-labeled subqueries instead of joins:
    # Referral rows carry encrypted provenance columns that must never be pulled
    # into queue SELECTs (they also break DISTINCT/COUNT semantics in tests).
    referral_reference = Subquery(
        Referral.objects.filter(pk=OuterRef("referral_id")).values("reference_code")[:1]
    )
    appointment_reference = Subquery(
        Appointment.objects.filter(pk=OuterRef("appointment_id")).values("reference_code")[:1]
    )
    return (
        base.select_related("student", "student__student_profile", "assigned_counselor")
        .annotate(
            _referral_reference=referral_reference,
            _appointment_reference=appointment_reference,
        )
    )


def _project_row(slip) -> dict:
    profile = slip.student.student_profile if hasattr(slip.student, "student_profile") else None
    return {
        "reference_code": slip.reference_code,
        "student_display_name": office_student_display_label(profile) if profile else "Student",
        "student_number": str(profile.student_number).strip()[:50] if profile and profile.student_number else None,
        "source_type": slip.source_type,
        "source_type_label": slip.get_source_type_display(),
        "purpose_code": slip.purpose_code,
        "purpose_label": slip.get_purpose_code_display(),
        "mode_code": slip.mode,
        "mode_label": slip.get_mode_display(),
        "destination_code": slip.destination_code,
        "destination_label": slip.get_destination_code_display(),
        "status": slip.status,
        "status_label": slip.get_status_display(),
        "assignment_state": "Assigned" if slip.assigned_counselor_id else "Unassigned",
        "schedule_bucket": _schedule_bucket(slip.scheduled_start_at),
        "scheduled_start_at": to_json_value(slip.scheduled_start_at),
        "scheduled_end_at": to_json_value(slip.scheduled_end_at),
        "referral_reference": getattr(slip, "_referral_reference", None),
        "appointment_reference": getattr(slip, "_appointment_reference", None),
        "issued_at": to_json_value(slip.issued_at),
        "acknowledged_at": to_json_value(slip.acknowledged_at),
        "created_at": to_json_value(slip.created_at),
        "updated_at": to_json_value(slip.updated_at),
    }
def queue_page(
    actor,
    page: PageRequest,
    *,
    query: str | None = None,
    statuses: str | None = None,
    academic_year: str | None = None,
    assignment: str = "all",
    purpose_codes: str | None = None,
    mode_codes: str | None = None,
    destination_codes: str | None = None,
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
    purpose_values = _codes(purpose_codes, PURPOSE_CODES)
    mode_values = _codes(mode_codes, MODE_CODES)
    destination_values = _codes(destination_codes, DESTINATION_CODES)
    ay_segment = _academic_year_segment(academic_year)

    queryset = _queue_queryset(actor)
    if status_values:
        queryset = queryset.filter(status__in=status_values)
    if purpose_values:
        queryset = queryset.filter(purpose_code__in=purpose_values)
    if mode_values:
        queryset = queryset.filter(mode__in=mode_values)
    if destination_values:
        queryset = queryset.filter(destination_code__in=destination_values)
    if ay_segment:
        queryset = queryset.filter(reference_code__istartswith=f"{CALL_SLIP_PREFIX}-{ay_segment}-")
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
        items=tuple(_project_row(row) for row in rows),
        page=page.page,
        page_size=page.page_size,
        total=total,
    ).as_dict()