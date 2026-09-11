"""Actor-aware query boundary for the appointments domain.

Query functions compose an existing scoped selector with a fixed projection
and never return HTTP responses or serialize ORM objects directly. Selectors
return scoped QuerySets/models or ``None``; queries return projections or
``PageResult`` envelopes.
"""

from datetime import date as date_type

from django.db.models import Case, DateField, F, Q, TimeField, When

from apps.common.contracts import PageRequest, PageResult, page_items, page_queryset

from django.contrib.auth import get_user_model

from apps.appointments.models import (
    Appointment,
    AppointmentModeChoices,
    AppointmentStatusChoices,
    AppointmentTypeChoices,
    AvailabilityRule,
    OfficeClosure,
    UnavailableBlock,
)
from apps.appointments.projections import (
    project_appointment_for_actor,
    project_available_slots,
    project_office_closure,
)
from apps.appointments.selectors import (
    get_appointments_visible_to,
)
from apps.access_control.rules import is_student


APPOINTMENT_STATUSES = frozenset(AppointmentStatusChoices.values)
APPOINTMENT_TYPES = frozenset(AppointmentTypeChoices.values)
APPOINTMENT_MODES = frozenset(AppointmentModeChoices.values)
ASSIGNMENT_FILTERS = frozenset({"all", "mine", "unassigned"})
ORDER_VALUES = frozenset({"recent", "upcoming"})
MAX_SEARCH_LENGTH = 120


def _effective_date_expression():
    return Case(
        When(confirmed_date__isnull=False, then=F("confirmed_date")),
        default=F("requested_date"),
        output_field=DateField(),
    )


def _effective_start_time_expression():
    return Case(
        When(confirmed_start_time__isnull=False, then=F("confirmed_start_time")),
        default=F("requested_start_time"),
        output_field=TimeField(),
    )


def _parse_statuses(value):
    if value is None or not str(value).strip():
        return None
    statuses = tuple(dict.fromkeys(
        item.strip().upper()
        for item in str(value).split(",")
        if item.strip()
    ))
    if not statuses or len(statuses) > len(APPOINTMENT_STATUSES):
        raise ValueError("Invalid appointment status filter.")
    if any(item not in APPOINTMENT_STATUSES for item in statuses):
        raise ValueError("Invalid appointment status filter.")
    return statuses


def _filtered_appointment_queryset(
    actor,
    *,
    q=None,
    statuses=None,
    appointment_type=None,
    appointment_mode=None,
    assignment="all",
    date_from: date_type | None = None,
    date_to: date_type | None = None,
    order="recent",
):
    if q is not None and len(str(q).strip()) > MAX_SEARCH_LENGTH:
        raise ValueError("Appointment search is too long.")
    if appointment_type and appointment_type.upper() not in APPOINTMENT_TYPES:
        raise ValueError("Invalid appointment type filter.")
    if appointment_mode and appointment_mode.upper() not in APPOINTMENT_MODES:
        raise ValueError("Invalid appointment mode filter.")
    if assignment not in ASSIGNMENT_FILTERS:
        raise ValueError("Invalid appointment assignment filter.")
    if order not in ORDER_VALUES:
        raise ValueError("Invalid appointment order.")
    if date_from and date_to and date_from > date_to:
        raise ValueError("Appointment date range is inverted.")

    queryset = get_appointments_visible_to(actor).select_related(
        "student",
        "student__student_profile",
        "assigned_counselor",
    )

    parsed_statuses = _parse_statuses(statuses)
    if parsed_statuses:
        queryset = queryset.filter(status__in=parsed_statuses)
    if appointment_type:
        queryset = queryset.filter(appointment_type=appointment_type.upper())
    if appointment_mode:
        queryset = queryset.filter(appointment_mode=appointment_mode.upper())
    if assignment == "mine":
        queryset = queryset.filter(assigned_counselor_id=getattr(actor, "pk", None))
    elif assignment == "unassigned":
        queryset = queryset.filter(assigned_counselor_id__isnull=True)

    queryset = queryset.annotate(
        _effective_appointment_date=_effective_date_expression(),
        _effective_appointment_start_time=_effective_start_time_expression(),
    )
    if date_from:
        queryset = queryset.filter(_effective_appointment_date__gte=date_from)
    if date_to:
        queryset = queryset.filter(_effective_appointment_date__lte=date_to)

    search = str(q or "").strip()
    if search:
        search_filter = Q(reference_code__icontains=search)
        # Appointment visibility is already applied before this predicate.
        # Student identity fields are intentionally the only profile fields
        # searchable from this queue; email and control number never enter the
        # query.
        if not is_student(actor):
            # Match every display-name token independently so a normal
            # "First Last" search works without ever widening into email,
            # control-number, or raw-user-id fields.
            identity_filter = Q()
            for term in search.split():
                identity_filter &= (
                    Q(student__first_name__icontains=term)
                    | Q(student__last_name__icontains=term)
                    | Q(student__student_profile__student_number__icontains=term)
                )
            search_filter |= identity_filter
        queryset = queryset.filter(search_filter)

    if order == "upcoming":
        queryset = queryset.order_by(
            F("_effective_appointment_date").asc(nulls_last=True),
            F("_effective_appointment_start_time").asc(nulls_last=True),
            "-updated_at",
            "-pk",
        )
    else:
        queryset = queryset.order_by("-updated_at", "-pk")
    return queryset


def scoped_appointment_page(
    actor,
    page: PageRequest | None = None,
    *,
    q=None,
    statuses=None,
    appointment_type=None,
    appointment_mode=None,
    assignment="all",
    date_from: date_type | None = None,
    date_to: date_type | None = None,
    order="recent",
) -> PageResult[dict]:
    """Return the actor-scoped appointment list as a projection page."""
    result = page_queryset(
        _filtered_appointment_queryset(
            actor,
            q=q,
            statuses=statuses,
            appointment_type=appointment_type,
            appointment_mode=appointment_mode,
            assignment=assignment,
            date_from=date_from,
            date_to=date_to,
            order=order,
        ),
        page or PageRequest(),
        lambda appointment: project_appointment_for_actor(actor, appointment),
    )
    return PageResult(
        items=tuple(result["items"]),
        page=result["page"],
        page_size=result["page_size"],
        total=result["total"],
    )


def appointment_detail(actor, reference_code: str) -> dict | None:
    """Return one appointment projection by immutable reference code."""
    normalized = str(reference_code or "").strip()
    if not normalized:
        return None
    appointment = (
        get_appointments_visible_to(actor)
        .select_related("student", "student__student_profile", "assigned_counselor")
        .filter(reference_code=normalized)
        .first()
    )
    return project_appointment_for_actor(actor, appointment)


def available_slots_page(
    actor,
    counselor_id: int | None,
    slot_date,
    mode: str,
    page: PageRequest | None = None,
) -> PageResult[dict]:
    """Return JSON-safe availability slots for one counselor and date."""
    User = get_user_model()
    counselor = None
    if counselor_id is not None:
        counselor = User.objects.filter(pk=counselor_id, is_active=True).first()
    slots = project_available_slots(actor, counselor, slot_date, mode)
    return page_items(slots, page or PageRequest())


def active_office_closure_page(
    actor,
    page: PageRequest | None = None,
) -> PageResult[dict]:
    """Return bounded safe metadata for active office closures."""
    from apps.access_control.rules import is_active_nonlegacy_actor

    request = page or PageRequest()
    if not is_active_nonlegacy_actor(actor):
        return PageResult(items=(), page=request.page, page_size=request.page_size, total=0)
    queryset = OfficeClosure.objects.filter(is_active=True).order_by("date", "start_time", "pk")
    result = page_queryset(
        queryset,
        request,
        project_office_closure,
    )
    return PageResult(
        items=tuple(result["items"]),
        page=result["page"],
        page_size=result["page_size"],
        total=result["total"],
    )


def replay_appointment(reference_code: str) -> dict | None:
    """Safe idempotent-replay projection for appointment mutations.

    Replay responses are intentionally limited to non-sensitive identity
    fields; they never include actor-specific or private detail fields.
    """
    appointment = Appointment.objects.filter(reference_code=str(reference_code or "").strip()).first()
    if appointment is None:
        return None
    return {
        "reference_code": appointment.reference_code,
        "status": appointment.status,
    }


def replay_by_id(object_id) -> dict | None:
    """Resolve an idempotency-related appointment id into a safe projection."""
    appointment = Appointment.objects.filter(pk=object_id).first()
    if appointment is None:
        return None
    return {
        "reference_code": appointment.reference_code,
        "status": appointment.status,
    }


def replay_schedule_change_by_id(object_id, target_model: str) -> dict | None:
    """Return the bounded result for a replayed schedule-management mutation."""
    model = {
        "AvailabilityRule": AvailabilityRule,
        "UnavailableBlock": UnavailableBlock,
        "OfficeClosure": OfficeClosure,
    }.get(str(target_model or ""))
    if model is None:
        return None
    record = model.objects.filter(pk=object_id).first()
    if record is None:
        return None
    return {
        "kind": model.__name__,
        "public_reference": str(record.public_reference),
        "is_active": bool(record.is_active),
    }
