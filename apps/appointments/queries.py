"""Actor-aware query boundary for the appointments domain.

Query functions compose an existing scoped selector with a fixed projection
and never return HTTP responses or serialize ORM objects directly. Selectors
return scoped QuerySets/models or ``None``; queries return projections or
``PageResult`` envelopes.
"""

from apps.common.contracts import PageRequest, PageResult, page_items, page_queryset

from django.contrib.auth import get_user_model

from apps.appointments.models import (
    Appointment,
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


def _ordered_visible(actor):
    return (
        get_appointments_visible_to(actor)
        .select_related(
            "student",
            "student__student_profile",
            "assigned_counselor",
        )
        .order_by("-updated_at", "-pk")
    )


def scoped_appointment_page(actor, page: PageRequest | None = None) -> PageResult[dict]:
    """Return the actor-scoped appointment list as a projection page."""
    result = page_queryset(
        _ordered_visible(actor),
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
