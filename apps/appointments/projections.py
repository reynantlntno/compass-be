"""Fixed JSON projection boundary for the appointments domain.

Only named projection functions with explicit allowlists may be added here.
Raw model instances, QuerySets, encrypted fields, secrets, and arbitrary
metadata must not be returned to a client.

The authoritative per-actor field allowlist lives in
``apps.appointments.selectors.appointment_view_projection``. The named tiers
below are the only entry points API adapters may call.
"""

from apps.common.contracts import to_json_object, to_json_value

from apps.access_control.rules import is_active_nonlegacy_actor, is_counselor
from apps.appointments.selectors import (
    appointment_view_projection,
    get_available_slots,
)


def project_appointment_for_actor(actor, appointment) -> dict | None:
    """Return the actor-scoped appointment projection, or ``None``.

    Students receive their own safe fields only; assigned counselors,
    coverage-matching counselors, scoped GCO Staff, and Head Guidance each
    receive their own confirmed tier. Unauthorized actors receive ``None``
    instead of serializing ORM objects.
    """
    if appointment is None:
        return None
    payload = appointment_view_projection(actor, appointment)
    if payload is None:
        return None
    return to_json_object(payload)


def project_available_slots(actor, counselor, slot_date, mode: str) -> list[dict]:
    """Return bounded availability slots as JSON-safe values."""
    if (
        not is_active_nonlegacy_actor(actor)
        or counselor is None
        or not is_active_nonlegacy_actor(counselor)
        or not is_counselor(counselor)
    ):
        return []
    slots = get_available_slots(counselor, slot_date, mode)
    return [
        {
            "start": to_json_value(slot["start"]),
            "end": to_json_value(slot["end"]),
            "max_appointments_per_slot": int(slot["max_appointments_per_slot"]),
        }
        for slot in slots
    ]


def project_office_closure(closure) -> dict:
    """Return the bounded schedule metadata safe for authenticated readers."""
    return {
        "public_reference": to_json_value(closure.public_reference),
        "date": to_json_value(closure.date),
        "start_time": to_json_value(closure.start_time),
        "end_time": to_json_value(closure.end_time),
        "is_all_day": bool(closure.is_all_day),
    }
