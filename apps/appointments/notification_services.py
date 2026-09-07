"""Privacy-safe appointment notification contracts and outbox handling."""

from apps.notifications.dispatch import enqueue_notification_event, fan_out_notification, safe_display_name


EVENT_COPY = {
    "scheduled": ("Appointment scheduled", "Your appointment schedule is confirmed.", "Scheduled"),
    "declined": ("Appointment update", "The Guidance Office has completed its review.", "Declined"),
    "late_cancellation_requested": ("Cancellation request received", "A late cancellation request needs review.", "Cancellation review requested"),
    "late_cancellation_approved": ("Cancellation confirmed", "Your appointment cancellation was approved.", "Cancellation approved"),
    "late_cancellation_declined": ("Appointment remains scheduled", "Your appointment remains scheduled. Open COMPASS for the current information.", "Scheduled"),
    "cancelled_by_student": ("Appointment cancelled", "The student cancelled the appointment.", "Cancelled"),
    "cancelled_by_office": ("Appointment cancelled", "The Guidance Office cancelled the appointment. Open COMPASS for the current status.", "Cancelled"),
    "session_ready": ("Counseling session ready", "Your counseling session is now available in COMPASS.", "Session ready"),
    "completed": ("Appointment completed", "Your appointment has been marked completed.", "Completed"),
    "no_show": ("Appointment update", "The appointment was marked as not attended.", "No show"),
    "counselor_assigned": ("Counselor assigned", "A counselor assignment has been updated.", "Assigned"),
}


def _notification_type(event):
    return "appointment_session_ready" if event == "session_ready" else (
        "counselor_assigned" if event == "counselor_assigned" else f"appointment_{event}"
    )


def _recipients(event, appointment):
    recipients = []
    if event in {
        "scheduled", "declined", "late_cancellation_approved", "late_cancellation_declined",
        "cancelled_by_office", "session_ready", "completed", "no_show", "counselor_assigned",
    }:
        recipients.append(appointment.student)
    if event in {
        "scheduled", "late_cancellation_requested", "cancelled_by_student", "cancelled_by_office",
        "session_ready", "counselor_assigned",
    } and appointment.assigned_counselor_id:
        recipients.append(appointment.assigned_counselor)
    return recipients


def _context(event, appointment):
    _, _, status_label = EVENT_COPY[event]
    context = {
        "action": event,
        "status": status_label,
        "reference_code": appointment.reference_code,
    }
    if appointment.assigned_counselor_id:
        context["counselor_name"] = safe_display_name(appointment.assigned_counselor, fallback="")
    return context


def enqueue_appointment_event(event, appointment, *, actor=None):
    if event not in EVENT_COPY:
        raise ValueError("Unsupported appointment notification event.")
    enqueue_notification_event(
        f"appointments.{event}",
        {
            "appointment_id": str(appointment.pk),
            "action": event,
            "status": str(appointment.status),
        },
        related_object=appointment,
        event_key=f"appointment:{appointment.pk}:{event}:{appointment.updated_at.isoformat()}",
    )


def _fan_out_appointment_event(event, appointment, event_key):
    title, preview, _ = EVENT_COPY[event]
    context = _context(event, appointment)
    fan_out_notification(
        event_key=event_key,
        notification_type=_notification_type(event),
        recipients=_recipients(event, appointment),
        title=title,
        body_preview=preview,
        related_object=appointment,
        metadata=context,
        email_context=context,
        subject="COMPASS: Appointment Update",
    )


def handle_appointment_event(payload, outbox_event):
    from apps.appointments.models import Appointment

    appointment = Appointment.objects.select_related("student", "assigned_counselor").get(pk=payload["appointment_id"])
    _fan_out_appointment_event(payload["action"], appointment, outbox_event.event_key)


def notify_appointment_event(event, appointment, *, actor=None) -> None:
    """Compatibility entry point for direct callers and focused tests.

    Domain transitions use ``enqueue_appointment_event``.  This function keeps
    the established service-level contract for callers that explicitly ask to
    fan out an already-recorded event.
    """
    if event not in EVENT_COPY:
        raise ValueError("Unsupported appointment notification event.")
    _fan_out_appointment_event(event, appointment, f"appointment:{appointment.pk}:{event}")
