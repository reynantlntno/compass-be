"""Transactional call-slip notification events and outbox handling."""

from apps.notifications.dispatch import enqueue_notification_event, fan_out_notification, safe_display_name


CALL_SLIP_COPY = {
    "issued": ("Call slip issued", "A call slip has been issued.", "Issued", "call_slip_issued", "high"),
    "rescheduled": ("Call slip reschedule", "A call slip reschedule decision is available.", "Rescheduled", "call_slip_rescheduled", "normal"),
    "completed": ("Call slip completed", "Your call slip has been marked completed.", "Completed", "call_slip_completed", "normal"),
    "no_show": ("Call slip update", "The call slip was marked as not attended.", "No show", "call_slip_no_show", "normal"),
    "cancelled": ("Call slip cancelled", "Your call slip was cancelled.", "Cancelled", "call_slip_cancelled", "high"),
    "expired": ("Call slip expired", "Your call slip is no longer active.", "Expired", "call_slip_expired", "normal"),
}


def enqueue_call_slip_event(event, slip, *, action=None):
    if event not in CALL_SLIP_COPY:
        raise ValueError("Unsupported call slip notification event.")
    action = action or event
    enqueue_notification_event(
        f"call_slip.{event}",
        {
            "call_slip_id": str(slip.pk),
            "action": action,
            "status": str(slip.status),
        },
        related_object=slip,
        event_key=f"call_slip:{slip.pk}:{event}:{slip.updated_at.isoformat()}",
    )


def handle_call_slip_event(payload, outbox_event):
    from apps.call_slips.models import CallSlip

    slip = CallSlip.objects.select_related("student", "assigned_counselor").get(pk=payload["call_slip_id"])
    title, preview, status_label, notification_type, priority = CALL_SLIP_COPY[payload["action"]]
    context = {
        "action": payload["action"],
        "status": status_label,
        "reference_code": slip.reference_code,
        "office_name": slip.get_destination_code_display(),
    }
    fan_out_notification(
        event_key=outbox_event.event_key,
        notification_type=notification_type,
        recipients=[slip.student],
        title=title,
        body_preview=preview,
        related_object=slip,
        metadata={"action": payload["action"], "status": status_label, "reference_code": slip.reference_code, "office_name": context["office_name"]},
        email_context=context,
        subject="COMPASS: Call Slip Update",
        priority=priority,
    )
