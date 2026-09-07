"""Transactional Good Moral notification events."""

from apps.notifications.dispatch import enqueue_notification_event, fan_out_notification


GOOD_MORAL_COPY = {
    "generated": ("Good Moral document generated", "Your Good Moral document is being prepared for release.", "Generated", "good_moral_generated", "normal"),
    "released": ("Good Moral certificate released", "Your printed and signed Good Moral certificate has been released to you. Any Registrar dry-seal confirmation is recorded separately.", "Released", "good_moral_released", "normal"),
    "rejected": ("Good Moral request update", "Your Good Moral request requires attention.", "Rejected", "good_moral_rejected", "normal"),
}


def enqueue_good_moral_event(event, request, *, reason_label=""):
    # ``reason_label`` remains accepted for service compatibility, but free
    # text/reason values are never persisted in notification payloads.
    enqueue_notification_event(
        f"good_moral.{event}",
        {
            "request_reference": request.reference_code,
        },
        related_object=request,
        event_key=f"good_moral:{request.reference_code}:{event}:{request.updated_at.isoformat()}",
    )


def handle_good_moral_event(payload, outbox_event):
    from apps.good_moral.models import GoodMoralRequest

    request = GoodMoralRequest.objects.select_related("requester_user").get(
        reference_code=payload["request_reference"]
    )
    action = outbox_event.event_type.rsplit(".", 1)[-1]
    title, preview, status_label, notification_type, priority = GOOD_MORAL_COPY[action]
    context = {
        "action": status_label,
        "status": status_label,
        "reference_code": request.reference_code,
    }
    fan_out_notification(
        event_key=outbox_event.event_key,
        notification_type=notification_type,
        recipients=[request.requester_user],
        title=title,
        body_preview=preview,
        related_object=request,
        metadata=context,
        email_context=context,
        subject="COMPASS: Good Moral Request Update",
        priority=priority,
    )
