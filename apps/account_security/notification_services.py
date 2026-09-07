"""Transactional account-security notification events."""

from apps.notifications.dispatch import enqueue_notification_event, fan_out_notification
from apps.notifications.services import enqueue_email_from_template, build_email_delivery_key


SECURITY_COPY = {
    "password_changed": ("Password changed", "Your COMPASS password was changed.", "Confirmed", "high"),
    "device_revoked": ("Trusted device revoked", "A trusted device was revoked from your account.", "Device revoked", "normal"),
    "session_terminated": ("Session terminated", "A COMPASS session was terminated.", "Session terminated", "normal"),
}


def enqueue_security_event(event, user, *, source_id="", device_label=""):
    enqueue_notification_event(
        f"account_security.{event}",
        {
            "user_id": str(user.pk),
            "source_id": str(source_id or user.pk),
            "action": "security_event",
            "status": "Confirmed",
            "device_label": device_label,
        },
        event_key=f"account_security:{event}:{user.pk}:{source_id or user.pk}",
    )


def handle_security_event(payload, outbox_event):
    from django.contrib.auth import get_user_model

    user = get_user_model().objects.get(pk=payload["user_id"])
    event = outbox_event.event_type.rsplit(".", 1)[-1]
    title, preview, status_label, priority = SECURITY_COPY[event]
    metadata = {"action": "security_event", "status": status_label}
    if payload.get("device_label"):
        metadata["device_label"] = payload["device_label"]
    fan_out_notification(
        event_key=outbox_event.event_key,
        notification_type=event,
        recipients=[user],
        title=title,
        body_preview=preview,
        related_object=None,
        metadata=metadata,
        priority=priority,
    )


def handle_recovery_requested_event(payload, outbox_event):
    """Create the queued recovery email without persisting a bearer token."""
    from apps.account_security.models import AccountRecoveryRequest
    from django.utils import timezone

    recovery_request = AccountRecoveryRequest.objects.select_related("user").get(
        pk=payload["recovery_request_id"],
    )
    if recovery_request.status != "pending" or recovery_request.expires_at <= timezone.now():
        return
    user = recovery_request.user
    if not user or not user.is_active:
        return
    context = {"recovery_request_id": str(recovery_request.id)}
    delivery_key = build_email_delivery_key(
        recipient_user=user,
        template_key="account_recovery",
        context=context,
        related_object=recovery_request,
        purpose=outbox_event.event_key,
    )
    enqueue_email_from_template(
        recipient_user=user,
        template_key="account_recovery",
        context=context,
        subject="COMPASS account recovery",
        related_object=recovery_request,
        delivery_key=delivery_key,
        purpose=outbox_event.event_key,
        preference_type="account_recovery",
        respect_preferences=False,
    )
