from uuid import UUID

from apps.notifications.models import Notification, NotificationPreference, EmailDelivery
from apps.access_control.rules import is_active_nonlegacy_actor
from apps.notifications.policies import can_view_email_delivery


def get_user_notifications(user, status_filter=None):
    """
    Returns a scoped queryset of notifications owned by the user.
    Ensures users cannot access others' notifications.
    """
    if not is_active_nonlegacy_actor(user):
        return Notification.objects.none()
    qs = Notification.objects.filter(recipient_user_id=user.pk)
    if status_filter:
        if isinstance(status_filter, list):
            qs = qs.filter(status__in=status_filter)
        else:
            qs = qs.filter(status=status_filter)
    return qs.order_by("-created_at")


def get_user_notification_by_id(user, notification_id):
    """Return one owned notification or ``None`` without leaking existence."""
    if not is_active_nonlegacy_actor(user):
        return None
    try:
        value = UUID(str(notification_id))
    except (TypeError, ValueError, AttributeError):
        return None
    return Notification.objects.filter(
        pk=value,
        recipient_user_id=user.pk,
    ).first()


def get_user_preferences(user):
    """Retrieves notification preference overrides for the user."""
    if not is_active_nonlegacy_actor(user):
        return NotificationPreference.objects.none()
    return NotificationPreference.objects.filter(user_id=user.pk).order_by("notification_type")


def get_email_delivery_by_id(actor, delivery_id):
    """Retrieve technical delivery metadata only for IT authority."""
    if not can_view_email_delivery(actor):
        return None
    if not is_active_nonlegacy_actor(actor):
        return None
    try:
        value = UUID(str(delivery_id))
    except (TypeError, ValueError, AttributeError):
        return None
    return EmailDelivery.objects.filter(pk=value).first()


def get_email_deliveries(actor, *, status_filter=None, delivery_state=None, template_key=None):
    """Return only technical delivery rows for an authorized IT actor."""
    if not is_active_nonlegacy_actor(actor) or not can_view_email_delivery(actor):
        return EmailDelivery.objects.none()
    queryset = EmailDelivery.objects.all()
    if status_filter:
        queryset = queryset.filter(status=status_filter)
    if delivery_state:
        queryset = queryset.filter(delivery_state=delivery_state)
    if template_key:
        queryset = queryset.filter(template_key=template_key)
    return queryset.order_by("-created_at")
