from apps.access_control.authority import has_fixed_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import is_active_nonlegacy_actor, owns_user
from apps.audit.services import audit_log


def can_read_notification(user, notification) -> bool:
    """
    Enforces that recipients can only read their own notifications.
    Staff or head roles do NOT grant access to other users' notifications.
    """
    if not is_active_nonlegacy_actor(user) or notification is None:
        return False

    if owns_user(user, notification.recipient_user_id):
        return True

    # Audit policy denial
    audit_log(
        action_type="POLICY_DENIAL",
        event_category="SECURITY",
        target_model="notifications.Notification",
        target_object_id=notification.id,
        actor_user=user,
        source_app="notifications",
        metadata={
            "reason": "Unauthorized access to another user's notification",
            "recipient_id": str(notification.recipient_user_id)
        }
    )
    return False


def can_manage_preferences(user, target_user) -> bool:
    """Users can only manage their own notification preferences."""
    if not is_active_nonlegacy_actor(user) or target_user is None:
        return False
    return owns_user(user, target_user.pk)


def can_view_email_delivery(user) -> bool:
    return has_fixed_capability(user, Capability.NOTIFICATIONS_DELIVERY_OPERATE)


def can_retry_email_delivery(user, delivery) -> bool:
    return can_view_email_delivery(user) and delivery.status in {"failed", "dead"} and delivery.delivery_state != "bounced"
