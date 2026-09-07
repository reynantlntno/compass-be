"""Post-commit invalidation for notification-template definitions."""

from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from apps.notifications.cache import invalidate_notification_template_after_commit
from apps.notifications.models import NotificationTemplate


@receiver([post_save, post_delete], sender=NotificationTemplate)
def invalidate_notification_template(sender, instance, **kwargs):
    invalidate_notification_template_after_commit(getattr(instance, "stable_key", "global"))
