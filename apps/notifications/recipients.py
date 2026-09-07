"""Recipient resolution helpers for notification outbox handlers."""

from apps.accounts.models import RoleChoices, User


def active_guidance_users():
    """Return active business-role Guidance users; never include IT admins."""
    return User.objects.filter(
        role__in=(RoleChoices.COUNSELOR, RoleChoices.GCO_STAFF),
        is_active=True,
        is_superuser=False,
    ).select_related("counselor_profile")


def authorized_queue_readers(policy, record):
    """Evaluate a record policy for every active Guidance queue reader."""
    return [user for user in active_guidance_users() if policy(user, record)]
