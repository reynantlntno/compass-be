"""Cache invalidation hooks for Governance policy records."""

from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from apps.governance.cache import invalidate_policy_after_commit
from apps.governance.models import PolicyRecord


def _invalidate(policy):
    invalidate_policy_after_commit(policy.key, policy.target_type, policy.target_reference)


@receiver(post_save, sender=PolicyRecord)
def invalidate_policy_cache_after_save(sender, instance, **kwargs):
    _invalidate(instance)


@receiver(post_delete, sender=PolicyRecord)
def invalidate_policy_cache_after_delete(sender, instance, **kwargs):
    _invalidate(instance)
