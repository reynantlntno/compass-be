"""Post-commit invalidation for public-content projections."""

from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from apps.common.cache.invalidation import invalidate_after_commit
from apps.content.models import (
    Announcement,
    ContentPage,
    ContentRevision,
    Resource,
    ServiceGuide,
)


@receiver([post_save, post_delete], sender=Announcement)
@receiver([post_save, post_delete], sender=Resource)
@receiver([post_save, post_delete], sender=ContentPage)
@receiver([post_save, post_delete], sender=ServiceGuide)
@receiver([post_save, post_delete], sender=ContentRevision)
def invalidate_public_content(sender, instance, **kwargs):
    invalidate_after_commit("content_public", "institution")
