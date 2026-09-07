"""Post-commit invalidation for onboarding catalog display metadata."""

from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from apps.imports.cache import invalidate_onboarding_catalog_after_commit
from apps.imports.models import OnboardingCatalog, OnboardingProgram


@receiver([post_save, post_delete], sender=OnboardingCatalog)
@receiver([post_save, post_delete], sender=OnboardingProgram)
def invalidate_onboarding_catalog(sender, instance, **kwargs):
    invalidate_onboarding_catalog_after_commit()
