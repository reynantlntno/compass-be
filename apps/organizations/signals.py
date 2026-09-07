"""Post-commit invalidation for safe organization metadata caches."""

from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from apps.organizations.models import (
    BrandAsset,
    FormFamily,
    FormRevision,
    AcademicTerm,
    InstitutionProfile,
    OfficeProfile,
    PublicLink,
)
from apps.organizations.cache import (
    invalidate_form_metadata_after_commit,
    invalidate_organization_branding_after_commit,
    invalidate_organization_identity_after_commit,
)


@receiver([post_save, post_delete], sender=InstitutionProfile)
@receiver([post_save, post_delete], sender=OfficeProfile)
@receiver([post_save, post_delete], sender=PublicLink)
def invalidate_identity(sender, instance, **kwargs):
    invalidate_organization_identity_after_commit()


@receiver([post_save, post_delete], sender=BrandAsset)
def invalidate_branding(sender, instance, **kwargs):
    target = f"{getattr(instance, 'institution_id', None) or 'global'}|{getattr(instance, 'asset_type', '')}|{getattr(instance, 'usage_context', '')}"
    invalidate_organization_branding_after_commit(target)


@receiver([post_save, post_delete], sender=FormFamily)
@receiver([post_save, post_delete], sender=FormRevision)
def invalidate_forms(sender, instance, **kwargs):
    key = getattr(instance, "stable_key", None)
    if key is None and getattr(instance, "form_family", None):
        key = getattr(instance.form_family, "stable_key", None)
    invalidate_form_metadata_after_commit(key or "global")


@receiver([post_save, post_delete], sender=AcademicTerm)
def invalidate_academic_term(sender, instance, **kwargs):
    from apps.inventory.cache import invalidate_academic_term_after_commit
    from apps.organizations.cache import invalidate_organization_identity_after_commit

    invalidate_academic_term_after_commit()
    invalidate_organization_identity_after_commit()
