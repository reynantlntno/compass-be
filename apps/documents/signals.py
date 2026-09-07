"""Post-commit invalidation for template metadata caches."""

from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from apps.documents.models import DocumentTemplate, DocumentTemplateVersion
from apps.documents.cache import invalidate_document_metadata_after_commit


@receiver([post_save, post_delete], sender=DocumentTemplate)
@receiver([post_save, post_delete], sender=DocumentTemplateVersion)
def invalidate_template_metadata(sender, instance, **kwargs):
    template = getattr(instance, "template", None)
    target = getattr(template, "stable_key", None) or getattr(instance, "stable_key", None) or "global"
    invalidate_document_metadata_after_commit(target)
