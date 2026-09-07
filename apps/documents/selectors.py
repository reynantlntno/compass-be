# Project: COMPASS
# File: apps/documents/selectors.py
# Module: apps.documents
# Purpose: Scope-filtered metadata selectors and safe DTOs for document models
# Domain boundary and service policy.
# Notes:
#   Selectors return safe metadata only. No existence leaks.
#   No protected object keys, signed URLs, or private filenames in DTOs.

from apps.documents.models import (
    DocumentTemplate,
    DocumentTemplateVersion,
    GeneratedDocument,
    TemplateStatusChoices,
)


# ---------------------------------------------------------------------------
# Template selectors
# ---------------------------------------------------------------------------

def get_active_template(stable_key: str):
    """Return the active DocumentTemplate for a stable_key, or None."""
    try:
        template = DocumentTemplate.objects.get(stable_key=stable_key)
    except DocumentTemplate.DoesNotExist:
        return None
    if template.status == TemplateStatusChoices.ACTIVE:
        return template
    return None


def get_active_template_version(stable_key: str):
    """Return the single active DocumentTemplateVersion for a template, or None.

    Fail-closed: returns None when missing or ambiguous.
    """
    template = get_active_template(stable_key)
    if not template:
        return None

    active_versions = list(
        DocumentTemplateVersion.objects.filter(
            template=template,
            status=TemplateStatusChoices.ACTIVE,
        ).order_by("-approved_at", "-pk")[:2]
    )
    if len(active_versions) != 1:
        return None
    return active_versions[0]


def get_template_version_by_id(version_id):
    """Return a DocumentTemplateVersion by ID, or None."""
    try:
        return DocumentTemplateVersion.objects.select_related("template").get(pk=version_id)
    except DocumentTemplateVersion.DoesNotExist:
        return None


# ---------------------------------------------------------------------------
# Generated document selectors
# ---------------------------------------------------------------------------

def get_generated_document_by_reference_code(reference_code: str):
    """Return a GeneratedDocument by reference code, or None.

    Does not reveal existence vs non-existence (generic None).
    """
    try:
        return GeneratedDocument.objects.select_related(
            "template_version",
            "template_version__template",
        ).get(reference_code=reference_code)
    except GeneratedDocument.DoesNotExist:
        return None


def get_generated_document_by_id(document_id):
    """Return a GeneratedDocument by UUID, or None."""
    try:
        return GeneratedDocument.objects.select_related(
            "template_version",
            "template_version__template",
        ).get(pk=document_id)
    except GeneratedDocument.DoesNotExist:
        return None


# ---------------------------------------------------------------------------
# Safe metadata DTOs
# ---------------------------------------------------------------------------

def template_metadata_dto(template) -> dict:
    """Build a safe metadata DTO for a DocumentTemplate."""
    if not template:
        return {}
    return {
        "id": template.pk,
        "stable_key": template.stable_key,
        "display_name": template.display_name,
        "document_kind": template.document_kind,
        "status": template.status,
        "default_output_format": template.default_output_format,
        "retention_classification": template.retention_classification,
    }


def template_version_metadata_dto(version) -> dict:
    """Build a safe metadata DTO for a DocumentTemplateVersion."""
    if not version:
        return {}
    return {
        "id": version.pk,
        "template_stable_key": version.template.stable_key,
        "version_label": version.version_label,
        "internal_template_version": version.internal_template_version,
        "renderer_backend": version.renderer_backend,
        "output_format": version.output_format,
        "status": version.status,
        "is_used": version.is_used,
    }


def generated_document_metadata_dto(document) -> dict:
    """Build a safe metadata DTO for a GeneratedDocument.

    No protected object keys, signed URLs, private filenames,
    student names/numbers, counseling notes, or referral reasons.
    """
    if not document:
        return {}
    return {
        "id": str(document.pk),
        "reference_code": document.reference_code,
        "document_status": document.document_status,
        "template_stable_key": document.template_version.template.stable_key,
        "template_version_label": document.template_version.version_label,
        "generated_at": document.generated_at.isoformat() if document.generated_at else None,
        "content_hash": document.content_hash,
    }
