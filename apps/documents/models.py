# Project: COMPASS
# File: apps/documents/models.py
# Module: apps.documents
# Purpose: Document template, template version, and generated document metadata models
# Domain boundary and service policy.
# Notes:
#   DocumentTemplate is a stable logical template family for generated/printed documents.
#   DocumentTemplateVersion is immutable versioned render/template metadata.
#   GeneratedDocument is metadata for rendered generated outputs.
#   Generated files go through apps.security.ProtectedFile.
#   Reference codes are lookup aids only, never authorization tokens.

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q

from apps.common.models import TimestampedModel
from apps.documents.renderers import (
    RendererError,
    validate_stylesheet_path_safety,
    validate_template_path_safety,
)


# ---------------------------------------------------------------------------
# Choices
# ---------------------------------------------------------------------------

class DocumentKindChoices(models.TextChoices):
    """Types of documents that can be generated."""

    CERTIFICATE = "CERTIFICATE", "Certificate"
    OFFICIAL_FORM = "OFFICIAL_FORM", "Official Form"
    RELEASE_RECORD = "RELEASE_RECORD", "Release Record"
    REPORT_EXPORT = "REPORT_EXPORT", "Report Export"
    SUMMARY = "SUMMARY", "Summary"


class TemplateStatusChoices(models.TextChoices):
    """Lifecycle status for document templates and versions."""

    DRAFT = "DRAFT", "Draft"
    ACTIVE = "ACTIVE", "Active"
    RETIRED = "RETIRED", "Retired"
    ARCHIVED = "ARCHIVED", "Archived"


class OutputFormatChoices(models.TextChoices):
    """Supported output formats."""

    HTML = "HTML", "HTML"
    PDF = "PDF", "PDF"


class RendererBackendChoices(models.TextChoices):
    """Available renderer backends."""

    HTML_ONLY = "HTML_ONLY", "HTML Only"
    PLAYWRIGHT_PDF = "PLAYWRIGHT_PDF", "Playwright PDF"


class DocumentStatusChoices(models.TextChoices):
    """Lifecycle status for generated documents."""

    DRAFT = "DRAFT", "Draft"
    GENERATED = "GENERATED", "Generated"
    RELEASED = "RELEASED", "Released"
    VOIDED = "VOIDED", "Voided"
    ARCHIVED = "ARCHIVED", "Archived"
    FAILED = "FAILED", "Failed"


class RetentionClassificationChoices(models.TextChoices):
    """Retention classification for document templates."""

    STANDARD = "STANDARD", "Standard"
    OFFICIAL_RECORD = "OFFICIAL_RECORD", "Official Record"
    CONFIDENTIAL = "CONFIDENTIAL", "Confidential"
    TEMPORARY = "TEMPORARY", "Temporary"


# ---------------------------------------------------------------------------
# DocumentTemplate
# ---------------------------------------------------------------------------

class DocumentTemplate(TimestampedModel):
    """Stable logical template family for generated/printed documents.

    Each template family (e.g. 'good_moral_student', 'call_slip') may have
    multiple DocumentTemplateVersion records representing different versioned
    render configurations.
    """

    stable_key = models.SlugField(
        "stable key",
        max_length=80,
        unique=True,
        help_text="Unique slug for this template family, e.g. 'good_moral_student'.",
    )
    display_name = models.CharField(
        "display name",
        max_length=255,
    )
    document_kind = models.CharField(
        "document kind",
        max_length=30,
        choices=DocumentKindChoices.choices,
    )
    related_form_family = models.ForeignKey(
        "organizations.FormFamily",
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="document_templates",
        help_text="Related source form family, if applicable.",
    )
    owner_office = models.ForeignKey(
        "organizations.OfficeProfile",
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="owned_document_templates",
        help_text="Office that owns this template family.",
    )
    status = models.CharField(
        "status",
        max_length=20,
        choices=TemplateStatusChoices.choices,
        default=TemplateStatusChoices.DRAFT,
    )
    description = models.TextField(
        "description",
        blank=True,
    )
    default_output_format = models.CharField(
        "default output format",
        max_length=10,
        choices=OutputFormatChoices.choices,
        default=OutputFormatChoices.HTML,
    )
    retention_classification = models.CharField(
        "retention classification",
        max_length=30,
        choices=RetentionClassificationChoices.choices,
        default=RetentionClassificationChoices.STANDARD,
    )
    access_policy_key = models.CharField(
        "access policy key",
        max_length=100,
        blank=True,
        help_text="Default access policy key for generated documents from this template.",
    )
    source_notes = models.TextField(
        "source notes",
        blank=True,
    )

    class Meta:
        verbose_name = "document template"
        verbose_name_plural = "document templates"
        indexes = [
            models.Index(fields=["status", "document_kind"]),
        ]

    def __str__(self):
        return f"{self.display_name} ({self.stable_key})"


# ---------------------------------------------------------------------------
# DocumentTemplateVersion
# ---------------------------------------------------------------------------

class DocumentTemplateVersion(TimestampedModel):
    """Immutable versioned render/template metadata.

    Once active or used, meaning-bearing fields become immutable.
    Changes require clone-to-draft. Activation must use services.
    """

    template = models.ForeignKey(
        DocumentTemplate,
        on_delete=models.PROTECT,
        related_name="versions",
    )
    version_label = models.CharField(
        "version label",
        max_length=50,
        help_text="Human-readable version label, e.g. 'v1.0'.",
    )
    related_form_revision = models.ForeignKey(
        "organizations.FormRevision",
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="document_template_versions",
        help_text="Related form revision for official forms.",
    )
    internal_template_version = models.CharField(
        "internal template version",
        max_length=30,
        default="1",
        help_text="COMPASS internal template version for this render configuration.",
    )
    template_path = models.CharField(
        "template path",
        max_length=500,
        help_text="Path to the Django template file, e.g. 'documents/print/good_moral_student/v1.html'.",
    )
    stylesheet_path = models.CharField(
        "stylesheet path",
        max_length=500,
        blank=True,
        help_text="Path to the print CSS stylesheet, if any.",
    )
    renderer_backend = models.CharField(
        "renderer backend",
        max_length=30,
        choices=RendererBackendChoices.choices,
        default=RendererBackendChoices.HTML_ONLY,
    )
    output_format = models.CharField(
        "output format",
        max_length=10,
        choices=OutputFormatChoices.choices,
        default=OutputFormatChoices.HTML,
    )

    # Page settings
    page_size = models.CharField(
        "page size",
        max_length=30,
        default="LETTER",
        help_text="Paper size, e.g. LETTER, A4, LEGAL.",
    )
    page_orientation = models.CharField(
        "page orientation",
        max_length=20,
        default="portrait",
        help_text="Page orientation: portrait or landscape.",
    )
    page_margins_json = models.JSONField(
        "page margins",
        default=dict,
        blank=True,
        help_text="Margins in mm, e.g. {'top': 25, 'right': 25, 'bottom': 25, 'left': 25}.",
    )

    # Context schema metadata (not a form builder)
    required_context_schema_json = models.JSONField(
        "required context schema",
        default=dict,
        blank=True,
        help_text="Metadata-only schema describing required context fields. Not a form builder.",
    )

    # Immutable snapshots frozen at activation
    institution_profile_snapshot = models.JSONField(
        "institution profile snapshot",
        default=dict,
        blank=True,
    )
    office_profile_snapshot = models.JSONField(
        "office profile snapshot",
        default=dict,
        blank=True,
    )
    brand_asset_snapshot = models.JSONField(
        "brand asset snapshot",
        default=dict,
        blank=True,
    )
    form_revision_snapshot = models.JSONField(
        "form revision snapshot",
        default=dict,
        blank=True,
    )

    # Lifecycle
    status = models.CharField(
        "status",
        max_length=20,
        choices=TemplateStatusChoices.choices,
        default=TemplateStatusChoices.DRAFT,
    )
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="approved_document_template_versions",
    )
    approved_at = models.DateTimeField(
        "approved at",
        blank=True,
        null=True,
    )
    retired_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="retired_document_template_versions",
    )
    retired_at = models.DateTimeField(
        "retired at",
        blank=True,
        null=True,
    )

    # Usage tracking
    is_used = models.BooleanField(
        "is used",
        default=False,
        help_text="Set to True once any generated document references this version.",
    )
    first_used_at = models.DateTimeField(
        "first used at",
        blank=True,
        null=True,
    )

    # Checksum and notes
    template_checksum = models.CharField(
        "template checksum",
        max_length=64,
        blank=True,
        help_text="SHA-256 checksum of the template file, if computed.",
    )
    source_notes = models.TextField(
        "source notes",
        blank=True,
    )

    # Meaning-bearing fields that become immutable once active or used
    IMMUTABLE_AFTER_USE_FIELDS = frozenset({
        "template",
        "version_label",
        "related_form_revision",
        "internal_template_version",
        "template_path",
        "stylesheet_path",
        "renderer_backend",
        "output_format",
        "page_size",
        "page_orientation",
        "page_margins_json",
        "required_context_schema_json",
        "institution_profile_snapshot",
        "office_profile_snapshot",
        "brand_asset_snapshot",
        "form_revision_snapshot",
    })

    class Meta:
        verbose_name = "document template version"
        verbose_name_plural = "document template versions"
        constraints = [
            models.UniqueConstraint(
                fields=["template", "version_label", "internal_template_version"],
                name="unique_template_version_tuple",
            ),
            models.UniqueConstraint(
                fields=["template"],
                condition=Q(status=TemplateStatusChoices.ACTIVE),
                name="unique_active_template_version_per_template",
            ),
        ]
        indexes = [
            models.Index(fields=["template", "status"]),
        ]

    def _immutable_field_value(self, field_name):
        if field_name == "template":
            return self.template_id
        if field_name == "related_form_revision":
            return self.related_form_revision_id
        return getattr(self, field_name)

    def clean(self):
        super().clean()
        errors = {}
        try:
            validate_template_path_safety(self.template_path)
        except RendererError as exc:
            errors["template_path"] = str(exc)
        try:
            validate_stylesheet_path_safety(self.stylesheet_path)
        except RendererError as exc:
            errors["stylesheet_path"] = str(exc)
        if errors:
            raise ValidationError(errors)
        if self.status == TemplateStatusChoices.ACTIVE and self.template_id:
            duplicate_active = type(self).objects.filter(
                template_id=self.template_id,
                status=TemplateStatusChoices.ACTIVE,
            )
            if self.pk:
                duplicate_active = duplicate_active.exclude(pk=self.pk)
            if duplicate_active.exists():
                raise ValidationError({
                    "status": "Only one active template version is allowed per template."
                })

        if not self.pk:
            return

        persisted = type(self).objects.filter(pk=self.pk).first()
        if not persisted:
            return
        if (
            persisted.status != TemplateStatusChoices.ACTIVE
            and not persisted.is_used
        ):
            return

        changed_fields = [
            field_name
            for field_name in self.IMMUTABLE_AFTER_USE_FIELDS
            if self._immutable_field_value(field_name)
            != persisted._immutable_field_value(field_name)
        ]
        if changed_fields:
            raise ValidationError({
                field_name: "Meaning-bearing template version fields are immutable once active or used."
                for field_name in changed_fields
            })

    def save(self, *args, **kwargs):
        self.clean()
        return super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.template.stable_key} {self.version_label} ({self.get_status_display()})"


# ---------------------------------------------------------------------------
# GeneratedDocument
# ---------------------------------------------------------------------------

class GeneratedDocument(TimestampedModel):
    """Metadata for rendered generated outputs.

    Generated files are stored through apps.security.ProtectedFile.
    Reference codes are lookup aids only, never authorization tokens.
    No student numbers, names, counseling topics, or case details in
    reference codes, filenames, object keys, or audit metadata.
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    reference_code = models.CharField(
        "reference code",
        max_length=30,
        unique=True,
        help_text="Generated DOC-prefix reference code. Lookup aid only, not authorization.",
    )
    template_version = models.ForeignKey(
        DocumentTemplateVersion,
        on_delete=models.PROTECT,
        related_name="generated_documents",
    )
    form_revision = models.ForeignKey(
        "organizations.FormRevision",
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="generated_documents",
    )
    protected_file = models.ForeignKey(
        "security.ProtectedFile",
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="generated_documents",
        help_text="Protected file storing the rendered output.",
    )
    generated_for_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="generated_documents_for",
        help_text="User this document was generated for, if applicable.",
    )

    # Generic owner tuple
    owning_app_label = models.CharField(
        "owning app label",
        max_length=100,
        blank=True,
    )
    owning_model_name = models.CharField(
        "owning model name",
        max_length=100,
        blank=True,
    )
    owning_object_id = models.CharField(
        "owning object id",
        max_length=255,
        blank=True,
    )

    # Status
    document_status = models.CharField(
        "document status",
        max_length=20,
        choices=DocumentStatusChoices.choices,
        default=DocumentStatusChoices.DRAFT,
    )

    # Generation metadata
    generated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="generated_documents_by",
    )
    generated_at = models.DateTimeField(
        "generated at",
        blank=True,
        null=True,
    )

    # Release metadata
    released_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="released_documents",
    )
    released_at = models.DateTimeField(
        "released at",
        blank=True,
        null=True,
    )

    # Void metadata
    voided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="voided_documents",
    )
    voided_at = models.DateTimeField(
        "voided at",
        blank=True,
        null=True,
    )
    void_reason_code = models.CharField(
        "void reason code",
        max_length=50,
        blank=True,
        help_text="Safe reason code for voiding, e.g. 'error', 'duplicate', 'superseded'.",
    )

    # Immutable snapshots
    generation_context_snapshot_json = models.JSONField(
        "generation context snapshot",
        default=dict,
        blank=True,
        help_text="Audit-safe metadata snapshot of the generation context. No sensitive content.",
    )
    template_version_snapshot = models.JSONField(
        "template version snapshot",
        default=dict,
        blank=True,
    )
    institution_profile_snapshot = models.JSONField(
        "institution profile snapshot",
        default=dict,
        blank=True,
    )
    office_profile_snapshot = models.JSONField(
        "office profile snapshot",
        default=dict,
        blank=True,
    )
    form_revision_snapshot = models.JSONField(
        "form revision snapshot",
        default=dict,
        blank=True,
    )
    brand_asset_snapshot = models.JSONField(
        "brand asset snapshot",
        default=dict,
        blank=True,
    )
    renderer_snapshot = models.JSONField(
        "renderer snapshot",
        default=dict,
        blank=True,
        help_text="Renderer backend/version metadata at generation time.",
    )

    # Content hash
    content_hash = models.CharField(
        "content hash",
        max_length=64,
        blank=True,
        help_text="SHA-256 hash of the rendered output content.",
    )

    # Access policy
    access_policy_key = models.CharField(
        "access policy key",
        max_length=100,
        blank=True,
    )

    # Retention
    retention_hold = models.BooleanField(
        "retention hold",
        default=False,
    )

    class Meta:
        verbose_name = "generated document"
        verbose_name_plural = "generated documents"
        indexes = [
            models.Index(fields=["document_status"]),
            models.Index(fields=["reference_code"]),
            models.Index(fields=["owning_app_label", "owning_model_name", "owning_object_id"]),
            models.Index(fields=["template_version", "document_status"]),
        ]

    def __str__(self):
        return f"{self.reference_code} ({self.get_document_status_display()})"
