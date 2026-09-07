# Project: COMPASS
# File: apps/organizations/models.py
# Module: organizations
# Purpose: Institution, office, brand asset, form registry, and reference-code models
# Domain boundary and service policy.
#   Section 11 — Form Registry; Section 4 — Reference Codes
# Notes:
#   These models make institution/office identity configurable instead of
#   hardcoded. UCN is the current default; CNSC is retained as legacy metadata.
#   Generated documents must store the profile version used at generation time
#   so later branding changes do not rewrite history.
#   FormFamily/FormRevision implement the source-form registry and version governance.
#   WorkflowReferenceCounter provides a shared, race-safe reference-code counter.

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import F, Q
from contextlib import contextmanager
from contextvars import ContextVar

from apps.common.models import TimestampedModel
from apps.content.validators import validate_safe_external_url
from apps.organizations.academic_year import AcademicYearConfigurationError, validate_academic_year


_ACADEMIC_TERM_LIFECYCLE_WRITE = ContextVar("academic_term_lifecycle_write", default=False)


@contextmanager
def academic_term_lifecycle_write():
    """Allow the organizations lifecycle service to persist a term mutation."""

    token = _ACADEMIC_TERM_LIFECYCLE_WRITE.set(True)
    try:
        yield
    finally:
        _ACADEMIC_TERM_LIFECYCLE_WRITE.reset(token)


# ---------------------------------------------------------------------------
# Status choices shared across governance models
# ---------------------------------------------------------------------------

class GovernanceStatusChoices(models.TextChoices):
    """Lifecycle status for governance-managed records."""

    DRAFT = "DRAFT", "Draft"
    ACTIVE = "ACTIVE", "Active"
    RETIRED = "RETIRED", "Retired"
    ARCHIVED = "ARCHIVED", "Archived"


class AcademicTermStatusChoices(models.TextChoices):
    """Controlled lifecycle for an academic term."""

    DRAFT = "DRAFT", "Draft"
    PENDING_APPROVAL = "PENDING_APPROVAL", "Pending approval"
    APPROVED = "APPROVED", "Approved"
    ACTIVE = "ACTIVE", "Active"
    CLOSED = "CLOSED", "Closed"
    ARCHIVED = "ARCHIVED", "Archived"


class AcademicTermQuerySet(models.QuerySet):
    """Prevent ORM write shortcuts from bypassing the term lifecycle."""

    @staticmethod
    def _assert_lifecycle_write():
        if not _ACADEMIC_TERM_LIFECYCLE_WRITE.get():
            raise ValidationError(
                "Academic terms may only be created or changed through the organizations lifecycle service."
            )

    def update(self, **kwargs):
        self._assert_lifecycle_write()
        return super().update(**kwargs)

    def bulk_create(self, objs, **kwargs):
        self._assert_lifecycle_write()
        return super().bulk_create(objs, **kwargs)

    def bulk_update(self, objs, fields, **kwargs):
        self._assert_lifecycle_write()
        return super().bulk_update(objs, fields, **kwargs)

    def delete(self, *args, **kwargs):
        self._assert_lifecycle_write()
        return super().delete(*args, **kwargs)


class ActivationRegisterStatusChoices(models.TextChoices):
    """Truthful states for decision and runtime activation evidence."""

    PROPOSED = "PROPOSED", "Proposed"
    APPROVED = "APPROVED", "Approved"
    CONFIGURED = "CONFIGURED", "Configured"
    ACTIVE = "ACTIVE", "Active"
    VERIFIED = "VERIFIED", "Verified"
    BLOCKED = "BLOCKED", "Blocked"
    RETIRED = "RETIRED", "Retired"


class FormRevisionStatusChoices(models.TextChoices):
    """Form revision lifecycle with explicit approval boundaries."""

    DRAFT = "DRAFT", "Draft"
    PENDING_APPROVAL = "PENDING_APPROVAL", "Pending approval"
    APPROVED = "APPROVED", "Approved"
    ACTIVE = "ACTIVE", "Active"
    RETIRED = "RETIRED", "Retired"
    ARCHIVED = "ARCHIVED", "Archived"


class AcademicTerm(TimestampedModel):
    """Office-approved academic period used by term-sensitive workflows.

    The one active ``AcademicTerm`` is the canonical source of the current
    academic year.  Public projections may derive ``is_current`` from this
    record's status, but no second persisted representation exists.
    """

    academic_year = models.CharField("academic year", max_length=20)
    semester = models.CharField("semester", max_length=100)
    start_date = models.DateField("start date")
    end_date = models.DateField("end date")
    status = models.CharField(
        "status",
        max_length=24,
        choices=AcademicTermStatusChoices.choices,
        default=AcademicTermStatusChoices.DRAFT,
        db_index=True,
    )
    configuration_identifier = models.CharField(
        "configuration identifier",
        max_length=160,
        blank=True,
        help_text="Migration, deployment, or runbook identifier for this term.",
    )
    source_reference = models.CharField("source reference", max_length=255, blank=True)
    source_note = models.TextField("source note", blank=True)
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="approved_academic_terms",
    )
    approved_at = models.DateTimeField("approved at", blank=True, null=True)
    activated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="activated_academic_terms",
    )
    activated_at = models.DateTimeField("activated at", blank=True, null=True)
    closed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="closed_academic_terms",
    )
    closed_at = models.DateTimeField("closed at", blank=True, null=True)

    objects = AcademicTermQuerySet.as_manager()

    class Meta:
        verbose_name = "academic term"
        verbose_name_plural = "academic terms"
        ordering = ["-start_date", "-pk"]
        constraints = [
            models.UniqueConstraint(
                fields=["academic_year", "semester"],
                name="unique_governed_academic_term",
            ),
            models.UniqueConstraint(
                fields=["status"],
                condition=Q(status=AcademicTermStatusChoices.ACTIVE),
                name="unique_active_academic_term",
            ),
            models.CheckConstraint(
                condition=Q(end_date__gte=F("start_date")),
                name="academic_term_end_on_or_after_start",
            ),
        ]

    def clean(self):
        super().clean()
        try:
            self.academic_year = validate_academic_year(self.academic_year)
        except AcademicYearConfigurationError as exc:
            raise ValidationError({"academic_year": str(exc)}) from exc
        if self.start_date and self.end_date and self.end_date < self.start_date:
            raise ValidationError({"end_date": "End date must be on or after the start date."})
        if self.status == AcademicTermStatusChoices.ACTIVE and not self.configuration_identifier:
            raise ValidationError({"configuration_identifier": "An activation configuration identifier is required."})
        if self.status in {
            AcademicTermStatusChoices.PENDING_APPROVAL,
            AcademicTermStatusChoices.APPROVED,
            AcademicTermStatusChoices.ACTIVE,
            AcademicTermStatusChoices.CLOSED,
        }:
            overlap_qs = type(self).objects.filter(
                status__in=(
                    AcademicTermStatusChoices.PENDING_APPROVAL,
                    AcademicTermStatusChoices.APPROVED,
                    AcademicTermStatusChoices.ACTIVE,
                    AcademicTermStatusChoices.CLOSED,
                ),
                start_date__lte=self.end_date,
                end_date__gte=self.start_date,
            ).exclude(pk=self.pk)
            if overlap_qs.exists():
                raise ValidationError("Official academic terms may not overlap.")
    IMMUTABLE_AFTER_APPROVAL_FIELDS = frozenset({
        "academic_year", "semester", "start_date", "end_date",
        "configuration_identifier", "source_reference", "source_note",
    })

    def save(self, *args, **kwargs):
        if not _ACADEMIC_TERM_LIFECYCLE_WRITE.get():
            raise ValidationError(
                "Academic terms may only be created or changed through the organizations lifecycle service."
            )
        if self.pk:
            persisted = type(self).objects.filter(pk=self.pk).first()
            if persisted and persisted.status in {
                AcademicTermStatusChoices.APPROVED,
                AcademicTermStatusChoices.ACTIVE,
                AcademicTermStatusChoices.CLOSED,
                AcademicTermStatusChoices.ARCHIVED,
            }:
                changed = {
                    field: (getattr(persisted, field), getattr(self, field))
                    for field in self.IMMUTABLE_AFTER_APPROVAL_FIELDS
                    if getattr(persisted, field) != getattr(self, field)
                }
                if changed:
                    raise ValidationError("Approved or historical academic-term meaning is immutable.")
        self.clean()
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        if not _ACADEMIC_TERM_LIFECYCLE_WRITE.get():
            raise ValidationError(
                "Academic terms may only be deleted through the organizations lifecycle service."
            )
        return super().delete(*args, **kwargs)

    def __str__(self):
        return f"{self.academic_year} — {self.semester}"


class AcademicTermTransition(TimestampedModel):
    """Append-only evidence for academic-term lifecycle transitions."""

    term = models.ForeignKey(AcademicTerm, on_delete=models.PROTECT, related_name="transitions")
    action = models.CharField("action", max_length=40)
    from_status = models.CharField("from status", max_length=24, blank=True)
    to_status = models.CharField("to status", max_length=24)
    actor_user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    reason_code = models.CharField("reason code", max_length=80)
    configuration_identifier = models.CharField("configuration identifier", max_length=160, blank=True)
    effective_at = models.DateTimeField("effective at")
    rollback_condition = models.CharField("rollback condition", max_length=255, blank=True)
    rollback_reference = models.CharField("rollback reference", max_length=255, blank=True)
    release_version = models.CharField("release version", max_length=64, blank=True)
    build_id = models.CharField("build id", max_length=128, blank=True)
    safe_evidence = models.JSONField("safe evidence", default=dict, blank=True)

    class Meta:
        ordering = ["-effective_at", "-pk"]

    def save(self, *args, **kwargs):
        if self.pk:
            raise ValidationError("Academic-term transition history is append-only.")
        return super().save(*args, **kwargs)


class ActivationRegisterEntry(TimestampedModel):
    """One current, reconciled decision/activation register item."""

    stable_key = models.SlugField("stable key", max_length=120, unique=True)
    title = models.CharField("title", max_length=255)
    item_type = models.CharField("item type", max_length=60)
    status = models.CharField(
        "status",
        max_length=20,
        choices=ActivationRegisterStatusChoices.choices,
        default=ActivationRegisterStatusChoices.PROPOSED,
        db_index=True,
    )
    source_kind = models.CharField("source kind", max_length=80)
    source_key = models.CharField("source key", max_length=255, blank=True)
    owner_role = models.CharField("owner role", max_length=80, blank=True)
    owner_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="owned_activation_register_entries",
    )
    effective_from = models.DateField("effective from", null=True, blank=True)
    configuration_identifier = models.CharField("configuration identifier", max_length=160, blank=True)
    rollback_condition = models.CharField("rollback condition", max_length=255, blank=True)
    missing_value_code = models.CharField("missing value code", max_length=100, blank=True)
    verification_evidence = models.JSONField("verification evidence", default=dict, blank=True)
    last_verified_at = models.DateTimeField("last verified at", null=True, blank=True)
    last_actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="activation_register_actions",
    )

    class Meta:
        ordering = ["item_type", "stable_key"]

    def __str__(self):
        return f"{self.title} ({self.status})"


class ActivationRegisterTransition(TimestampedModel):
    """Append-only state/evidence history for an activation register item."""

    entry = models.ForeignKey(ActivationRegisterEntry, on_delete=models.PROTECT, related_name="transitions")
    from_status = models.CharField("from status", max_length=20, blank=True)
    to_status = models.CharField("to status", max_length=20)
    actor_user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    reason_code = models.CharField("reason code", max_length=80)
    configuration_identifier = models.CharField("configuration identifier", max_length=160, blank=True)
    evidence = models.JSONField("evidence", default=dict, blank=True)
    release_version = models.CharField("release version", max_length=64, blank=True)
    build_id = models.CharField("build id", max_length=128, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-pk"]

    def save(self, *args, **kwargs):
        if self.pk:
            raise ValidationError("Activation-register transition history is append-only.")
        return super().save(*args, **kwargs)


# ---------------------------------------------------------------------------
# InstitutionProfile
# ---------------------------------------------------------------------------

class InstitutionProfile(TimestampedModel):
    """Configurable institution identity.

    Supports the UCN/CNSC transition by storing both current and former
    names, logos, seals, and brand colors as database records rather
    than hardcoded values in templates or views.
    """

    legal_name = models.CharField(
        "legal name",
        max_length=255,
        help_text="Current official institution name, e.g. University of Camarines Norte.",
    )
    short_name = models.CharField(
        "short name",
        max_length=50,
        help_text="Current abbreviation, e.g. UCN.",
    )
    former_name = models.CharField(
        "former name",
        max_length=255,
        blank=True,
        help_text="Legacy institution name, e.g. Camarines Norte State College.",
    )
    former_short_name = models.CharField(
        "former short name",
        max_length=50,
        blank=True,
        help_text="Legacy abbreviation, e.g. CNSC.",
    )
    address = models.TextField(
        "address",
        blank=True,
    )
    main_campus = models.CharField(
        "main campus",
        max_length=255,
        blank=True,
        help_text="Name or location of the main campus.",
    )
    primary_brand_color = models.CharField(
        "primary brand color",
        max_length=30,
        blank=True,
        help_text="Hex or HSL color value for primary brand, e.g. maroon.",
    )
    secondary_brand_color = models.CharField(
        "secondary brand color",
        max_length=30,
        blank=True,
        help_text="Hex or HSL color value for secondary brand, e.g. gold.",
    )
    accent_brand_color = models.CharField(
        "accent brand color",
        max_length=30,
        blank=True,
    )
    transition_note = models.TextField(
        "transition note",
        blank=True,
        help_text="Notes about institutional name/identity transition.",
    )
    # --- Governance lifecycle fields ---
    status = models.CharField(
        "status",
        max_length=20,
        choices=GovernanceStatusChoices.choices,
        default=GovernanceStatusChoices.DRAFT,
    )
    version_label = models.CharField(
        "version label",
        max_length=50,
        blank=True,
        help_text="Human-readable profile version, e.g. 'v1' or '2026-A'.",
    )
    effective_from = models.DateField(
        "effective from",
        blank=True,
        null=True,
        help_text="Date when this profile version becomes effective.",
    )
    effective_until = models.DateField(
        "effective until",
        blank=True,
        null=True,
        help_text="Date when this profile version ceases to be effective.",
    )
    activated_at = models.DateTimeField(
        "activated at",
        blank=True,
        null=True,
    )
    activated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="activated_institution_profiles",
    )
    retired_at = models.DateTimeField(
        "retired at",
        blank=True,
        null=True,
    )
    retired_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="retired_institution_profiles",
    )
    source_note = models.TextField(
        "source note",
        blank=True,
        help_text="Provenance or authority for this profile version.",
    )

    class Meta:
        verbose_name = "institution profile"
        verbose_name_plural = "institution profiles"
        indexes = [
            models.Index(fields=["status", "effective_from", "effective_until"]),
        ]

    def __str__(self):
        return self.short_name or self.legal_name


# ---------------------------------------------------------------------------
# OfficeProfile
# ---------------------------------------------------------------------------

class OfficeProfile(TimestampedModel):
    """Configurable Guidance and Counseling Office identity.

    Stores office name, contact information, document header details,
    and signatory defaults. Supports the GCO/GTAO transition.
    """

    institution = models.ForeignKey(
        InstitutionProfile,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="offices",
        help_text="Parent institution, if applicable.",
    )
    office_name = models.CharField(
        "office name",
        max_length=255,
        help_text="Current office name, e.g. Guidance and Counseling Office.",
    )
    office_short_name = models.CharField(
        "office short name",
        max_length=50,
        help_text="Current abbreviation, e.g. GCO.",
    )
    legacy_office_name = models.CharField(
        "legacy office name",
        max_length=255,
        blank=True,
        help_text="Former office name, e.g. Guidance, Testing and Admission Office.",
    )
    document_header_name = models.CharField(
        "document header name",
        max_length=255,
        blank=True,
        help_text="Name used in generated document headers.",
    )
    office_address = models.TextField(
        "office address",
        blank=True,
    )
    contact_email = models.EmailField(
        "contact email",
        blank=True,
    )
    contact_number = models.CharField(
        "contact number",
        max_length=50,
        blank=True,
    )
    office_hours = models.CharField(
        "office hours",
        max_length=255,
        blank=True,
    )
    default_signatory_name = models.CharField(
        "default signatory name",
        max_length=255,
        blank=True,
    )
    default_signatory_title = models.CharField(
        "default signatory title",
        max_length=255,
        blank=True,
    )
    footer_note = models.TextField(
        "footer note",
        blank=True,
        help_text="Footer text for generated documents.",
    )
    # --- Governance lifecycle fields ---
    status = models.CharField(
        "status",
        max_length=20,
        choices=GovernanceStatusChoices.choices,
        default=GovernanceStatusChoices.DRAFT,
    )
    version_label = models.CharField(
        "version label",
        max_length=50,
        blank=True,
        help_text="Human-readable office profile version.",
    )
    effective_from = models.DateField(
        "effective from",
        blank=True,
        null=True,
    )
    effective_until = models.DateField(
        "effective until",
        blank=True,
        null=True,
    )
    activated_at = models.DateTimeField(
        "activated at",
        blank=True,
        null=True,
    )
    activated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="activated_office_profiles",
    )
    retired_at = models.DateTimeField(
        "retired at",
        blank=True,
        null=True,
    )
    retired_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="retired_office_profiles",
    )
    source_note = models.TextField(
        "source note",
        blank=True,
        help_text="Provenance or authority for this office profile version.",
    )

    class Meta:
        verbose_name = "office profile"
        verbose_name_plural = "office profiles"
        indexes = [
            models.Index(
                fields=["institution", "status", "effective_from", "effective_until"],
            ),
        ]

    def __str__(self):
        return self.office_short_name or self.office_name


# ---------------------------------------------------------------------------
# BrandAsset choices and model
# ---------------------------------------------------------------------------

class AssetTypeChoices(models.TextChoices):
    """Types of brand/visual assets."""

    LOGO_FULL = "LOGO_FULL", "Full Logo"
    LOGO_MARK = "LOGO_MARK", "Logo Mark"
    SEAL = "SEAL", "Institutional Seal"
    FAVICON = "FAVICON", "Favicon"
    DOCUMENT_HEADER_LOGO = "DOCUMENT_HEADER_LOGO", "Document Header Logo"
    LOGIN_HERO = "LOGIN_HERO", "Login Hero Image"
    PUBLIC_PAGE_LOGO = "PUBLIC_PAGE_LOGO", "Public Page Logo"


class BackgroundVariantChoices(models.TextChoices):
    """Background context for brand assets."""

    LIGHT = "LIGHT", "Light background"
    DARK = "DARK", "Dark background"
    TRANSPARENT = "TRANSPARENT", "Transparent background"
    PRINT = "PRINT", "Print use"


class AssetStatusChoices(models.TextChoices):
    """Lifecycle status for brand assets."""

    PROVISIONAL = "PROVISIONAL", "Provisional"
    ACTIVE = "ACTIVE", "Active"
    RETIRED = "RETIRED", "Retired"
    ARCHIVED = "ARCHIVED", "Archived"


class BrandAssetRoleChoices(models.TextChoices):
    """Semantic meaning of a governed public asset."""

    IDENTITY = "IDENTITY", "Institutional identity"
    CERTIFICATION = "CERTIFICATION", "Certification"
    RECOGNITION = "RECOGNITION", "Recognition"
    CAMPAIGN = "CAMPAIGN", "Campaign"
    PRIVACY_CREDENTIAL = "PRIVACY_CREDENTIAL", "Privacy credential"
    PARTNER = "PARTNER", "Partner"
    PUBLICATION = "PUBLICATION", "Publication"


class BrandAssetOwnerChoices(models.TextChoices):
    INSTITUTION = "INSTITUTION", "Institution"
    OFFICE = "OFFICE", "Office"
    COMPASS = "COMPASS", "COMPASS"
    PARTNER = "PARTNER", "Partner"


class BrandAssetPlacementChoices(models.TextChoices):
    HEADER_IDENTITY = "HEADER_IDENTITY", "Header identity"
    FOOTER_IDENTITY = "FOOTER_IDENTITY", "Footer identity"
    FOOTER_IDENTITY_ROW = "FOOTER_IDENTITY_ROW", "Footer identity row"
    FOOTER_CERTIFICATIONS = "FOOTER_CERTIFICATIONS", "Footer certifications"
    FOOTER_RECOGNITIONS = "FOOTER_RECOGNITIONS", "Footer recognitions"
    FOOTER_PRIVACY_CREDENTIALS = "FOOTER_PRIVACY_CREDENTIALS", "Footer privacy credentials"
    PUBLICATION_MARKS = "PUBLICATION_MARKS", "Publication marks"


class BrandAsset(TimestampedModel):
    """Versioned brand/visual asset for configurable institutional identity.

    Screenshot-extracted logo assets are allowed only as unlinked.
    Official deployment should use authorized source files.
    """

    institution = models.ForeignKey(
        InstitutionProfile,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="brand_assets",
        help_text="Parent institution for this asset.",
    )
    office = models.ForeignKey(
        "organizations.OfficeProfile",
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="brand_assets",
        help_text="Owning office when the asset is office-specific.",
    )
    asset_type = models.CharField(
        "asset type",
        max_length=30,
        choices=AssetTypeChoices.choices,
    )
    semantic_role = models.CharField(
        "semantic role",
        max_length=20,
        choices=BrandAssetRoleChoices.choices,
        default=BrandAssetRoleChoices.IDENTITY,
    )
    owner_type = models.CharField(
        "owner type",
        max_length=20,
        choices=BrandAssetOwnerChoices.choices,
        default=BrandAssetOwnerChoices.INSTITUTION,
    )
    placement = models.CharField(
        "public placement",
        max_length=30,
        choices=BrandAssetPlacementChoices.choices,
        blank=True,
        help_text="Explicit public slot; blank assets are never rendered publicly.",
    )
    display_order = models.PositiveSmallIntegerField(
        "display order",
        default=0,
        help_text="Deterministic order within a public placement.",
    )
    file = models.FileField(
        "asset file",
        upload_to="organizations/brand_assets/",
    )
    alt_text = models.CharField(
        "alt text",
        max_length=255,
        blank=True,
        help_text="Accessible alt text for this asset.",
    )
    usage_context = models.CharField(
        "usage context",
        max_length=255,
        blank=True,
        help_text="Where this asset is intended to be used.",
    )
    background_variant = models.CharField(
        "background variant",
        max_length=20,
        choices=BackgroundVariantChoices.choices,
        default=BackgroundVariantChoices.TRANSPARENT,
    )
    status = models.CharField(
        "status",
        max_length=20,
        choices=AssetStatusChoices.choices,
        default=AssetStatusChoices.PROVISIONAL,
    )
    version_label = models.CharField(
        "version label",
        max_length=50,
        blank=True,
    )
    source_note = models.TextField(
        "source note",
        blank=True,
        help_text="Where this asset came from, e.g. 'extracted from screenshot' or 'official SVG'.",
    )
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="uploaded_brand_assets",
    )

    # --- Governance lifecycle fields ---
    effective_from = models.DateField(
        "effective from",
        blank=True,
        null=True,
    )
    effective_until = models.DateField(
        "effective until",
        blank=True,
        null=True,
    )
    approved_at = models.DateTimeField(
        "approved at",
        blank=True,
        null=True,
    )
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="approved_brand_assets",
    )
    retired_at = models.DateTimeField(
        "retired at",
        blank=True,
        null=True,
    )
    retired_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="retired_brand_assets",
    )
    content_type_hint = models.CharField(
        "content type",
        max_length=100,
        blank=True,
        help_text="MIME type of the uploaded file, e.g. image/svg+xml.",
    )
    file_size_bytes = models.PositiveBigIntegerField(
        "file size (bytes)",
        blank=True,
        null=True,
    )
    original_filename = models.CharField(
        "original filename",
        max_length=255,
        blank=True,
    )
    verification_url = models.URLField(
        "verification URL",
        max_length=2048,
        blank=True,
        validators=[validate_safe_external_url],
    )
    credential_reference = models.CharField(
        "credential or reference",
        max_length=255,
        blank=True,
        help_text="Bounded public reference; do not store secrets or credentials.",
    )
    # privacy.credential_readiness evidence. These fields are
    # metadata only; missing/ambiguous evidence keeps the public projection
    # pending rather than inventing a holder or certification claim.
    credential_holder = models.CharField("credential holder", max_length=255, blank=True)
    credential_issuer = models.CharField("credential issuer", max_length=255, blank=True)
    credential_verified_at = models.DateTimeField("credential verified at", blank=True, null=True)
    credential_source_reference = models.CharField("credential source reference", max_length=500, blank=True)
    image_width = models.PositiveIntegerField("image width", blank=True, null=True)
    image_height = models.PositiveIntegerField("image height", blank=True, null=True)

    def clean(self):
        super().clean()
        errors = {}
        if self.verification_url:
            try:
                validate_safe_external_url(self.verification_url)
            except ValidationError as exc:
                errors["verification_url"] = exc.messages
        if self.owner_type == BrandAssetOwnerChoices.OFFICE and not self.office_id:
            errors["office"] = "An office owner is required for office assets."
        if self.owner_type == BrandAssetOwnerChoices.OFFICE and self.institution_id:
            errors["institution"] = "Office assets cannot reference an institution directly."
        if self.owner_type == BrandAssetOwnerChoices.INSTITUTION and not self.institution_id:
            errors["institution"] = "An institution owner is required for institution assets."
        if self.owner_type == BrandAssetOwnerChoices.INSTITUTION and self.office_id:
            errors["office"] = "Institution assets cannot reference an office directly."
        if self.owner_type in {
            BrandAssetOwnerChoices.COMPASS,
            BrandAssetOwnerChoices.PARTNER,
        } and (self.institution_id or self.office_id):
            errors["owner_type"] = "COMPASS and partner assets cannot carry institution or office ownership."
        if self.office_id and self.institution_id and self.office.institution_id != self.institution_id:
            errors["office"] = "The office must belong to the selected institution."
        if self.image_width is not None and not 1 <= self.image_width <= 4096:
            errors["image_width"] = "Image width must be between 1 and 4096 pixels."
        if self.image_height is not None and not 1 <= self.image_height <= 1200:
            errors["image_height"] = "Image height must be between 1 and 1200 pixels."
        if self.file_size_bytes is not None and self.file_size_bytes > 5 * 1024 * 1024:
            errors["file_size_bytes"] = "Brand assets are limited to 5 MiB."
        if self.effective_from and self.effective_until and self.effective_until < self.effective_from:
            errors["effective_until"] = "Effective until must not precede effective from."
        if self.asset_type == AssetTypeChoices.SEAL and self.placement != BrandAssetPlacementChoices.FOOTER_PRIVACY_CREDENTIALS:
            errors["placement"] = "Seal assets may only use the footer privacy-credential placement."
        if self.semantic_role == BrandAssetRoleChoices.PRIVACY_CREDENTIAL and self.placement != BrandAssetPlacementChoices.FOOTER_PRIVACY_CREDENTIALS:
            errors["placement"] = "Privacy credentials must use the footer privacy-credential placement."
        if self.placement == BrandAssetPlacementChoices.FOOTER_PRIVACY_CREDENTIALS:
            if self.asset_type != AssetTypeChoices.SEAL:
                errors["asset_type"] = "Footer privacy credentials must use a seal asset."
            if self.semantic_role != BrandAssetRoleChoices.PRIVACY_CREDENTIAL:
                errors["semantic_role"] = "Footer privacy credentials must use the privacy-credential role."
        if (
            self.semantic_role == BrandAssetRoleChoices.PRIVACY_CREDENTIAL
            or self.placement == BrandAssetPlacementChoices.FOOTER_PRIVACY_CREDENTIALS
        ):
            if self.owner_type != BrandAssetOwnerChoices.INSTITUTION:
                errors["owner_type"] = "Privacy credentials must be institution-owned."
            if not self.institution_id:
                errors["institution"] = "Privacy credentials require an institution owner."
            if self.office_id:
                errors["office"] = "Privacy credentials cannot reference an office."
        if errors:
            raise ValidationError(errors)

    class Meta:
        verbose_name = "brand asset"
        verbose_name_plural = "brand assets"
        indexes = [
            models.Index(
                fields=["institution", "asset_type", "status", "updated_at"],
            ),
            models.Index(
                fields=["placement", "display_order", "status"],
                name="org_brand_public_slot_idx",
            ),
        ]

    def __str__(self):
        return f"{self.get_asset_type_display()} ({self.get_status_display()})"


class PublicLinkOwnerChoices(models.TextChoices):
    INSTITUTION = "INSTITUTION", "Institution"
    OFFICE = "OFFICE", "Office"
    COMPASS = "COMPASS", "COMPASS"
    PARTNER = "PARTNER", "Partner"


class PublicLinkTypeChoices(models.TextChoices):
    WEBSITE = "WEBSITE", "Website"
    OFFICE = "OFFICE", "Office destination"
    SERVICE = "SERVICE", "Service"
    POLICY = "POLICY", "Policy"
    PARTNER = "PARTNER", "Partner"
    OTHER = "OTHER", "Other approved link"


class PublicLinkPlacementChoices(models.TextChoices):
    FOOTER = "FOOTER", "Footer"
    HEADER = "HEADER", "Header"
    ABOUT = "ABOUT", "About"


class PublicLink(TimestampedModel):
    """Explicitly governed public destination.

    Legacy JSON link arrays remain on the profile models for compatibility,
    but are intentionally not projected by the approved public footer.
    """

    owner_type = models.CharField(
        "owner type",
        max_length=20,
        choices=PublicLinkOwnerChoices.choices,
    )
    institution = models.ForeignKey(
        InstitutionProfile,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="governed_public_links",
    )
    office = models.ForeignKey(
        OfficeProfile,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="governed_public_links",
    )
    link_type = models.CharField(
        "link type",
        max_length=20,
        choices=PublicLinkTypeChoices.choices,
        default=PublicLinkTypeChoices.OTHER,
    )
    label = models.CharField("label", max_length=120)
    url = models.URLField(
        "HTTPS URL",
        max_length=2048,
        validators=[validate_safe_external_url],
    )
    placement = models.CharField(
        "placement",
        max_length=20,
        choices=PublicLinkPlacementChoices.choices,
        default=PublicLinkPlacementChoices.FOOTER,
    )
    display_order = models.PositiveSmallIntegerField("display order", default=0)
    status = models.CharField(
        "status",
        max_length=20,
        choices=GovernanceStatusChoices.choices,
        default=GovernanceStatusChoices.DRAFT,
    )
    effective_from = models.DateField(blank=True, null=True)
    effective_until = models.DateField(blank=True, null=True)
    approved_at = models.DateTimeField(blank=True, null=True)
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="approved_public_links",
    )
    source_note = models.TextField(
        blank=True,
        help_text="Provenance or authority note; never store credentials or tokens.",
    )

    def clean(self):
        super().clean()
        errors = {}
        try:
            validate_safe_external_url(self.url)
        except ValidationError as exc:
            errors["url"] = exc.messages
        relation_count = sum(bool(value) for value in (self.institution_id, self.office_id))
        if self.owner_type == PublicLinkOwnerChoices.INSTITUTION and self.institution_id is None:
            errors["institution"] = "Institution ownership requires an institution."
        if self.owner_type == PublicLinkOwnerChoices.OFFICE and self.office_id is None:
            errors["office"] = "Office ownership requires an office."
        if self.owner_type in {
            PublicLinkOwnerChoices.COMPASS,
            PublicLinkOwnerChoices.PARTNER,
        } and relation_count:
            errors["owner_type"] = "This owner type cannot reference an institution or office."
        if self.owner_type == PublicLinkOwnerChoices.INSTITUTION and self.office_id:
            errors["office"] = "Institution links cannot reference an office."
        if self.owner_type == PublicLinkOwnerChoices.OFFICE and self.institution_id:
            errors["institution"] = "Office links cannot reference an institution directly."
        if self.effective_from and self.effective_until and self.effective_until < self.effective_from:
            errors["effective_until"] = "Effective until must not precede effective from."
        if not self.label.strip():
            errors["label"] = "A meaningful label is required."
        if errors:
            raise ValidationError(errors)

    class Meta:
        verbose_name = "public link"
        verbose_name_plural = "public links"
        indexes = [
            models.Index(
                fields=["owner_type", "placement", "status", "display_order"],
                name="org_public_link_owner_idx",
            ),
            models.Index(
                fields=["url", "status"],
                name="org_public_link_url_idx",
            ),
        ]

    def __str__(self):
        return self.label


# ---------------------------------------------------------------------------
# FormFamily
# ---------------------------------------------------------------------------

class FormFamily(TimestampedModel):
    """Stable registry entry for a logical official form family.

    Each family (e.g. 'referral_slip', 'call_slip') may have multiple
    FormRevision records representing different official and internal versions.
    """

    stable_key = models.SlugField(
        "stable key",
        max_length=80,
        unique=True,
        help_text="Unique slug for this form family, e.g. 'referral_slip'.",
    )
    display_name = models.CharField(
        "display name",
        max_length=255,
    )
    description = models.TextField(
        "description",
        blank=True,
    )
    owner_office = models.ForeignKey(
        OfficeProfile,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="owned_form_families",
        help_text="Office that owns this form family.",
    )
    status = models.CharField(
        "status",
        max_length=20,
        choices=GovernanceStatusChoices.choices,
        default=GovernanceStatusChoices.DRAFT,
    )
    current_active_revision = models.OneToOneField(
        "organizations.FormRevision",
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="+",
        help_text="Cached pointer to the currently active revision.",
    )
    source_notes = models.TextField(
        "source notes",
        blank=True,
    )
    class Meta:
        verbose_name = "form family"
        verbose_name_plural = "form families"
        indexes = [
            models.Index(fields=["status"]),
        ]

    def __str__(self):
        return f"{self.display_name} ({self.stable_key})"


# ---------------------------------------------------------------------------
# FormRevision
# ---------------------------------------------------------------------------

class FormRevision(TimestampedModel):
    """Versioned official source-form metadata and internal version registry.

    Tracks both the official printed revision (e.g. '1' for CNSC-OP-GTA-01F9
    Rev 1) and the internal COMPASS schema/template version separately.
    Once active or used, meaning-bearing fields become immutable.
    """

    form_family = models.ForeignKey(
        FormFamily,
        on_delete=models.PROTECT,
        related_name="revisions",
    )
    official_form_code = models.CharField(
        "official form code",
        max_length=50,
        blank=True,
        help_text="Official document-control code, e.g. CNSC-OP-GTA-01F9. Blank when unknown.",
    )
    legacy_form_code = models.CharField(
        "legacy form code",
        max_length=50,
        blank=True,
        help_text="Previous/legacy document-control code if superseded.",
    )
    official_revision = models.CharField(
        "official revision",
        max_length=20,
        blank=True,
        help_text="Official printed revision label, e.g. '0' or '1'. Blank when unknown.",
    )
    internal_schema_version = models.CharField(
        "internal schema version",
        max_length=30,
        default="1",
        help_text="COMPASS internal schema version for this form.",
    )
    internal_template_version = models.CharField(
        "internal template version",
        max_length=30,
        blank=True,
        help_text="COMPASS internal template version for generated documents.",
    )
    display_title = models.CharField(
        "display title",
        max_length=255,
        blank=True,
        help_text="Human-readable title for this revision.",
    )
    institution_profile = models.ForeignKey(
        InstitutionProfile,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="form_revisions",
    )
    office_profile = models.ForeignKey(
        OfficeProfile,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="form_revisions",
    )
    institution_profile_snapshot = models.JSONField(
        "institution profile snapshot",
        default=dict,
        blank=True,
        help_text="Frozen institution identity at activation time.",
    )
    office_profile_snapshot = models.JSONField(
        "office profile snapshot",
        default=dict,
        blank=True,
        help_text="Frozen office identity at activation time.",
    )
    effective_from = models.DateField(
        "effective from",
        blank=True,
        null=True,
    )
    effective_until = models.DateField(
        "effective until",
        blank=True,
        null=True,
    )
    status = models.CharField(
        "status",
        max_length=20,
        choices=FormRevisionStatusChoices.choices,
        default=GovernanceStatusChoices.DRAFT,
    )
    source_document_reference = models.CharField(
        "source document reference",
        max_length=500,
        blank=True,
        help_text="Repo path or official label for the source document.",
    )
    source_notes = models.TextField(
        "source notes",
        blank=True,
    )
    source_protected_file = models.ForeignKey(
        "security.ProtectedFile",
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="form_revision_sources",
        help_text="Protected controlling source attachment, when supplied.",
    )
    source_label = models.CharField(
        "source label",
        max_length=255,
        blank=True,
        help_text="Safe human-readable source label; never a raw path or secret.",
    )
    source_checksum = models.CharField("source checksum", max_length=64, blank=True)
    schema_summary_json = models.JSONField(
        "schema summary",
        default=dict,
        blank=True,
        help_text="Metadata-only summary of fields. Not a full form builder.",
    )
    printable_template_path = models.CharField(
        "printable template path",
        max_length=500,
        blank=True,
        help_text="Optional template path for future generated documents.",
    )
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="approved_form_revisions",
    )
    approved_at = models.DateTimeField(
        "approved at",
        blank=True,
        null=True,
    )
    submitted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="submitted_form_revisions",
    )
    submitted_at = models.DateTimeField("submitted at", blank=True, null=True)
    activated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="activated_form_revisions",
    )
    activated_at = models.DateTimeField("activated at", blank=True, null=True)
    retired_at = models.DateTimeField(
        "retired at",
        blank=True,
        null=True,
    )
    retired_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="retired_form_revisions",
    )
    is_used = models.BooleanField(
        "is used",
        default=False,
        help_text="Set to True once any workflow record references this revision.",
    )
    first_used_at = models.DateTimeField(
        "first used at",
        blank=True,
        null=True,
    )

    class Meta:
        verbose_name = "form revision"
        verbose_name_plural = "form revisions"
        constraints = [
            models.UniqueConstraint(
                fields=[
                    "form_family",
                    "official_form_code",
                    "official_revision",
                    "internal_schema_version",
                    "internal_template_version",
                ],
                name="unique_form_revision_version_tuple",
            ),
            models.UniqueConstraint(
                fields=["form_family"],
                condition=Q(status=FormRevisionStatusChoices.ACTIVE),
                name="unique_active_form_revision_per_family",
            ),
        ]
        indexes = [
            models.Index(
                fields=["form_family", "status", "official_form_code", "effective_from"],
            ),
        ]

    # Meaning-bearing fields that become immutable once active or used.
    IMMUTABLE_AFTER_USE_FIELDS = frozenset({
        "form_family",
        "official_form_code",
        "official_revision",
        "internal_schema_version",
        "internal_template_version",
        "display_title",
        "schema_summary_json",
        "printable_template_path",
        "source_document_reference",
        "source_protected_file",
        "source_label",
        "source_checksum",
        "institution_profile_snapshot",
        "office_profile_snapshot",
    })

    def _immutable_field_value(self, field_name):
        if field_name == "form_family":
            return self.form_family_id
        return getattr(self, field_name)

    def clean(self):
        super().clean()
        if not self.pk:
            return

        persisted = type(self).objects.filter(pk=self.pk).first()
        if not persisted:
            return
        if (
            persisted.status != GovernanceStatusChoices.ACTIVE
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
                field_name: "Meaning-bearing form revision fields are immutable once active or used."
                for field_name in changed_fields
            })

    def save(self, *args, **kwargs):
        self.clean()
        return super().save(*args, **kwargs)

    def __str__(self):
        code = self.official_form_code or self.form_family.stable_key
        rev = self.official_revision or "?"
        return f"{code} Rev {rev} (schema {self.internal_schema_version})"


# ---------------------------------------------------------------------------
# WorkflowReferenceCounter
# ---------------------------------------------------------------------------

class WorkflowReferenceCounter(TimestampedModel):
    """Central reference-code counter for future workflows.

    Each row tracks the last issued sequence number for a given
    prefix/period combination. Uses row-level locking for race safety.

    This model lives in apps.organizations as shared infrastructure storage;
    allocation mechanics are implemented by ``apps.common.references``.
    """

    KNOWN_PREFIXES = (
        ("APT", "Appointment"),
        ("REF", "Referral"),
        ("CSL", "Call Slip"),
        ("SES", "Counseling Session"),
        ("CAS", "Counseling Case"),
        ("ECS", "E-Counseling"),
        ("ESC", "Urgent Support"),
        ("GMC", "Good Moral"),
        ("EIT", "Exit Interview"),
        ("GTS", "Graduate Tracer Survey"),
        ("FBK", "Feedback / CSM"),
        ("DOC", "Generated Document"),
        ("CNT", "Contact / Suggestion"),
    )
    KNOWN_PREFIX_CODES = frozenset({
        "APT", "REF", "CSL", "SES", "CAS", "ECS", "ESC", "GMC", "EIT", "GTS", "FBK", "DOC", "CNT",
    })

    prefix = models.CharField(
        "prefix",
        max_length=10,
        choices=KNOWN_PREFIXES,
        help_text="Reference code prefix, e.g. GMC, DOC.",
    )
    period_key = models.CharField(
        "period key",
        max_length=30,
        help_text="Academic year or calendar period, e.g. '2025-2026'.",
    )
    last_sequence = models.PositiveIntegerField(
        "last sequence",
        default=0,
    )
    description = models.CharField(
        "description",
        max_length=255,
        blank=True,
    )

    class Meta:
        verbose_name = "workflow reference counter"
        verbose_name_plural = "workflow reference counters"
        constraints = [
            models.UniqueConstraint(
                fields=["prefix", "period_key"],
                name="unique_prefix_period",
            ),
        ]
        indexes = [
            models.Index(fields=["prefix", "period_key"]),
        ]

    def __str__(self):
        return f"{self.prefix} / {self.period_key} → {self.last_sequence}"

    def clean(self):
        super().clean()
        if self.prefix not in self.KNOWN_PREFIX_CODES:
            raise ValidationError({
                "prefix": "Unknown workflow reference-code prefix."
            })

    def save(self, *args, **kwargs):
        self.clean()
        return super().save(*args, **kwargs)
