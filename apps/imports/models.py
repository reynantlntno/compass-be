# Project: COMPASS
# File: apps/imports/models.py
# Module: apps.imports
# Purpose: Models for tracking student import batches and individual rows
# Domain boundary and service policy.

from django.conf import settings
from django.db import models

from apps.common.models import TimestampedModel
from apps.profiles.models import StudentLifecycleChoices


class StudentImportBatchStatus(models.TextChoices):
    """Execution status choices for student import batches."""
    DRAFT = "DRAFT", "Draft"
    VALIDATED = "VALIDATED", "Validated"
    IMPORTED = "IMPORTED", "Imported"
    PARTIALLY_IMPORTED = "PARTIALLY_IMPORTED", "Partially Imported"
    FAILED = "FAILED", "Failed"
    ARCHIVED = "ARCHIVED", "Archived"
    NEEDS_REVIEW = "NEEDS_REVIEW", "Needs manual review"
    APPROVED = "APPROVED", "Approved for execution"
    EXECUTING = "EXECUTING", "Executing"
    EXECUTED = "EXECUTED", "Executed"
    SUPERSEDED = "SUPERSEDED", "Superseded"


class RowValidationStatus(models.TextChoices):
    """Validation and execution status choices for individual import rows."""
    PENDING = "PENDING", "Pending"
    VALID = "VALID", "Valid"
    INVALID = "INVALID", "Invalid"
    IMPORTED = "IMPORTED", "Imported"
    SKIPPED = "SKIPPED", "Skipped"
    MANUAL_REVIEW = "MANUAL_REVIEW", "Manual review"
    RECONCILED_EXISTING = "RECONCILED_EXISTING", "Reconciled to existing profile"
    EXCLUDED = "EXCLUDED", "Explicitly excluded"
    PROVISIONED = "PROVISIONED", "Account provisioned"
    SUPERSEDED = "SUPERSEDED", "Superseded"


class OnboardingCatalogAuthority(models.TextChoices):
    APPROVED = "APPROVED", "Institutionally approved"
    DEMO_ONLY = "DEMO_ONLY", "Synthetic demo only"


class OnboardingCatalog(TimestampedModel):
    """Versioned catalog authority for the student onboarding importer."""

    version = models.CharField(max_length=80, unique=True)
    authority = models.CharField(
        max_length=20,
        choices=OnboardingCatalogAuthority.choices,
        default=OnboardingCatalogAuthority.DEMO_ONLY,
    )
    is_active = models.BooleanField(default=False)
    source_reference = models.CharField(max_length=255, blank=True)
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="approved_onboarding_catalogs",
    )
    approved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "student onboarding catalog"
        verbose_name_plural = "student onboarding catalogs"

    def __str__(self):
        return self.version


class OnboardingProgram(TimestampedModel):
    """Canonical campus/college/program placement for one catalog version."""

    catalog = models.ForeignKey(
        OnboardingCatalog,
        on_delete=models.CASCADE,
        related_name="programs",
    )
    program_code = models.CharField(max_length=100)
    campus = models.CharField(max_length=100)
    college = models.CharField(max_length=100)
    department = models.CharField(max_length=100)
    program = models.CharField(max_length=100)
    max_year_level = models.PositiveIntegerField(default=4)
    is_active = models.BooleanField(default=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["catalog", "program_code"],
                name="uniq_onboarding_program_catalog_code",
            )
        ]
        ordering = ["program_code"]

    def __str__(self):
        return f"{self.catalog.version}:{self.program_code}"


class StudentImportBatch(TimestampedModel):
    """Represents a batch run of student records imported into the system.

    Tracks staging status, source information, academic target, and key
    actors responsible for creation, validation, and final execution.
    """
    source_name = models.CharField(
        "source name",
        max_length=255,
        help_text="Name or description of the import source (e.g., OSSD Admission List)."
    )
    academic_year = models.CharField(
        "academic year",
        max_length=50,
        help_text="Target academic year for the import batch (e.g., 2026-2027)."
    )
    status = models.CharField(
        "batch status",
        max_length=30,
        choices=StudentImportBatchStatus.choices,
        default=StudentImportBatchStatus.DRAFT,
        help_text="Operational workflow stage of the batch."
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_batches",
        help_text="User who created/uploaded this import batch."
    )
    validated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="validated_batches",
        help_text="User who executed validation checks on this batch."
    )
    validated_at = models.DateTimeField(
        "validated at",
        null=True,
        blank=True,
        help_text="Timestamp when validation was run."
    )
    executed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="executed_batches",
        help_text="User who executed account provisioning for this batch."
    )
    executed_at = models.DateTimeField(
        "executed at",
        null=True,
        blank=True,
        help_text="Timestamp when account provisioning was executed."
    )
    template_version = models.CharField(max_length=40, blank=True, default="")
    catalog_version = models.CharField(max_length=80, blank=True, default="")
    content_hmac = models.CharField(max_length=64, blank=True, default="", db_index=True)
    validation_revision = models.PositiveIntegerField(default=0)
    validation_digest = models.CharField(max_length=64, blank=True, default="")
    replacement_of = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="replacements",
    )
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="approved_student_onboarding_batches",
    )
    approved_at = models.DateTimeField(null=True, blank=True)
    approved_digest = models.CharField(max_length=64, blank=True, default="")
    approval_revoked_at = models.DateTimeField(null=True, blank=True)
    approval_revocation_reason = models.CharField(max_length=80, blank=True, default="")
    execution_idempotency_key = models.CharField(max_length=64, blank=True, default="")
    execution_summary = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = "student import batch"
        verbose_name_plural = "student import batches"
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["template_version", "academic_year", "content_hmac"],
                condition=(
                    models.Q(template_version="student_onboarding-v1")
                    & ~models.Q(content_hmac="")
                ),
                name="uniq_student_onboarding_content_hmac_per_academic_year",
            ),
        ]

    def __str__(self):
        return f"Batch #{self.id} - {self.source_name} ({self.status})"


class StudentImportRow(TimestampedModel):
    """Staging model representing a single student record imported from a list.

    Contains raw data columns and matching references. Rows undergo validation and
    are processed to provision inactive Users and linked StudentProfiles.

    SECURITY: control_number is stored only for temporary validation/matching.
    """
    batch = models.ForeignKey(
        StudentImportBatch,
        on_delete=models.CASCADE,
        related_name="rows",
        help_text="The import batch this row belongs to."
    )
    row_number = models.PositiveIntegerField(
        "row number",
        help_text="Row index from the source CSV file."
    )
    control_number = models.CharField(
        "control number",
        max_length=50,
        null=True,
        blank=True,
        help_text="Temporary control number matching admissions tokens."
    )
    student_number = models.CharField(
        "student number",
        max_length=50,
        null=True,
        blank=True,
        help_text="Unique student ID number."
    )
    first_name = models.CharField("first name", max_length=150)
    last_name = models.CharField("last name", max_length=150)
    email = models.EmailField(
        "email address",
        null=True,
        blank=True,
        help_text="Target institutional email address."
    )
    campus = models.CharField(
        "campus",
        max_length=100,
        blank=True,
        help_text="Target UCN campus."
    )
    college = models.CharField(
        "college",
        max_length=100,
        blank=True,
        help_text="Target UCN college."
    )
    department = models.CharField(
        "department",
        max_length=100,
        blank=True,
        help_text="Target department."
    )
    program = models.CharField(
        "program",
        max_length=100,
        blank=True,
        help_text="Target academic program."
    )
    program_code = models.CharField("program code", max_length=100, blank=True)
    year_level = models.PositiveIntegerField(
        "year level",
        null=True,
        blank=True,
        help_text="Target year level."
    )
    lifecycle_status = models.CharField(
        "lifecycle status",
        max_length=30,
        choices=StudentLifecycleChoices.choices,
        default=StudentLifecycleChoices.ACTIVE,
        help_text="Enrollment status mapping."
    )
    validation_status = models.CharField(
        "validation status",
        max_length=30,
        choices=RowValidationStatus.choices,
        default=RowValidationStatus.PENDING,
        help_text="Validation status of this individual row."
    )
    error_message = models.TextField(
        "error message",
        null=True,
        blank=True,
        help_text="Description of any validation or execution errors (must not contain PII or control numbers)."
    )
    error_code = models.CharField(max_length=60, blank=True, default="")
    error_metadata = models.JSONField(default=dict, blank=True)
    provisioned_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="student_onboarding_rows",
    )
    reconciled_profile = models.ForeignKey(
        "profiles.StudentProfile",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reconciled_onboarding_rows",
    )
    correction_revision = models.PositiveIntegerField(default=0)
    correction_metadata = models.JSONField(default=list, blank=True)
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reviewed_student_onboarding_rows",
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "student import row"
        verbose_name_plural = "student import rows"
        ordering = ["batch", "row_number"]
        unique_together = [["batch", "row_number"]]

    def __str__(self):
        return f"Batch #{self.batch_id} Row {self.row_number} ({self.validation_status})"
