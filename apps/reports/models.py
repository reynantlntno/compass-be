# Project: COMPASS
# File: apps/reports/models.py
# Module: apps.reports
# Purpose: Metadata and policy models for privacy-safe reporting

import uuid
from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError
from apps.common.models import TimestampedModel
from apps.reports.choices import (
    ReportFamilyChoices,
    SensitivityLevel,
    ReportRunStatus,
    SuppressionMode,
    ExportTypeChoices,
    ExportFormatChoices,
    ExportStatusChoices,
)



DEFAULT_SUPPRESSION_MODE = SuppressionMode.CELL

# Authoritative family fallback map for generic report definitions. Special
# report shapes whose runtime path is keyed by definition key are declared in
# the definition-key map below.
ALLOWED_SUPPRESSION_MODES_BY_FAMILY = {
    # The generic student-profile/inventory selector uses the CELL path. The
    # dedicated `students_profile` definition is the SECTION exception below.
    ReportFamilyChoices.STUDENT_PROFILE_INVENTORY: frozenset({SuppressionMode.CELL}),
    ReportFamilyChoices.FEEDBACK_CSM: frozenset({SuppressionMode.DISCLOSURE_SET}),
    ReportFamilyChoices.WORKFLOW_NOTIFICATIONS: frozenset({SuppressionMode.NONE}),
    ReportFamilyChoices.AUDIT_REPORT_ACCESS: frozenset({SuppressionMode.NONE}),
}

# Single canonical fallback mode per family, used by generic definitions.
CANONICAL_SUPPRESSION_MODE_BY_FAMILY = {
    ReportFamilyChoices.STUDENT_PROFILE_INVENTORY: SuppressionMode.CELL,
    ReportFamilyChoices.FEEDBACK_CSM: SuppressionMode.DISCLOSURE_SET,
    ReportFamilyChoices.WORKFLOW_NOTIFICATIONS: SuppressionMode.NONE,
    ReportFamilyChoices.AUDIT_REPORT_ACCESS: SuppressionMode.NONE,
}

# Key-specific runtime routes also carry an expected family so a malformed
# definition cannot opt into the profiling path merely by reusing its key.
SUPPRESSION_MODE_DEFINITION_FAMILY_BY_KEY = {
    "students_profile": ReportFamilyChoices.STUDENT_PROFILE_INVENTORY,
}

# Definition-key exceptions must match the runtime routing in services.py.
# `students_profile` is the only current definition that uses the dedicated
# whole-section profiling builder; generic definitions in the same family use
# the ordinary cell-suppression path.
ALLOWED_SUPPRESSION_MODES_BY_DEFINITION_KEY = {
    "students_profile": frozenset({SuppressionMode.SECTION}),
}
CANONICAL_SUPPRESSION_MODE_BY_DEFINITION_KEY = {
    "students_profile": SuppressionMode.SECTION,
}


def allowed_suppression_modes(family) -> frozenset[SuppressionMode]:
    """Return permitted modes for a generic report definition in a family."""
    return ALLOWED_SUPPRESSION_MODES_BY_FAMILY.get(family, frozenset({DEFAULT_SUPPRESSION_MODE}))


def canonical_suppression_mode(family) -> SuppressionMode:
    """Return the canonical fallback mode for a generic report definition."""
    return CANONICAL_SUPPRESSION_MODE_BY_FAMILY.get(family, DEFAULT_SUPPRESSION_MODE)


def allowed_suppression_modes_for_definition(*, key: str, family) -> frozenset[SuppressionMode]:
    """Return modes permitted by the definition's key-specific runtime path."""
    return ALLOWED_SUPPRESSION_MODES_BY_DEFINITION_KEY.get(key, allowed_suppression_modes(family))


def canonical_suppression_mode_for_definition(*, key: str, family) -> SuppressionMode:
    """Return the canonical mode for a definition key, with family fallback."""
    return CANONICAL_SUPPRESSION_MODE_BY_DEFINITION_KEY.get(
        key,
        canonical_suppression_mode(family),
    )



class ProfilingFactStatus(models.TextChoices):
    """Content-free state of a snapshot's profiling projection."""

    READY = "READY", "Ready"
    UNREADABLE = "UNREADABLE", "Unreadable confidential source"
    INVALID = "INVALID", "Invalid profiling source"
    REOPENED = "REOPENED", "Reopened for correction"


class StudentProfilingFact(TimestampedModel):
    """Approved normalized analytical projection of one Inventory snapshot.

    The model intentionally contains category codes only.  Report selectors
    must aggregate this projection and must never read confidential Inventory
    JSON directly.
    """

    inventory_snapshot = models.OneToOneField(
        "inventory.StudentInventorySnapshot",
        on_delete=models.CASCADE,
        related_name="profiling_fact",
    )
    cohort = models.ForeignKey(
        "profiles.StudentAcademicCohort",
        on_delete=models.CASCADE,
        related_name="profiling_facts",
    )
    source_schema_key = models.CharField(max_length=100)
    source_schema_version = models.CharField(max_length=50)
    mapping_version = models.CharField(max_length=50)
    status = models.CharField(
        max_length=20,
        choices=ProfilingFactStatus.choices,
        default=ProfilingFactStatus.READY,
        db_index=True,
    )
    data_quality_code = models.CharField(max_length=80, blank=True)

    gender_code = models.CharField(max_length=60, blank=True)
    age_band_code = models.CharField(max_length=60, blank=True)
    civil_status_code = models.CharField(max_length=60, blank=True)
    physical_disability_code = models.CharField(max_length=60, blank=True)
    religion_code = models.CharField(max_length=80, blank=True)
    mother_living_status_code = models.CharField(max_length=60, blank=True)
    father_living_status_code = models.CharField(max_length=60, blank=True)
    parents_marital_status_code = models.CharField(max_length=80, blank=True)
    municipality_code = models.CharField(max_length=100, blank=True)
    parents_annual_income_code = models.CharField(max_length=60, blank=True)
    mother_occupation_code = models.CharField(max_length=60, blank=True)
    father_occupation_code = models.CharField(max_length=60, blank=True)
    living_condition_code = models.CharField(max_length=60, blank=True)

    class Meta:
        verbose_name = "student profiling fact"
        verbose_name_plural = "student profiling facts"
        indexes = [
            models.Index(fields=["cohort", "status"]),
            models.Index(fields=["mapping_version", "status"]),
        ]

    def __str__(self):
        return f"Profiling fact {self.inventory_snapshot_id} ({self.status})"

    def clean(self):
        super().clean()
        if (
            self.inventory_snapshot_id
            and self.cohort_id
            and (
                self.inventory_snapshot.student_profile_id != self.cohort.student_profile_id
                or self.inventory_snapshot.academic_year != self.cohort.academic_year
            )
        ):
            raise ValidationError(
                "Profiling fact cohort must match the Inventory snapshot student and academic year."
            )

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)


class ReportDefinition(TimestampedModel):
    """Metadata catalog defining an approved aggregate report template."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    key = models.CharField(
        "report key",
        max_length=100,
        unique=True,
        db_index=True,
        help_text="Unique key identifier, e.g., exit_interview_completion_summary"
    )
    title = models.CharField("title", max_length=255)
    description = models.TextField("description", blank=True)
    family = models.CharField(
        "report family",
        max_length=50,
        choices=ReportFamilyChoices.choices,
        db_index=True
    )
    sensitivity_level = models.CharField(
        "sensitivity level",
        max_length=30,
        choices=SensitivityLevel.choices,
        default=SensitivityLevel.SENSITIVE
    )
    is_active = models.BooleanField("is active", default=True, db_index=True)

    # Authorized scope details (e.g. required roles or departments)
    allowed_scope_metadata_json = models.JSONField(
        "allowed scope metadata",
        default=dict,
        blank=True,
        help_text="Governance scopes allowed to view/run this report"
    )

    # Audit governance fields
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_report_definitions"
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="updated_report_definitions"
    )
    activated_at = models.DateTimeField("activated at", null=True, blank=True)
    deactivated_at = models.DateTimeField("deactivated at", null=True, blank=True)

    metadata_json = models.JSONField("metadata", default=dict, blank=True)

    class Meta:
        verbose_name = "report definition"
        verbose_name_plural = "report definitions"
        indexes = [
            models.Index(fields=["key"]),
            models.Index(fields=["family"]),
            models.Index(fields=["is_active"]),
        ]

    def __str__(self):
        return f"{self.title} ({self.key})"

    def clean(self):
        super().clean()
        expected_family = SUPPRESSION_MODE_DEFINITION_FAMILY_BY_KEY.get(self.key)
        if expected_family is not None and self.family != expected_family:
            raise ValidationError(
                {"family": f"Definition key {self.key!r} requires family {expected_family!r}."}
            )

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)


class ReportRun(TimestampedModel):
    """Execution metadata record for tracking report runs and view events."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    report_definition = models.ForeignKey(
        ReportDefinition,
        on_delete=models.CASCADE,
        related_name="runs"
    )
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="report_runs",
        db_index=True
    )
    filter_hash = models.CharField(
        "filter hash",
        max_length=64,
        db_index=True,
        help_text="Deterministic HMAC-SHA256 hash of sanitized/redacted filters"
    )
    filter_summary_json = models.JSONField(
        "filter summary JSON",
        default=dict,
        blank=True,
        help_text="Redacted/safe filter summary (no PII or raw parameters)"
    )
    status = models.CharField(
        "status",
        max_length=30,
        choices=ReportRunStatus.choices,
        default=ReportRunStatus.PENDING,
        db_index=True
    )

    # Safe metadata metrics only - no raw data row storage
    aggregate_count = models.IntegerField("aggregate count", null=True, blank=True)
    cell_count = models.IntegerField("cell count", null=True, blank=True)
    suppression_applied = models.BooleanField("suppression applied", default=False)
    suppressed_cell_count = models.IntegerField("suppressed cell count", default=0)

    started_at = models.DateTimeField("started at", null=True, blank=True)
    completed_at = models.DateTimeField("completed at", null=True, blank=True)
    failed_at = models.DateTimeField("failed at", null=True, blank=True)
    expires_at = models.DateTimeField("expires at", null=True, blank=True)

    metadata_json = models.JSONField("metadata", default=dict, blank=True)

    class Meta:
        verbose_name = "report run"
        verbose_name_plural = "report runs"
        indexes = [
            models.Index(fields=["status"]),
            models.Index(fields=["requested_by"]),
            models.Index(fields=["filter_hash"]),
            models.Index(fields=["created_at"]),
        ]

    def __str__(self):
        return f"Run {self.id} for {self.report_definition.key} ({self.status})"


class ReportExportRequest(TimestampedModel):
    """Governance request model for tracking report export workflow."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="report_export_requests_requested",
        db_index=True
    )
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="report_export_requests_approved"
    )
    denied_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="report_export_requests_denied"
    )
    generated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="report_export_requests_generated"
    )
    report_definition = models.ForeignKey(
        ReportDefinition,
        on_delete=models.CASCADE,
        related_name="export_requests"
    )
    report_run = models.ForeignKey(
        ReportRun,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="export_requests"
    )
    document_template_version = models.ForeignKey(
        "documents.DocumentTemplateVersion",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="export_requests"
    )
    generated_document = models.ForeignKey(
        "documents.GeneratedDocument",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="export_requests"
    )
    protected_file = models.ForeignKey(
        "security.ProtectedFile",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="export_requests"
    )
    export_type = models.CharField(
        "export type",
        max_length=50,
        choices=ExportTypeChoices.choices,
        default=ExportTypeChoices.AGGREGATE
    )
    export_format = models.CharField(
        "export format",
        max_length=50,
        choices=ExportFormatChoices.choices,
        default=ExportFormatChoices.CSV
    )
    status = models.CharField(
        "status",
        max_length=50,
        choices=ExportStatusChoices.choices,
        default=ExportStatusChoices.REQUESTED,
        db_index=True
    )
    scope_summary_json = models.JSONField("scope summary JSON", default=dict, blank=True)
    filter_hash = models.CharField("filter hash", max_length=64, db_index=True)
    filter_summary_json = models.JSONField("filter summary JSON", default=dict, blank=True)
    includes_identifiable_data = models.BooleanField("includes identifiable data", default=False)
    includes_sensitive_data = models.BooleanField("includes sensitive data", default=False)
    purpose = models.CharField("purpose", max_length=500, blank=True)
    approval_reason = models.CharField("approval reason", max_length=500, blank=True)
    denial_reason = models.CharField("denial reason", max_length=500, blank=True)
    suppression_applied = models.BooleanField("suppression applied", default=False)
    suppressed_cell_count = models.IntegerField("suppressed cell count", default=0)
    generation_metadata_json = models.JSONField("generation metadata JSON", default=dict, blank=True)

    # Timestamps
    requested_at = models.DateTimeField("requested at", auto_now_add=True)
    approved_at = models.DateTimeField("approved at", null=True, blank=True)
    denied_at = models.DateTimeField("denied at", null=True, blank=True)
    generation_started_at = models.DateTimeField("generation started at", null=True, blank=True)
    generated_at = models.DateTimeField("generated at", null=True, blank=True)
    downloaded_at = models.DateTimeField("downloaded at", null=True, blank=True)
    expires_at = models.DateTimeField("expires at", null=True, blank=True)
    expired_at = models.DateTimeField("expired at", null=True, blank=True)
    cancelled_at = models.DateTimeField("cancelled at", null=True, blank=True)
    archived_at = models.DateTimeField("archived at", null=True, blank=True)

    class Meta:
        verbose_name = "report export request"
        verbose_name_plural = "report export requests"
        indexes = [
            models.Index(fields=["status"]),
            models.Index(fields=["requested_by"]),
            models.Index(fields=["report_definition"]),
            models.Index(fields=["report_run"]),
            models.Index(fields=["export_type"]),
            models.Index(fields=["export_format"]),
            models.Index(fields=["expires_at"]),
            models.Index(fields=["requested_at"]),
            models.Index(fields=["filter_hash"]),
        ]

    def __str__(self):
        return f"ExportRequest {self.id} (Status: {self.status})"
