# Project: COMPASS
# File: apps/support_needs/models.py
# Module: apps.support_needs
# Purpose: Database models for Student Support Needs and student-specific support records.
# Domain boundary and service policy.

from django.conf import settings
import datetime

from django.core.exceptions import ValidationError
from django.db import models
from apps.common.models import TimestampedModel
from apps.profiles.models import StudentProfile
from apps.support_needs.choices import (
    SupportNeedCategory,
    SupportNeedStatus,
    SupportNeedSourceType,
    SupportNeedSensitivity,
)


SENSITIVE_KEYWORDS = (
    "counseling_notes", "referral_reason", "case_details",
    "narrative", "free_text", "student_number",
    "control_number", "email", "birthdate", "guardian", "diagnosis",
    "severity", "risk_score", "raw_score", "scaled_score", "file_path",
    "storage_key", "public_url", "exception", "traceback", "stack",
)

SENSITIVE_VALUE_KEYWORDS = (
    "counseling", "referral", "case detail", "diagnosis",
    "severity", "risk score", "student number", "control number", "journal", "@",
)

SAFE_EVIDENCE_KEYS = {
    "source_section",
    "source_field",
    "observed_category",
    "evidence_date",
    "academic_year",
    "schema_version",
    "mapping_version",
    "submission_sequence",
    "review_code",
}

SAFE_SUPPORT_METADATA_KEYS = {
    "review_code",
    "needs_review_reason",
    "dispute_reason",
    "deactivation_reason",
    "archival_reason",
}


def _validate_safe_scalar(key, value):
    if value in (None, ""):
        return
    if isinstance(value, (bool, int, float)):
        return
    if isinstance(value, datetime.date):
        return
    if not isinstance(value, str):
        raise ValidationError(f"Unsafe metadata value for '{key}'. Only bounded scalar values are allowed.")
    if len(value) > 120:
        raise ValidationError(f"Unsafe metadata value for '{key}'. Value is too long.")
    value_lower = value.lower()
    if any(keyword in value_lower for keyword in SENSITIVE_VALUE_KEYWORDS):
        raise ValidationError(f"Unsafe metadata value for '{key}'. Sensitive content is blocked.")


def validate_safe_keys(value):
    """Validator to block raw counseling, case, or journal narratives in JSON fields."""
    if not value:
        return
    if not isinstance(value, dict):
        raise ValidationError("Value must be a JSON object (dictionary).")

    def check_dict(d):
        for k, v in d.items():
            k_lower = str(k).lower()
            if any(keyword in k_lower for keyword in SENSITIVE_KEYWORDS):
                raise ValidationError(
                    f"Unsafe metadata key '{k}' detected. Sensitive narrative keys are blocked."
                )
            if isinstance(v, dict):
                check_dict(v)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        check_dict(item)
                    else:
                        _validate_safe_scalar(k, item)
            else:
                _validate_safe_scalar(k, v)

    check_dict(value)


def validate_support_evidence_summary(value):
    """Allowlist support-need evidence summaries so they cannot become raw data dumps."""
    if not value:
        return
    if not isinstance(value, dict):
        raise ValidationError("Evidence summary must be a JSON object.")
    unknown_keys = set(value) - SAFE_EVIDENCE_KEYS
    if unknown_keys:
        raise ValidationError(f"Unsupported evidence metadata key(s): {', '.join(sorted(unknown_keys))}.")
    for key, val in value.items():
        if isinstance(val, (dict, list)):
            raise ValidationError(f"Evidence metadata '{key}' must be a bounded scalar value.")
        _validate_safe_scalar(key, val)


def validate_support_metadata(value):
    """Allowlist lifecycle metadata managed by support-need services."""
    if not value:
        return
    if not isinstance(value, dict):
        raise ValidationError("Support metadata must be a JSON object.")
    unknown_keys = set(value) - SAFE_SUPPORT_METADATA_KEYS
    if unknown_keys:
        raise ValidationError(f"Unsupported support metadata key(s): {', '.join(sorted(unknown_keys))}.")
    for key, val in value.items():
        if isinstance(val, (dict, list)):
            raise ValidationError(f"Support metadata '{key}' must be a bounded scalar value.")
        _validate_safe_scalar(key, val)


class SupportNeedType(TimestampedModel):
    """Catalog of approved support-need types."""
    key = models.SlugField(
        "stable key",
        max_length=100,
        unique=True,
        help_text="Unique lowercase stable identifier."
    )
    label = models.CharField(
        "display label",
        max_length=200,
        help_text="Human-readable label for the support need type."
    )
    category = models.CharField(
        "category",
        max_length=50,
        choices=SupportNeedCategory.choices,
        help_text="Controlled category for grouping."
    )
    sensitivity_level = models.CharField(
        "sensitivity level",
        max_length=50,
        choices=SupportNeedSensitivity.choices,
        default=SupportNeedSensitivity.INTERNAL
    )
    requires_verification = models.BooleanField(
        "requires verification",
        default=True,
        help_text="If true, a counselor or staff must verify the record before it becomes official."
    )
    is_active = models.BooleanField(
        "is active",
        default=True,
        help_text="Whether this support need type is currently active."
    )
    source_notes = models.TextField(
        "source notes",
        blank=True,
        help_text="Safe governance notes regarding the support need definition/standards only."
    )

    class Meta:
        verbose_name = "support need type"
        verbose_name_plural = "support need types"
        indexes = [
            models.Index(fields=["category"]),
            models.Index(fields=["is_active"]),
            models.Index(fields=["requires_verification"]),
        ]

    def __str__(self):
        return f"{self.label} ({self.key})"

    def clean(self):
        super().clean()
        if self.key:
            self.key = self.key.lower().strip()


class StudentSupportNeed(TimestampedModel):
    """Sensitive support record associated with a student profile."""
    student_profile = models.ForeignKey(
        StudentProfile,
        on_delete=models.CASCADE,
        related_name="support_needs"
    )
    support_need_type = models.ForeignKey(
        SupportNeedType,
        on_delete=models.CASCADE,
        related_name="student_support_needs"
    )
    status = models.CharField(
        "status",
        max_length=50,
        choices=SupportNeedStatus.choices,
        default=SupportNeedStatus.DRAFT
    )
    source_type = models.CharField(
        "source type",
        max_length=50,
        choices=SupportNeedSourceType.choices
    )
    source_app_label = models.CharField(
        "source app label",
        max_length=100,
        blank=True,
        null=True
    )
    source_model_name = models.CharField(
        "source model name",
        max_length=100,
        blank=True,
        null=True
    )
    source_object_id = models.CharField(
        "source object ID",
        max_length=255,
        blank=True,
        null=True
    )
    source_snapshot_label = models.CharField(
        "source snapshot label",
        max_length=100,
        blank=True,
        null=True,
        help_text="Safe label such as academic year, schema version."
    )
    source_inventory_snapshot = models.ForeignKey(
        "inventory.StudentInventorySnapshot",
        on_delete=models.PROTECT,
        blank=True,
        null=True,
        related_name="support_needs",
        help_text="Protected provenance for an Inventory-derived record.",
    )
    source_submission_history = models.ForeignKey(
        "inventory.StudentInventoryStatusHistory",
        on_delete=models.PROTECT,
        blank=True,
        null=True,
        related_name="support_needs",
        help_text="Protected immutable submission provenance.",
    )
    source_mapping_version = models.CharField(
        "source mapping version",
        max_length=50,
        blank=True,
        null=True,
        help_text="Version of the bounded source mapping used for derivation.",
    )
    evidence_summary_json = models.JSONField(
        "evidence summary json",
        blank=True,
        null=True,
        validators=[validate_support_evidence_summary],
        help_text="Safe structured evidence metadata. No raw narrative/PII."
    )
    verified_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="verified_support_needs"
    )
    verified_at = models.DateTimeField(
        "verified at",
        blank=True,
        null=True
    )
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="reviewed_support_needs"
    )
    reviewed_at = models.DateTimeField(
        "reviewed at",
        blank=True,
        null=True
    )
    effective_from = models.DateField(
        "effective from",
        blank=True,
        null=True
    )
    effective_until = models.DateField(
        "effective until",
        blank=True,
        null=True
    )
    review_due_at = models.DateTimeField(
        "review due at",
        blank=True,
        null=True
    )
    recorded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="recorded_support_needs"
    )
    archived_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="archived_support_needs"
    )
    archived_at = models.DateTimeField(
        "archived at",
        blank=True,
        null=True
    )
    disputed_at = models.DateTimeField(
        "disputed at",
        blank=True,
        null=True
    )
    metadata_json = models.JSONField(
        "metadata json",
        blank=True,
        null=True,
        validators=[validate_support_metadata]
    )

    class Meta:
        verbose_name = "student support need"
        verbose_name_plural = "student support needs"
        indexes = [
            models.Index(fields=["student_profile"]),
            models.Index(fields=["support_need_type"]),
            models.Index(fields=["status"]),
            models.Index(fields=["source_type"]),
            models.Index(fields=["effective_from"]),
            models.Index(fields=["effective_until"]),
            models.Index(fields=["review_due_at"]),
            models.Index(fields=["source_inventory_snapshot", "support_need_type"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["source_inventory_snapshot", "support_need_type"],
                condition=models.Q(source_inventory_snapshot__isnull=False),
                name="unique_inventory_support_need_per_snapshot_type",
            ),
            models.UniqueConstraint(
                fields=["student_profile", "support_need_type"],
                condition=models.Q(
                    source_inventory_snapshot__isnull=True,
                    status__in=[
                        SupportNeedStatus.DRAFT,
                        SupportNeedStatus.ACTIVE,
                        SupportNeedStatus.NEEDS_REVIEW,
                        SupportNeedStatus.VERIFIED,
                    ]
                ),
                name="unique_manual_active_support_need_per_student_type"
            )
        ]

    def __str__(self):
        return f"Student support need - {self.support_need_type.label} ({self.get_status_display()})"

    def clean(self):
        super().clean()
        if self.effective_from and self.effective_until:
            if self.effective_until < self.effective_from:
                raise ValidationError("effective_until cannot be earlier than effective_from.")
        if self.source_inventory_snapshot_id:
            if self.source_type != SupportNeedSourceType.INDIVIDUAL_INVENTORY:
                raise ValidationError("Inventory provenance requires the Individual Inventory source type.")
            if not self.source_mapping_version:
                raise ValidationError("Inventory provenance requires a source mapping version.")
        if self.source_submission_history_id and not self.source_inventory_snapshot_id:
            raise ValidationError("Submission history provenance requires an Inventory snapshot.")
        if (
            self.source_submission_history_id
            and self.source_inventory_snapshot_id
            and self.source_submission_history.snapshot_id != self.source_inventory_snapshot_id
        ):
            raise ValidationError("Submission history provenance does not match the Inventory snapshot.")
