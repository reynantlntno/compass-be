# Project: COMPASS
# File: apps/inventory/models.py
# Module: apps.inventory
# Purpose: StudentInventorySnapshot data model representing confidential annual inventory answers.
# Domain boundary and service policy.

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from apps.common.models import TimestampedModel
from apps.security.fields import EncryptedJSONField, EncryptedTextField

# Compatibility Constants from docs/source-forms/specs/individual-inventory.md
INVENTORY_SCHEMA_KEY = "individual-inventory-v2"
INVENTORY_SCHEMA_VERSION = "2.1.0"
SUPPORT_CONTEXT_MAPPING_VERSION = "support-needs-v1"
# Content-compatible JSON extension: optional controlled reporting fields
# introduced for students_profile_aggregate. Existing 2.0.0 snapshots remain valid and are never
# rewritten; the projection maps their documented exact aliases only.
INVENTORY_PROFILING_EXTENSION_VERSION = "profiling-v1"
INVENTORY_SOURCE_FORM_CODE = "CNSC-OP-GCO-01F5"
INVENTORY_SOURCE_FORM_REVISION = "0"
INVENTORY_SOURCE_FORM_FAMILY = "student_inventory"

# Normalized internal keys mapped from docs/source-forms/specs/individual-inventory.md headings
INVENTORY_SECTIONS = [
    "personal_data",
    "family_data",
    "urgent_support_contact",
    "siblings",
    "unique",
    "living_conditions",
    "health_conditions",
    "support_context",
    "educational_background",
    "interest",
    "membership",
    "transportation",
    "perception",
]


class InventoryStatusChoices(models.TextChoices):
    DRAFT = "DRAFT", "Draft"
    SUBMITTED = "SUBMITTED", "Submitted"
    REOPENED_FOR_CORRECTION = "REOPENED_FOR_CORRECTION", "Reopened for Correction"


class StudentInventorySnapshot(TimestampedModel):
    """Stores confidential annual individual inventory answers submitted by students.
    
    Each record represents an inventory snapshot for a specific student and academic year.
    It contains personal, family, health, and perception data in a versioned JSONField structure.
    
    SECURITY/PRIVACY:
    - Under no circumstances is raw data in list_display or admin details exposed without policy gates.
    - Fields like reopen_reason and correction_notes must be treated as sensitive operational texts.
    - DB readers can access JSONField plain data as encryption is deferred in this PR.
    """
    student_profile = models.ForeignKey(
        "profiles.StudentProfile",
        on_delete=models.CASCADE,
        related_name="inventory_snapshots",
        help_text="The StudentProfile associated with this snapshot."
    )
    academic_year = models.CharField(
        max_length=50,
        help_text="The academic year of this snapshot, e.g., '2025-2026'."
    )
    schema_key = models.CharField(
        max_length=100,
        default=INVENTORY_SCHEMA_KEY,
        help_text="Key identifying the structure/family of the form."
    )
    schema_version = models.CharField(
        max_length=50,
        default=INVENTORY_SCHEMA_VERSION,
        help_text="Semantic version code of the form schema."
    )
    status = models.CharField(
        max_length=50,
        choices=InventoryStatusChoices.choices,
        default=InventoryStatusChoices.DRAFT,
        help_text="The current workflow state of the inventory."
    )
    data = models.JSONField(
        default=dict,
        help_text="Confidential questionnaire answer dictionary."
    )
    data_encrypted = EncryptedJSONField(
        null=True,
        blank=True,
        default=None,
        max_plaintext_bytes=1_048_576,
    )
    submitted_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp when the student submitted this snapshot."
    )
    reopened_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp when an authorized user reopened this snapshot for corrections."
    )
    reopened_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reopened_inventories",
        help_text="The counselor or staff member who authorized reopening this record."
    )
    reopen_reason = models.TextField(
        blank=True,
        help_text="The justification captured when this record was reopened."
    )
    reopen_reason_encrypted = EncryptedTextField(
        null=True,
        blank=True,
        default=None,
        max_plaintext_bytes=1_048_576,
    )
    correction_notes = models.TextField(
        blank=True,
        help_text="Internal notes concerning the requested correction or verification."
    )
    correction_notes_encrypted = EncryptedTextField(
        null=True,
        blank=True,
        default=None,
        max_plaintext_bytes=1_048_576,
    )

    class Meta:
        verbose_name = "student inventory snapshot"
        verbose_name_plural = "student inventory snapshots"
        constraints = [
            models.UniqueConstraint(
                fields=["student_profile", "academic_year"],
                name="unique_student_academic_year"
            )
        ]

    def __str__(self):
        return f"{self.student_profile} - AY {self.academic_year} ({self.get_status_display()})"


class StudentInventoryStatusHistory(TimestampedModel):
    """Append-only workflow and submission evidence for one Inventory snapshot.

    The canonical ``StudentInventorySnapshot`` remains the one editable row per
    student and academic year.  This relation preserves each locked submission
    in an encrypted payload and records every correction transition without
    copying confidential answers into audit metadata or generic history text.
    """

    snapshot = models.ForeignKey(
        StudentInventorySnapshot,
        on_delete=models.PROTECT,
        related_name="status_history",
    )
    from_status = models.CharField(max_length=50, blank=True)
    to_status = models.CharField(
        max_length=50,
        choices=InventoryStatusChoices.choices,
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="inventory_status_history_entries",
    )
    transitioned_at = models.DateTimeField(default=timezone.now)
    schema_key = models.CharField(max_length=100, blank=True)
    schema_version = models.CharField(max_length=50, blank=True)
    submission_sequence = models.PositiveIntegerField(null=True, blank=True)
    is_baseline = models.BooleanField(
        default=False,
        help_text="Marks a legacy submitted payload captured before history was introduced.",
    )
    submitted_data_encrypted = EncryptedJSONField(
        null=True,
        blank=True,
        default=None,
        max_plaintext_bytes=1_048_576,
    )
    reason_encrypted = EncryptedTextField(
        null=True,
        blank=True,
        default=None,
        max_plaintext_bytes=2_048,
    )

    class Meta:
        verbose_name = "student inventory status history"
        verbose_name_plural = "student inventory status histories"
        ordering = ["-transitioned_at", "-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["snapshot", "submission_sequence"],
                condition=models.Q(submission_sequence__isnull=False),
                name="unique_inventory_submission_history_sequence",
            ),
            models.CheckConstraint(
                condition=models.Q(
                    from_status__in=[
                        "",
                        InventoryStatusChoices.DRAFT,
                        InventoryStatusChoices.SUBMITTED,
                        InventoryStatusChoices.REOPENED_FOR_CORRECTION,
                    ]
                ),
                name="inventory_history_from_status_known",
            ),
        ]

    def clean(self):
        super().clean()
        if self.to_status == InventoryStatusChoices.SUBMITTED:
            if self.submission_sequence is None or self.submission_sequence < 1:
                raise ValidationError(
                    {"submission_sequence": "Submitted history requires a sequence number."}
                )
            if self.submitted_data_encrypted is None:
                raise ValidationError(
                    {"submitted_data_encrypted": "Submitted history requires encrypted data."}
                )
            if self.reason_encrypted is not None:
                raise ValidationError(
                    {"reason_encrypted": "Submission history cannot store a correction reason."}
                )
            if self.is_baseline and self.from_status:
                raise ValidationError(
                    {"is_baseline": "A baseline history entry must not claim a prior state."}
                )
        elif self.to_status == InventoryStatusChoices.REOPENED_FOR_CORRECTION:
            if self.submission_sequence is not None:
                raise ValidationError(
                    {"submission_sequence": "Reopen history cannot have a submission sequence."}
                )
            if self.submitted_data_encrypted is not None:
                raise ValidationError(
                    {"submitted_data_encrypted": "Reopen history cannot store submitted data."}
                )
            if self.reason_encrypted is None:
                raise ValidationError(
                    {"reason_encrypted": "Reopen history requires an encrypted reason."}
                )
            if self.is_baseline:
                raise ValidationError(
                    {"is_baseline": "Reopen history cannot be a baseline entry."}
                )
        else:
            raise ValidationError({"to_status": "Inventory history state is not supported."})

    def save(self, *args, **kwargs):
        if self.pk:
            raise ValidationError("Inventory status history is append-only.")
        self.full_clean(exclude=self.get_deferred_fields())
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Inventory status history cannot be deleted.")

    def __str__(self):
        return f"Inventory {self.snapshot_id}: {self.from_status or 'initial'} -> {self.to_status}"
