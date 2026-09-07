# Project: COMPASS
# File: apps/assessments/models.py
# Module: apps.assessments
# Purpose: Database models for assessment instruments and student assessment results.
# Domain boundary and service policy.

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from apps.common.models import TimestampedModel
from apps.profiles.models import StudentProfile
from apps.security.models import ProtectedFile
from apps.support_needs.models import validate_safe_keys
from apps.assessments.choices import (
    AssessmentInstrumentCategory,
    AssessmentRecordStatus,
    AssessmentInterpretationVisibility,
)


class AssessmentInstrument(TimestampedModel):
    """Catalog of approved assessment instruments (e.g., career, wellness)."""
    key = models.SlugField(
        "stable key",
        max_length=100,
        unique=True,
        help_text="Unique lowercase stable identifier."
    )
    title = models.CharField(
        "display title",
        max_length=200,
        help_text="Human-readable title of the assessment instrument."
    )
    category = models.CharField(
        "category",
        max_length=50,
        choices=AssessmentInstrumentCategory.choices
    )
    official_source_reference = models.CharField(
        "official source reference",
        max_length=255,
        blank=True,
        help_text="Safe reference to approved source specification, manual, or policy."
    )
    has_official_scoring_guide = models.BooleanField(
        "has official scoring guide",
        default=False
    )
    allows_scores = models.BooleanField(
        "allows scores",
        default=False,
        help_text="If true, score fields are permitted on records of this instrument."
    )
    allows_interpretation = models.BooleanField(
        "allows interpretation",
        default=True,
        help_text="If true, professional interpretation narrative/records are permitted."
    )
    is_active = models.BooleanField(
        "is active",
        default=True
    )
    notes = models.TextField(
        "notes",
        blank=True,
        help_text="Safe governance notes regarding the instrument only."
    )

    class Meta:
        verbose_name = "assessment instrument"
        verbose_name_plural = "assessment instruments"
        indexes = [
            models.Index(fields=["category"]),
            models.Index(fields=["is_active"]),
        ]

    def __str__(self):
        return f"{self.title} ({self.key})"

    def clean(self):
        super().clean()
        if self.key:
            self.key = self.key.lower().strip()
        if self.allows_scores and not self.has_official_scoring_guide:
            raise ValidationError("Scores require an approved official scoring guide.")
        if self.allows_scores and not self.official_source_reference:
            raise ValidationError("Scores require a safe official source reference.")
        if self.official_source_reference and len(self.official_source_reference.strip()) < 3:
            raise ValidationError("Official source reference is too short.")


FORBIDDEN_SCORE_LABEL_TERMS = ("diagnosis", "diagnostic", "severity", "risk", "risk_score", "mental health")


def _has_score_value(record) -> bool:
    return bool(record.raw_score or record.scaled_score or record.score_label)


def _instrument_allows_entered_scores(instrument) -> bool:
    return bool(
        instrument
        and instrument.allows_scores
        and instrument.has_official_scoring_guide
        and instrument.official_source_reference
    )


def validate_score_governance(record):
    if _has_score_value(record) and not _instrument_allows_entered_scores(record.instrument):
        raise ValidationError(
            "Score fields require an active instrument with scores enabled, an official scoring guide, and a source reference."
        )
    if record.score_label:
        label = record.score_label.lower()
        if any(term in label for term in FORBIDDEN_SCORE_LABEL_TERMS):
            raise ValidationError("Score label cannot contain diagnosis, severity, or risk language.")


class StudentAssessmentRecord(TimestampedModel):
    """Sensitive record of an administered assessment and its outcomes."""
    student_profile = models.ForeignKey(
        StudentProfile,
        on_delete=models.CASCADE,
        related_name="assessment_records"
    )
    instrument = models.ForeignKey(
        AssessmentInstrument,
        on_delete=models.CASCADE,
        related_name="student_support_needs"
    )
    administered_at = models.DateTimeField(
        "administered at",
        blank=True,
        null=True
    )
    administered_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="administered_assessments"
    )
    status = models.CharField(
        "status",
        max_length=50,
        choices=AssessmentRecordStatus.choices,
        default=AssessmentRecordStatus.DRAFT
    )
    raw_score = models.CharField(
        "raw score",
        max_length=50,
        blank=True,
        null=True
    )
    scaled_score = models.CharField(
        "scaled score",
        max_length=50,
        blank=True,
        null=True
    )
    score_label = models.CharField(
        "score label",
        max_length=100,
        blank=True,
        null=True,
        help_text="Safe categorical label (e.g. High, Medium, Low) if non-diagnostic."
    )
    interpretation_text_encrypted = models.TextField(
        "interpretation text encrypted",
        blank=True,
        null=True,
        help_text="Base64-encoded encrypted Fernet envelope for sensitive interpretation text."
    )
    interpretation_visibility = models.CharField(
        "interpretation visibility",
        max_length=50,
        choices=AssessmentInterpretationVisibility.choices,
        default=AssessmentInterpretationVisibility.COUNSELOR_ONLY
    )
    protected_file = models.ForeignKey(
        ProtectedFile,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="assessment_records"
    )
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="reviewed_assessments"
    )
    reviewed_at = models.DateTimeField(
        "reviewed at",
        blank=True,
        null=True
    )
    released_to_student = models.BooleanField(
        "released to student",
        default=False
    )
    released_to_student_at = models.DateTimeField(
        "released to student at",
        blank=True,
        null=True
    )
    released_to_student_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="released_assessments"
    )
    source_form_reference = models.CharField(
        "source form reference",
        max_length=100,
        blank=True,
        null=True
    )
    metadata_json = models.JSONField(
        "metadata json",
        blank=True,
        null=True,
        validators=[validate_safe_keys]
    )

    class Meta:
        verbose_name = "student assessment record"
        verbose_name_plural = "student assessment records"
        indexes = [
            models.Index(fields=["student_profile"]),
            models.Index(fields=["instrument"]),
            models.Index(fields=["status"]),
            models.Index(fields=["administered_at"]),
            models.Index(fields=["administered_by"]),
            models.Index(fields=["reviewed_by"]),
            models.Index(fields=["released_to_student"]),
        ]

    def __str__(self):
        return f"Student assessment - {self.instrument.title} ({self.get_status_display()})"

    @property
    def interpretation_text(self) -> str:
        """Decrypts and returns the interpretation text if set and valid."""
        if not self.interpretation_text_encrypted:
            return ""
        from apps.security.encryption import decrypt_value
        return decrypt_value(self.interpretation_text_encrypted)

    @interpretation_text.setter
    def interpretation_text(self, value: str):
        """Encrypts the provided text using field encryption key purpose."""
        if not value:
            self.interpretation_text_encrypted = ""
        else:
            from apps.security.encryption import encrypt_value
            from apps.security.models import KeyPurposeChoices
            self.interpretation_text_encrypted = encrypt_value(
                value, KeyPurposeChoices.FIELD_ENCRYPTION
            )

    def clean(self):
        super().clean()
        validate_score_governance(self)

        # Validate interpretation blank when allows_interpretation is false
        if not self.instrument.allows_interpretation:
            if self.interpretation_text_encrypted:
                raise ValidationError("This instrument does not allow interpretation text.")

        # Student release is available only through the explicit safe-summary
        # service transition.  Direct model writes cannot mark a counselor-only
        # record as released.
        if self.released_to_student:
            if self.status not in {
                AssessmentRecordStatus.RELEASED_TO_STUDENT,
                AssessmentRecordStatus.SUPERSEDED,
                AssessmentRecordStatus.ARCHIVED,
            }:
                raise ValidationError("Released assessments must use the released status.")
            if self.interpretation_visibility != AssessmentInterpretationVisibility.RELEASED_TO_STUDENT_SAFE_SUMMARY:
                raise ValidationError("Only an explicitly safe assessment summary may be released.")
            if not self.released_to_student_at or not self.released_to_student_by_id:
                raise ValidationError("Released assessments require release provenance.")
        elif self.status == AssessmentRecordStatus.RELEASED_TO_STUDENT:
            raise ValidationError("Released status requires release provenance.")
