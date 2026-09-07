# Project: COMPASS
# File: apps/graduate_tracer/models.py
# Module: apps.graduate_tracer
# Purpose: Graduate Tracer Survey response models, status choices, and metadata
# Domain boundary and service policy.

import uuid
from django.db import models
from django.conf import settings
from apps.common.models import TimestampedModel


class GTSResponseStatus(models.TextChoices):
    DRAFT = "DRAFT", "Draft"
    SUBMITTED = "SUBMITTED", "Submitted"
    REOPENED_FOR_CORRECTION = "REOPENED_FOR_CORRECTION", "Reopened for Correction"
    VOIDED = "VOIDED", "Voided"
    ARCHIVED = "ARCHIVED", "Archived"


class EmploymentStatus(models.TextChoices):
    EMPLOYED = "EMPLOYED", "Employed"
    UNEMPLOYED = "UNEMPLOYED", "Unemployed"
    NEVER_EMPLOYED = "NEVER_EMPLOYED", "Never Employed"
    SELF_EMPLOYED = "SELF_EMPLOYED", "Self Employed"


# ---------------------------------------------------------------------------
# Source-form field registries
#
# These mirror the Graduate Tracer Survey form (docs/source-forms/specs/graduate-tracer.md):
#   - Section A: General Information (demographic/contact snapshot)
#   - Section B: Educational Background (baccalaureate attainment + exam table)
#   - Section C: Trainings / Advance Studies (training table)
#   - Section D: Employment Data (status, first-job history, job-level grid)
#
# Variable-length tables (professional examinations, trainings/advance
# studies) are stored as structured lists in ``response_json`` with
# service-level extractors; single-value reportable answers are normalised
# to dedicated columns so reports can aggregate without touching raw JSON.
# ---------------------------------------------------------------------------

# Q30 Job Level Position — two-row grid, four columns each.
JOB_LEVEL_CHOICES = (
    ("rank_clerical", "Rank or Clerical"),
    ("professional_supervisory", "Professional, Technical or Supervisory"),
    ("managerial_executive", "Managerial or Executive"),
    ("self_employed", "Self-employed"),
)


class GraduateTracerResponse(TimestampedModel):
    """Submitted response document for an alumnus' Graduate Tracer Survey (GTS)."""

    SOURCE_FORM_CODE = "CNSC-OP-GTA-01F10"
    SOURCE_FORM_REVISION = "0"
    SOURCE_FORM_FAMILY = "graduate_tracer_survey"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    reference_code = models.CharField(
        "reference code",
        max_length=50,
        unique=True,
        db_index=True,
        help_text="Canonical GTS reference code."
    )
    student = models.ForeignKey(
        "profiles.StudentProfile",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="gts_responses"
    )
    unlinked_submission = models.ForeignKey(
        "form_collection.UnlinkedFormSubmission",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="gts_responses"
    )
    
    # Snapshot fields
    lifecycle_snapshot = models.CharField("lifecycle snapshot", max_length=50, blank=True)
    graduation_year = models.CharField("graduation year", max_length=20, blank=True, db_index=True)
    program_snapshot = models.CharField("program snapshot", max_length=100, blank=True)
    college_snapshot = models.CharField("college snapshot", max_length=100, blank=True)
    
    form_family = models.ForeignKey(
        "organizations.FormFamily",
        on_delete=models.PROTECT,
        related_name="gts_responses"
    )
    form_revision = models.ForeignKey(
        "organizations.FormRevision",
        on_delete=models.PROTECT,
        related_name="gts_responses"
    )
    form_collection = models.ForeignKey(
        "form_collection.FormCollection",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="gts_responses"
    )
    form_invitation = models.ForeignKey(
        "form_collection.FormInvitation",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="gts_responses"
    )
    
    status = models.CharField(
        "status",
        max_length=30,
        choices=GTSResponseStatus.choices,
        default=GTSResponseStatus.DRAFT,
        db_index=True
    )
    
    # Normalized employment details
    employment_status = models.CharField(
        "employment status",
        max_length=30,
        choices=EmploymentStatus.choices,
        blank=True,
        db_index=True
    )
    first_job_related = models.BooleanField("first job related", null=True, blank=True)
    job_relevance_summary = models.CharField("job relevance summary", max_length=255, blank=True)

    # Section A — General Information (demographic/contact snapshot fields).
    # Name and verified email resolve from the student account or unlinked
    # record rather than free text; see decision_gts_legacy_pii_fields_omitted.
    telephone_number = models.CharField("telephone number", max_length=30, blank=True)
    sex = models.CharField("sex", max_length=10, blank=True, db_index=True)
    region_of_origin = models.CharField("region of origin", max_length=30, blank=True, db_index=True)
    province = models.CharField("province", max_length=100, blank=True)

    # Section B — Educational Background. Q12 is a single-row baccalaureate
    # record (degree, institution, honours) captured in response_json; this
    # flag rolls up whether any honour/award was received for reporting.
    received_honors = models.BooleanField("received honors", null=True, blank=True)

    # Section D — Employment Data. Q16 presently-employed answer is distinct
    # from the Q18 employment-category checkbox; the legacy
    # ``employment_status`` column is derived for backward compatibility.
    presently_employed = models.CharField("presently employed", max_length=20, blank=True, db_index=True)
    present_employment_category = models.CharField("present employment category", max_length=30, blank=True, db_index=True)
    business_line = models.CharField("major line of business", max_length=50, blank=True, db_index=True)
    place_of_work = models.CharField("place of work", max_length=10, blank=True)
    is_first_job = models.BooleanField("is first job", null=True, blank=True)

    # Q29 first-job search duration (normalized for reporting); Q27 length of
    # stay is kept in response_json.
    first_job_search_duration = models.CharField("first job search duration", max_length=40, blank=True, db_index=True)

    # Q30 Job Level Position grid (two rows, four columns).
    first_job_level = models.CharField("first job level", max_length=40, blank=True)
    current_job_level = models.CharField("current job level", max_length=40, blank=True)

    # Q31 initial gross monthly earning range.
    initial_gross_earnings = models.CharField("initial gross monthly earnings", max_length=40, blank=True)

    # Q32 curriculum relevant to first job (distinct from Q24 first-job related).
    curriculum_relevant = models.BooleanField("curriculum relevant", null=True, blank=True)

    # Paper transcription lineage (data-model ready; dedicated route deferred).
    is_paper_transcription = models.BooleanField("paper transcription", default=False)
    transcribed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="transcribed_gts",
    )
    
    # Consent
    contact_listing_consent = models.BooleanField("contact listing consent", default=False)
    consent_given_at = models.DateTimeField("consent given at", null=True, blank=True)
    
    # Audit trail
    submitted_at = models.DateTimeField("submitted at", null=True, blank=True, db_index=True)
    reopened_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reopened_gts"
    )
    reopened_at = models.DateTimeField("reopened at", null=True, blank=True)
    reopen_reason = models.TextField("reopen reason", blank=True)
    
    voided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="voided_gts"
    )
    voided_at = models.DateTimeField("voided at", null=True, blank=True)
    void_reason = models.TextField("void reason", blank=True)

    # Response answers
    response_json = models.JSONField("response json", default=dict, blank=True)
    metadata_json = models.JSONField("metadata json", default=dict, blank=True)

    class Meta:
        verbose_name = "graduate tracer response"
        verbose_name_plural = "graduate tracer responses"
        indexes = [
            models.Index(fields=["status", "submitted_at"]),
            models.Index(fields=["employment_status"]),
            models.Index(fields=["graduation_year", "status"]),
            models.Index(fields=["presently_employed"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["student", "form_revision"],
                condition=models.Q(
                    student__isnull=False,
                    status__in=["DRAFT", "SUBMITTED", "REOPENED_FOR_CORRECTION"],
                ),
                name="uniq_active_gts_student_revision",
            ),
            models.UniqueConstraint(
                fields=["unlinked_submission", "form_revision"],
                condition=models.Q(
                    unlinked_submission__isnull=False,
                    status__in=["DRAFT", "SUBMITTED", "REOPENED_FOR_CORRECTION"],
                ),
                name="uniq_active_gts_unlinked_revision",
            ),
        ]

    def __str__(self):
        return f"{self.reference_code} - {self.get_status_display()}"
