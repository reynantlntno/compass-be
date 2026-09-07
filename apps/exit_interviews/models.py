# Project: COMPASS
# File: apps/exit_interviews/models.py
# Module: apps.exit_interviews
# Purpose: Exit Interview models, assignment status, and response status choices
# Domain boundary and service policy.

import uuid
from django.db import models
from django.conf import settings
from apps.common.models import TimestampedModel


class AssignmentStatus(models.TextChoices):
    ASSIGNED = "ASSIGNED", "Assigned"
    COMPLETED = "COMPLETED", "Completed"
    OVERDUE = "OVERDUE", "Overdue"


class ExitResponseStatus(models.TextChoices):
    DRAFT = "DRAFT", "Draft"
    SUBMITTED = "SUBMITTED", "Submitted"
    REOPENED_FOR_CORRECTION = "REOPENED_FOR_CORRECTION", "Reopened for Correction"
    VOIDED = "VOIDED", "Voided"
    ARCHIVED = "ARCHIVED", "Archived"


# ---------------------------------------------------------------------------
# Source-form matrix field registries
#
# These mirror the Exit Interview form (docs/source-forms/specs/exit-interview.md):
#   - Section II: 15-item self-assessment (5-point scale)
#   - Section III: six feedback-to-college category matrices
#
# Centralising the field names here keeps forms, views, services, reports,
# and admin aligned with the official source form without scattered literals.
# ---------------------------------------------------------------------------

SELF_ASSESSMENT_FIELDS = [
    "self_pride_confidence",
    "self_balance_academics_recreation",
    "self_holistic_wellbeing",
    "self_integrate_knowledge",
    "self_career_clarity",
    "self_esteem",
    "self_awareness",
    "self_pressure_coping",
    "self_people_comfort",
    "self_leadership",
    "self_communication",
    "self_civic_mindedness",
    "self_initiative",
    "self_decision_making",
    "self_relationship_god",
]

DEAN_FIELDS = [
    "dean_availability",
    "dean_open_mindedness",
    "dean_concern_students",
    "dean_commitment",
    "dean_approachability",
]

FACULTY_FIELDS = [
    "faculty_availability",
    "faculty_approachability",
    "faculty_knowledge_subject",
    "faculty_teaching_skills",
]

CURRICULUM_FIELDS = [
    "curriculum_relevance",
    "curriculum_sequencing",
    "curriculum_completeness",
]

COUNSELOR_FIELDS = [
    "counselor_availability",
    "counselor_approachability",
    "counselor_concern_students",
    "counselor_efficiency",
]

OFFICE_STAFF_FIELDS = [
    "staff_service_oriented",
    "staff_availability",
    "staff_concern_students",
    "staff_approachability",
]

FACILITIES_FIELDS = [
    "facilities_maintenance",
    "facilities_availability",
    "facilities_completeness",
]

FEEDBACK_CATEGORY_FIELDS = {
    "dean": DEAN_FIELDS,
    "faculty": FACULTY_FIELDS,
    "curriculum": CURRICULUM_FIELDS,
    "counselor": COUNSELOR_FIELDS,
    "office_staff": OFFICE_STAFF_FIELDS,
    "facilities": FACILITIES_FIELDS,
}

FEEDBACK_COMMENT_FIELDS = [
    "comment_dean",
    "comment_faculty",
    "comment_curriculum",
    "comment_counselor",
    "comment_office_staff",
    "comment_facilities",
]

RATING_MATRIX_FIELDS = (
    SELF_ASSESSMENT_FIELDS
    + DEAN_FIELDS
    + FACULTY_FIELDS
    + CURRICULUM_FIELDS
    + COUNSELOR_FIELDS
    + OFFICE_STAFF_FIELDS
    + FACILITIES_FIELDS
)


class ExitInterviewAssignment(TimestampedModel):
    """GCO assignment of an Exit Interview requirement to a specific student."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    student = models.ForeignKey(
        "profiles.StudentProfile",
        on_delete=models.CASCADE,
        related_name="exit_assignments"
    )
    assigned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_exit_interviews"
    )
    assigned_at = models.DateTimeField("assigned at", auto_now_add=True)
    due_at = models.DateTimeField("due at", null=True, blank=True)
    status = models.CharField(
        "status",
        max_length=30,
        choices=AssignmentStatus.choices,
        default=AssignmentStatus.ASSIGNED
    )
    collection = models.ForeignKey(
        "form_collection.FormCollection",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="exit_assignments"
    )
    metadata_json = models.JSONField("metadata", default=dict, blank=True)

    class Meta:
        verbose_name = "exit interview assignment"
        verbose_name_plural = "exit interview assignments"
        indexes = [
            models.Index(fields=["status"]),
            models.Index(fields=["student", "status"]),
        ]

    def __str__(self):
        return f"Assignment for {self.student} ({self.get_status_display()})"


class ExitInterviewResponse(TimestampedModel):
    """Submitted response document for a student's Exit Interview."""

    SOURCE_FORM_CODE = "CNSC-OP-GTA-01F12"
    SOURCE_FORM_REVISION = "0"
    SOURCE_FORM_FAMILY = "exit_interview"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    reference_code = models.CharField(
        "reference code",
        max_length=50,
        unique=True,
        db_index=True,
        help_text="Canonical EIT reference code."
    )
    student = models.ForeignKey(
        "profiles.StudentProfile",
        on_delete=models.CASCADE,
        related_name="exit_responses"
    )
    
    # Snapshot fields
    lifecycle_snapshot = models.CharField("lifecycle snapshot", max_length=50, blank=True)
    program_snapshot = models.CharField("program snapshot", max_length=100, blank=True)
    college_snapshot = models.CharField("college snapshot", max_length=100, blank=True)
    academic_year = models.CharField("academic year", max_length=20, db_index=True)
    graduation_year_snapshot = models.CharField(
        "graduation year snapshot",
        max_length=20,
        blank=True,
        db_index=True,
        help_text="Governed cohort value captured from assignment or collection metadata.",
    )
    
    eligibility_source = models.CharField(
        "eligibility source",
        max_length=50,
        help_text="Reason student was eligible (lifecycle, assignment, collection, manual)."
    )
    
    form_family = models.ForeignKey(
        "organizations.FormFamily",
        on_delete=models.PROTECT,
        related_name="exit_responses"
    )
    form_revision = models.ForeignKey(
        "organizations.FormRevision",
        on_delete=models.PROTECT,
        related_name="exit_responses"
    )
    form_collection = models.ForeignKey(
        "form_collection.FormCollection",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="exit_responses"
    )
    form_invitation = models.ForeignKey(
        "form_collection.FormInvitation",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="exit_responses"
    )
    
    status = models.CharField(
        "status",
        max_length=30,
        choices=ExitResponseStatus.choices,
        default=ExitResponseStatus.DRAFT,
        db_index=True
    )
    
    # Audit trail
    submitted_at = models.DateTimeField("submitted at", null=True, blank=True, db_index=True)
    reopened_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reopened_exits"
    )
    reopened_at = models.DateTimeField("reopened at", null=True, blank=True)
    reopen_reason = models.TextField("reopen reason", blank=True)
    
    voided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="voided_exits"
    )
    voided_at = models.DateTimeField("voided at", null=True, blank=True)
    void_reason = models.TextField("void reason", blank=True)

    # Paper transcription lineage (data-model ready; dedicated route deferred).
    is_paper_transcription = models.BooleanField("paper transcription", default=False)
    transcribed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="transcribed_exits",
    )
    counselor_acknowledged_at = models.DateTimeField(
        "counselor acknowledged at",
        null=True,
        blank=True,
        help_text="Metadata-only acknowledgment; enforcement is governance-controlled.",
    )
    counselor_acknowledged_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="acknowledged_exit_interviews",
    )

    # Normalized source-form answers. Rating columns are 1-5 (null = N/A) so
    # reports can aggregate per-item averages; structured JSON preserves the
    # full form shape for reference.

    # Demographic / general information
    civil_status = models.CharField("civil status", max_length=20, blank=True)
    program_schedule = models.CharField("academic program schedule", max_length=30, blank=True)
    suggestions = models.TextField("suggestions/recommendations", blank=True)

    # Section II — Self-Assessment (15 items, 5-point scale)
    self_pride_confidence = models.PositiveSmallIntegerField(null=True, blank=True)
    self_balance_academics_recreation = models.PositiveSmallIntegerField(null=True, blank=True)
    self_holistic_wellbeing = models.PositiveSmallIntegerField(null=True, blank=True)
    self_integrate_knowledge = models.PositiveSmallIntegerField(null=True, blank=True)
    self_career_clarity = models.PositiveSmallIntegerField(null=True, blank=True)
    self_esteem = models.PositiveSmallIntegerField(null=True, blank=True)
    self_awareness = models.PositiveSmallIntegerField(null=True, blank=True)
    self_pressure_coping = models.PositiveSmallIntegerField(null=True, blank=True)
    self_people_comfort = models.PositiveSmallIntegerField(null=True, blank=True)
    self_leadership = models.PositiveSmallIntegerField(null=True, blank=True)
    self_communication = models.PositiveSmallIntegerField(null=True, blank=True)
    self_civic_mindedness = models.PositiveSmallIntegerField(null=True, blank=True)
    self_initiative = models.PositiveSmallIntegerField(null=True, blank=True)
    self_decision_making = models.PositiveSmallIntegerField(null=True, blank=True)
    self_relationship_god = models.PositiveSmallIntegerField(null=True, blank=True)

    # Section III — Feedback to the College: Dean (5 attributes)
    dean_availability = models.PositiveSmallIntegerField(null=True, blank=True)
    dean_open_mindedness = models.PositiveSmallIntegerField(null=True, blank=True)
    dean_concern_students = models.PositiveSmallIntegerField(null=True, blank=True)
    dean_commitment = models.PositiveSmallIntegerField(null=True, blank=True)
    dean_approachability = models.PositiveSmallIntegerField(null=True, blank=True)

    # Section III — Faculty (4 attributes)
    faculty_availability = models.PositiveSmallIntegerField(null=True, blank=True)
    faculty_approachability = models.PositiveSmallIntegerField(null=True, blank=True)
    faculty_knowledge_subject = models.PositiveSmallIntegerField(null=True, blank=True)
    faculty_teaching_skills = models.PositiveSmallIntegerField(null=True, blank=True)

    # Section III — Curriculum (3 attributes)
    curriculum_relevance = models.PositiveSmallIntegerField(null=True, blank=True)
    curriculum_sequencing = models.PositiveSmallIntegerField(null=True, blank=True)
    curriculum_completeness = models.PositiveSmallIntegerField(null=True, blank=True)

    # Section III — Guidance Counselor (4 attributes)
    counselor_availability = models.PositiveSmallIntegerField(null=True, blank=True)
    counselor_approachability = models.PositiveSmallIntegerField(null=True, blank=True)
    counselor_concern_students = models.PositiveSmallIntegerField(null=True, blank=True)
    counselor_efficiency = models.PositiveSmallIntegerField(null=True, blank=True)

    # Section III — Office Staff (4 attributes)
    staff_service_oriented = models.PositiveSmallIntegerField(null=True, blank=True)
    staff_availability = models.PositiveSmallIntegerField(null=True, blank=True)
    staff_concern_students = models.PositiveSmallIntegerField(null=True, blank=True)
    staff_approachability = models.PositiveSmallIntegerField(null=True, blank=True)

    # Section III — Facilities (3 attributes)
    facilities_maintenance = models.PositiveSmallIntegerField(null=True, blank=True)
    facilities_availability = models.PositiveSmallIntegerField(null=True, blank=True)
    facilities_completeness = models.PositiveSmallIntegerField(null=True, blank=True)

    # Section III — per-category comments (free text, privacy-guarded)
    comment_dean = models.TextField(blank=True)
    comment_faculty = models.TextField(blank=True)
    comment_curriculum = models.TextField(blank=True)
    comment_counselor = models.TextField(blank=True)
    comment_office_staff = models.TextField(blank=True)
    comment_facilities = models.TextField(blank=True)

    # Response answers
    response_json = models.JSONField("response json", default=dict, blank=True)
    metadata_json = models.JSONField("metadata json", default=dict, blank=True)

    class Meta:
        verbose_name = "exit interview response"
        verbose_name_plural = "exit interview responses"
        indexes = [
            models.Index(fields=["status", "submitted_at"]),
            models.Index(fields=["student", "academic_year"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["student", "academic_year"],
                condition=models.Q(status__in=["DRAFT", "SUBMITTED", "REOPENED_FOR_CORRECTION"]),
                name="uniq_active_exit_response_student_year",
            ),
        ]

    def __str__(self):
        return f"{self.reference_code} - {self.student} ({self.get_status_display()})"
