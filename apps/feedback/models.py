# Project: COMPASS
# File: apps/feedback/models.py
# Module: apps.feedback
# Purpose: Feedback / CSM submission models and status choices
# Domain boundary and service policy.

import uuid
from django.db import models
from django.conf import settings
from apps.common.models import TimestampedModel


class FeedbackStatus(models.TextChoices):
    DRAFT = "DRAFT", "Draft"
    SUBMITTED = "SUBMITTED", "Submitted"
    REVIEWED = "REVIEWED", "Reviewed"
    RESPONDED = "RESPONDED", "Responded"
    CLOSED = "CLOSED", "Closed"
    SPAM = "SPAM", "Spam"
    ARCHIVED = "ARCHIVED", "Archived"
    VOIDED = "VOIDED", "Voided"


class FeedbackSource(models.TextChoices):
    PUBLIC = "PUBLIC", "Public"
    AUTHENTICATED = "AUTHENTICATED", "Authenticated"
    TOKEN = "TOKEN", "Token"
    STAFF_ENCODED = "STAFF_ENCODED", "Staff Encoded"
    SERVICE_INVITATION = "SERVICE_INVITATION", "Service invitation"


class FeedbackSexChoices(models.TextChoices):
    """Non-PII demographic sex question from CSM Part 2."""

    MALE = "Male", "Male"
    FEMALE = "Female", "Female"
    PREFER_NOT = "PREFER_NOT", "Prefer not to say"


class CSMInvitationStatus(models.TextChoices):
    AVAILABLE = "AVAILABLE", "Available"
    SUBMITTED = "SUBMITTED", "Submitted"
    EXPIRED = "EXPIRED", "Expired"


class CSMServiceFamily(models.TextChoices):
    COUNSELING = "COUNSELING", "Counseling"
    CALL_SLIP = "CALL_SLIP", "Call Slip Assistance"
    GOOD_MORAL = "GOOD_MORAL", "Good Moral Certificate"
    REFERRAL = "REFERRAL", "Referral Assistance"


class CSMInvitation(TimestampedModel):
    """One bounded CSM response opportunity for one rendered-service event."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    student = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="csm_invitations",
    )
    service_family = models.CharField(max_length=30, choices=CSMServiceFamily.choices)
    service_label = models.CharField(max_length=100)
    service_category = models.CharField(max_length=100)
    related_workflow_type = models.CharField(max_length=100)
    related_reference_code = models.CharField(max_length=50)
    completion_event_key = models.CharField(max_length=255, unique=True)
    completed_at = models.DateTimeField()
    expires_at = models.DateTimeField(db_index=True)
    status = models.CharField(
        max_length=20,
        choices=CSMInvitationStatus.choices,
        default=CSMInvitationStatus.AVAILABLE,
        db_index=True,
    )
    first_sent_at = models.DateTimeField(null=True, blank=True)
    last_sent_at = models.DateTimeField(null=True, blank=True)
    send_count = models.PositiveIntegerField(default=0)
    submitted_at = models.DateTimeField(null=True, blank=True)
    issued_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="issued_csm_invitations",
    )

    class Meta:
        ordering = ["-completed_at", "-created_at"]
        indexes = [
            models.Index(fields=["student", "status", "expires_at"]),
            models.Index(fields=["service_family", "completed_at"]),
            models.Index(fields=["related_workflow_type", "related_reference_code"]),
        ]
        constraints = [
            models.CheckConstraint(
                condition=(
                    models.Q(status=CSMInvitationStatus.SUBMITTED, submitted_at__isnull=False)
                    | ~models.Q(status=CSMInvitationStatus.SUBMITTED)
                ),
                name="csm_submitted_requires_timestamp",
            ),
        ]

    def __str__(self):
        return f"{self.service_label} ({self.get_status_display()})"


class FeedbackSubmission(TimestampedModel):
    """Formal Customer Feedback / Client Satisfaction Measurement (CSM) submission."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    reference_code = models.CharField(
        "reference code",
        max_length=50,
        unique=True,
        db_index=True,
        help_text="Canonical FBK reference code."
    )
    respondent_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="feedback_submissions"
    )
    client_type = models.CharField(
        "client type",
        max_length=50,
        blank=True,
        help_text="Demographic client type (e.g. Citizen, Business, Government)."
    )
    lifecycle_snapshot = models.CharField(
        "lifecycle snapshot",
        max_length=50,
        blank=True,
        null=True,
        help_text="Frozen lifecycle status of respondent at time of submission."
    )
    is_anonymous = models.BooleanField(
        "is anonymous",
        default=False
    )
    source = models.CharField(
        "source",
        max_length=30,
        choices=FeedbackSource.choices,
        default=FeedbackSource.PUBLIC
    )
    service_category = models.CharField(
        "service category",
        max_length=100,
        help_text=" GTAO service availed (e.g. Counseling, Admission, Testing, etc.)"
    )
    related_workflow_type = models.CharField(
        "related workflow type",
        max_length=100,
        blank=True,
        null=True,
        help_text="Workflow app boundary key, e.g. appointments, referrals."
    )
    related_reference_code = models.CharField(
        "related reference code",
        max_length=50,
        blank=True,
        null=True,
        help_text="Reference code of the related transaction (e.g., APT-AY2526-000001)."
    )
    form_family = models.ForeignKey(
        "organizations.FormFamily",
        on_delete=models.PROTECT,
        related_name="feedback_submissions"
    )
    form_revision = models.ForeignKey(
        "organizations.FormRevision",
        on_delete=models.PROTECT,
        related_name="feedback_submissions"
    )
    form_collection = models.ForeignKey(
        "form_collection.FormCollection",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="feedback_submissions"
    )
    form_invitation = models.ForeignKey(
        "form_collection.FormInvitation",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="feedback_submissions"
    )
    invitation = models.OneToOneField(
        CSMInvitation,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="submission",
    )
    status = models.CharField(
        "status",
        max_length=30,
        choices=FeedbackStatus.choices,
        default=FeedbackStatus.DRAFT,
        db_index=True
    )
    
    # Audit trail / timestamps / assignees
    submitted_at = models.DateTimeField("submitted at", null=True, blank=True, db_index=True)
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reviewed_feedbacks"
    )
    reviewed_at = models.DateTimeField("reviewed at", null=True, blank=True)
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_feedbacks"
    )
    closed_at = models.DateTimeField("closed at", null=True, blank=True)
    
    # Normalized ratings
    overall_satisfaction = models.PositiveIntegerField(
        "overall satisfaction",
        null=True,
        blank=True,
        help_text="Overall client satisfaction score."
    )
    sqd_average = models.FloatField(
        "sqd average",
        null=True,
        blank=True,
        help_text="Average rating across Service Quality Dimensions."
    )

    # CSM Part 2 SQD — per-item normalized columns (1-5; null = N/A / unanswered)
    sqd0 = models.PositiveSmallIntegerField("sqd0", null=True, blank=True, help_text="SQD0 satisfied with service.")
    sqd1 = models.PositiveSmallIntegerField("sqd1", null=True, blank=True, help_text="SQD1 reasonable time.")
    sqd2 = models.PositiveSmallIntegerField("sqd2", null=True, blank=True, help_text="SQD2 followed requirements.")
    sqd3 = models.PositiveSmallIntegerField("sqd3", null=True, blank=True, help_text="SQD3 easy and simple steps.")
    sqd4 = models.PositiveSmallIntegerField("sqd4", null=True, blank=True, help_text="SQD4 found transaction info.")
    sqd5 = models.PositiveSmallIntegerField("sqd5", null=True, blank=True, help_text="SQD5 reasonable fees.")
    sqd6 = models.PositiveSmallIntegerField("sqd6", null=True, blank=True, help_text="SQD6 office was fair.")
    sqd7 = models.PositiveSmallIntegerField("sqd7", null=True, blank=True, help_text="SQD7 treated courteously.")
    sqd8 = models.PositiveSmallIntegerField("sqd8", null=True, blank=True, help_text="SQD8 got what was needed.")

    # Part 1 IV — service personnel matrix (1-5; null = not rated)
    sq_personnel_helpfulness = models.PositiveSmallIntegerField(
        "personnel helpfulness", null=True, blank=True,
        help_text="Part 1 IV-1: accommodating, attentive and helpfulness."
    )
    sq_personnel_competence = models.PositiveSmallIntegerField(
        "personnel competence", null=True, blank=True,
        help_text="Part 1 IV-2: knows the job well."
    )
    sq_personnel_flexibility = models.PositiveSmallIntegerField(
        "personnel flexibility", null=True, blank=True,
        help_text="Part 1 IV-3: flexible in handling request."
    )
    sq_personnel_accuracy = models.PositiveSmallIntegerField(
        "personnel accuracy", null=True, blank=True,
        help_text="Part 1 IV-4: gave accurate information."
    )
    sq_personnel_appearance = models.PositiveSmallIntegerField(
        "personnel appearance", null=True, blank=True,
        help_text="Part 1 IV-5: appearance of service personnel."
    )
    sq_personnel_delivered = models.PositiveSmallIntegerField(
        "personnel delivered", null=True, blank=True,
        help_text="Part 1 IV-6: delivered what was committed."
    )

    # Part 1 V — office/premises matrix (1-5; null = not rated)
    op_located = models.PositiveSmallIntegerField(
        "premises located", null=True, blank=True,
        help_text="Part 1 V-1: conveniently located and easy to find."
    )
    op_cleanliness = models.PositiveSmallIntegerField(
        "premises cleanliness", null=True, blank=True,
        help_text="Part 1 V-2: cleanliness of the premises."
    )
    op_environment = models.PositiveSmallIntegerField(
        "premises environment", null=True, blank=True,
        help_text="Part 1 V-3: conducive working environment."
    )
    op_office_hours = models.PositiveSmallIntegerField(
        "premises office hours", null=True, blank=True,
        help_text="Part 1 V-4: convenient office hours."
    )
    op_availability = models.PositiveSmallIntegerField(
        "premises availability", null=True, blank=True,
        help_text="Part 1 V-5: availability of the service of the personnel."
    )
    
    # Citizen's Charter awareness
    cc_awareness = models.CharField(
        "cc awareness",
        max_length=100,
        blank=True,
        help_text="CC1 answer choice."
    )
    cc_visibility = models.CharField(
        "cc visibility",
        max_length=100,
        blank=True,
        help_text="CC2 answer choice."
    )
    cc_helpfulness = models.CharField(
        "cc helpfulness",
        max_length=100,
        blank=True,
        help_text="CC3 answer choice."
    )

    # CSM Part 2 — non-PII demographics
    sex = models.CharField(
        "sex",
        max_length=20,
        choices=FeedbackSexChoices.choices,
        blank=True,
        help_text="CSM Part 2 demographic sex question."
    )
    age = models.PositiveSmallIntegerField(
        "age",
        null=True,
        blank=True,
        help_text="CSM Part 2 demographic age."
    )
    region_of_residence = models.CharField(
        "region of residence",
        max_length=100,
        blank=True,
        help_text="CSM Part 2 region of residence."
    )

    # Part 1 — counselor contact and visit context
    talked_to_counselor = models.BooleanField(
        "talked to counselor",
        null=True,
        blank=True,
        help_text="Part 1 II: whether the respondent spoke with the Guidance Counselor."
    )
    accommodated_by = models.CharField(
        "accommodated by",
        max_length=100,
        blank=True,
        help_text="Part 1 II: who accommodated the respondent if not the counselor."
    )
    visit_count = models.PositiveSmallIntegerField(
        "visit count",
        null=True,
        blank=True,
        help_text="Part 1 III: how many times the respondent visited the office."
    )
    transaction_duration_text = models.CharField(
        "transaction duration",
        max_length=100,
        blank=True,
        help_text="Part 1: free-text duration the respondent took to finish the transaction."
    )
    
    # Payload details
    response_json = models.JSONField(
        "response json",
        default=dict,
        blank=True,
        help_text="Restricted full survey response body."
    )
    comment_text = models.TextField(
        "comment text",
        blank=True,
        help_text="Restricted open-ended comment or suggestions."
    )
    experience_feedback = models.TextField(
        "experience feedback",
        blank=True,
        help_text="Restricted open-ended feedback about the respondent's experience."
    )
    metadata_json = models.JSONField(
        "metadata json",
        default=dict,
        blank=True,
        help_text="Non-PII audit-safe metadata."
    )

    # Paper-transcription / staff-encoding marker (Part 1 paper-form lineage)
    is_paper_transcription = models.BooleanField(
        "is paper transcription",
        default=False,
        help_text="Marks a response transcribed from a paper form by office staff."
    )
    transcribed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="transcribed_feedbacks"
    )

    class Meta:
        verbose_name = "feedback submission"
        verbose_name_plural = "feedback submissions"
        indexes = [
            models.Index(fields=["status", "submitted_at"]),
            models.Index(fields=["reference_code"]),
            models.Index(fields=["service_category"]),
        ]
        constraints = [
            models.CheckConstraint(
                condition=(
                    ~models.Q(source=FeedbackSource.SERVICE_INVITATION)
                    | (
                        models.Q(invitation__isnull=False)
                        & models.Q(related_workflow_type__isnull=False)
                        & ~models.Q(related_workflow_type="")
                        & models.Q(related_reference_code__isnull=False)
                        & ~models.Q(related_reference_code="")
                    )
                ),
                name="feedback_service_source_requires_invitation",
            ),
        ]

    def __str__(self):
        return f"{self.reference_code} - {self.get_status_display()}"
