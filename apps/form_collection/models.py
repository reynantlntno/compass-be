# Project: COMPASS
# File: apps/form_collection/models.py
# Module: apps.form_collection
# Purpose: Form collection lifecycle, invitation batches, form invitations, and unlinked submissions
# Domain boundary and service policy.

import uuid
from django.conf import settings
from django.db import models
from apps.common.models import TimestampedModel


class CollectionStatus(models.TextChoices):
    DRAFT = "DRAFT", "Draft"
    ACTIVE = "ACTIVE", "Active / Open"
    PAUSED = "PAUSED", "Paused"
    CLOSED = "CLOSED", "Closed"
    ARCHIVED = "ARCHIVED", "Archived"


class CollectionAudience(models.TextChoices):
    FRESHMEN = "FRESHMEN", "Freshmen"
    GRADUATING = "GRADUATING", "Graduating Students"
    ALUMNI = "ALUMNI", "Alumni"
    STUDENTS = "STUDENTS", "Students"
    CUSTOM = "CUSTOM", "Custom"


class IdentityVerificationPolicy(models.TextChoices):
    NONE = "NONE", "None"
    CONTROL_SURNAME_BIRTHDATE = "CONTROL_SURNAME_BIRTHDATE", "Control Number + Surname + Birthdate"
    CONTROL_EMAIL_OTP = "CONTROL_EMAIL_OTP", "Control Number + Email OTP"
    STUDENT_EMAIL = "STUDENT_EMAIL", "Student Number + Verified Email"
    EMAIL_OTP = "EMAIL_OTP", "Email OTP"


class FormType(models.TextChoices):
    INDIVIDUAL_INVENTORY = "individual_inventory", "Individual Inventory"
    EXIT_INTERVIEW = "exit_interview", "Exit Interview"
    GRADUATE_TRACER = "graduate_tracer", "Graduate Tracer Survey"
    CSM_FEEDBACK = "csm_feedback", "Client Satisfaction Feedback"
    ALUMNI_ACCESS = "alumni_access", "Alumni Document Access"
    CUSTOM_CONTROLLED = "custom_controlled", "Custom Controlled Intake"


class InvitationBatchStatus(models.TextChoices):
    DRAFT = "DRAFT", "Draft"
    VALIDATING = "VALIDATING", "Validating"
    ISSUED = "ISSUED", "Issued"
    PARTIALLY_ISSUED = "PARTIALLY_ISSUED", "Partially Issued"
    FAILED = "FAILED", "Failed"
    REVOKED = "REVOKED", "Revoked"
    ARCHIVED = "ARCHIVED", "Archived"


class InvitationBatchSource(models.TextChoices):
    MANUAL = "MANUAL", "Manual"
    CSV_IMPORT = "CSV_IMPORT", "CSV Import"
    SYSTEM_JOB = "SYSTEM_JOB", "System Job"


class FormInvitationStatus(models.TextChoices):
    ISSUED = "ISSUED", "Issued"
    OPENED = "OPENED", "Opened"
    VERIFIED = "VERIFIED", "Verified"
    DRAFT_STARTED = "DRAFT_STARTED", "Draft Started"
    SUBMITTED = "SUBMITTED", "Submitted"
    LINKED_TO_ACCOUNT = "LINKED_TO_ACCOUNT", "Linked to Account"
    EXPIRED = "EXPIRED", "Expired"
    REVOKED = "REVOKED", "Revoked"


class StudentMatchStatus(models.TextChoices):
    UNMATCHED = "UNMATCHED", "Unmatched"
    MATCHED = "MATCHED", "Matched"
    LINKED = "LINKED", "Linked"
    NEEDS_MANUAL_REVIEW = "NEEDS_MANUAL_REVIEW", "Needs Manual Review"
    REJECTED = "REJECTED", "Rejected"


class FormInvitationAttemptStatus(models.TextChoices):
    SUCCESS = "SUCCESS", "Success"
    FAILED = "FAILED", "Failed"
    RATE_LIMITED = "RATE_LIMITED", "Rate Limited"
    EXPIRED = "EXPIRED", "Expired"
    REVOKED = "REVOKED", "Revoked"


class FormInvitationFailureReason(models.TextChoices):
    INVALID_TOKEN = "INVALID_TOKEN", "Invalid Token"
    INVALID_VERIFIER = "INVALID_VERIFIER", "Invalid Verifier"
    EXPIRED = "EXPIRED", "Expired"
    REVOKED = "REVOKED", "Revoked"
    MAX_USES = "MAX_USES", "Max Uses Exceeded"
    COLLECTION_INACTIVE = "COLLECTION_INACTIVE", "Collection Inactive"


class FormCollection(TimestampedModel):
    """Manages form collections to organize invitation batches and form access."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField("name", max_length=255)
    description = models.TextField("description", blank=True)
    audience = models.CharField(
        "audience",
        max_length=50,
        choices=CollectionAudience.choices,
        default=CollectionAudience.CUSTOM
    )
    status = models.CharField(
        "status",
        max_length=30,
        choices=CollectionStatus.choices,
        default=CollectionStatus.DRAFT
    )
    start_at = models.DateTimeField("start time")
    end_at = models.DateTimeField("end time")
    form_family = models.ForeignKey(
        "organizations.FormFamily",
        on_delete=models.PROTECT,
        related_name="collections",
        null=True,
        blank=True,
        help_text="The target form family."
    )
    form_revision = models.ForeignKey(
        "organizations.FormRevision",
        on_delete=models.PROTECT,
        related_name="collections",
        null=True,
        blank=True,
        help_text="The target form revision (required before launch)."
    )
    form_type = models.CharField(
        "form type",
        max_length=50,
        choices=FormType.choices,
        help_text="The classification/target key of the form."
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_collections"
    )
    launched_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="launched_collections"
    )
    closed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="closed_collections"
    )
    launched_at = models.DateTimeField("launched at", null=True, blank=True)
    closed_at = models.DateTimeField("closed at", null=True, blank=True)
    metadata_json = models.JSONField("metadata", default=dict, blank=True)

    class Meta:
        verbose_name = "form collection"
        verbose_name_plural = "form collections"
        indexes = [
            models.Index(fields=["status"]),
            models.Index(fields=["form_type"]),
            models.Index(fields=["start_at", "end_at"]),
        ]

    def __str__(self):
        return f"{self.name} ({self.get_status_display()})"


class InvitationBatch(TimestampedModel):
    """Groups of invitations generated for collections."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    collection = models.ForeignKey(
        FormCollection,
        on_delete=models.CASCADE,
        related_name="invitation_batches"
    )
    invitation_batch_name = models.CharField("invitation batch name", max_length=255)
    source_type = models.CharField(
        "source type",
        max_length=50,
        choices=InvitationBatchSource.choices,
        default=InvitationBatchSource.MANUAL
    )
    total_requested = models.PositiveIntegerField("total requested", default=0)
    total_issued = models.PositiveIntegerField("total issued", default=0)
    total_failed = models.PositiveIntegerField("total failed", default=0)
    status = models.CharField(
        "status",
        max_length=30,
        choices=InvitationBatchStatus.choices,
        default=InvitationBatchStatus.DRAFT
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_collection_batches"
    )
    issued_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="issued_collection_batches"
    )
    issued_at = models.DateTimeField("issued at", null=True, blank=True)
    metadata_json = models.JSONField("metadata", default=dict, blank=True)

    class Meta:
        verbose_name = "invitation batch"
        verbose_name_plural = "invitation batches"

    def __str__(self):
        return f"{self.invitation_batch_name} - {self.collection.name} ({self.get_status_display()})"


class FormInvitation(TimestampedModel):
    """Provides controlled, tokenized access to a collection form."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    token_hash = models.CharField("token hash", max_length=255, unique=True, db_index=True)
    selector = models.CharField("selector", max_length=64, unique=True, db_index=True)
    collection = models.ForeignKey(
        FormCollection,
        on_delete=models.PROTECT,
        related_name="form_invitations"
    )
    invitation_batch = models.ForeignKey(
        InvitationBatch,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="form_invitations"
    )
    target_form_key = models.CharField("target form key", max_length=50)
    intended_recipient_name = models.CharField("intended recipient name", max_length=255, blank=True, null=True)
    intended_email_hash = models.CharField("intended email hash", max_length=255, blank=True, null=True, db_index=True)
    control_number_hash = models.CharField("control number hash", max_length=255, blank=True, null=True, db_index=True)
    student_number_hash = models.CharField("student number hash", max_length=255, blank=True, null=True, db_index=True)
    expires_at = models.DateTimeField("expires at")
    max_uses = models.PositiveIntegerField("max uses", default=1)
    used_count = models.PositiveIntegerField("used count", default=0)
    status = models.CharField(
        "status",
        max_length=30,
        choices=FormInvitationStatus.choices,
        default=FormInvitationStatus.ISSUED
    )
    verified_at = models.DateTimeField("verified at", null=True, blank=True)
    first_opened_at = models.DateTimeField("first opened at", null=True, blank=True)
    last_opened_at = models.DateTimeField("last opened at", null=True, blank=True)
    submitted_at = models.DateTimeField("submitted at", null=True, blank=True)
    linked_student = models.ForeignKey(
        "profiles.StudentProfile",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="form_invitations"
    )
    unlinked_submission = models.ForeignKey(
        "UnlinkedFormSubmission",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="form_invitations"
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_form_invitations"
    )
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="revoked_form_invitations"
    )
    revoked_at = models.DateTimeField("revoked at", null=True, blank=True)
    revoke_reason = models.TextField("revoke reason", blank=True, null=True)
    metadata_json = models.JSONField("metadata", default=dict, blank=True)

    class Meta:
        verbose_name = "form invitation"
        verbose_name_plural = "form invitations"
        indexes = [
            models.Index(fields=["status"]),
            models.Index(fields=["expires_at"]),
        ]

    def __str__(self):
        return f"Form invitation {self.id} ({self.get_status_display()})"


class FormInvitationAttempt(TimestampedModel):
    """Tracks identity verification attempts to prevent brute-forcing."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    form_invitation = models.ForeignKey(
        FormInvitation,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="attempts"
    )
    collection = models.ForeignKey(
        FormCollection,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="attempts"
    )
    action_scope = models.CharField("action scope", max_length=50, default="VERIFY")
    identifier_hash = models.CharField("identifier hash", max_length=255, blank=True, null=True, db_index=True)
    ip_hash = models.CharField("ip hash", max_length=255, blank=True, null=True, db_index=True)
    user_agent_hash = models.CharField("user agent hash", max_length=255, blank=True, null=True, db_index=True)
    session_hash = models.CharField("session hash", max_length=255, blank=True, null=True, db_index=True)
    status = models.CharField(
        "status",
        max_length=30,
        choices=FormInvitationAttemptStatus.choices
    )
    failure_reason = models.CharField(
        "failure reason",
        max_length=100,
        choices=FormInvitationFailureReason.choices,
        blank=True,
        null=True
    )
    metadata_json = models.JSONField("metadata", default=dict, blank=True)

    class Meta:
        verbose_name = "form invitation attempt"
        verbose_name_plural = "form invitation attempts"

    def __str__(self):
        return f"Attempt {self.id} - {self.status}"


class UnlinkedFormSubmission(TimestampedModel):
    """Holds form submission data before linking to a verified StudentProfile."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    control_number_hash = models.CharField("control number hash", max_length=255, blank=True, null=True, db_index=True)
    student_number_hash = models.CharField("student number hash", max_length=255, blank=True, null=True, db_index=True)
    email_hash = models.CharField("email hash", max_length=255, blank=True, null=True, db_index=True)
    name_snapshot = models.CharField("name snapshot", max_length=255, blank=True, null=True)
    program_snapshot = models.CharField("program snapshot", max_length=100, blank=True, null=True)
    submitted_inventory = models.BooleanField("submitted inventory", default=False)
    student_match_status = models.CharField(
        "matching status",
        max_length=30,
        choices=StudentMatchStatus.choices,
        default=StudentMatchStatus.UNMATCHED
    )
    linked_student = models.ForeignKey(
        "profiles.StudentProfile",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="unlinked_submissions"
    )
    source_collection = models.ForeignKey(
        FormCollection,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="unlinked_submissions"
    )
    source_invitation = models.ForeignKey(
        FormInvitation,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="unlinked_submissions"
    )
    matched_at = models.DateTimeField("matched at", null=True, blank=True)
    linked_at = models.DateTimeField("linked at", null=True, blank=True)
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reviewed_unlinked_submissions"
    )
    reviewed_at = models.DateTimeField("reviewed at", null=True, blank=True)
    metadata_json = models.JSONField("metadata", default=dict, blank=True)

    class Meta:
        verbose_name = "unlinked student record"
        verbose_name_plural = "unlinked student records"
        indexes = [
            models.Index(fields=["student_match_status"]),
        ]

    def __str__(self):
        return f"Unlinked submission {self.id} ({self.get_student_match_status_display()})"
