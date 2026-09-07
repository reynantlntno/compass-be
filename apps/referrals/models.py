# Project: COMPASS
# File: apps/referrals/models.py
# Module: apps.referrals
# Purpose: Referral records, append-only evidence, reassignment, and AY counters.
# Domain boundary and service policy.

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from apps.accounts.models import RoleChoices
from apps.common.models import TimestampedModel
from apps.security.fields import EncryptedTextField


class ReferralSourceTypeChoices(models.TextChoices):
    FACULTY = "FACULTY", "Faculty"
    ADVISER = "ADVISER", "Adviser"
    INSTITUTIONAL_STAFF = "INSTITUTIONAL_STAFF", "Institutional Staff"
    PARENT_GUARDIAN = "PARENT_GUARDIAN", "Parent or Guardian"
    GCO = "GCO", "Guidance Office"
    OTHER = "OTHER", "Other"


class ReferralReasonCategoryChoices(models.TextChoices):
    UNCATEGORIZED = "UNCATEGORIZED", "Uncategorized"
    ACADEMIC = "ACADEMIC", "Academic"
    ATTENDANCE = "ATTENDANCE", "Attendance"
    BEHAVIOR_OR_CONDUCT = "BEHAVIOR_OR_CONDUCT", "Behavior or Conduct"
    PERSONAL_OR_SOCIAL = "PERSONAL_OR_SOCIAL", "Personal or Social"
    FAMILY_OR_HOME = "FAMILY_OR_HOME", "Family or Home"
    FINANCIAL = "FINANCIAL", "Financial"
    CAREER_OR_PLANNING = "CAREER_OR_PLANNING", "Career or Planning"
    OTHER = "OTHER", "Other"


class ReferralStatusChoices(models.TextChoices):
    DRAFT = "DRAFT", "Draft"
    SUBMITTED = "SUBMITTED", "Submitted"
    RECEIVED = "RECEIVED", "Received"
    UNDER_REVIEW = "UNDER_REVIEW", "Under Review"
    ACTION_REQUIRED = "ACTION_REQUIRED", "Action Required"
    ESCALATED = "ESCALATED", "Head Review"
    CLOSED = "CLOSED", "Closed"
    CANCELLED = "CANCELLED", "Cancelled"


class ReferralActionCodeChoices(models.TextChoices):
    PARENT_CONTACT_ATTEMPTED = "PARENT_CONTACT_ATTEMPTED", "Parent contact attempted"
    PARENT_NOTIFICATION_RECORDED = "PARENT_NOTIFICATION_RECORDED", "Parent notification recorded"
    CALL_SLIP_NEEDED = "CALL_SLIP_NEEDED", "Call slip needed"
    INTERVIEW_SCHEDULING_NEEDED = "INTERVIEW_SCHEDULING_NEEDED", "Interview scheduling needed"
    MONITORING_RECORDED = "MONITORING_RECORDED", "Monitoring recorded"
    HEAD_REVIEW_REQUESTED = "HEAD_REVIEW_REQUESTED", "Head review requested"
    CLOSURE_RECOMMENDED = "CLOSURE_RECOMMENDED", "Closure recommended"
    OTHER_OPERATIONAL_ACTION = "OTHER_OPERATIONAL_ACTION", "Other operational action"


class ReferralActionOutcomeCodeChoices(models.TextChoices):
    ATTEMPTED = "ATTEMPTED", "Attempted"
    COMPLETED = "COMPLETED", "Completed"
    RECORDED = "RECORDED", "Recorded"
    NO_RESPONSE = "NO_RESPONSE", "No response"
    FOLLOW_UP_REQUIRED = "FOLLOW_UP_REQUIRED", "Follow-up required"
    NOT_APPLICABLE = "NOT_APPLICABLE", "Not applicable"


class ReferralWorkflowReasonCodeChoices(models.TextChoices):
    WORKFLOW_PROGRESSION = "WORKFLOW_PROGRESSION", "Workflow progression"
    HEAD_REVIEW = "HEAD_REVIEW", "Head review"
    WORK_COMPLETED = "WORK_COMPLETED", "Work completed"
    DUPLICATE = "DUPLICATE", "Duplicate record"
    INVALID_INTAKE = "INVALID_INTAKE", "Invalid intake"
    WRONG_STUDENT = "WRONG_STUDENT", "Wrong student selected"
    TRANSFER_REQUIRED = "TRANSFER_REQUIRED", "Transfer required"
    OTHER_STRUCTURED = "OTHER_STRUCTURED", "Other structured reason"


class ReferralAssignmentChangeTypeChoices(models.TextChoices):
    INITIAL_ASSIGNMENT = "INITIAL_ASSIGNMENT", "Initial Assignment"
    REASSIGNMENT = "REASSIGNMENT", "Reassignment"


class ReferralReassignmentStatusChoices(models.TextChoices):
    PENDING = "PENDING", "Pending"
    APPROVED = "APPROVED", "Approved"
    DECLINED = "DECLINED", "Declined"
    CANCELLED = "CANCELLED", "Cancelled"


SUBMITTED_OR_LATER_STATUSES = {
    ReferralStatusChoices.SUBMITTED,
    ReferralStatusChoices.RECEIVED,
    ReferralStatusChoices.UNDER_REVIEW,
    ReferralStatusChoices.ACTION_REQUIRED,
    ReferralStatusChoices.ESCALATED,
    ReferralStatusChoices.CLOSED,
}
RECEIVED_OR_LATER_STATUSES = SUBMITTED_OR_LATER_STATUSES - {ReferralStatusChoices.SUBMITTED}


class Referral(TimestampedModel):
    SOURCE_FORM_CODE = "CNSC-OP-GTA-01F9"
    SOURCE_FORM_REVISION = 1
    SOURCE_FORM_FAMILY = "referral_slip"

    reference_code = models.CharField(max_length=25, unique=True, editable=False)
    student = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="referrals")
    source_type = models.CharField(max_length=30, choices=ReferralSourceTypeChoices.choices)
    referred_by_user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="submitted_referrals")
    referrer_display_snapshot = models.CharField(max_length=255, blank=True)
    reason_text = models.TextField(blank=True)
    reason_text_encrypted = EncryptedTextField(
        null=True,
        blank=True,
        default=None,
        max_plaintext_bytes=1_048_576,
    )
    reason_category_code = models.CharField(max_length=30, choices=ReferralReasonCategoryChoices.choices, default=ReferralReasonCategoryChoices.UNCATEGORIZED, blank=True)
    occurred_at = models.DateTimeField(null=True, blank=True)
    source_signed_on = models.DateField(null=True, blank=True)
    submitted_at = models.DateTimeField(null=True, blank=True)
    submitted_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="referrals_submitted")
    received_at = models.DateTimeField(null=True, blank=True)
    received_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="referrals_received")
    course_snapshot = models.CharField(max_length=100, blank=True)
    year_level_snapshot = models.CharField(max_length=30, blank=True)
    block_snapshot = models.CharField(max_length=100, blank=True)
    assigned_counselor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="assigned_referrals")
    status = models.CharField(max_length=30, choices=ReferralStatusChoices.choices, default=ReferralStatusChoices.DRAFT)
    source_form_code = models.CharField(max_length=50, default=SOURCE_FORM_CODE, editable=False)
    source_form_revision = models.PositiveIntegerField(default=SOURCE_FORM_REVISION, editable=False)
    source_form_family = models.CharField(max_length=50, default=SOURCE_FORM_FAMILY, editable=False)
    internal_schema_version = models.PositiveIntegerField(default=1)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="referrals_created")
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="referrals_updated")
    closed_at = models.DateTimeField(null=True, blank=True)
    closed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="referrals_closed")
    close_reason_code = models.CharField(max_length=50, choices=ReferralWorkflowReasonCodeChoices.choices, blank=True)
    cancelled_at = models.DateTimeField(null=True, blank=True)
    cancelled_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="referrals_cancelled")
    cancel_reason_code = models.CharField(max_length=50, choices=ReferralWorkflowReasonCodeChoices.choices, blank=True)
    reopened_at = models.DateTimeField(null=True, blank=True)
    reopened_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="referrals_reopened")
    reopen_reason_code = models.CharField(max_length=50, choices=ReferralWorkflowReasonCodeChoices.choices, blank=True)
    creation_request_key = models.CharField(max_length=100, unique=True, editable=False)

    class Meta:
        ordering = ["-updated_at"]
        indexes = [
            models.Index(fields=["status", "updated_at"]),
            models.Index(fields=["assigned_counselor", "status"]),
            models.Index(fields=["student", "status"]),
            models.Index(fields=["received_at"]),
        ]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(source_type__in=[
                    "FACULTY", "ADVISER", "INSTITUTIONAL_STAFF",
                    "PARENT_GUARDIAN", "GCO", "OTHER",
                ]),
                name="referral_source_type_known",
            ),
            models.CheckConstraint(
                condition=models.Q(reason_category_code__in=[
                    "", "UNCATEGORIZED", "ACADEMIC", "ATTENDANCE",
                    "BEHAVIOR_OR_CONDUCT", "PERSONAL_OR_SOCIAL",
                    "FAMILY_OR_HOME", "FINANCIAL", "CAREER_OR_PLANNING", "OTHER",
                ]),
                name="referral_reason_category_known",
            ),
            models.CheckConstraint(
                condition=models.Q(status__in=[
                    "DRAFT", "SUBMITTED", "RECEIVED", "UNDER_REVIEW",
                    "ACTION_REQUIRED", "ESCALATED", "CLOSED", "CANCELLED",
                ]),
                name="referral_status_known",
            ),
            models.CheckConstraint(
                condition=models.Q(close_reason_code__in=[
                    "", "WORKFLOW_PROGRESSION", "HEAD_REVIEW", "WORK_COMPLETED",
                    "DUPLICATE", "INVALID_INTAKE", "WRONG_STUDENT",
                    "TRANSFER_REQUIRED", "OTHER_STRUCTURED",
                ]),
                name="referral_close_reason_known",
            ),
            models.CheckConstraint(
                condition=models.Q(cancel_reason_code__in=[
                    "", "WORKFLOW_PROGRESSION", "HEAD_REVIEW", "WORK_COMPLETED",
                    "DUPLICATE", "INVALID_INTAKE", "WRONG_STUDENT",
                    "TRANSFER_REQUIRED", "OTHER_STRUCTURED",
                ]),
                name="referral_cancel_reason_known",
            ),
            models.CheckConstraint(
                condition=models.Q(reopen_reason_code__in=[
                    "", "WORKFLOW_PROGRESSION", "HEAD_REVIEW", "WORK_COMPLETED",
                    "DUPLICATE", "INVALID_INTAKE", "WRONG_STUDENT",
                    "TRANSFER_REQUIRED", "OTHER_STRUCTURED",
                ]),
                name="referral_reopen_reason_known",
            ),
        ]

    def __str__(self):
        return self.reference_code or f"Referral #{self.pk}"

    def clean(self):
        super().clean()
        deferred = self.get_deferred_fields()
        if self.student_id:
            if self.student.role != RoleChoices.STUDENT or not self.student.is_active or not hasattr(self.student, "student_profile"):
                raise ValidationError({"student": "Select an active student account with a student profile."})
        if self.assigned_counselor_id:
            if self.assigned_counselor.role != RoleChoices.COUNSELOR or not self.assigned_counselor.is_active:
                raise ValidationError({"assigned_counselor": "Select an active counselor account."})
        if self.status in SUBMITTED_OR_LATER_STATUSES:
            missing = []
            if "reason_text" not in deferred and not self.reason_text.strip():
                missing.append("reason_text")
            if not self.course_snapshot.strip():
                missing.append("course_snapshot")
            if not self.year_level_snapshot.strip():
                missing.append("year_level_snapshot")
            if not self.block_snapshot.strip():
                missing.append("block_snapshot")
            if not self.submitted_at or not self.submitted_by_id:
                missing.append("submitted_at")
            if missing:
                raise ValidationError("Submitted referrals require complete source evidence.")
        if self.status in RECEIVED_OR_LATER_STATUSES and (not self.received_at or not self.received_by_id):
            raise ValidationError("Received referrals require receipt attribution.")
        if self.status == ReferralStatusChoices.CLOSED and (not self.closed_at or not self.closed_by_id or not self.close_reason_code):
            raise ValidationError("Closed referrals require close attribution and a reason code.")
        if self.status == ReferralStatusChoices.CANCELLED and (not self.cancelled_at or not self.cancelled_by_id or not self.cancel_reason_code):
            raise ValidationError("Cancelled referrals require cancellation attribution and a reason code.")

    def save(self, *args, **kwargs):
        if self.pk:
            immutable = ("reference_code", "source_form_code", "source_form_revision", "source_form_family", "creation_request_key")
            snapshots = ("course_snapshot", "year_level_snapshot", "block_snapshot")
            original = type(self).objects.only(*immutable, *snapshots, "status").get(pk=self.pk)
            if any(getattr(self, field) != getattr(original, field) for field in immutable):
                raise ValidationError("Referral reference and source metadata are immutable.")
            if original.status != ReferralStatusChoices.DRAFT:
                if any(getattr(self, field) != getattr(original, field) for field in snapshots):
                    raise ValidationError("Submitted source evidence snapshots are immutable.")
        self.full_clean(exclude=self.get_deferred_fields())
        return super().save(*args, **kwargs)


class AppendOnlyReferralModel(TimestampedModel):
    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        if self.pk:
            raise ValidationError("This evidence record is append-only.")
        self.full_clean()
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("This evidence record cannot be deleted.")


class ReferralAction(AppendOnlyReferralModel):
    referral = models.ForeignKey(Referral, on_delete=models.PROTECT, related_name="actions")
    action_code = models.CharField(max_length=50, choices=ReferralActionCodeChoices.choices)
    outcome_code = models.CharField(max_length=50, choices=ReferralActionOutcomeCodeChoices.choices, blank=True)
    remarks = models.TextField(blank=True)
    remarks_encrypted = EncryptedTextField(
        null=True,
        blank=True,
        default=None,
        max_plaintext_bytes=1_048_576,
    )
    performed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="referral_actions_performed")
    performed_at = models.DateTimeField()
    request_key = models.CharField(max_length=100)

    class Meta:
        ordering = ["-performed_at"]
        constraints = [
            models.UniqueConstraint(fields=["referral", "request_key"], name="uniq_referral_action_request"),
            models.CheckConstraint(
                condition=models.Q(action_code__in=[
                    "PARENT_CONTACT_ATTEMPTED", "PARENT_NOTIFICATION_RECORDED",
                    "CALL_SLIP_NEEDED", "INTERVIEW_SCHEDULING_NEEDED",
                    "MONITORING_RECORDED", "HEAD_REVIEW_REQUESTED",
                    "CLOSURE_RECOMMENDED", "OTHER_OPERATIONAL_ACTION",
                ]),
                name="referral_action_code_known",
            ),
            models.CheckConstraint(
                condition=models.Q(outcome_code__in=[
                    "", "ATTEMPTED", "COMPLETED", "RECORDED", "NO_RESPONSE",
                    "FOLLOW_UP_REQUIRED", "NOT_APPLICABLE",
                ]),
                name="referral_action_outcome_known",
            ),
        ]


class ReferralStatusHistory(AppendOnlyReferralModel):
    referral = models.ForeignKey(Referral, on_delete=models.PROTECT, related_name="status_history")
    from_status = models.CharField(max_length=30, blank=True)
    to_status = models.CharField(max_length=30, choices=ReferralStatusChoices.choices)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="referral_status_changes")
    reason_code = models.CharField(max_length=50, choices=ReferralWorkflowReasonCodeChoices.choices, blank=True)
    reason_detail = models.TextField(blank=True)
    reason_detail_encrypted = EncryptedTextField(
        null=True,
        blank=True,
        default=None,
        max_plaintext_bytes=1_048_576,
    )
    transitioned_at = models.DateTimeField()
    request_key = models.CharField(max_length=100, blank=True)

    class Meta:
        ordering = ["-transitioned_at"]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(from_status__in=[
                    "", "DRAFT", "SUBMITTED", "RECEIVED", "UNDER_REVIEW",
                    "ACTION_REQUIRED", "ESCALATED", "CLOSED", "CANCELLED",
                ]),
                name="referral_history_from_status_known",
            ),
            models.CheckConstraint(
                condition=models.Q(to_status__in=[
                    "DRAFT", "SUBMITTED", "RECEIVED", "UNDER_REVIEW",
                    "ACTION_REQUIRED", "ESCALATED", "CLOSED", "CANCELLED",
                ]),
                name="referral_history_to_status_known",
            ),
            models.CheckConstraint(
                condition=models.Q(reason_code__in=[
                    "", "WORKFLOW_PROGRESSION", "HEAD_REVIEW", "WORK_COMPLETED",
                    "DUPLICATE", "INVALID_INTAKE", "WRONG_STUDENT",
                    "TRANSFER_REQUIRED", "OTHER_STRUCTURED",
                ]),
                name="referral_history_reason_known",
            ),
        ]


class ReferralAssignmentHistory(AppendOnlyReferralModel):
    referral = models.ForeignKey(Referral, on_delete=models.PROTECT, related_name="assignment_history")
    from_counselor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    to_counselor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    changed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="referral_assignment_changes")
    reason_code = models.CharField(max_length=50, choices=ReferralWorkflowReasonCodeChoices.choices)
    detail = models.TextField(blank=True)
    detail_encrypted = EncryptedTextField(
        null=True,
        blank=True,
        default=None,
        max_plaintext_bytes=1_048_576,
    )
    change_type = models.CharField(max_length=30, choices=ReferralAssignmentChangeTypeChoices.choices)
    changed_at = models.DateTimeField()

    class Meta:
        ordering = ["-changed_at"]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(reason_code__in=[
                    "WORKFLOW_PROGRESSION", "HEAD_REVIEW", "WORK_COMPLETED",
                    "DUPLICATE", "INVALID_INTAKE", "WRONG_STUDENT",
                    "TRANSFER_REQUIRED", "OTHER_STRUCTURED",
                ]),
                name="referral_assignment_reason_known",
            ),
            models.CheckConstraint(
                condition=models.Q(change_type__in=["INITIAL_ASSIGNMENT", "REASSIGNMENT"]),
                name="referral_assignment_change_type_known",
            ),
        ]


class ReferralReassignmentRequest(TimestampedModel):
    referral = models.ForeignKey(Referral, on_delete=models.PROTECT, related_name="reassignment_requests")
    requester = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="referral_reassignment_requests")
    current_counselor_snapshot = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    proposed_counselor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="proposed_referral_reassignments")
    request_reason_code = models.CharField(max_length=50, choices=ReferralWorkflowReasonCodeChoices.choices)
    request_detail = models.TextField(blank=True)
    request_detail_encrypted = EncryptedTextField(
        null=True,
        blank=True,
        default=None,
        max_plaintext_bytes=1_048_576,
    )
    request_key = models.CharField(max_length=100)
    status = models.CharField(max_length=20, choices=ReferralReassignmentStatusChoices.choices, default=ReferralReassignmentStatusChoices.PENDING)
    decider = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="referral_reassignment_decisions")
    decided_at = models.DateTimeField(null=True, blank=True)
    decision_code = models.CharField(max_length=50, choices=ReferralWorkflowReasonCodeChoices.choices, blank=True)
    decision_detail = models.TextField(blank=True)
    decision_detail_encrypted = EncryptedTextField(
        null=True,
        blank=True,
        default=None,
        max_plaintext_bytes=1_048_576,
    )

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(fields=["referral", "request_key"], name="uniq_referral_reassignment_request"),
            models.UniqueConstraint(fields=["referral"], condition=models.Q(status=ReferralReassignmentStatusChoices.PENDING), name="uniq_pending_referral_reassignment"),
            models.CheckConstraint(
                condition=models.Q(request_reason_code__in=[
                    "WORKFLOW_PROGRESSION", "HEAD_REVIEW", "WORK_COMPLETED",
                    "DUPLICATE", "INVALID_INTAKE", "WRONG_STUDENT",
                    "TRANSFER_REQUIRED", "OTHER_STRUCTURED",
                ]),
                name="referral_reassign_request_reason_known",
            ),
            models.CheckConstraint(
                condition=models.Q(status__in=["PENDING", "APPROVED", "DECLINED", "CANCELLED"]),
                name="referral_reassign_status_known",
            ),
            models.CheckConstraint(
                condition=models.Q(decision_code__in=[
                    "", "WORKFLOW_PROGRESSION", "HEAD_REVIEW", "WORK_COMPLETED",
                    "DUPLICATE", "INVALID_INTAKE", "WRONG_STUDENT",
                    "TRANSFER_REQUIRED", "OTHER_STRUCTURED",
                ]),
                name="referral_reassign_decision_known",
            ),
        ]

    def clean(self):
        super().clean()
        if self.proposed_counselor_id and (self.proposed_counselor.role != RoleChoices.COUNSELOR or not self.proposed_counselor.is_active):
            raise ValidationError({"proposed_counselor": "Select an active counselor account."})

    def save(self, *args, **kwargs):
        if self.pk:
            original = type(self).objects.only("status").get(pk=self.pk)
            if original.status != ReferralReassignmentStatusChoices.PENDING:
                raise ValidationError("Decided reassignment requests are immutable.")
        self.full_clean(exclude=self.get_deferred_fields())
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Reassignment requests cannot be deleted.")
