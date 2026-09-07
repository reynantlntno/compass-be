# Project: COMPASS
# File: apps/call_slips/models.py
# Module: apps.call_slips
# Purpose: Call Slip records, status/assignment/schedule history, and reschedule requests.
# Domain boundary and service policy.

from datetime import timedelta
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from apps.accounts.models import RoleChoices
from apps.common.models import TimestampedModel
from apps.security.fields import EncryptedTextField
from apps.security.exceptions import FieldEncryptionUnsupportedORMOperation


class CallSlipQuerySet(models.QuerySet):
    def _reject_confidential_fields(self, fields):
        prohibited = getattr(self.model, "CONFIDENTIAL_WRITE_FIELDS", frozenset())
        if prohibited.intersection(fields):
            raise FieldEncryptionUnsupportedORMOperation()

    def update(self, **kwargs):
        self._reject_confidential_fields(kwargs)
        return super().update(**kwargs)

    def bulk_update(self, objs, fields, batch_size=None):
        self._reject_confidential_fields(fields)
        return super().bulk_update(objs, fields, batch_size=batch_size)


class CallSlipSourceTypeChoices(models.TextChoices):
    OFFICE_INITIATED = "OFFICE_INITIATED", "Office Initiated"
    REFERRAL = "REFERRAL", "Referral"
    APPOINTMENT = "APPOINTMENT", "Appointment"
    COUNSELOR_FOLLOW_UP = "COUNSELOR_FOLLOW_UP", "Counselor Follow-up"
    OTHER_APPROVED = "OTHER_APPROVED", "Other Approved"


class CallSlipPurposeCodeChoices(models.TextChoices):
    ROUTINE_INTERVIEW_REPORTING = "ROUTINE_INTERVIEW_REPORTING", "Routine Interview Reporting"
    COUNSELOR_FOLLOW_UP = "COUNSELOR_FOLLOW_UP", "Counselor Follow-up"
    GUIDANCE_INTERVIEW = "GUIDANCE_INTERVIEW", "Guidance Interview"
    APPOINTMENT_REPORTING = "APPOINTMENT_REPORTING", "Appointment Reporting"
    GENERAL_OFFICE_REPORTING = "GENERAL_OFFICE_REPORTING", "General Office Reporting"
    DOCUMENT_FOLLOW_UP = "DOCUMENT_FOLLOW_UP", "Document Follow-up"
    OTHER_APPROVED = "OTHER_APPROVED", "Other Approved"


class CallSlipModeChoices(models.TextChoices):
    ONSITE = "ONSITE", "On-site"
    ONLINE = "ONLINE", "Online"


class CallSlipDestinationChoices(models.TextChoices):
    GUIDANCE_OFFICE = "GUIDANCE_OFFICE", "Guidance Office"
    ASSIGNED_COUNSELOR = "ASSIGNED_COUNSELOR", "Assigned Counselor"
    APPROVED_OFFICE_LOCATION = "APPROVED_OFFICE_LOCATION", "Approved Office Location"
    AUTHENTICATED_ONLINE_ARRANGEMENT = "AUTHENTICATED_ONLINE_ARRANGEMENT", "Authenticated Online Arrangement"


class CallSlipWorkflowReasonChoices(models.TextChoices):
    WORKFLOW_PROGRESSION = "WORKFLOW_PROGRESSION", "Workflow Progression"
    SCHEDULE_CHANGE = "SCHEDULE_CHANGE", "Schedule Change"
    ASSIGNMENT_CHANGE = "ASSIGNMENT_CHANGE", "Assignment Change"
    STUDENT_REQUEST_APPROVED = "STUDENT_REQUEST_APPROVED", "Student Request Approved"
    STUDENT_REQUEST_DECLINED = "STUDENT_REQUEST_DECLINED", "Student Request Declined"
    DUPLICATE = "DUPLICATE", "Duplicate Record"
    INVALID_NOTICE = "INVALID_NOTICE", "Invalid Notice"
    WRONG_STUDENT = "WRONG_STUDENT", "Wrong Student"
    OFFICE_CLOSURE = "OFFICE_CLOSURE", "Office Closure"
    COUNSELOR_UNAVAILABLE = "COUNSELOR_UNAVAILABLE", "Counselor Unavailable"
    STUDENT_UNAVAILABLE = "STUDENT_UNAVAILABLE", "Student Unavailable"
    NO_RESPONSE = "NO_RESPONSE", "No Response"
    OTHER_STRUCTURED = "OTHER_STRUCTURED", "Other Structured Reason"


class CallSlipReissueReasonChoices(models.TextChoices):
    AFTER_NO_SHOW = "AFTER_NO_SHOW", "Follow-up after no-show"
    AFTER_EXPIRY = "AFTER_EXPIRY", "Replacement after expiry"
    AFTER_CANCELLATION = "AFTER_CANCELLATION", "Replacement after cancellation"


class CallSlipStatusChoices(models.TextChoices):
    DRAFT = "DRAFT", "Draft"
    ISSUED = "ISSUED", "Issued"
    ACKNOWLEDGED = "ACKNOWLEDGED", "Acknowledged"
    RESCHEDULE_REQUESTED = "RESCHEDULE_REQUESTED", "Reschedule Requested"
    ATTENDED = "ATTENDED", "Attended"
    NO_SHOW = "NO_SHOW", "No Show"
    EXPIRED = "EXPIRED", "Expired"
    CANCELLED = "CANCELLED", "Cancelled"


class CallSlipRescheduleRequestStatusChoices(models.TextChoices):
    PENDING = "PENDING", "Pending"
    APPROVED = "APPROVED", "Approved"
    DECLINED = "DECLINED", "Declined"


class CallSlipAssignmentChangeTypeChoices(models.TextChoices):
    INITIAL_ASSIGNMENT = "INITIAL_ASSIGNMENT", "Initial Assignment"
    REASSIGNMENT = "REASSIGNMENT", "Reassignment"


class CallSlipScheduleChangeTypeChoices(models.TextChoices):
    INITIAL_ISSUE = "INITIAL_ISSUE", "Initial Issue"
    REISSUE = "REISSUE", "Reissue"
    RESCHEDULE_APPROVED = "RESCHEDULE_APPROVED", "Reschedule Approved"
    ASSIGNMENT_REEVALUATION = "ASSIGNMENT_REEVALUATION", "Assignment Reevaluation"
    CANCELLATION = "CANCELLATION", "Cancellation"


COUNSELOR_TIME_PURPOSES = {
    CallSlipPurposeCodeChoices.ROUTINE_INTERVIEW_REPORTING,
    CallSlipPurposeCodeChoices.COUNSELOR_FOLLOW_UP,
    CallSlipPurposeCodeChoices.GUIDANCE_INTERVIEW,
    CallSlipPurposeCodeChoices.APPOINTMENT_REPORTING,
}

NON_COUNSELOR_TIME_PURPOSES = {
    CallSlipPurposeCodeChoices.GENERAL_OFFICE_REPORTING,
    CallSlipPurposeCodeChoices.DOCUMENT_FOLLOW_UP,
}

EVER_ISSUED_STATUSES = {
    CallSlipStatusChoices.ISSUED,
    CallSlipStatusChoices.ACKNOWLEDGED,
    CallSlipStatusChoices.RESCHEDULE_REQUESTED,
    CallSlipStatusChoices.ATTENDED,
    CallSlipStatusChoices.NO_SHOW,
    CallSlipStatusChoices.EXPIRED,
}

TERMINAL_STATUSES = {
    CallSlipStatusChoices.ATTENDED,
    CallSlipStatusChoices.NO_SHOW,
    CallSlipStatusChoices.EXPIRED,
    CallSlipStatusChoices.CANCELLED,
}


class CallSlip(TimestampedModel):
    CONFIDENTIAL_WRITE_FIELDS = frozenset({
        "student_safe_instructions", "student_safe_instructions_encrypted",
        "office_only_remarks", "office_only_remarks_encrypted",
        "cancellation_detail", "cancellation_detail_encrypted",
        "no_show_detail", "no_show_detail_encrypted",
    })
    objects = CallSlipQuerySet.as_manager()
    SOURCE_FORM_CODE = "CNSC-OP-GTA-01F8"
    SOURCE_FORM_REVISION = 0
    SOURCE_FORM_FAMILY = "call_slip"

    reference_code = models.CharField(max_length=25, unique=True, editable=False)
    student = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="call_slips")
    referral = models.ForeignKey("referrals.Referral", on_delete=models.PROTECT, null=True, blank=True, related_name="call_slips")
    appointment = models.ForeignKey("appointments.Appointment", on_delete=models.PROTECT, null=True, blank=True, related_name="call_slips")
    reissued_from = models.OneToOneField(
        "self", on_delete=models.PROTECT, null=True, blank=True, related_name="reissued_as"
    )
    reissue_reason_code = models.CharField(
        max_length=30, choices=CallSlipReissueReasonChoices.choices, blank=True
    )

    source_type = models.CharField(max_length=30, choices=CallSlipSourceTypeChoices.choices)
    purpose_code = models.CharField(max_length=30, choices=CallSlipPurposeCodeChoices.choices)
    assigned_counselor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, blank=True, related_name="assigned_call_slips")
    destination_code = models.CharField(max_length=50, choices=CallSlipDestinationChoices.choices)
    report_to_destination = models.CharField(max_length=255)

    scheduled_start_at = models.DateTimeField(null=True, blank=True)
    scheduled_end_at = models.DateTimeField(null=True, blank=True)
    expected_duration_minutes = models.PositiveIntegerField(default=60)
    mode = models.CharField(max_length=10, choices=CallSlipModeChoices.choices, default=CallSlipModeChoices.ONSITE)
    student_safe_location = models.CharField(max_length=255, blank=True)
    student_safe_instructions = models.TextField(blank=True)
    student_safe_instructions_encrypted = EncryptedTextField(
        null=True, blank=True, default=None, max_plaintext_bytes=1_048_576
    )
    status = models.CharField(max_length=30, choices=CallSlipStatusChoices.choices, default=CallSlipStatusChoices.DRAFT)

    course_snapshot = models.CharField(max_length=100, blank=True)
    year_level_snapshot = models.CharField(max_length=30, blank=True)
    office_only_remarks = models.TextField(blank=True)
    office_only_remarks_encrypted = EncryptedTextField(
        null=True, blank=True, default=None, max_plaintext_bytes=1_048_576
    )

    cancel_reason_code = models.CharField(max_length=50, choices=CallSlipWorkflowReasonChoices.choices, blank=True)
    cancellation_detail = models.TextField(blank=True)
    cancellation_detail_encrypted = EncryptedTextField(
        null=True, blank=True, default=None, max_plaintext_bytes=1_048_576
    )
    expiry_reason_code = models.CharField(max_length=50, choices=CallSlipWorkflowReasonChoices.choices, blank=True)
    no_show_reason_code = models.CharField(max_length=50, choices=CallSlipWorkflowReasonChoices.choices, blank=True)
    no_show_detail = models.TextField(blank=True)
    no_show_detail_encrypted = EncryptedTextField(
        null=True, blank=True, default=None, max_plaintext_bytes=1_048_576
    )

    issued_at = models.DateTimeField(null=True, blank=True)
    issued_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="call_slips_issued")
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    acknowledged_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="call_slips_acknowledged")
    reported_at = models.DateTimeField(null=True, blank=True)
    attendance_recorded_at = models.DateTimeField(null=True, blank=True)
    attendance_recorded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="call_slips_attendance_recorded")
    interview_ended_at = models.DateTimeField(null=True, blank=True)
    no_show_at = models.DateTimeField(null=True, blank=True)
    no_show_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="call_slips_no_shown")
    expired_at = models.DateTimeField(null=True, blank=True)
    expired_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="call_slips_expired")
    cancelled_at = models.DateTimeField(null=True, blank=True)
    cancelled_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="call_slips_cancelled")

    source_form_code = models.CharField(max_length=50, default=SOURCE_FORM_CODE, editable=False)
    source_form_revision = models.PositiveIntegerField(default=SOURCE_FORM_REVISION, editable=False)
    source_form_family = models.CharField(max_length=50, default=SOURCE_FORM_FAMILY, editable=False)
    internal_schema_version = models.PositiveIntegerField(default=1)

    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="call_slips_created")
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="call_slips_updated")
    creation_request_key = models.CharField(max_length=100, unique=True, editable=False)

    class Meta:
        ordering = ["-updated_at"]
        indexes = [
            models.Index(fields=["status", "scheduled_start_at"]),
            models.Index(fields=["assigned_counselor", "status", "scheduled_start_at"]),
            models.Index(fields=["student", "status"]),
            models.Index(fields=["reference_code"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["referral"],
                condition=(
                    models.Q(referral__isnull=False)
                    & models.Q(status__in=["DRAFT", "ISSUED", "ACKNOWLEDGED", "RESCHEDULE_REQUESTED"])
                ),
                name="uniq_active_referral_call_slip",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(source_type="REFERRAL", referral__isnull=False)
                    | (~models.Q(source_type="REFERRAL") & models.Q(referral__isnull=True))
                ),
                name="call_slip_referral_source_pair",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(reissued_from__isnull=True, reissue_reason_code="")
                    | (
                        models.Q(reissued_from__isnull=False)
                        & models.Q(reissue_reason_code__in=[
                            "AFTER_NO_SHOW", "AFTER_EXPIRY", "AFTER_CANCELLATION",
                        ])
                    )
                ),
                name="call_slip_reissue_pair",
            ),
        ]

    def __str__(self):
        return self.reference_code or f"Call Slip #{self.pk}"

    def clean(self):
        super().clean()
        deferred = self.get_deferred_fields()
        # 1. Student validation
        if self.student_id:
            if not self.student.is_active:
                raise ValidationError({"student": "Student account must be active."})
            if self.student.role != RoleChoices.STUDENT:
                raise ValidationError({"student": "Assigned user is not a student."})
            if not hasattr(self.student, "student_profile"):
                raise ValidationError({"student": "Student must have a profile."})

        # 2. Counselor validation
        if self.assigned_counselor_id:
            if not self.assigned_counselor.is_active:
                raise ValidationError({"assigned_counselor": "Assigned counselor must be active."})
            if self.assigned_counselor.role != RoleChoices.COUNSELOR:
                raise ValidationError({"assigned_counselor": "Assigned user is not a counselor."})

        # 3. Referral and Appointment validation
        if self.referral_id and self.referral.student_id != self.student_id:
            raise ValidationError({"referral": "Linked referral must belong to the same student."})
        if self.appointment_id and self.appointment.student_id != self.student_id:
            raise ValidationError({"appointment": "Linked appointment must belong to the same student."})

        # 4. Source constraints
        if self.source_type == CallSlipSourceTypeChoices.REFERRAL and not self.referral_id:
            raise ValidationError({"referral": "Referral source type requires a linked Referral."})
        if self.referral_id and self.source_type != CallSlipSourceTypeChoices.REFERRAL:
            raise ValidationError({"source_type": "Linked Referral requires Referral source type."})
        if self.source_type == CallSlipSourceTypeChoices.APPOINTMENT and not self.appointment_id:
            raise ValidationError({"appointment": "Appointment source type requires a linked Appointment."})

        if self.reissued_from_id:
            predecessor = self.reissued_from
            if predecessor.student_id != self.student_id or predecessor.referral_id != self.referral_id:
                raise ValidationError({"reissued_from": "Reissued Call Slip must keep the same student and Referral."})
            expected_reason = {
                CallSlipStatusChoices.NO_SHOW: CallSlipReissueReasonChoices.AFTER_NO_SHOW,
                CallSlipStatusChoices.EXPIRED: CallSlipReissueReasonChoices.AFTER_EXPIRY,
                CallSlipStatusChoices.CANCELLED: CallSlipReissueReasonChoices.AFTER_CANCELLATION,
            }.get(predecessor.status)
            if expected_reason is None or self.reissue_reason_code != expected_reason:
                raise ValidationError({"reissue_reason_code": "Reissue reason must match an eligible terminal Call Slip."})
            if self.status != CallSlipStatusChoices.DRAFT:
                raise ValidationError({"status": "A reissued Call Slip must begin as a draft."})
        elif self.reissue_reason_code:
            raise ValidationError({"reissue_reason_code": "Reissue reason requires a predecessor Call Slip."})

        # 5. Issued or later state completeness
        requires_issued_evidence = self.status in EVER_ISSUED_STATUSES or (
            self.status == CallSlipStatusChoices.CANCELLED and self.issued_at is not None
        )
        if requires_issued_evidence:
            if not self.scheduled_start_at or not self.scheduled_end_at:
                raise ValidationError("Issued call slips require scheduled start and end timestamps.")
            if self.scheduled_start_at >= self.scheduled_end_at:
                raise ValidationError("Scheduled start must be before scheduled end.")
            if self.expected_duration_minutes <= 0:
                raise ValidationError({"expected_duration_minutes": "Expected duration must be positive."})

            # scheduled_end_at == scheduled_start_at + expected_duration_minutes
            calculated_end = self.scheduled_start_at + timedelta(minutes=self.expected_duration_minutes)
            # Compare up to second/minute level tolerance or exact equality
            if abs((self.scheduled_end_at - calculated_end).total_seconds()) > 1:
                raise ValidationError("Scheduled end must match scheduled start plus expected duration.")

            if not self.report_to_destination.strip():
                raise ValidationError({"report_to_destination": "Report destination is required."})
            if not self.student_safe_location.strip():
                raise ValidationError({"student_safe_location": "Safe location label is required for student viewing."})
            if "student_safe_instructions" not in deferred and not self.student_safe_instructions.strip():
                raise ValidationError({"student_safe_instructions": "Safe instructions are required for student viewing."})
            if not self.issued_at or not self.issued_by_id:
                raise ValidationError("Issued call slips require issue attribution.")

            # Counselor-time purpose classification checks counselor
            if self.purpose_code in COUNSELOR_TIME_PURPOSES and not self.assigned_counselor_id:
                raise ValidationError({"assigned_counselor": "Counselor-time purposes require an assigned counselor."})

        # 6. Online provider safeguards
        if self.mode == CallSlipModeChoices.ONLINE:
            unsafe_fragments = ["daily", "daily.co", "zoom", "teams", "http", "jwt", "password"]
            instructions = "" if "student_safe_instructions" in deferred else self.student_safe_instructions
            haystack = f"{self.report_to_destination} {self.student_safe_location} {instructions}".lower()
            if any(frag in haystack for frag in unsafe_fragments):
                raise ValidationError("Online call slip fields must not contain provider URLs, credentials, or meeting links.")

        # 7. State-specific attributions
        if self.status == CallSlipStatusChoices.ATTENDED:
            if not self.attendance_recorded_at or not self.attendance_recorded_by_id:
                raise ValidationError("Attended call slips require attendance attribution.")
        if self.status == CallSlipStatusChoices.NO_SHOW:
            if not self.no_show_at or not self.no_show_by_id or not self.no_show_reason_code:
                raise ValidationError("No-show call slips require no-show attribution and a structured reason code.")
        if self.status == CallSlipStatusChoices.EXPIRED:
            if not self.expired_at or not self.expired_by_id or not self.expiry_reason_code:
                raise ValidationError("Expired call slips require expiry attribution and a structured reason code.")
        if self.status == CallSlipStatusChoices.CANCELLED:
            if not self.cancelled_at or not self.cancelled_by_id or not self.cancel_reason_code:
                raise ValidationError("Cancelled call slips require cancellation attribution and a structured reason code.")

    def save(self, *args, **kwargs):
        if self.pk:
            # Immutability validation
            immutable = (
                "reference_code", "source_form_code", "source_form_revision",
                "source_form_family", "creation_request_key",
            )
            # Referral-originated creation inputs are server-derived and
            # immutable.  Preserve the legacy generic Call Slip workflow,
            # where purpose/source can still be completed while a draft is
            # being prepared.
            original_referral_id = type(self).objects.only("referral_id").get(pk=self.pk).referral_id
            if original_referral_id or self.referral_id:
                immutable += (
                    "student_id", "referral_id", "source_type", "purpose_code",
                    "reissued_from_id", "reissue_reason_code",
                )
            snapshots = ("course_snapshot", "year_level_snapshot")
            original = type(self).objects.only(*immutable, *snapshots, "status").get(pk=self.pk)
            for field in immutable:
                if getattr(self, field) != getattr(original, field):
                    raise ValidationError(f"The field '{field}' is immutable.")
            # Frozen snapshots on issue
            if original.status in EVER_ISSUED_STATUSES:
                for field in snapshots:
                    if getattr(self, field) != getattr(original, field):
                        raise ValidationError(f"The frozen field '{field}' cannot be changed after issuance.")

            # Terminal state validation
            if original.status in TERMINAL_STATUSES:
                # Disallow edits entirely once terminal
                raise ValidationError("Terminal call slip records cannot be edited, assigned, rescheduled, or mutated.")

        self.full_clean(exclude=self.get_deferred_fields())
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Call Slip records cannot be deleted.")


class AppendOnlyCallSlipModel(TimestampedModel):
    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        if self.pk:
            raise ValidationError("This evidence record is append-only.")
        self.full_clean(exclude=self.get_deferred_fields())
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("This evidence record cannot be deleted.")


class CallSlipStatusHistory(AppendOnlyCallSlipModel):
    call_slip = models.ForeignKey(CallSlip, on_delete=models.PROTECT, related_name="status_histories")
    from_status = models.CharField(max_length=30, blank=True)
    to_status = models.CharField(max_length=30, choices=CallSlipStatusChoices.choices)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="call_slip_status_changes")
    reason_code = models.CharField(max_length=50, choices=CallSlipWorkflowReasonChoices.choices)
    transitioned_at = models.DateTimeField(default=timezone.now)
    request_key = models.CharField(max_length=100, blank=True)

    class Meta:
        ordering = ["-transitioned_at"]


class CallSlipAssignmentHistory(AppendOnlyCallSlipModel):
    CONFIDENTIAL_WRITE_FIELDS = frozenset({"detail", "detail_encrypted"})
    objects = CallSlipQuerySet.as_manager()
    call_slip = models.ForeignKey(CallSlip, on_delete=models.PROTECT, related_name="assignment_histories")
    from_counselor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    to_counselor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    changed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="call_slip_assignment_changes")
    reason_code = models.CharField(max_length=50, choices=CallSlipWorkflowReasonChoices.choices)
    change_type = models.CharField(max_length=30, choices=CallSlipAssignmentChangeTypeChoices.choices)
    changed_at = models.DateTimeField(default=timezone.now)
    detail = models.TextField(blank=True) # Sensitive internal detail excluded from audit/unsafe surfaces
    detail_encrypted = EncryptedTextField(
        null=True, blank=True, default=None, max_plaintext_bytes=1_048_576
    )

    class Meta:
        ordering = ["-changed_at"]

    def clean(self):
        super().clean()
        if self.to_counselor_id:
            if not self.to_counselor.is_active:
                raise ValidationError({"to_counselor": "Target counselor must be active."})
            if self.to_counselor.role != RoleChoices.COUNSELOR:
                raise ValidationError({"to_counselor": "Target user is not a counselor."})


class CallSlipScheduleHistory(AppendOnlyCallSlipModel):
    call_slip = models.ForeignKey(CallSlip, on_delete=models.PROTECT, related_name="schedule_histories")
    change_type = models.CharField(max_length=30, choices=CallSlipScheduleChangeTypeChoices.choices)

    previous_start_at = models.DateTimeField(null=True, blank=True)
    previous_end_at = models.DateTimeField(null=True, blank=True)
    previous_expected_duration_minutes = models.PositiveIntegerField(null=True, blank=True)

    new_start_at = models.DateTimeField(null=True, blank=True)
    new_end_at = models.DateTimeField(null=True, blank=True)
    new_expected_duration_minutes = models.PositiveIntegerField(null=True, blank=True)

    previous_counselor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    new_counselor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+")

    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="call_slip_schedule_changes")
    reason_code = models.CharField(max_length=50, choices=CallSlipWorkflowReasonChoices.choices)
    changed_at = models.DateTimeField(default=timezone.now)

    availability_blocking_before = models.BooleanField(default=False)
    availability_blocking_after = models.BooleanField(default=False)

    class Meta:
        ordering = ["-changed_at"]


class CallSlipRescheduleRequest(TimestampedModel):
    CONFIDENTIAL_WRITE_FIELDS = frozenset({
        "student_reason", "student_reason_encrypted",
        "decision_detail", "decision_detail_encrypted",
    })
    objects = CallSlipQuerySet.as_manager()
    call_slip = models.ForeignKey(CallSlip, on_delete=models.PROTECT, related_name="reschedule_requests")
    student = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="call_slip_reschedule_requests")

    previous_status_snapshot = models.CharField(max_length=30, choices=CallSlipStatusChoices.choices)

    previous_start_at = models.DateTimeField()
    previous_end_at = models.DateTimeField()
    previous_expected_duration_minutes = models.PositiveIntegerField()

    proposed_start_at = models.DateTimeField()
    proposed_end_at = models.DateTimeField()
    proposed_expected_duration_minutes = models.PositiveIntegerField()

    student_reason = models.TextField() # Sensitive student reason
    student_reason_encrypted = EncryptedTextField(
        null=True, blank=True, default=None, max_plaintext_bytes=1_048_576
    )
    request_key = models.CharField(max_length=100)
    status = models.CharField(
        max_length=20,
        choices=CallSlipRescheduleRequestStatusChoices.choices,
        default=CallSlipRescheduleRequestStatusChoices.PENDING
    )

    decider = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="call_slip_reschedule_decisions")
    decided_at = models.DateTimeField(null=True, blank=True)
    decision_code = models.CharField(max_length=50, choices=CallSlipWorkflowReasonChoices.choices, blank=True)
    decision_detail = models.TextField(blank=True) # Sensitive decision detail
    decision_detail_encrypted = EncryptedTextField(
        null=True, blank=True, default=None, max_plaintext_bytes=1_048_576
    )

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["call_slip", "request_key"],
                name="uniq_call_slip_reschedule_request"
            ),
            models.UniqueConstraint(
                fields=["call_slip"],
                condition=models.Q(status=CallSlipRescheduleRequestStatusChoices.PENDING),
                name="uniq_pending_call_slip_reschedule"
            ),
        ]

    def clean(self):
        super().clean()
        if self.proposed_start_at and self.proposed_end_at:
            if self.proposed_start_at >= self.proposed_end_at:
                raise ValidationError({"proposed_end_at": "Proposed start must be before proposed end."})
            calculated_end = self.proposed_start_at + timedelta(minutes=self.proposed_expected_duration_minutes)
            if abs((self.proposed_end_at - calculated_end).total_seconds()) > 1:
                raise ValidationError("Proposed end must match proposed start plus proposed expected duration.")

        if self.previous_status_snapshot not in (CallSlipStatusChoices.ISSUED, CallSlipStatusChoices.ACKNOWLEDGED):
            raise ValidationError({"previous_status_snapshot": "Reschedule requests can only snapshot ISSUED or ACKNOWLEDGED statuses."})

        if self.status != CallSlipRescheduleRequestStatusChoices.PENDING:
            if not self.decided_at or not self.decider_id or not self.decision_code:
                raise ValidationError("Decided requests require decider, decided time, and decision code.")

    def save(self, *args, **kwargs):
        if self.pk:
            original = type(self).objects.only(
                "status", "call_slip_id", "student_id", "previous_status_snapshot",
                "previous_start_at", "previous_end_at", "previous_expected_duration_minutes",
                "proposed_start_at", "proposed_end_at", "proposed_expected_duration_minutes",
                "request_key",
            ).get(pk=self.pk)
            immutable = (
                "call_slip_id",
                "student_id",
                "previous_status_snapshot",
                "previous_start_at",
                "previous_end_at",
                "previous_expected_duration_minutes",
                "proposed_start_at",
                "proposed_end_at",
                "proposed_expected_duration_minutes",
                "request_key",
            )
            for field in immutable:
                if getattr(self, field) != getattr(original, field):
                    raise ValidationError(f"The reschedule snapshot field '{field}' is immutable.")
            if original.status != CallSlipRescheduleRequestStatusChoices.PENDING:
                raise ValidationError("Decided reschedule requests are immutable.")
        self.full_clean(exclude=self.get_deferred_fields())
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Reschedule requests cannot be deleted.")
