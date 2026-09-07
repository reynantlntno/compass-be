# Project: COMPASS
# File: apps/counseling/models.py
# Module: apps.counseling
# Purpose: Backend-only counseling session core models
# Domain boundary and service policy.

from datetime import timedelta
import uuid
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.db.models import Q
from django.utils import timezone

from apps.common.models import TimestampedModel
from apps.security.fields import EncryptedTextField


class SessionTypeChoices(models.TextChoices):
    COUNSELING = "COUNSELING", "Counseling"
    ROUTINE_INTERVIEW = "ROUTINE_INTERVIEW", "Routine Interview"
    FOLLOW_UP = "FOLLOW_UP", "Follow-up"
    TRIAGE = "TRIAGE", "Triage"
    ADMINISTRATIVE_INTERVIEW = "ADMINISTRATIVE_INTERVIEW", "Administrative Interview"


class SessionModeChoices(models.TextChoices):
    ONSITE = "ONSITE", "On-site"
    ONLINE = "ONLINE", "Online"


class SessionSourceChoices(models.TextChoices):
    WALK_IN = "WALK_IN", "Walk-in"
    CALLED_IN = "CALLED_IN", "Called-in"
    REFERRED = "REFERRED", "Referred"
    APPOINTMENT = "APPOINTMENT", "Appointment"
    COUNSELOR_INITIATED = "COUNSELOR_INITIATED", "Counselor-initiated"
    CALL_SLIP = "CALL_SLIP", "Call Slip"
    ROUTINE_COLLECTION = "ROUTINE_COLLECTION", "Routine Form Collection"
    ECOUNSELING = "ECOUNSELING", "E-Counseling"
    URGENT_SUPPORT = "URGENT_SUPPORT", "Urgent Student Support"


class SessionStatusChoices(models.TextChoices):
    SCHEDULED = "SCHEDULED", "Scheduled"
    IN_PROGRESS = "IN_PROGRESS", "In Progress"
    COUNSELOR_NOTES_DRAFT = "COUNSELOR_NOTES_DRAFT", "Counselor Notes Draft"
    COMPLETED = "COMPLETED", "Completed"
    FINALIZED = "FINALIZED", "Finalized"
    LOCKED = "LOCKED", "Locked"
    CANCELLED = "CANCELLED", "Cancelled"
    NO_SHOW = "NO_SHOW", "No Show"


class ECounselingProviderChoices(models.TextChoices):
    DAILY = "DAILY", "Daily.co"


class ECounselingProviderModeChoices(models.TextChoices):
    DAILY_CLOUD = "DAILY_CLOUD", "Daily Cloud Recording"


class ECounselingStatusChoices(models.TextChoices):
    SCHEDULED = "SCHEDULED", "Scheduled"
    WAITING = "WAITING", "Waiting"
    ACTIVE = "ACTIVE", "Active"
    COMPLETED = "COMPLETED", "Completed"
    CANCELLED = "CANCELLED", "Cancelled"
    EXPIRED = "EXPIRED", "Expired"


class ECounselingRecordingConsentStatusChoices(models.TextChoices):
    NOT_REQUESTED = "NOT_REQUESTED", "Not requested"
    PENDING = "PENDING", "Pending"
    APPROVED = "APPROVED", "Approved"
    DENIED = "DENIED", "Denied"
    WITHDRAWN = "WITHDRAWN", "Withdrawn"


class ECounselingRecordingDecisionChoices(models.TextChoices):
    REQUESTED = "REQUESTED", "Requested"
    APPROVED = "APPROVED", "Approved"
    DENIED = "DENIED", "Denied"
    WITHDRAWN = "WITHDRAWN", "Withdrawn"


class ECounselingJoinAttemptStatusChoices(models.TextChoices):
    ALLOWED = "ALLOWED", "Allowed"
    DENIED = "DENIED", "Denied"


class ECounselingDeniedReasonCodeChoices(models.TextChoices):
    NOT_AUTHENTICATED = "NOT_AUTHENTICATED", "Not authenticated"
    NOT_PARTICIPANT = "NOT_PARTICIPANT", "Not participant"
    SESSION_NOT_ONLINE = "SESSION_NOT_ONLINE", "Session not online"
    OUTSIDE_JOIN_WINDOW = "OUTSIDE_JOIN_WINDOW", "Outside join window"
    SESSION_CANCELLED = "SESSION_CANCELLED", "Session cancelled"
    SESSION_COMPLETED = "SESSION_COMPLETED", "Session completed"
    CONSENT_REQUIRED = "CONSENT_REQUIRED", "Consent required"
    RATE_LIMITED = "RATE_LIMITED", "Rate limited"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE", "Provider unavailable"
    UNSAFE_PROVIDER_CONFIGURATION = "UNSAFE_PROVIDER_CONFIGURATION", "Unsafe provider configuration"


class ECounselingParticipantRoleChoices(models.TextChoices):
    STUDENT = "STUDENT", "Student"
    COUNSELOR = "COUNSELOR", "Counselor"
    HEAD_GUIDANCE = "HEAD_GUIDANCE", "Head Guidance"
    APPROVED_PARTICIPANT = "APPROVED_PARTICIPANT", "Approved participant"


class ECounselingPurposeCodeChoices(models.TextChoices):
    COUNSELING_DELIVERY = "COUNSELING_DELIVERY", "Counseling delivery"
    SUPERVISION = "SUPERVISION", "Supervision"
    QUALITY_REVIEW = "QUALITY_REVIEW", "Quality review"


class ECounselingRecordingScopeCodeChoices(models.TextChoices):
    AUDIO_VIDEO = "AUDIO_VIDEO", "Audio and video"
    AUDIO_ONLY = "AUDIO_ONLY", "Audio only"


class ECounselingRetentionPolicyCodeChoices(models.TextChoices):
    DEFERRED_STORAGE_POLICY = "DEFERRED_STORAGE_POLICY", "Deferred storage policy"
    THIRTY_CALENDAR_DAYS = "THIRTY_CALENDAR_DAYS", "30 calendar days"
    GOVERNANCE_RETENTION_POLICY = "GOVERNANCE_RETENTION_POLICY", "Governance retention policy"


class ECounselingRecordingRunStatusChoices(models.TextChoices):
    REQUESTED = "REQUESTED", "Requested"
    STARTING = "STARTING", "Starting"
    RECORDING = "RECORDING", "Recording"
    STOP_REQUESTED = "STOP_REQUESTED", "Stop requested"
    PROCESSING = "PROCESSING", "Processing"
    AVAILABLE = "AVAILABLE", "Available"
    FAILED = "FAILED", "Failed"
    EXPIRED = "EXPIRED", "Expired"
    DELETED = "DELETED", "Deleted"


class ECounselingTranscriptionStatusChoices(models.TextChoices):
    NOT_REQUESTED = "NOT_REQUESTED", "Not requested"
    STARTING = "STARTING", "Starting"
    TRANSCRIBING = "TRANSCRIBING", "Transcribing"
    PROCESSING = "PROCESSING", "Processing"
    AVAILABLE = "AVAILABLE", "Available"
    FAILED = "FAILED", "Failed"
    EXPIRED = "EXPIRED", "Expired"
    DELETED = "DELETED", "Deleted"


class ECounselingRecordingEventTypeChoices(models.TextChoices):
    START_REQUESTED = "START_REQUESTED", "Start requested"
    STARTED = "STARTED", "Started"
    STOP_REQUESTED = "STOP_REQUESTED", "Stop requested"
    STOPPED = "STOPPED", "Stopped"
    PROCESSING = "PROCESSING", "Processing"
    AVAILABLE = "AVAILABLE", "Available"
    FAILED = "FAILED", "Failed"
    ACCESS_GRANTED = "ACCESS_GRANTED", "Access granted"
    EXPIRED = "EXPIRED", "Expired"
    DELETED = "DELETED", "Deleted"
    TRANSCRIPTION_REQUESTED = "TRANSCRIPTION_REQUESTED", "Transcription requested"
    TRANSCRIPTION_STARTED = "TRANSCRIPTION_STARTED", "Transcription started"
    TRANSCRIPTION_PROCESSING = "TRANSCRIPTION_PROCESSING", "Transcription processing"
    TRANSCRIPTION_AVAILABLE = "TRANSCRIPTION_AVAILABLE", "Transcription available"
    TRANSCRIPTION_FAILED = "TRANSCRIPTION_FAILED", "Transcription failed"
    TRANSCRIPTION_EXPIRED = "TRANSCRIPTION_EXPIRED", "Transcription expired"
    TRANSCRIPTION_DELETED = "TRANSCRIPTION_DELETED", "Transcription deleted"


class RoutineInterviewStatusChoices(models.TextChoices):
    NOT_STARTED = "NOT_STARTED", "Not Started"
    INTAKE_DRAFT = "INTAKE_DRAFT", "Intake Draft"
    INTAKE_SUBMITTED = "INTAKE_SUBMITTED", "Intake Submitted"
    EVALUATION_DRAFT = "EVALUATION_DRAFT", "Evaluation Draft"
    COMPLETED = "COMPLETED", "Completed"
    FINALIZED = "FINALIZED", "Finalized"
    LOCKED = "LOCKED", "Locked"
    REOPENED_FOR_CORRECTION = "REOPENED_FOR_CORRECTION", "Reopened for Correction"


class RoutineInterviewCorrectionTargetChoices(models.TextChoices):
    INTAKE = "INTAKE", "Student Intake"
    EVALUATION = "EVALUATION", "Counselor Evaluation"
    BOTH = "BOTH", "Intake and Evaluation"


class CounselingStatusHistoryReasonChoices(models.TextChoices):
    NONE = "", "No reason"
    CREATED = "Counseling session created", "Counseling session created"
    ECOUNSELING_CREATED = "E-counseling session created", "E-counseling session created"
    URGENT_SUPPORT_TRIAGE_CREATED = "Urgent support triage session created", "Urgent support triage session created"
    COMPLETED = "Counseling session completed", "Counseling session completed"
    CANCELLED = "Counseling session cancelled", "Counseling session cancelled"
    NO_SHOW = "Student did not attend", "Student did not attend"


class CounselingAssignmentHistoryReasonChoices(models.TextChoices):
    NONE = "", "No reason"
    INITIAL = "Initial assignment", "Initial assignment"
    CHANGED = "Counseling session assignment changed", "Counseling session assignment changed"


class RoutineStatusHistoryReasonChoices(models.TextChoices):
    NONE = "", "No reason"
    INTAKE_SUBMITTED = "Student intake submitted", "Student intake submitted"
    COMPLETED = "Routine interview completed", "Routine interview completed"
    FINALIZED = "Routine interview finalized", "Routine interview finalized"
    LOCKED = "Routine interview locked", "Routine interview locked"
    REOPENED = "Routine interview reopened for correction", "Routine interview reopened for correction"


class RoutineVisitNatureChoices(models.TextChoices):
    WALK_IN = "WALK_IN", "Walk-in"
    CALLED_IN = "CALLED_IN", "Called-in"
    REFERRED = "REFERRED", "Referred"


class CounselingSession(TimestampedModel):
    """Confidential encounter container for actual counseling/interview sessions."""

    reference_code = models.CharField(
        max_length=25,
        unique=True,
        editable=False,
        help_text="Immutable AY-based reference code, e.g. SES-AY2526-000001.",
    )
    student = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="counseling_sessions",
    )
    appointment = models.ForeignKey(
        "appointments.Appointment",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="counseling_sessions",
    )
    assigned_counselor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_counseling_sessions",
    )
    session_type = models.CharField(max_length=30, choices=SessionTypeChoices.choices)
    session_mode = models.CharField(max_length=10, choices=SessionModeChoices.choices)
    session_source = models.CharField(max_length=30, choices=SessionSourceChoices.choices)
    status = models.CharField(
        max_length=30,
        choices=SessionStatusChoices.choices,
        default=SessionStatusChoices.SCHEDULED,
    )
    # PRIVACY: counselor/operational-only; never student-visible.
    concern_summary = models.TextField(blank=True)
    concern_summary_encrypted = EncryptedTextField(null=True, blank=True, default=None)
    scheduled_start_at = models.DateTimeField(null=True, blank=True)
    scheduled_end_at = models.DateTimeField(null=True, blank=True)
    actual_started_at = models.DateTimeField(null=True, blank=True)
    actual_ended_at = models.DateTimeField(null=True, blank=True)
    actual_duration_minutes = models.PositiveIntegerField(null=True, blank=True)
    ended_early_flag = models.BooleanField(default=False)
    # PRIVACY: counselor-only; not for student-facing rendering or audit metadata.
    ended_early_reason = models.TextField(blank=True)
    ended_early_reason_encrypted = EncryptedTextField(null=True, blank=True, default=None)
    # PRIVACY: counselor-only; not for student-facing rendering or audit metadata.
    cancellation_reason = models.TextField(blank=True)
    cancellation_reason_encrypted = EncryptedTextField(null=True, blank=True, default=None)
    completed_at = models.DateTimeField(null=True, blank=True)
    finalized_at = models.DateTimeField(null=True, blank=True)
    finalized_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    locked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["assigned_counselor", "status"]),
            models.Index(fields=["student", "status"]),
            models.Index(fields=["status", "scheduled_start_at"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["appointment"],
                condition=Q(appointment__isnull=False),
                name="unique_counseling_session_per_appointment",
            ),
        ]
        verbose_name = "counseling session"
        verbose_name_plural = "counseling sessions"

    def clean(self):
        super().clean()
        if self.scheduled_start_at and self.scheduled_end_at:
            if self.scheduled_start_at >= self.scheduled_end_at:
                raise ValidationError(
                    {"scheduled_end_at": "Scheduled end must be after scheduled start."}
                )
        if self.actual_started_at and self.actual_ended_at:
            if self.actual_started_at > self.actual_ended_at:
                raise ValidationError(
                    {"actual_ended_at": "Actual end must be on or after actual start."}
                )
        if self.pk:
            original = type(self).objects.filter(pk=self.pk).only("reference_code").first()
            if original and original.reference_code != self.reference_code:
                raise ValidationError({"reference_code": "Reference code is immutable."})

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.reference_code or f"Counseling Session #{self.pk}"


class CounselingSessionNote(TimestampedModel):
    """Two-tier session notes with a single student-safe summary field."""

    session = models.OneToOneField(
        CounselingSession,
        on_delete=models.CASCADE,
        related_name="note",
    )
    # PRIVACY: this is the ONLY note field safe for student-facing rendering.
    student_visible_summary = models.TextField(blank=True)
    student_visible_summary_encrypted = EncryptedTextField(null=True, blank=True, default=None)
    # PRIVACY: counselor-only; never in student views, list cards, search, or audit metadata.
    counselor_narrative = models.TextField(blank=True)
    counselor_narrative_encrypted = EncryptedTextField(null=True, blank=True, default=None)
    # PRIVACY: counselor-only; never in student views, list cards, search, or audit metadata.
    recommendations = models.TextField(blank=True)
    recommendations_encrypted = EncryptedTextField(null=True, blank=True, default=None)
    # PRIVACY: counselor-only; never in student views, list cards, search, or audit metadata.
    special_concerns = models.TextField(blank=True)
    special_concerns_encrypted = EncryptedTextField(null=True, blank=True, default=None)
    follow_up_needed = models.BooleanField(default=False)
    # PRIVACY: counselor-only; never in student views, list cards, search, or audit metadata.
    follow_up_notes = models.TextField(blank=True)
    follow_up_notes_encrypted = EncryptedTextField(null=True, blank=True, default=None)
    authored_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )

    class Meta:
        verbose_name = "counseling session note"
        verbose_name_plural = "counseling session notes"

    def __str__(self):
        return f"Note for {self.session.reference_code}"


class CounselingSessionStatusHistory(TimestampedModel):
    session = models.ForeignKey(
        CounselingSession,
        on_delete=models.CASCADE,
        related_name="status_history",
    )
    from_status = models.CharField(max_length=50, blank=True)
    to_status = models.CharField(max_length=50)
    changed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="+",
    )
    reason = models.TextField(blank=True, choices=CounselingStatusHistoryReasonChoices.choices)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "counseling session status history"
        verbose_name_plural = "counseling session status histories"
        constraints = [
            models.CheckConstraint(
                condition=Q(reason__in=CounselingStatusHistoryReasonChoices.values),
                name="counsel_sess_status_reason_safe",
            ),
        ]

    def __str__(self):
        return f"{self.session.reference_code}: {self.from_status} -> {self.to_status}"


class CounselingSessionAssignmentHistory(TimestampedModel):
    session = models.ForeignKey(
        CounselingSession,
        on_delete=models.CASCADE,
        related_name="assignment_history",
    )
    from_counselor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    to_counselor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    changed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="+",
    )
    reason = models.TextField(blank=True, choices=CounselingAssignmentHistoryReasonChoices.choices)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "counseling session assignment history"
        verbose_name_plural = "counseling session assignment histories"
        constraints = [
            models.CheckConstraint(
                condition=Q(reason__in=CounselingAssignmentHistoryReasonChoices.values),
                name="counsel_sess_assign_reason_safe",
            ),
        ]

    def __str__(self):
        return f"Assignment: {self.session.reference_code} from {self.from_counselor_id} to {self.to_counselor_id}"


class ECounselingSession(TimestampedModel):
    """Online delivery layer for an official CounselingSession record."""

    reference_code = models.CharField(max_length=25, unique=True, editable=False)
    counseling_session = models.OneToOneField(
        CounselingSession,
        on_delete=models.CASCADE,
        related_name="ecounseling_session",
    )
    provider = models.CharField(
        max_length=64,
        choices=ECounselingProviderChoices.choices,
        default=ECounselingProviderChoices.DAILY,
    )
    provider_mode = models.CharField(
        max_length=64,
        choices=ECounselingProviderModeChoices.choices,
        default=ECounselingProviderModeChoices.DAILY_CLOUD,
    )
    room_slug = models.SlugField(max_length=120, unique=True)
    room_name_hash = models.CharField(max_length=128, blank=True)
    room_display_name = models.CharField(max_length=120, blank=True)
    scheduled_start_at = models.DateTimeField()
    scheduled_end_at = models.DateTimeField()
    join_window_start_at = models.DateTimeField()
    join_window_end_at = models.DateTimeField()
    status = models.CharField(
        max_length=20,
        choices=ECounselingStatusChoices.choices,
        default=ECounselingStatusChoices.SCHEDULED,
    )
    moderator_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    recording_requested = models.BooleanField(default=False)
    recording_consent_status = models.CharField(
        max_length=20,
        choices=ECounselingRecordingConsentStatusChoices.choices,
        default=ECounselingRecordingConsentStatusChoices.NOT_REQUESTED,
    )
    recording_consent_requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    recording_consent_requested_at = models.DateTimeField(null=True, blank=True)
    recording_consent_decided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    recording_consent_decided_at = models.DateTimeField(null=True, blank=True)
    recording_consent_withdrawn_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-scheduled_start_at", "-created_at"]
        indexes = [
            models.Index(fields=["status", "scheduled_start_at"]),
            models.Index(fields=["provider", "provider_mode"]),
            models.Index(fields=["recording_consent_status"]),
        ]
        verbose_name = "e-counseling session"
        verbose_name_plural = "e-counseling sessions"

    def clean(self):
        super().clean()
        if self.counseling_session_id and self.counseling_session.session_mode != SessionModeChoices.ONLINE:
            raise ValidationError({"counseling_session": "E-counseling requires an online Counseling Session."})
        if self.scheduled_start_at and self.scheduled_end_at and self.scheduled_start_at >= self.scheduled_end_at:
            raise ValidationError({"scheduled_end_at": "Scheduled end must be after scheduled start."})
        if self.join_window_start_at and self.join_window_end_at and self.join_window_start_at >= self.join_window_end_at:
            raise ValidationError({"join_window_end_at": "Join window end must be after join window start."})
        unsafe_fragments = ["http", "meet.jit.si", "@", "student", "counselor", "email", "case", "routine", "emergency"]
        haystack = f"{self.room_slug} {self.room_display_name}".lower()
        if any(fragment in haystack for fragment in unsafe_fragments):
            raise ValidationError({"room_slug": "Room identifiers must be non-PII provider metadata."})
        if self.pk:
            original = type(self).objects.filter(pk=self.pk).only("reference_code", "room_slug").first()
            if original:
                if original.reference_code != self.reference_code:
                    raise ValidationError({"reference_code": "Reference code is immutable."})
                if original.room_slug != self.room_slug:
                    raise ValidationError({"room_slug": "Room slug is immutable."})

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.reference_code or f"E-Counseling Session #{self.pk}"


class ECounselingParticipant(TimestampedModel):
    """Exact-session participant grant for e-counseling join access."""

    ecounseling_session = models.ForeignKey(
        ECounselingSession,
        on_delete=models.CASCADE,
        related_name="participants",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="ecounseling_participant_grants",
    )
    role = models.CharField(max_length=30, choices=ECounselingParticipantRoleChoices.choices)
    is_active = models.BooleanField(default=True)
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    approved_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    revoked_at = models.DateTimeField(null=True, blank=True)
    purpose_code = models.CharField(
        max_length=40,
        choices=ECounselingPurposeCodeChoices.choices,
        default=ECounselingPurposeCodeChoices.COUNSELING_DELIVERY,
    )

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["ecounseling_session", "user"],
                condition=Q(is_active=True),
                name="unique_active_ecounseling_participant",
            )
        ]
        verbose_name = "e-counseling participant"
        verbose_name_plural = "e-counseling participants"

    def clean(self):
        super().clean()
        if self.user_id and not self.user.is_active:
            raise ValidationError({"user": "Approved participants must be active users."})
        if not self.is_active and not self.revoked_at:
            raise ValidationError({"revoked_at": "Revoked participants require a revoked timestamp."})

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.get_role_display()} participant for {self.ecounseling_session.reference_code}"


class ECounselingJoinEvent(TimestampedModel):
    """Privacy-safe join attempt record for e-counseling sessions."""

    ecounseling_session = models.ForeignKey(
        ECounselingSession,
        on_delete=models.CASCADE,
        related_name="join_events",
    )
    counseling_session = models.ForeignKey(
        CounselingSession,
        on_delete=models.CASCADE,
        related_name="ecounseling_join_events",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    role = models.CharField(max_length=30, choices=ECounselingParticipantRoleChoices.choices, blank=True)
    attempt_status = models.CharField(max_length=10, choices=ECounselingJoinAttemptStatusChoices.choices)
    denied_reason_code = models.CharField(
        max_length=50,
        choices=ECounselingDeniedReasonCodeChoices.choices,
        blank=True,
    )
    ip_hash = models.CharField(max_length=128, blank=True)
    user_agent_hash = models.CharField(max_length=128, blank=True)
    joined_at = models.DateTimeField(null=True, blank=True)
    left_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["attempt_status", "created_at"]),
            models.Index(fields=["denied_reason_code"]),
        ]
        verbose_name = "e-counseling join event"
        verbose_name_plural = "e-counseling join events"

    def clean(self):
        super().clean()
        if self.ecounseling_session_id and self.counseling_session_id:
            if self.ecounseling_session.counseling_session_id != self.counseling_session_id:
                raise ValidationError({"counseling_session": "Join event parent session mismatch."})
        if self.attempt_status == ECounselingJoinAttemptStatusChoices.DENIED and not self.denied_reason_code:
            raise ValidationError({"denied_reason_code": "Denied join events require a reason code."})
        if self.attempt_status == ECounselingJoinAttemptStatusChoices.ALLOWED and self.denied_reason_code:
            raise ValidationError({"denied_reason_code": "Allowed join events must not have a denied reason."})

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.ecounseling_session.reference_code}: {self.attempt_status}"


class ECounselingRecordingConsentEvent(TimestampedModel):
    """Immutable operational recording consent history for one e-counseling session."""

    ecounseling_session = models.ForeignKey(
        ECounselingSession,
        on_delete=models.CASCADE,
        related_name="recording_consent_events",
    )
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    requested_at = models.DateTimeField(null=True, blank=True)
    decided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    decision = models.CharField(max_length=20, choices=ECounselingRecordingDecisionChoices.choices)
    decision_at = models.DateTimeField(null=True, blank=True)
    withdrawn_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    withdrawn_at = models.DateTimeField(null=True, blank=True)
    notice_version = models.CharField(max_length=40, default="recording-notice-v1")
    privacy_notice_revision = models.ForeignKey(
        "privacy.PrivacyNoticeRevision",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="recording_consent_events",
    )
    purpose_code = models.CharField(
        max_length=40,
        choices=ECounselingPurposeCodeChoices.choices,
        default=ECounselingPurposeCodeChoices.COUNSELING_DELIVERY,
    )
    scope_code = models.CharField(
        max_length=30,
        choices=ECounselingRecordingScopeCodeChoices.choices,
        default=ECounselingRecordingScopeCodeChoices.AUDIO_ONLY,
    )
    retention_policy_code = models.CharField(
        max_length=50,
        choices=ECounselingRetentionPolicyCodeChoices.choices,
        default=ECounselingRetentionPolicyCodeChoices.GOVERNANCE_RETENTION_POLICY,
    )

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["decision", "created_at"]),
            models.Index(fields=["notice_version"]),
        ]
        verbose_name = "e-counseling recording consent event"
        verbose_name_plural = "e-counseling recording consent events"

    def clean(self):
        super().clean()
        if self.decision == ECounselingRecordingDecisionChoices.REQUESTED and not self.requested_at:
            raise ValidationError({"requested_at": "Consent requests require requested_at."})
        if self.decision in (
            ECounselingRecordingDecisionChoices.APPROVED,
            ECounselingRecordingDecisionChoices.DENIED,
        ) and not self.decision_at:
            raise ValidationError({"decision_at": "Consent decisions require decision_at."})
        if self.decision == ECounselingRecordingDecisionChoices.WITHDRAWN and not self.withdrawn_at:
            raise ValidationError({"withdrawn_at": "Consent withdrawals require withdrawn_at."})

    def save(self, *args, **kwargs):
        if self.pk:
            raise ValidationError("Recording consent events are immutable.")
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.ecounseling_session.reference_code}: {self.decision}"


class ECounselingRecordingRun(TimestampedModel):
    """One provider recording attempt; the official record remains CounselingSession."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    ecounseling_session = models.ForeignKey(
        ECounselingSession,
        on_delete=models.CASCADE,
        related_name="recording_runs",
    )
    consent_event = models.ForeignKey(
        ECounselingRecordingConsentEvent,
        on_delete=models.PROTECT,
        related_name="recording_runs",
    )
    status = models.CharField(
        max_length=30,
        choices=ECounselingRecordingRunStatusChoices.choices,
        default=ECounselingRecordingRunStatusChoices.REQUESTED,
    )
    purpose_code_snapshot = models.CharField(
        max_length=40,
        choices=ECounselingPurposeCodeChoices.choices,
    )
    scope_code_snapshot = models.CharField(
        max_length=30,
        choices=ECounselingRecordingScopeCodeChoices.choices,
    )
    retention_policy_code_snapshot = models.CharField(
        max_length=50,
        choices=ECounselingRetentionPolicyCodeChoices.choices,
    )
    transcription_status = models.CharField(
        max_length=20,
        choices=ECounselingTranscriptionStatusChoices.choices,
        default=ECounselingTranscriptionStatusChoices.NOT_REQUESTED,
    )
    notice_version_snapshot = models.CharField(max_length=40)
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="+",
    )
    started_at = models.DateTimeField(null=True, blank=True)
    stop_requested_at = models.DateTimeField(null=True, blank=True)
    stopped_at = models.DateTimeField(null=True, blank=True)
    available_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    deleted_at = models.DateTimeField(null=True, blank=True)
    hard_stop_at = models.DateTimeField()
    transcription_started_at = models.DateTimeField(null=True, blank=True)
    transcription_available_at = models.DateTimeField(null=True, blank=True)
    transcription_expires_at = models.DateTimeField(null=True, blank=True)
    transcription_deleted_at = models.DateTimeField(null=True, blank=True)
    transcription_failure_code = models.CharField(max_length=50, blank=True)
    # Daily's start/stop APIs use an instance id; the recording id is assigned
    # asynchronously by Daily and arrives through recording webhooks.
    provider_instance_id = models.CharField(max_length=64, unique=True)
    provider_recording_id = models.CharField(max_length=128, unique=True, null=True, blank=True)
    provider_transcript_id = models.CharField(max_length=128, unique=True, null=True, blank=True)
    provider_transcription_instance_id = models.CharField(max_length=128, blank=True)
    provider_deleted_at = models.DateTimeField(null=True, blank=True)
    provider_delete_failure_code = models.CharField(max_length=50, blank=True)
    safe_failure_code = models.CharField(max_length=50, blank=True)
    file_size_bytes = models.PositiveBigIntegerField(null=True, blank=True)
    checksum_sha256 = models.CharField(max_length=64, blank=True)
    protected_file = models.OneToOneField(
        "security.ProtectedFile",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="ecounseling_recording_run",
    )
    transcript_protected_file = models.OneToOneField(
        "security.ProtectedFile",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="ecounseling_transcript_run",
    )

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status", "hard_stop_at"]),
            models.Index(fields=["expires_at"]),
            models.Index(fields=["transcription_status", "updated_at"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["ecounseling_session"],
                condition=Q(
                    status__in=[
                        ECounselingRecordingRunStatusChoices.REQUESTED,
                        ECounselingRecordingRunStatusChoices.STARTING,
                        ECounselingRecordingRunStatusChoices.RECORDING,
                        ECounselingRecordingRunStatusChoices.STOP_REQUESTED,
                        ECounselingRecordingRunStatusChoices.PROCESSING,
                    ]
                ),
                name="one_active_recording_run_per_ecs",
            ),
        ]

    def clean(self):
        super().clean()
        if self.consent_event_id and self.ecounseling_session_id:
            if self.consent_event.ecounseling_session_id != self.ecounseling_session_id:
                raise ValidationError({"consent_event": "Recording consent must belong to this session."})
        if self.hard_stop_at and self.ecounseling_session_id:
            latest = self.ecounseling_session.scheduled_end_at + timedelta(minutes=30)
            if self.hard_stop_at > latest:
                raise ValidationError({"hard_stop_at": "Recording cannot extend past the session safety deadline."})
        from apps.governance.runtime_config import resolve_runtime_setting

        max_size = int(
            resolve_runtime_setting(
                "counseling.ecounseling_controls",
                "ECOUNSELING_RECORDING_MAX_FILE_SIZE_BYTES",
            )
        )
        if self.file_size_bytes and self.file_size_bytes > max_size:
            raise ValidationError({"file_size_bytes": "Recording exceeds the configured safety limit."})
        transcript_max_size = int(
            resolve_runtime_setting(
                "counseling.ecounseling_controls",
                "ECOUNSELING_RECORDING_TRANSCRIPTION_MAX_FILE_SIZE_BYTES",
            )
        )
        transcript_file = self.transcript_protected_file if getattr(self, "transcript_protected_file_id", None) else None
        if transcript_file and transcript_file.file_size_bytes > transcript_max_size:
            raise ValidationError({"transcript_protected_file": "Transcript exceeds the configured safety limit."})

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)




class ECounselingRecordingEvent(TimestampedModel):
    """Append-only, privacy-safe lifecycle evidence for a recording run."""

    recording_run = models.ForeignKey(
        ECounselingRecordingRun,
        on_delete=models.CASCADE,
        related_name="events",
    )
    event_type = models.CharField(
        max_length=30,
        choices=ECounselingRecordingEventTypeChoices.choices,
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    safe_code = models.CharField(max_length=50, blank=True)

    class Meta:
        ordering = ["created_at"]
        indexes = [models.Index(fields=["event_type", "created_at"])]

    def save(self, *args, **kwargs):
        if self.pk:
            raise ValidationError("Recording events are immutable.")
        self.full_clean()
        super().save(*args, **kwargs)


class ECounselingRecordingCallbackReceipt(TimestampedModel):
    """Replay-prevention receipt for signed provider callbacks."""

    recording_run = models.ForeignKey(
        ECounselingRecordingRun,
        on_delete=models.CASCADE,
        related_name="callback_receipts",
    )
    nonce_digest = models.CharField(max_length=64, unique=True)
    provider_event_id = models.CharField(max_length=128, unique=True, null=True, blank=True)
    callback_status = models.CharField(max_length=20)

    class Meta:
        indexes = [models.Index(fields=["created_at"])]


class ECounselingRecordingAccessGrant(TimestampedModel):
    """Short-lived, user-bound grant reused for range requests."""

    recording_run = models.ForeignKey(
        ECounselingRecordingRun,
        on_delete=models.CASCADE,
        related_name="access_grants",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="+",
    )
    token_digest = models.CharField(max_length=64, unique=True)
    intent = models.CharField(
        max_length=10,
        choices=[("PLAYBACK", "Playback"), ("DOWNLOAD", "Download")],
    )
    expires_at = models.DateTimeField()

    class Meta:
        indexes = [models.Index(fields=["user", "expires_at"])]


class RoutineInterviewRecord(TimestampedModel):
    """Official structured Routine Interview form attached to a counseling session."""

    SOURCE_FORM_CODE = "CNSC-OP-GTA-01F11"
    SOURCE_FORM_REVISION = "0"
    SOURCE_FORM_FAMILY = "routine_interview"

    session = models.OneToOneField(
        CounselingSession,
        on_delete=models.CASCADE,
        related_name="routine_interview_record",
    )
    form_family = models.CharField(max_length=50, default="routine_interview")
    source_form_label = models.CharField(
        max_length=255,
        default="CNSC Guidance, Testing and Admission Office Routine Interview Form",
    )
    source_form_version = models.CharField(max_length=50, default="legacy-extracted-v1")
    source_form_code = models.CharField(max_length=50, blank=True)
    source_form_revision = models.CharField(max_length=50, blank=True)
    internal_schema_version = models.CharField(max_length=20, default="1.0.0")

    student_name_snapshot = models.CharField(max_length=255, blank=True)
    course_snapshot = models.CharField(max_length=255, blank=True)
    major_snapshot = models.CharField(max_length=255, blank=True)
    snapshot_taken_at = models.DateTimeField(null=True, blank=True)

    visit_date = models.DateField(null=True, blank=True)
    visit_time = models.TimeField(null=True, blank=True)
    duration_minutes = models.PositiveIntegerField(null=True, blank=True)
    nature_of_visit = models.CharField(
        max_length=20,
        choices=RoutineVisitNatureChoices.choices,
        blank=True,
    )

    coping_challenges = models.TextField(blank=True)
    coping_challenges_encrypted = EncryptedTextField(null=True, blank=True, default=None)
    coping_remarks = models.TextField(blank=True)
    coping_remarks_encrypted = EncryptedTextField(null=True, blank=True, default=None)
    ucn_experience = models.TextField(blank=True)
    ucn_experience_encrypted = EncryptedTextField(null=True, blank=True, default=None)
    reason_for_coming = models.TextField(blank=True)
    reason_for_coming_encrypted = EncryptedTextField(null=True, blank=True, default=None)
    difficulties_encountered = models.TextField(blank=True)
    difficulties_encountered_encrypted = EncryptedTextField(null=True, blank=True, default=None)
    stress_anxiety_causes = models.TextField(blank=True)
    stress_anxiety_causes_encrypted = EncryptedTextField(null=True, blank=True, default=None)
    stress_anxiety_management = models.TextField(blank=True)
    stress_anxiety_management_encrypted = EncryptedTextField(null=True, blank=True, default=None)
    family_background_notes = models.TextField(blank=True)
    family_background_notes_encrypted = EncryptedTextField(null=True, blank=True, default=None)
    concerns_explanation = models.TextField(blank=True)
    concerns_explanation_encrypted = EncryptedTextField(null=True, blank=True, default=None)
    college_adjustment = models.TextField(blank=True)
    college_adjustment_encrypted = EncryptedTextField(null=True, blank=True, default=None)
    academic_goals = models.TextField(blank=True)
    academic_goals_encrypted = EncryptedTextField(null=True, blank=True, default=None)
    career_goals = models.TextField(blank=True)
    career_goals_encrypted = EncryptedTextField(null=True, blank=True, default=None)

    concern_academic = models.BooleanField(default=False)
    concern_friends = models.BooleanField(default=False)
    concern_classmates = models.BooleanField(default=False)
    concern_vices = models.BooleanField(default=False)
    concern_love_life = models.BooleanField(default=False)
    concern_sleeping_problems = models.BooleanField(default=False)
    concern_family = models.BooleanField(default=False)
    concern_financial = models.BooleanField(default=False)
    concern_suicidal_thought = models.BooleanField(default=False)
    concern_dorm_boarding_house = models.BooleanField(default=False)
    concern_past_painful_experience = models.BooleanField(default=False)
    concern_others = models.BooleanField(default=False)
    concern_others_text = models.CharField(max_length=255, blank=True)
    concern_others_text_encrypted = EncryptedTextField(
        max_length=255,
        max_plaintext_bytes=1_020,
        null=True,
        blank=True,
        default=None,
    )

    rating_emotionally = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(10)],
    )
    rating_academically = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(10)],
    )
    rating_physically = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(10)],
    )
    rating_socially = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(10)],
    )
    rating_spiritually = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(10)],
    )
    rating_financially = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(10)],
    )
    rating_others_label = models.CharField(max_length=100, blank=True)
    rating_others_label_encrypted = EncryptedTextField(
        max_length=100,
        max_plaintext_bytes=400,
        null=True,
        blank=True,
        default=None,
    )
    rating_others = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(10)],
    )
    # PRIVACY: counselor/Head-only official-form content.
    special_concern = models.TextField(blank=True)
    special_concern_encrypted = EncryptedTextField(null=True, blank=True, default=None)
    # PRIVACY: counselor/Head-only official-form content.
    recommendations = models.TextField(blank=True)
    recommendations_encrypted = EncryptedTextField(null=True, blank=True, default=None)
    assigned_counselor_confirmation = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    evaluation_date = models.DateField(null=True, blank=True)

    status = models.CharField(
        max_length=50,
        choices=RoutineInterviewStatusChoices.choices,
        default=RoutineInterviewStatusChoices.NOT_STARTED,
    )
    submitted_at = models.DateTimeField(null=True, blank=True)
    submitted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    evaluated_at = models.DateTimeField(null=True, blank=True)
    evaluated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    completed_at = models.DateTimeField(null=True, blank=True)
    completed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    finalized_at = models.DateTimeField(null=True, blank=True)
    finalized_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    locked_at = models.DateTimeField(null=True, blank=True)
    locked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    reopened_at = models.DateTimeField(null=True, blank=True)
    reopened_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    reopen_reason = models.TextField(blank=True)
    reopen_reason_encrypted = EncryptedTextField(null=True, blank=True, default=None)
    reopen_target = models.CharField(
        max_length=20,
        choices=RoutineInterviewCorrectionTargetChoices.choices,
        blank=True,
    )

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status", "updated_at"]),
            models.Index(fields=["submitted_at"]),
            models.Index(fields=["finalized_at"]),
            models.Index(fields=["locked_at"]),
        ]
        verbose_name = "routine interview record"
        verbose_name_plural = "routine interview records"

    def clean(self):
        super().clean()
        if self.session_id and self.session.session_type != SessionTypeChoices.ROUTINE_INTERVIEW:
            raise ValidationError({"session": "Routine Interview records require a Routine Interview session."})
        if self.status == RoutineInterviewStatusChoices.REOPENED_FOR_CORRECTION:
            if not self.reopen_target:
                raise ValidationError({"reopen_target": "A correction target is required when reopened."})
        elif self.reopen_target:
            raise ValidationError({"reopen_target": "Correction target is only active while reopened."})

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Routine Interview {self.session.reference_code}"


class RoutineInterviewStatusHistory(TimestampedModel):
    record = models.ForeignKey(
        RoutineInterviewRecord,
        on_delete=models.CASCADE,
        related_name="status_history",
    )
    from_status = models.CharField(max_length=50, blank=True)
    to_status = models.CharField(max_length=50)
    changed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="+",
    )
    reason = models.TextField(blank=True, choices=RoutineStatusHistoryReasonChoices.choices)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "routine interview status history"
        verbose_name_plural = "routine interview status histories"
        constraints = [
            models.CheckConstraint(
                condition=Q(reason__in=RoutineStatusHistoryReasonChoices.values),
                name="counsel_routine_status_reason_safe",
            ),
        ]

    def __str__(self):
        return f"{self.record.session.reference_code}: {self.from_status} -> {self.to_status}"


class CounselingCaseStatus(models.TextChoices):
    OPEN = "OPEN", "Open"
    MONITORING = "MONITORING", "Under Monitoring"
    FOLLOW_UP_PENDING = "FOLLOW_UP_PENDING", "Follow-up Pending"
    ON_HOLD = "ON_HOLD", "On Hold"
    RESOLVED = "RESOLVED", "Resolved"
    CLOSED = "CLOSED", "Closed"
    REOPENED = "REOPENED", "Reopened"


class CounselingCasePriority(models.TextChoices):
    LOW = "LOW", "Low"
    MEDIUM = "MEDIUM", "Medium"
    HIGH = "HIGH", "High"
    URGENT = "URGENT", "Urgent"


class CounselingCaseConcernCategory(models.TextChoices):
    ACADEMIC = "ACADEMIC", "Academic"
    PERSONAL = "PERSONAL", "Personal / Social"
    FAMILY = "FAMILY", "Family"
    FINANCIAL = "FINANCIAL", "Financial"
    BEHAVIORAL = "BEHAVIORAL", "Behavioral"
    MENTAL_WELLNESS = "MENTAL_WELLNESS", "Mental Wellness"
    ADJUSTMENT = "ADJUSTMENT", "Adjustment / Transition"
    CAREER = "CAREER", "Career / Vocational"
    PEER_RELATIONSHIP = "PEER_RELATIONSHIP", "Peer Relationship"
    SUBSTANCE = "SUBSTANCE", "Substance-Related"
    DISCIPLINARY = "DISCIPLINARY", "Disciplinary"
    OTHER = "OTHER", "Other"


class CounselingCaseReasonCode(models.TextChoices):
    FOLLOW_UP_NEEDED = "FOLLOW_UP_NEEDED", "Follow-up needed"
    ONGOING_MONITORING = "ONGOING_MONITORING", "Ongoing monitoring"
    STUDENT_TRANSFERRED = "STUDENT_TRANSFERRED", "Student transferred or inactive"
    CONCERN_RESOLVED = "CONCERN_RESOLVED", "Concern resolved"
    NO_FURTHER_ACTION = "NO_FURTHER_ACTION", "No further action"
    REFERRED_TO_OTHER_SERVICE = "REFERRED_TO_OTHER_SERVICE", "Referred to another service"
    REOPENED_NEW_INFORMATION = "REOPENED_NEW_INFORMATION", "Reopened due to new information"
    REOPENED_RECURRING_CONCERN = "REOPENED_RECURRING_CONCERN", "Reopened due to recurring concern"
    ASSIGNMENT_CHANGE = "ASSIGNMENT_CHANGE", "Assignment change"
    OTHER = "OTHER", "Other"


class CounselingCaseSessionLinkType(models.TextChoices):
    ORIGINATING = "ORIGINATING", "Originating session"
    FOLLOW_UP = "FOLLOW_UP", "Follow-up session"
    RELATED = "RELATED", "Related session"
    ROUTINE_INTERVIEW = "ROUTINE_INTERVIEW", "Routine interview session"
    OTHER = "OTHER", "Other"


class CounselingCase(TimestampedModel):
    """Ongoing tracking container for student concerns requiring continuous monitoring."""

    # METADATA-ONLY FOUNDATION: No narrative fields (case_summary, internal_notes,
    #   closure_summary) are present. They require field-level encryption and will
    #   be added after sensitive-field-encryption-foundation is completed.
    # PRIVACY: concern_category and priority are counselor/Head-only operational
    #   metadata. They must NEVER be rendered in student-facing templates,
    #   portal cards, notification previews, or audit log metadata values.

    reference_code = models.CharField(
        max_length=25,
        unique=True,
        editable=False,
    )
    student = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="counseling_cases",
    )
    assigned_counselor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_counseling_cases",
    )
    concern_category = models.CharField(
        max_length=30,
        choices=CounselingCaseConcernCategory.choices,
    )
    priority = models.CharField(
        max_length=10,
        choices=CounselingCasePriority.choices,
        default=CounselingCasePriority.MEDIUM,
    )
    status = models.CharField(
        max_length=30,
        choices=CounselingCaseStatus.choices,
        default=CounselingCaseStatus.OPEN,
    )
    opened_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    close_reason_code = models.CharField(
        max_length=50,
        choices=CounselingCaseReasonCode.choices,
        blank=True,
    )
    closed_at = models.DateTimeField(null=True, blank=True)
    closed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    reopen_reason_code = models.CharField(
        max_length=50,
        choices=CounselingCaseReasonCode.choices,
        blank=True,
    )
    reopened_at = models.DateTimeField(null=True, blank=True)
    reopened_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    case_collaborators = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        through="CounselingCaseCollaborator",
        through_fields=("counseling_case", "counselor"),
        related_name="case_collaborator_counseling_cases",
        blank=True,
    )

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["assigned_counselor", "status"]),
            models.Index(fields=["student", "status"]),
            models.Index(fields=["status"]),
        ]
        verbose_name = "counseling folder"
        verbose_name_plural = "counseling folders"

    def clean(self):
        super().clean()
        if self.pk:
            original = type(self).objects.filter(pk=self.pk).only("reference_code").first()
            if original and original.reference_code != self.reference_code:
                raise ValidationError({"reference_code": "Reference code is immutable."})

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.reference_code or "Counseling Folder"


class CounselingCaseCollaborator(TimestampedModel):
    """Explicit through model for managing case collaborator access on counseling cases."""

    counseling_case = models.ForeignKey(
        CounselingCase,
        on_delete=models.CASCADE,
        related_name="case_collaborator_entries",
    )
    counselor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="+",
    )
    is_active = models.BooleanField(default=True)
    added_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    added_at = models.DateTimeField(auto_now_add=True)
    removed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    removed_at = models.DateTimeField(null=True, blank=True)
    reason_code = models.CharField(
        max_length=50,
        choices=CounselingCaseReasonCode.choices,
        blank=True,
    )

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["counseling_case", "counselor"],
                condition=Q(is_active=True),
                name="unique_active_case_collaborator_per_case",
            )
        ]
        verbose_name = "counseling case collaborator"
        verbose_name_plural = "counseling case collaborators"

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        status_str = "Active" if self.is_active else "Removed"
        return f"Case collaborator {self.counselor_id} ({status_str}) for {self.counseling_case.reference_code}"


class CounselingCaseSession(TimestampedModel):
    """Explicit link table connecting Counseling Cases with Counseling Sessions."""

    counseling_case = models.ForeignKey(
        CounselingCase,
        on_delete=models.CASCADE,
        related_name="case_sessions",
    )
    session = models.ForeignKey(
        CounselingSession,
        on_delete=models.CASCADE,
        related_name="case_links",
    )
    linked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    link_type = models.CharField(
        max_length=30,
        choices=CounselingCaseSessionLinkType.choices,
        default=CounselingCaseSessionLinkType.RELATED,
    )

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["counseling_case", "session"],
                name="unique_case_session_link",
            )
        ]
        verbose_name = "counseling case session link"
        verbose_name_plural = "counseling case session links"

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.counseling_case.reference_code} <-> {self.session.reference_code}"


class CounselingCaseStatusHistory(TimestampedModel):
    """Transition history for Counseling Case statuses."""

    counseling_case = models.ForeignKey(
        CounselingCase,
        on_delete=models.CASCADE,
        related_name="status_history",
    )
    from_status = models.CharField(max_length=50, blank=True)
    to_status = models.CharField(max_length=50)
    changed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="+",
    )
    reason_code = models.CharField(
        max_length=50,
        choices=CounselingCaseReasonCode.choices,
        blank=True,
    )

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "counseling case status history"
        verbose_name_plural = "counseling case status histories"

    def __str__(self):
        return f"{self.counseling_case.reference_code}: {self.from_status} -> {self.to_status}"


class CounselingCaseAssignmentHistory(TimestampedModel):
    """Assignment history for Counseling Case counselors."""

    counseling_case = models.ForeignKey(
        CounselingCase,
        on_delete=models.CASCADE,
        related_name="assignment_history",
    )
    from_counselor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    to_counselor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    changed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="+",
    )
    reason_code = models.CharField(
        max_length=50,
        choices=CounselingCaseReasonCode.choices,
        blank=True,
    )

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "counseling case assignment history"
        verbose_name_plural = "counseling case assignment histories"

    def __str__(self):
        return f"Assignment: {self.counseling_case.reference_code} from {self.from_counselor_id} to {self.to_counselor_id}"


# --- Urgent Support Choices ---

class UrgentSupportSourceType(models.TextChoices):
    COUNSELOR_MANUAL = "COUNSELOR_MANUAL", "Counselor Manual"
    HEAD_GUIDANCE_MANUAL = "HEAD_GUIDANCE_MANUAL", "Head Guidance Manual"
    SESSION_FLAG = "SESSION_FLAG", "Session Flag"
    CASE_FLAG = "CASE_FLAG", "Case Flag"


ACTIVE_URGENT_SUPPORT_SOURCE_TYPES = {
    UrgentSupportSourceType.COUNSELOR_MANUAL,
    UrgentSupportSourceType.HEAD_GUIDANCE_MANUAL,
    UrgentSupportSourceType.SESSION_FLAG,
    UrgentSupportSourceType.CASE_FLAG,
}


class UrgentSupportStatus(models.TextChoices):
    OPEN = "OPEN", "Open"
    TRIAGE_ACCESS_GRANTED = "TRIAGE_ACCESS_GRANTED", "Triage Access Granted"
    TRIAGE_IN_PROGRESS = "TRIAGE_IN_PROGRESS", "Triage In Progress"
    PENDING_HEAD_REVIEW = "PENDING_HEAD_REVIEW", "Pending Head Review"
    CONFIRMED = "CONFIRMED", "Confirmed"
    REVOKED = "REVOKED", "Revoked"
    CLOSED = "CLOSED", "Closed"
    EXPIRED = "EXPIRED", "Expired"


class UrgentSupportReviewStatus(models.TextChoices):
    NOT_REVIEWED = "NOT_REVIEWED", "Not Reviewed"
    REVIEWED_CONFIRMED = "REVIEWED_CONFIRMED", "Reviewed and Confirmed"
    REVIEWED_REASSIGNMENT_REQUIRED = "REVIEWED_REASSIGNMENT_REQUIRED", "Reassignment Required"
    REVIEWED_CASE_COLLABORATOR_REQUIRED = "REVIEWED_CASE_COLLABORATOR_REQUIRED", "Case Collaborator Required"
    REVIEWED_CLOSE_ALLOWED = "REVIEWED_CLOSE_ALLOWED", "Close Allowed"
    REVIEWED_REVOKED = "REVIEWED_REVOKED", "Reviewed and Revoked"


class UrgentSupportDocumentationStatus(models.TextChoices):
    NOT_STARTED = "NOT_STARTED", "Not Started"
    TRIAGE_SESSION_CREATED = "TRIAGE_SESSION_CREATED", "Triage Session Created"
    LINKED_TO_EXISTING_SESSION = "LINKED_TO_EXISTING_SESSION", "Linked to Existing Session"
    DOCUMENTED_IN_SESSION = "DOCUMENTED_IN_SESSION", "Documented in Session"
    NOT_REQUIRED_CLOSED = "NOT_REQUIRED_CLOSED", "Not Required (Closed)"


class UrgentSupportUrgencyLevel(models.TextChoices):
    IMMEDIATE_TRIAGE = "IMMEDIATE_TRIAGE", "Immediate Triage"
    SAME_DAY_REVIEW = "SAME_DAY_REVIEW", "Same Day Review"
    PROMPT_REVIEW = "PROMPT_REVIEW", "Prompt Review"


class TemporarySupportAccessType(models.TextChoices):
    TRIAGE_SESSION = "TRIAGE_SESSION", "Triage Session"
    CASE_REVIEW = "CASE_REVIEW", "Case Review"
    SESSION_REVIEW = "SESSION_REVIEW", "Session Review"
    DOCUMENTATION_ONLY = "DOCUMENTATION_ONLY", "Documentation Only"


class TemporarySupportAccessPurpose(models.TextChoices):
    URGENT_TRIAGE = "URGENT_TRIAGE", "Urgent Triage"
    HEAD_GUIDANCE_REVIEW = "HEAD_GUIDANCE_REVIEW", "Head Guidance Review"
    POST_ACTION_DOCUMENTATION = "POST_ACTION_DOCUMENTATION", "Post-Action Documentation"
    ASSIGNMENT_DECISION = "ASSIGNMENT_DECISION", "Assignment Decision"


class TemporarySupportAccessStatus(models.TextChoices):
    ACTIVE = "ACTIVE", "Active"
    REVOKED = "REVOKED", "Revoked"
    EXPIRED = "EXPIRED", "Expired"


class UrgentSupportClosureReasonCode(models.TextChoices):
    TRIAGE_COMPLETED = "TRIAGE_COMPLETED", "Triage Completed"
    FORMAL_ASSIGNMENT_COMPLETED = "FORMAL_ASSIGNMENT_COMPLETED", "Formal Assignment Completed"
    CASE_COLLABORATOR_ADDED = "CASE_COLLABORATOR_ADDED", "Case Collaborator Added"
    NO_FURTHER_URGENT_SUPPORT_NEEDED = "NO_FURTHER_URGENT_SUPPORT_NEEDED", "No Further Urgent Support Needed"
    DUPLICATE_OR_CREATED_IN_ERROR = "DUPLICATE_OR_CREATED_IN_ERROR", "Duplicate or Created in Error"
    REVOKED_BY_HEAD_GUIDANCE = "REVOKED_BY_HEAD_GUIDANCE", "Revoked by Head Guidance"


# --- Urgent Support Models ---

class UrgentSupportRequest(TimestampedModel):
    reference_code = models.CharField(
        max_length=25,
        unique=True,
        editable=False,
    )
    student = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="urgent_support_requests",
    )
    source_type = models.CharField(
        max_length=50,
        choices=UrgentSupportSourceType.choices,
    )
    source_object_type = models.CharField(
        max_length=100,
        blank=True,
    )
    source_object_id = models.CharField(
        max_length=100,
        blank=True,
    )
    originating_session = models.ForeignKey(
        CounselingSession,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="originating_urgent_supports",
    )
    counseling_case = models.ForeignKey(
        CounselingCase,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="urgent_support_requests",
    )
    urgency_level = models.CharField(
        max_length=50,
        choices=UrgentSupportUrgencyLevel.choices,
    )
    status = models.CharField(
        max_length=50,
        choices=UrgentSupportStatus.choices,
        default=UrgentSupportStatus.OPEN,
    )
    initiated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="initiated_urgent_supports",
    )
    initiated_at = models.DateTimeField(default=timezone.now)
    triage_counselor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="triage_urgent_supports",
    )
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reviewed_urgent_supports",
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    review_status = models.CharField(
        max_length=50,
        choices=UrgentSupportReviewStatus.choices,
        default=UrgentSupportReviewStatus.NOT_REVIEWED,
    )
    closed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="closed_urgent_supports",
    )
    closed_at = models.DateTimeField(null=True, blank=True)
    closure_reason_code = models.CharField(
        max_length=50,
        choices=UrgentSupportClosureReasonCode.choices,
        blank=True,
    )
    documentation_status = models.CharField(
        max_length=50,
        choices=UrgentSupportDocumentationStatus.choices,
        default=UrgentSupportDocumentationStatus.NOT_STARTED,
    )
    documentation_session = models.ForeignKey(
        CounselingSession,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="documented_urgent_supports",
    )
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status"]),
            models.Index(fields=["review_status"]),
            models.Index(fields=["expires_at"]),
            models.Index(fields=["student"]),
            models.Index(fields=["triage_counselor"]),
        ]
        verbose_name = "urgent student support case"
        verbose_name_plural = "urgent student support cases"

    def clean(self):
        super().clean()
        if self.student:
            from apps.access_control.rules import is_student
            if not self.student.is_active or not is_student(self.student):
                raise ValidationError({"student": "Student must be an active student account."})

        if self.source_type not in ACTIVE_URGENT_SUPPORT_SOURCE_TYPES:
            raise ValidationError({"source_type": "Urgent support source type is not active for this foundation."})
        
        if self.triage_counselor:
            from apps.access_control.rules import is_counselor
            if not self.triage_counselor.is_active or not is_counselor(self.triage_counselor):
                raise ValidationError({"triage_counselor": "Assigned triage counselor must be an active counselor."})

        if self.review_status != UrgentSupportReviewStatus.NOT_REVIEWED:
            if not self.reviewed_by:
                raise ValidationError({"reviewed_by": "Reviewer is required when review status is set."})
            if not self.reviewed_at:
                raise ValidationError({"reviewed_at": "Review timestamp is required when review status is set."})
        else:
            if self.reviewed_by or self.reviewed_at:
                raise ValidationError({"review_status": "Review status must not be NOT_REVIEWED if reviewer or review timestamp is set."})

        if self.status == UrgentSupportStatus.CLOSED:
            if not self.closed_by:
                raise ValidationError({"closed_by": "Closed by is required when status is closed."})
            if not self.closed_at:
                raise ValidationError({"closed_at": "Closed timestamp is required when status is closed."})
            if not self.closure_reason_code:
                raise ValidationError({"closure_reason_code": "Closure reason code is required when status is closed."})
        else:
            if self.closed_by or self.closed_at or self.closure_reason_code:
                raise ValidationError({"status": "Status must be CLOSED if closure details are set."})

        if self.originating_session and self.originating_session.student_id != self.student_id:
            raise ValidationError({"originating_session": "Originating session student does not match the urgent_support student."})
        if self.documentation_session and self.documentation_session.student_id != self.student_id:
            raise ValidationError({"documentation_session": "Documentation session student does not match the urgent_support student."})
        if self.counseling_case and self.counseling_case.student_id != self.student_id:
            raise ValidationError({"counseling_case": "Counseling case student does not match the urgent-support student."})

        if self.pk:
            original = type(self).objects.filter(pk=self.pk).only("reference_code").first()
            if original and original.reference_code != self.reference_code:
                raise ValidationError({"reference_code": "Reference code is immutable."})

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.reference_code or "Urgent Student Support"


class TemporarySupportAccessGrant(TimestampedModel):
    urgent_support = models.ForeignKey(
        UrgentSupportRequest,
        on_delete=models.CASCADE,
        related_name="access_grants",
    )
    grantee = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="access_grants",
    )
    granted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="granted_access_grants",
    )
    grant_type = models.CharField(
        max_length=50,
        choices=TemporarySupportAccessType.choices,
    )
    purpose_code = models.CharField(
        max_length=50,
        choices=TemporarySupportAccessPurpose.choices,
    )
    starts_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="revoked_access_grants",
    )
    status = models.CharField(
        max_length=50,
        choices=TemporarySupportAccessStatus.choices,
        default=TemporarySupportAccessStatus.ACTIVE,
    )

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["grantee"]),
            models.Index(fields=["status"]),
            models.Index(fields=["starts_at"]),
            models.Index(fields=["expires_at"]),
        ]
        verbose_name = "urgent support temporary access grant"
        verbose_name_plural = "urgent support temporary access grants"

    def clean(self):
        super().clean()
        if self.grantee:
            from apps.access_control.rules import is_counselor
            if not self.grantee.is_active or not is_counselor(self.grantee):
                raise ValidationError({"grantee": "Grantee must be an active counselor."})

        if self.starts_at and self.expires_at:
            if self.expires_at <= self.starts_at:
                raise ValidationError({"expires_at": "Expires at must be after starts at."})
            duration = self.expires_at - self.starts_at
            if duration > timedelta(hours=24):
                raise ValidationError({"expires_at": "Access grant duration cannot exceed 24 hours."})

        if self.status == TemporarySupportAccessStatus.REVOKED:
            if not self.revoked_at:
                raise ValidationError({"revoked_at": "Revoked timestamp is required when grant is revoked."})
            if not self.revoked_by:
                raise ValidationError({"revoked_by": "Revoking user is required when grant is revoked."})
        else:
            if self.revoked_at or self.revoked_by:
                raise ValidationError({"status": "Status must be REVOKED if revoked details are set."})

        if self.starts_at and self.expires_at and self.status == TemporarySupportAccessStatus.ACTIVE and not self.revoked_at:
            overlapping = TemporarySupportAccessGrant.objects.filter(
                urgent_support=self.urgent_support,
                grantee=self.grantee,
                grant_type=self.grant_type,
                purpose_code=self.purpose_code,
                status=TemporarySupportAccessStatus.ACTIVE,
                revoked_at__isnull=True,
            ).exclude(pk=self.pk)
            
            overlapping = overlapping.filter(
                starts_at__lt=self.expires_at,
                expires_at__gt=self.starts_at,
            )
            if overlapping.exists():
                raise ValidationError("An active overlapping grant already exists for this grantee, type, and purpose.")

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Grant to {self.grantee_id} for {self.urgent_support.reference_code}"


class UrgentSupportHistory(TimestampedModel):
    urgent_support = models.ForeignKey(
        UrgentSupportRequest,
        on_delete=models.CASCADE,
        related_name="status_history",
    )
    from_status = models.CharField(max_length=50, blank=True)
    to_status = models.CharField(max_length=50)
    changed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="+",
    )
    reason_code = models.CharField(max_length=50, blank=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "urgent support history"
        verbose_name_plural = "urgent support histories"

    def __str__(self):
        return f"{self.urgent_support.reference_code}: {self.from_status} -> {self.to_status}"
