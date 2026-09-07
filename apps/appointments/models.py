# Project: COMPASS
# File: apps/appointments/models.py
# Module: apps.appointments
# Purpose: Seven models and four enum classes for appointment scheduling
# Domain boundary and service policy.
# Notes:
#   - AppointmentTypeChoices, AppointmentModeChoices, AvailabilityModeChoices,
#     and AppointmentStatusChoices define the static enum sets.
#   - Appointment is the core scheduling record.
#   - WorkflowReferenceCounter is the shared concurrency-safe sequence store.
#     tracker for AY-based reference code generation. AcademicTerm is the
#     canonical source for the academic-year period; no metadata projection
#     is used for sequence tracking.
#   - PRIVACY: internal_notes, decline_reason, cancellation_reason are never
#     rendered in student-facing templates.

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q

from apps.common.models import TimestampedModel


# ---------------------------------------------------------------------------
# Enum classes
# ---------------------------------------------------------------------------


class AppointmentTypeChoices(models.TextChoices):
    """Types of appointments a student may request."""
    COUNSELING = "COUNSELING", "Counseling"
    ROUTINE_INTERVIEW = "ROUTINE_INTERVIEW", "Routine Interview"
    FOLLOW_UP = "FOLLOW_UP", "Follow-up"
    OTHER = "OTHER", "Other"


class AppointmentModeChoices(models.TextChoices):
    """Delivery mode for an individual appointment — two values only."""
    ONSITE = "ONSITE", "On-site"
    ONLINE = "ONLINE", "Online"


class AvailabilityModeChoices(models.TextChoices):
    """Availability mode for counselor schedules — three values.
    BOTH matches either ONSITE or ONLINE appointment modes.
    """
    ONSITE = "ONSITE", "On-site"
    ONLINE = "ONLINE", "Online"
    BOTH = "BOTH", "Both"


class AppointmentStatusChoices(models.TextChoices):
    """13-value initial status set for appointment lifecycle.

    Deferred statuses (not in this set):
    - RESCHEDULE_REQUESTED
    - CONVERTED_TO_SESSION
    - CONVERTED_TO_CASE
    """
    DRAFT = "DRAFT", "Draft"
    SUBMITTED = "SUBMITTED", "Submitted"
    PENDING_REVIEW = "PENDING_REVIEW", "Pending Review"
    APPROVED = "APPROVED", "Approved"
    SCHEDULED = "SCHEDULED", "Scheduled"
    DECLINED = "DECLINED", "Declined"
    CANCELLED_BY_STUDENT = "CANCELLED_BY_STUDENT", "Cancelled by Student"
    CANCELLED_BY_OFFICE = "CANCELLED_BY_OFFICE", "Cancelled by Office"
    LATE_CANCELLATION_REQUESTED = "LATE_CANCELLATION_REQUESTED", "Late Cancellation Requested"
    LATE_CANCELLATION_APPROVED = "LATE_CANCELLATION_APPROVED", "Late Cancellation Approved"
    LATE_CANCELLATION_DECLINED = "LATE_CANCELLATION_DECLINED", "Late Cancellation Declined"
    COMPLETED = "COMPLETED", "Completed"
    NO_SHOW = "NO_SHOW", "No Show"


ACTIVE_APPOINTMENT_STATUSES = (
    AppointmentStatusChoices.DRAFT,
    AppointmentStatusChoices.SUBMITTED,
    AppointmentStatusChoices.PENDING_REVIEW,
    AppointmentStatusChoices.APPROVED,
    AppointmentStatusChoices.SCHEDULED,
    AppointmentStatusChoices.LATE_CANCELLATION_REQUESTED,
    # Retained as active for legacy rows. New declines return to SCHEDULED.
    AppointmentStatusChoices.LATE_CANCELLATION_DECLINED,
)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class Appointment(TimestampedModel):
    """Core appointment record.

    Tracks the full lifecycle from student request through scheduling,
    completion, cancellation, or no-show. The reference_code is the
    primary public identifier — never the PK.
    """

    reference_code = models.CharField(
        max_length=25,
        unique=True,
        editable=False,
        help_text="Immutable AY-based reference code (e.g. APT-AY2526-000001).",
    )
    student = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="appointments",
        help_text="The student who requested the appointment.",
    )
    appointment_type = models.CharField(
        max_length=30,
        choices=AppointmentTypeChoices.choices,
        help_text="Type of appointment requested.",
    )
    appointment_mode = models.CharField(
        max_length=10,
        choices=AppointmentModeChoices.choices,
        help_text="Delivery mode: on-site or online.",
    )
    preferred_counselor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="preferred_appointments",
        help_text="Student's preferred counselor. Does not grant access.",
    )
    assigned_counselor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_appointments",
        help_text="Office-assigned counselor.",
    )
    status = models.CharField(
        max_length=40,
        choices=AppointmentStatusChoices.choices,
        default=AppointmentStatusChoices.DRAFT,
        help_text="Current appointment status.",
    )
    reason = models.TextField(
        blank=True,
        help_text="Student-provided reason for the appointment.",
    )
    requested_date = models.DateField(
        null=True, blank=True,
        help_text="Student's preferred date.",
    )
    requested_start_time = models.TimeField(
        null=True, blank=True,
        help_text="Student's preferred start time.",
    )
    confirmed_date = models.DateField(
        null=True, blank=True,
        help_text="Office-confirmed date.",
    )
    confirmed_start_time = models.TimeField(
        null=True, blank=True,
        help_text="Office-confirmed start time.",
    )
    confirmed_end_time = models.TimeField(
        null=True, blank=True,
        help_text="Office-confirmed end time (default: start + slot duration).",
    )
    actual_start_time = models.DateTimeField(
        null=True, blank=True,
        help_text="Actual session start timestamp.",
    )
    actual_end_time = models.DateTimeField(
        null=True, blank=True,
        help_text="Actual session end timestamp.",
    )
    cancellation_reason = models.TextField(
        blank=True,
        help_text="Reason if cancelled.",
    )
    decline_reason = models.TextField(
        blank=True,
        help_text="Reason if declined by office. Not visible to student in raw form.",
    )
    internal_notes = models.TextField(
        blank=True,
        help_text="Staff/counselor-only notes. Never rendered in student templates.",
    )
    submitted_at = models.DateTimeField(
        null=True, blank=True,
        help_text="Timestamp when the appointment was submitted.",
    )
    reviewed_at = models.DateTimeField(
        null=True, blank=True,
        help_text="Timestamp when the appointment was reviewed.",
    )
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reviewed_appointments",
        help_text="The staff/counselor who reviewed the appointment.",
    )
    completed_at = models.DateTimeField(
        null=True, blank=True,
        help_text="Timestamp when the appointment was completed.",
    )

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["assigned_counselor", "status"]),
            models.Index(fields=["student", "status"]),
            models.Index(fields=["status", "confirmed_date"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["student"],
                condition=Q(status__in=ACTIVE_APPOINTMENT_STATUSES),
                name="uniq_active_appointment_per_student",
            ),
        ]
        verbose_name = "appointment"
        verbose_name_plural = "appointments"

    def __str__(self):
        return self.reference_code or f"Appointment #{self.pk}"


class AppointmentStatusHistory(TimestampedModel):
    """Audit trail for every status transition on an appointment."""

    appointment = models.ForeignKey(
        Appointment,
        on_delete=models.CASCADE,
        related_name="status_history",
    )
    from_status = models.CharField(
        max_length=50,
        blank=True,
        help_text="Previous status. Empty for initial creation.",
    )
    to_status = models.CharField(
        max_length=50,
        help_text="New status after transition.",
    )
    changed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        help_text="The user who performed the transition.",
    )
    reason = models.TextField(
        blank=True,
        help_text="Optional reason for the transition.",
    )

    class Meta:
        verbose_name = "appointment status history"
        verbose_name_plural = "appointment status histories"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.appointment.reference_code}: {self.from_status} -> {self.to_status}"


class AssignmentHistory(TimestampedModel):
    """Tracks counselor assignment and reassignment for an appointment."""

    appointment = models.ForeignKey(
        Appointment,
        on_delete=models.CASCADE,
        related_name="assignment_history",
    )
    from_counselor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
        help_text="Previous assigned counselor. Null on initial assignment.",
    )
    to_counselor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
        help_text="New assigned counselor.",
    )
    assigned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="+",
        help_text="The user who performed the assignment.",
    )
    reason = models.TextField(
        blank=True,
        help_text="Reason for the assignment or reassignment.",
    )

    class Meta:
        verbose_name = "assignment history"
        verbose_name_plural = "assignment histories"
        ordering = ["-created_at"]

    def __str__(self):
        return f"Assignment: {self.appointment.reference_code} from {self.from_counselor_id} to {self.to_counselor_id}"


class AvailabilityRule(TimestampedModel):
    """Recurring weekly counselor availability rule."""

    counselor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="availability_rules",
        help_text="The counselor whose availability is defined.",
    )
    public_reference = models.UUIDField(
        default=uuid.uuid4,
        unique=True,
        editable=False,
        help_text="Opaque route reference; never display the database primary key.",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_availability_rules",
        help_text="The actor who recorded this rule.",
    )
    day_of_week = models.PositiveSmallIntegerField(
        help_text="Day of week: 0=Monday through 6=Sunday (ISO weekday).",
    )
    start_time = models.TimeField(
        help_text="Start time for this availability window.",
    )
    end_time = models.TimeField(
        help_text="End time for this availability window.",
    )
    mode = models.CharField(
        max_length=10,
        choices=AvailabilityModeChoices.choices,
        help_text="Availability mode: ONSITE, ONLINE, or BOTH.",
    )
    location = models.CharField(
        max_length=200,
        blank=True,
        help_text="Room or office description.",
    )
    slot_duration_minutes = models.PositiveIntegerField(
        default=60,
        help_text="Default slot duration in minutes.",
    )
    max_appointments_per_slot = models.PositiveIntegerField(
        default=1,
        help_text="Maximum appointments per slot.",
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this rule is currently active.",
    )
    effective_from = models.DateField(
        help_text="Date when this rule becomes effective.",
    )
    effective_until = models.DateField(
        null=True, blank=True,
        help_text="Date when this rule ends. Null indicates indefinite.",
    )

    class Meta:
        verbose_name = "availability rule"
        verbose_name_plural = "availability rules"
        ordering = ["counselor", "day_of_week", "start_time"]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(slot_duration_minutes__gt=0),
                name="availability_rule_positive_duration",
            ),
            models.CheckConstraint(
                condition=models.Q(max_appointments_per_slot__gt=0),
                name="availability_rule_positive_capacity",
            ),
        ]

    def clean(self):
        super().clean()
        if self.start_time and self.end_time and self.start_time >= self.end_time:
            raise ValidationError(
                {"end_time": "End time must be after start time."}
            )
        if self.effective_from and self.effective_until and self.effective_from > self.effective_until:
            raise ValidationError(
                {"effective_until": "Effective end date must be on or after the start date."}
            )
        if self.day_of_week is not None and not (0 <= self.day_of_week <= 6):
            raise ValidationError(
                {"day_of_week": "Day of week must be between 0 (Monday) and 6 (Sunday)."}
            )
        if self.slot_duration_minutes is not None and self.slot_duration_minutes <= 0:
            raise ValidationError({"slot_duration_minutes": "Slot duration must be greater than zero."})
        if self.max_appointments_per_slot is not None and self.max_appointments_per_slot <= 0:
            raise ValidationError({"max_appointments_per_slot": "Slot capacity must be greater than zero."})

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def get_day_of_week_display(self):
        """Return a human-readable weekday without changing the schema."""
        return (
            "Monday",
            "Tuesday",
            "Wednesday",
            "Thursday",
            "Friday",
            "Saturday",
            "Sunday",
        )[self.day_of_week] if self.day_of_week in range(7) else str(self.day_of_week)

    def __str__(self):
        return f"{self.counselor.get_full_name()} - {self.get_day_of_week_display()} ({self.start_time}-{self.end_time})"


class UnavailableBlock(TimestampedModel):
    """One-off counselor-specific unavailability."""

    counselor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="unavailable_blocks",
        help_text="The counselor who is unavailable.",
    )
    public_reference = models.UUIDField(
        default=uuid.uuid4,
        unique=True,
        editable=False,
        help_text="Opaque route reference; never display the database primary key.",
    )
    date = models.DateField(
        help_text="Date of unavailability.",
    )
    start_time = models.TimeField(
        null=True, blank=True,
        help_text="Start time of unavailability. Null = entire day.",
    )
    end_time = models.TimeField(
        null=True, blank=True,
        help_text="End time of unavailability.",
    )
    reason = models.CharField(
        max_length=200,
        blank=True,
        help_text="E.g. 'Meeting', 'Leave'.",
    )
    is_all_day = models.BooleanField(
        default=False,
        help_text="If true, the counselor is unavailable for the entire day.",
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this block currently affects slot calculation.",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_unavailable_blocks",
        help_text="The actor who recorded this block.",
    )

    class Meta:
        verbose_name = "unavailable block"
        verbose_name_plural = "unavailable blocks"
        ordering = ["counselor", "date", "start_time"]
        constraints = [
            models.CheckConstraint(
                condition=(
                    models.Q(is_all_day=True, start_time__isnull=True, end_time__isnull=True)
                    | models.Q(
                        is_all_day=False,
                        start_time__isnull=False,
                        end_time__isnull=False,
                        end_time__gt=models.F("start_time"),
                    )
                ),
                name="unavailable_block_complete_interval",
            ),
        ]

    def clean(self):
        super().clean()
        if self.is_all_day and (self.start_time is not None or self.end_time is not None):
            raise ValidationError({"is_all_day": "All-day blocks must not have start or end times."})
        if not self.is_all_day and (self.start_time is None or self.end_time is None):
            raise ValidationError({"start_time": "A timed block requires both start and end times."})
        if self.start_time and self.end_time and self.start_time >= self.end_time:
            raise ValidationError(
                {"end_time": "End time must be after start time."}
            )

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.counselor.get_full_name()} unavailable on {self.date}"


class OfficeClosure(TimestampedModel):
    """Office-wide no-service periods (holidays, campus events, etc.)."""

    date = models.DateField(
        help_text="Date of office closure.",
    )
    public_reference = models.UUIDField(
        default=uuid.uuid4,
        unique=True,
        editable=False,
        help_text="Opaque route reference; never display the database primary key.",
    )
    start_time = models.TimeField(
        null=True, blank=True,
        help_text="Start time of closure. Null = entire day.",
    )
    end_time = models.TimeField(
        null=True, blank=True,
        help_text="End time of closure.",
    )
    reason = models.CharField(
        max_length=200,
        blank=True,
        help_text="E.g. 'Holiday', 'Campus event'.",
    )
    is_all_day = models.BooleanField(
        default=True,
        help_text="If true, the office is closed for the entire day.",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        help_text="The user who recorded this closure.",
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this closure currently affects slot calculation.",
    )

    class Meta:
        verbose_name = "office closure"
        verbose_name_plural = "office closures"
        ordering = ["date", "start_time"]
        constraints = [
            models.CheckConstraint(
                condition=(
                    models.Q(is_all_day=True, start_time__isnull=True, end_time__isnull=True)
                    | models.Q(
                        is_all_day=False,
                        start_time__isnull=False,
                        end_time__isnull=False,
                        end_time__gt=models.F("start_time"),
                    )
                ),
                name="office_closure_complete_interval",
            ),
        ]

    def clean(self):
        super().clean()
        if self.is_all_day and (self.start_time is not None or self.end_time is not None):
            raise ValidationError({"is_all_day": "All-day closures must not have start or end times."})
        if not self.is_all_day and (self.start_time is None or self.end_time is None):
            raise ValidationError({"start_time": "A timed closure requires both start and end times."})
        if self.start_time and self.end_time and self.start_time >= self.end_time:
            raise ValidationError(
                {"end_time": "End time must be after start time."}
            )

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Office Closure: {self.date}"


class ScheduleCoordinationLock(TimestampedModel):
    """Database lock rows shared by booking and schedule-management services."""

    scope_key = models.CharField(max_length=120, unique=True)

    class Meta:
        verbose_name = "schedule coordination lock"
        verbose_name_plural = "schedule coordination locks"

    def __str__(self):
        return self.scope_key


class ScheduleChangeEvent(TimestampedModel):
    """Immutable, privacy-safe history for schedule-management mutations."""

    target_type = models.CharField(max_length=40)
    target_object_id = models.CharField(max_length=40)
    target_public_reference = models.UUIDField(null=True, blank=True)
    action_type = models.CharField(max_length=40)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="schedule_change_events",
    )
    reason = models.CharField(max_length=200)
    prior_state = models.JSONField(default=dict)
    resulting_state = models.JSONField(default=dict)
    pending_appointment_count = models.PositiveIntegerField(default=0)
    scheduled_appointment_count = models.PositiveIntegerField(default=0)
    affected_appointment_outcome = models.CharField(max_length=60, default="NONE")
    request_key = models.CharField(max_length=64, unique=True)

    class Meta:
        ordering = ["-created_at", "-pk"]
        indexes = [
            models.Index(fields=["target_type", "target_object_id"]),
            models.Index(fields=["action_type", "created_at"]),
        ]

    def __str__(self):
        return f"{self.action_type}: {self.target_type} {self.target_public_reference or self.target_object_id}"

    def save(self, *args, **kwargs):
        if self.pk:
            raise ValidationError("Schedule change history is immutable.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Schedule change history is immutable.")
