# Project: COMPASS
# File: apps/profiles/models.py
# Module: apps.profiles
# Purpose: User profile models for students, counselors, and staff
# Domain boundary and service policy.

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q

from apps.common.models import TimestampedModel


class StudentLifecycleChoices(models.TextChoices):
    """Student lifecycle statuses for COMPASS.
    
    Alumni and graduates are represented by these lifecycle states
    rather than having a separate application role.
    """
    ACTIVE = "ACTIVE", "Active"
    GRADUATING = "GRADUATING", "Graduating"
    GRADUATED = "GRADUATED", "Graduated"
    ALUMNI = "ALUMNI", "Alumni"
    TRANSFERRED = "TRANSFERRED", "Transferred"
    DROPPED_INACTIVE = "DROPPED_INACTIVE", "Dropped / Inactive"
    SUSPENDED_RESTRICTED = "SUSPENDED_RESTRICTED", "Suspended / Restricted"
    ARCHIVED = "ARCHIVED", "Archived"


class StudentProfile(TimestampedModel):
    """Profile for students and alumni.
    
    Stores academic identifiers, campus location details, program tracking,
    and lifecycle status.
    
    SECURITY: control_number must not be raw logged or treated as authentication.
    """
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="student_profile",
        help_text="The linked User account."
    )
    student_number = models.CharField(
        "student number",
        max_length=50,
        unique=True,
        blank=True,
        null=True,
        help_text="Unique student ID number."
    )
    control_number = models.CharField(
        "control number",
        max_length=50,
        unique=True,
        blank=True,
        null=True,
        help_text="Used for matching intake submissions before account registration."
    )
    lifecycle_status = models.CharField(
        "lifecycle status",
        max_length=30,
        choices=StudentLifecycleChoices.choices,
        default=StudentLifecycleChoices.ACTIVE,
        help_text="Current enrollment or alumni status of the student."
    )
    campus = models.CharField(
        "campus",
        max_length=100,
        blank=True,
        help_text="UCN campus name, e.g. Main Campus."
    )
    college = models.CharField(
        "college",
        max_length=100,
        blank=True,
        help_text="UCN college name, e.g. CCMS."
    )
    department = models.CharField(
        "department",
        max_length=100,
        blank=True,
        help_text="Academic department name."
    )
    program = models.CharField(
        "program",
        max_length=100,
        blank=True,
        help_text="Specific academic program/degree course."
    )
    year_level = models.PositiveIntegerField(
        "year level",
        null=True,
        blank=True,
        help_text="Current academic year level."
    )

    class Meta:
        verbose_name = "student profile"
        verbose_name_plural = "student profiles"

    def __str__(self):
        return f"{self.user.get_full_name()} ({self.student_number or 'No ID'})"


class CohortEnrollmentState(models.TextChoices):
    """Historical roster state used as the reporting denominator."""

    ENROLLED = "ENROLLED", "Enrolled"
    EXCLUDED = "EXCLUDED", "Excluded from reporting cohort"


class CohortProvenance(models.TextChoices):
    IMPORT = "IMPORT", "Official import"
    DEMO = "DEMO", "Synthetic operating demo"
    MANUAL = "MANUAL", "Authorized manual cohort capture"


class StudentAcademicCohort(TimestampedModel):
    """Immutable organizational context for one student's reporting year.

    This is deliberately separate from ``StudentProfile``.  The latter is the
    current academic placement and must not rewrite historical report totals.
    """

    student_profile = models.ForeignKey(
        StudentProfile,
        on_delete=models.CASCADE,
        related_name="academic_cohorts",
    )
    academic_year = models.CharField(max_length=50, db_index=True)
    campus = models.CharField(max_length=100, blank=True)
    college = models.CharField(max_length=100, blank=True)
    college_code = models.CharField(max_length=80, blank=True)
    department = models.CharField(max_length=100, blank=True)
    program = models.CharField(max_length=100, blank=True)
    program_code = models.CharField(max_length=100, blank=True)
    year_level = models.PositiveIntegerField(null=True, blank=True)
    enrollment_state = models.CharField(
        max_length=20,
        choices=CohortEnrollmentState.choices,
        default=CohortEnrollmentState.ENROLLED,
        db_index=True,
    )
    provenance = models.CharField(
        max_length=20,
        choices=CohortProvenance.choices,
        default=CohortProvenance.MANUAL,
    )
    source_reference = models.CharField(
        max_length=80,
        blank=True,
        help_text="Non-PII source identifier, such as an import batch/row reference.",
    )

    class Meta:
        verbose_name = "student academic cohort"
        verbose_name_plural = "student academic cohorts"
        constraints = [
            models.UniqueConstraint(
                fields=["student_profile", "academic_year"],
                name="unique_student_academic_cohort",
            )
        ]
        indexes = [
            models.Index(fields=["academic_year", "college", "year_level"]),
            models.Index(fields=["academic_year", "campus", "department", "program"]),
        ]

    def __str__(self):
        return f"Cohort {self.academic_year} / {self.student_profile_id}"

    def clean(self):
        super().clean()
        if not self._state.adding:
            original = type(self).objects.filter(pk=self.pk).values(
                "student_profile_id", "academic_year", "campus", "college",
                "college_code", "department", "program", "program_code",
                "year_level", "enrollment_state", "provenance", "source_reference",
            ).first()
            if original:
                immutable_fields = tuple(original)
                changed = [
                    field for field in immutable_fields
                    if original[field] != getattr(self, field)
                ]
                if changed:
                    raise ValidationError(
                        "Historical academic cohort records are immutable in this reporting boundary."
                    )

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)


class CounselorProfile(TimestampedModel):
    """Profile for professional guidance counselors.
    
    Holds licenses and designates the office lead (Head Guidance).
    """
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="counselor_profile",
        help_text="The linked User account."
    )
    is_head_guidance = models.BooleanField(
        "is head guidance",
        default=False,
        help_text="Designation flag indicating administrative authority over the office."
    )
    license_number = models.CharField(
        "license number",
        max_length=50,
        blank=True,
        help_text="Professional guidance counselor license identification."
    )

    class Meta:
        verbose_name = "counselor profile"
        verbose_name_plural = "counselor profiles"
        constraints = [
            models.UniqueConstraint(
                fields=["is_head_guidance"],
                condition=Q(is_head_guidance=True),
                name="profiles_one_active_head_guidance",
            )
        ]

    def __str__(self):
        head_suffix = " [Head Guidance]" if self.is_head_guidance else ""
        return f"{self.user.get_full_name()}{head_suffix}"


class GCOStaffProfile(TimestampedModel):
    """Profile for operational and administrative support staff.
    
    Used to track administrative designations and support roles.
    """
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="staff_profile",
        help_text="The linked User account."
    )
    employee_number = models.CharField(
        "employee number",
        max_length=50,
        blank=True
    )
    designation = models.CharField(
        "designation",
        max_length=100,
        blank=True,
        help_text="Internal staff role title, e.g., Front Desk Coordinator."
    )

    class Meta:
        verbose_name = "GCO staff profile"
        verbose_name_plural = "GCO staff profiles"

    def __str__(self):
        return f"{self.user.get_full_name()} ({self.designation or 'Staff'})"
