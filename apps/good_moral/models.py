# Project: COMPASS
# File: apps/good_moral/models.py
# Module: apps.good_moral
# Purpose: Good Moral Character request models and lifecycle choices
# Domain boundary and service policy.

import uuid
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from apps.common.models import TimestampedModel


class RequestTypeChoices(models.TextChoices):
    STUDENT = "STUDENT", "Student"
    GRADUATE = "GRADUATE", "Graduate"


class GoodMoralStatusChoices(models.TextChoices):
    DRAFT = "DRAFT", "Draft"
    SUBMITTED = "SUBMITTED", "Submitted"
    FOR_PAYMENT = "FOR_PAYMENT", "For Payment"
    PAYMENT_ENCODED = "PAYMENT_ENCODED", "Payment Encoded"
    FOR_RECORD_CHECKING = "FOR_RECORD_CHECKING", "For Record Checking"
    PENDING_MANUAL_OSSD_VERIFICATION = "PENDING_MANUAL_OSSD_VERIFICATION", "Pending Manual OSSD Verification"
    ON_HOLD_FOR_REVIEW = "ON_HOLD_FOR_REVIEW", "On Hold for Review"
    FOR_APPROVAL = "FOR_APPROVAL", "For Approval"
    APPROVED_FOR_GENERATION = "APPROVED_FOR_GENERATION", "Approved for Generation"
    GENERATING = "GENERATING", "Generating"
    GENERATED = "GENERATED", "Generated"
    PRINTED = "PRINTED", "Printed"
    RELEASED = "RELEASED", "Released"
    REJECTED = "REJECTED", "Rejected"
    CANCELLED = "CANCELLED", "Cancelled"
    VOIDED = "VOIDED", "Voided"
    ARCHIVED = "ARCHIVED", "Archived"
    FAILED = "FAILED", "Failed"


class ReceiptStatusChoices(models.TextChoices):
    PENDING = "PENDING", "Pending"
    ENCODED = "ENCODED", "Encoded"
    VERIFIED = "VERIFIED", "Verified"
    REJECTED = "REJECTED", "Rejected"


class DrySealStatusChoices(models.TextChoices):
    PENDING = "PENDING", "Pending"
    SEALED = "SEALED", "External Registrar seal confirmed"


class DrySealConfirmationMethodChoices(models.TextChoices):
    STUDENT_ATTESTED = "STUDENT_ATTESTED", "Student attested"
    COUNSELOR_RECORDED = "COUNSELOR_RECORDED", "Counselor recorded"
    GCO_STAFF_RECORDED = "GCO_STAFF_RECORDED", "GCO Staff recorded"


class OSSDVerificationStatusChoices(models.TextChoices):
    PENDING = "PENDING", "Pending"
    VERIFIED = "VERIFIED", "Verified"
    NOT_REQUIRED = "NOT_REQUIRED", "Not Required"


class GoodMoralRequest(TimestampedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    reference_code = models.CharField(
        "reference code",
        max_length=30,
        unique=True,
        editable=False,
        help_text="Immutable unique lookup code (GMC-AYxxxx-xxxxxx).",
    )
    request_type = models.CharField(
        "request type",
        max_length=20,
        choices=RequestTypeChoices.choices,
    )
    requester_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="good_moral_requests",
    )
    student_profile = models.ForeignKey(
        "profiles.StudentProfile",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="good_moral_requests",
    )

    # Privacy-minimized applicant snapshots (frozen at submission/intake)
    applicant_display_name = models.CharField(max_length=255)
    applicant_lifecycle_status = models.CharField(max_length=100)
    applicant_campus = models.CharField(max_length=255)
    applicant_college = models.CharField(max_length=255)
    applicant_department = models.CharField(max_length=255)
    applicant_program_degree = models.CharField(max_length=255)
    applicant_year_level = models.CharField(max_length=100, blank=True)
    applicant_major = models.CharField(max_length=100, blank=True)
    applicant_semester = models.CharField(max_length=100, blank=True)
    applicant_academic_year = models.CharField(max_length=100)
    applicant_graduation_date = models.DateField(null=True, blank=True)

    # Plain-text bounded purpose
    purpose_text = models.TextField("purpose text", max_length=500)

    # Receipt/Payment manual metadata
    official_receipt_number = models.CharField(max_length=100, blank=True)
    official_receipt_date = models.DateField(null=True, blank=True)
    official_receipt_amount = models.DecimalField(
        max_digits=10, decimal_places=2, null=True, blank=True
    )
    receipt_status = models.CharField(
        max_length=30,
        choices=ReceiptStatusChoices.choices,
        default=ReceiptStatusChoices.PENDING,
    )
    receipt_encoded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="encoded_receipt_gmc_requests",
    )
    receipt_encoded_at = models.DateTimeField(null=True, blank=True)
    receipt_verified_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="verified_receipt_gmc_requests",
    )
    receipt_verified_at = models.DateTimeField(null=True, blank=True)
    receipt_rejection_code = models.CharField(max_length=50, blank=True)

    # Review metadata (no counseling notes/disciplinary narratives)
    assigned_reviewer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_review_gmc_requests",
    )
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reviewed_gmc_requests",
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    ossd_verification_status = models.CharField(
        max_length=30,
        choices=OSSDVerificationStatusChoices.choices,
        default=OSSDVerificationStatusChoices.NOT_REQUIRED,
    )
    hold_rejection_reason_code = models.CharField(max_length=50, blank=True)
    office_only_note = models.TextField(
        "office-only safe note",
        max_length=1000,
        blank=True,
        help_text="Safe administrative metadata. Never store counseling notes or case details.",
    )

    # Approval metadata
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="approved_gmc_requests",
    )
    approved_at = models.DateTimeField(null=True, blank=True)
    approval_signatory_name = models.CharField(max_length=255, blank=True)
    approval_signatory_title = models.CharField(max_length=255, blank=True)

    # Generation metadata
    generated_document = models.ForeignKey(
        "documents.GeneratedDocument",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="good_moral_requests",
    )
    generated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="generated_gmc_requests",
    )
    generated_at = models.DateTimeField(null=True, blank=True)
    generation_failure_code = models.CharField(max_length=50, blank=True)

    # Print/Release and external Registrar dry-seal confirmation metadata
    printed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="printed_gmc_requests",
    )
    printed_at = models.DateTimeField(null=True, blank=True)
    dry_seal_status = models.CharField(
        max_length=30,
        choices=DrySealStatusChoices.choices,
        default=DrySealStatusChoices.PENDING,
    )
    dry_seal_confirmation_method = models.CharField(
        max_length=30,
        choices=DrySealConfirmationMethodChoices.choices,
        blank=True,
        default="",
    )
    dry_seal_confirmed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="confirmed_dry_seal_gmc_requests",
    )
    dry_seal_confirmed_at = models.DateTimeField(null=True, blank=True)
    released_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="released_gmc_requests",
    )
    released_at = models.DateTimeField(null=True, blank=True)

    # Terminal metadata
    voided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="voided_gmc_requests",
    )
    voided_at = models.DateTimeField(null=True, blank=True)
    cancelled_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="cancelled_gmc_requests",
    )
    cancelled_at = models.DateTimeField(null=True, blank=True)
    archived_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="archived_gmc_requests",
    )
    archived_at = models.DateTimeField(null=True, blank=True)
    terminal_reason_code = models.CharField(max_length=50, blank=True)

    status = models.CharField(
        max_length=40,
        choices=GoodMoralStatusChoices.choices,
        default=GoodMoralStatusChoices.DRAFT,
    )

    class Meta:
        verbose_name = "good moral request"
        verbose_name_plural = "good moral requests"
        indexes = [
            models.Index(fields=["status"]),
            models.Index(fields=["reference_code"]),
            models.Index(fields=["request_type"]),
            models.Index(fields=["requester_user"]),
        ]

    def __str__(self):
        return f"{self.reference_code} ({self.status})"

    def save(self, *args, **kwargs):
        if self.pk:
            persisted = type(self).objects.filter(pk=self.pk).only("reference_code").first()
            if persisted and persisted.reference_code != self.reference_code:
                raise ValidationError({"reference_code": "Reference code is immutable."})
        return super().save(*args, **kwargs)
