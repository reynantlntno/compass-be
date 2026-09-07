# Project: COMPASS
# File: apps/student_activation/models.py
# Module: apps.student_activation
# Purpose: Model for student activation tokens
# Domain boundary and service policy.

from django.conf import settings
from django.db import models
import uuid

from apps.common.models import TimestampedModel


class StudentActivationInvitation(TimestampedModel):
    """Staging model for single-use student account activation tokens.

    SECURITY: The token_hash stores the HMAC-SHA256 hash of a cryptographically secure
    raw token. The raw token itself is NEVER saved in the database, printed in standard
    logs, or exposed in Django Admin.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="activation_invitations",
        help_text="The inactive STUDENT user account associated with this token.",
    )
    token_hash = models.CharField(
        "token hash",
        max_length=64,
        unique=True,
        db_index=True,
        help_text="HMAC-SHA256 hex digest of the raw activation token.",
    )
    token_version = models.CharField(max_length=40, default="account-activation-student-v1")
    token_reference = models.UUIDField(
        default=uuid.uuid4,
        unique=True,
        db_index=True,
        help_text="Opaque invitation reference used to reconstruct the signed token at send time.",
    )
    delivery_email_hash = models.CharField(max_length=64, default="")
    expires_at = models.DateTimeField(
        "expires at",
        help_text="The date and time when the invitation expires.",
    )
    used_at = models.DateTimeField(
        "used at",
        null=True,
        blank=True,
        help_text="Timestamp when the token was successfully used.",
    )
    revoked_at = models.DateTimeField(
        "revoked at",
        null=True,
        blank=True,
        help_text="Timestamp when the token was manually or programmatically revoked.",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_invitations",
        help_text="The user who issued or reissued this invitation.",
    )
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="revoked_student_activation_invitations",
    )
    revocation_reason = models.CharField(max_length=80, blank=True, default="")
    reissued_from = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reissues",
    )

    class Meta:
        verbose_name = "student activation invitation"
        verbose_name_plural = "student activation invitations"

    def __str__(self):
        return f"Student activation invitation #{self.pk} ({self.token_version})"
