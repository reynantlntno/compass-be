# Project: COMPASS
# File: apps/accounts/models.py
# Module: accounts
# Purpose: Custom User model with normalized COMPASS roles
# Domain boundary and service policy.
# Notes:
#   - Email is USERNAME_FIELD. Student number belongs to StudentProfile (later task).
#   - Only four application roles: STUDENT, COUNSELOR, GCO_STAFF, IT_ADMIN.
#   - HEAD_GUIDANCE is a counselor designation, NOT a standalone role.
#   - ALUMNI is a student lifecycle status, NOT a standalone role.
#   SECURITY: Django Admin and standard superuser provisioning are disabled;
#   is_superuser is a legacy framework flag and NOT equivalent to IT_ADMIN.

import uuid

from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.core.exceptions import ValidationError
from django.db import models

from apps.accounts.managers import UserManager


class RoleChoices(models.TextChoices):
    """Normalized COMPASS application roles.

    HEAD_GUIDANCE is NOT a role — use CounselorProfile.is_head_guidance.
    ALUMNI is NOT a role — use StudentProfile.lifecycle_status.
    """

    STUDENT = "STUDENT", "Student"
    COUNSELOR = "COUNSELOR", "Counselor"
    GCO_STAFF = "GCO_STAFF", "GCO Staff"
    IT_ADMIN = "IT_ADMIN", "IT Admin"


class User(AbstractBaseUser, PermissionsMixin):
    """Custom User model for COMPASS.

    Uses email as the unique identifier (USERNAME_FIELD).
    Student number is NOT stored here — it belongs to StudentProfile.

    Role field uses normalized COMPASS roles only:
    - STUDENT: current, former, or alumni student
    - COUNSELOR: guidance counselor (Head Guidance is a designation, not a role)
    - GCO_STAFF: guidance office operational staff
    - IT_ADMIN: COMPASS technical/system administrator

    SECURITY: is_superuser is a legacy framework flag retained for explicit
        API deny/assurance checks. It is NOT the normal IT Admin role.
    """

    email = models.EmailField(
        "email address",
        unique=True,
        help_text="Used as the login identifier.",
    )
    first_name = models.CharField("first name", max_length=150, blank=True)
    last_name = models.CharField("last name", max_length=150, blank=True)
    role = models.CharField(
        "application role",
        max_length=20,
        choices=RoleChoices.choices,
        help_text="COMPASS application role. Not a Django permission group.",
    )
    is_active = models.BooleanField(
        "active",
        default=False,
        help_text=(
            "Designates whether this user account is active. "
            "New accounts require activation."
        ),
    )
    date_joined = models.DateTimeField("date joined", auto_now_add=True)
    updated_at = models.DateTimeField("last updated", auto_now=True)
    auth_security_stamp = models.UUIDField(default=uuid.uuid4, editable=False)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name"]

    class Meta:
        verbose_name = "user"
        verbose_name_plural = "users"

    def __str__(self):
        return self.email

    def get_full_name(self):
        """Return first_name plus last_name, with a space in between."""
        full_name = f"{self.first_name} {self.last_name}".strip()
        return full_name or self.email

    def get_short_name(self):
        """Return the first name."""
        return self.first_name or self.email

    def rotate_auth_security_stamp(self, *, using=None):
        """Invalidate authentication assurance bound to the prior security context."""
        self.auth_security_stamp = uuid.uuid4()
        self.save(using=using, update_fields=["auth_security_stamp"])

    def save(self, *args, **kwargs):
        security_fields = ("role", "is_superuser", "is_active", "password")
        security_state_changed = False
        if self.pk and not self._state.adding:
            previous = (
                type(self)
                .objects.filter(pk=self.pk)
                .values(*security_fields, "auth_security_stamp")
                .first()
            )
            state_fields_changed = bool(
                previous
                and any(previous[field] != getattr(self, field) for field in security_fields)
            )
            stamp_changed = bool(
                previous and previous["auth_security_stamp"] != self.auth_security_stamp
            )
            if state_fields_changed:
                self.auth_security_stamp = uuid.uuid4()
                security_state_changed = True
            elif stamp_changed:
                security_state_changed = True
            if security_state_changed:
                update_fields = kwargs.get("update_fields")
                if update_fields is not None:
                    kwargs["update_fields"] = set(update_fields) | {"auth_security_stamp"}
        result = super().save(*args, **kwargs)
        if security_state_changed:
            from apps.account_security.api_tokens import revoke_all_api_tokens_for_user

            revoke_all_api_tokens_for_user(
                self,
                reason="account_security_state_changed",
            )
        return result


class StaffInvitationProfileChoices(models.TextChoices):
    COUNSELOR = RoleChoices.COUNSELOR, "Counselor"
    GCO_STAFF = RoleChoices.GCO_STAFF, "GCO Staff"


class StaffAccountInvitation(models.Model):
    """Single-use, hash-only invitation for a provisioned staff account."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="staff_account_invitations",
    )
    role_snapshot = models.CharField(max_length=20, choices=RoleChoices.choices)
    profile_type = models.CharField(max_length=20, choices=StaffInvitationProfileChoices.choices)
    token_reference = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    token_hash = models.CharField(max_length=64, unique=True, editable=False)
    delivery_email_hash = models.CharField(max_length=64, editable=False)
    expires_at = models.DateTimeField()
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="issued_staff_account_invitations",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="revoked_staff_account_invitations",
    )
    revocation_reason = models.CharField(max_length=80, blank=True, default="")
    reissued_from = models.ForeignKey(
        "self", on_delete=models.SET_NULL, null=True, blank=True,
        related_name="reissues",
    )

    class Meta:
        indexes = [
            models.Index(fields=["user", "expires_at"]),
            models.Index(fields=["used_at", "revoked_at"]),
        ]

    def clean(self):
        super().clean()
        if self.role_snapshot not in {RoleChoices.COUNSELOR, RoleChoices.GCO_STAFF}:
            raise ValidationError({"role_snapshot": "Only counselor and GCO Staff invitations are allowed."})
        if self.profile_type != self.role_snapshot:
            raise ValidationError({"profile_type": "Profile type must match the role snapshot."})
        user = self.user if getattr(self, "user_id", None) else None
        if user is not None and (
            user.role != self.role_snapshot or user.is_active or user.is_superuser
        ):
            raise ValidationError("Staff invitations require an inactive, non-legacy matching account.")
        if self.used_at and self.revoked_at:
            raise ValidationError("An invitation cannot be both used and revoked.")

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)
