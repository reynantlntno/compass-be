"""Canonical access-control models.

``CounselorCoverage`` is the durable baseline scope for counselors.
``WorkflowAuthorityGrant`` is the only optional business-authority record.
Historical assignment names remain only in historical migrations.
"""

from datetime import timedelta

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from apps.accounts.models import RoleChoices
from apps.common.models import TimestampedModel
from apps.access_control.choices import (
    GrantReasonCode,
    GrantSourceType,
    GrantStatus,
    RevocationReasonCode,
    ScopeMode,
)
from apps.access_control.capabilities import AuthoritySource, get_capability_spec


class CounselorCoverage(TimestampedModel):
    counselor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="coverages")
    campus = models.CharField(max_length=100, null=True, blank=True)
    college = models.CharField(max_length=100, null=True, blank=True)
    department = models.CharField(max_length=100, null=True, blank=True)
    program = models.CharField(max_length=100, null=True, blank=True)
    is_primary = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)
    starts_at = models.DateField()
    ends_at = models.DateField(null=True, blank=True)
    assigned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="assigned_coverages",
    )

    class Meta:
        verbose_name = "counselor coverage"
        verbose_name_plural = "counselor coverages"

    def clean(self):
        super().clean()
        if self.counselor_id and self.counselor.role != RoleChoices.COUNSELOR:
            raise ValidationError({"counselor": "Only COUNSELOR accounts may have coverage."})
        if self.starts_at and self.ends_at and self.starts_at > self.ends_at:
            raise ValidationError({"ends_at": "Coverage end must be on or after its start."})

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)


class WorkflowAuthorityGrant(TimestampedModel):
    """One dated, auditable optional workflow authority for one account."""

    grantee = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="authority_grants")
    capability = models.CharField(max_length=120, db_index=True)
    scope_mode = models.CharField(max_length=30, choices=ScopeMode.choices)
    campus = models.CharField(max_length=100, null=True, blank=True)
    college = models.CharField(max_length=100, null=True, blank=True)
    department = models.CharField(max_length=100, null=True, blank=True)
    program = models.CharField(max_length=100, null=True, blank=True)
    valid_from = models.DateField()
    valid_until = models.DateField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=GrantStatus.choices, default=GrantStatus.ACTIVE, db_index=True)
    granted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, blank=True,
        related_name="authority_grants_created",
    )
    grant_reason_code = models.CharField(max_length=40, choices=GrantReasonCode.choices)
    grant_reason_note = models.CharField(max_length=500, blank=True)
    source_type = models.CharField(max_length=20, choices=GrantSourceType.choices, default=GrantSourceType.MANUAL)
    source_reference = models.CharField(max_length=120, blank=True)
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, blank=True,
        related_name="authority_grants_revoked",
    )
    revoked_at = models.DateTimeField(null=True, blank=True)
    revocation_reason_code = models.CharField(max_length=40, choices=RevocationReasonCode.choices, blank=True)

    class Meta:
        verbose_name = "workflow authority grant"
        verbose_name_plural = "workflow authority grants"
        indexes = [
            models.Index(fields=("grantee", "capability", "status")),
            models.Index(fields=("valid_from", "valid_until")),
        ]

    IMMUTABLE_FIELDS = (
        "grantee_id", "capability", "scope_mode", "campus", "college", "department", "program",
        "valid_from", "valid_until", "granted_by_id", "grant_reason_code",
        "grant_reason_note", "source_type", "source_reference",
    )

    def clean(self):
        super().clean()
        if self.grantee_id:
            if self.grantee.role not in {RoleChoices.COUNSELOR, RoleChoices.GCO_STAFF}:
                raise ValidationError({"grantee": "Only active counselor or GCO Staff accounts may receive grants."})
            if not self.grantee.is_active or self.grantee.is_superuser:
                raise ValidationError({"grantee": "Inactive and legacy-superuser accounts cannot receive grants."})
        spec = get_capability_spec(self.capability)
        if spec is None or AuthoritySource.ACCOUNT_GRANT not in spec.authority_sources:
            raise ValidationError({"capability": "Capability is unknown or not delegable."})
        if self.grantee_id and self.grantee.role not in spec.grant_eligible_roles:
            raise ValidationError({"capability": "Capability is not eligible for this grantee role."})
        if self.scope_mode not in {mode.value for mode in spec.grant_scope_modes}:
            raise ValidationError({"scope_mode": "Scope mode is not allowed for this capability."})
        if self.valid_until and self.valid_until < self.valid_from:
            raise ValidationError({"valid_until": "Grant end must be on or after its start."})
        if spec.expiry_required and not self.valid_until:
            raise ValidationError({"valid_until": "This capability requires an expiry."})
        if self.valid_until and self.valid_from and self.valid_until > self.valid_from + timedelta(days=366):
            raise ValidationError({"valid_until": "Grant validity may not exceed 366 days."})
        if self.scope_mode == ScopeMode.OFFICE_WIDE and self.grantee.role != RoleChoices.GCO_STAFF:
            raise ValidationError({"scope_mode": "Counselor grants cannot be office-wide."})
        if self.scope_mode == ScopeMode.OFFICE_WIDE and not spec.office_wide_grant_allowed:
            raise ValidationError({"scope_mode": "This capability is not approved for office-wide GCO authority."})
        if self.grantee.role == RoleChoices.GCO_STAFF and self.scope_mode not in {
            ScopeMode.EXPLICIT_ORGANIZATION,
            ScopeMode.ASSIGNED_RECORDS,
            ScopeMode.OFFICE_WIDE,
        }:
            raise ValidationError({"scope_mode": "GCO Staff grants must use organization, assigned-record, or approved office-wide scope."})
        if self.scope_mode == ScopeMode.OFFICE_WIDE and not self.valid_until:
            raise ValidationError({"valid_until": "Office-wide grants require an expiry."})
        if self.scope_mode == ScopeMode.OFFICE_WIDE and any(
            getattr(self, field) for field in ("campus", "college", "department", "program")
        ):
            raise ValidationError({"scope_mode": "Office-wide grants cannot carry organization fields."})
        organization_values = tuple(
            getattr(self, field) for field in ("campus", "college", "department", "program")
        )
        if self.scope_mode == ScopeMode.EXPLICIT_ORGANIZATION and not any(organization_values):
            raise ValidationError({"scope_mode": "Organization grants require at least one target scope value."})
        if self.scope_mode == ScopeMode.ASSIGNED_RECORDS and any(organization_values):
            raise ValidationError({"scope_mode": "Assigned-record grants cannot carry organization scope fields."})

    def save(self, *args, **kwargs):
        if self.pk and not self._state.adding:
            previous = type(self).objects.get(pk=self.pk)
            changed = [field for field in self.IMMUTABLE_FIELDS if getattr(previous, field) != getattr(self, field)]
            if changed:
                raise ValidationError("Grant semantics are immutable; revoke and create a new grant.")
        self.full_clean()
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Authority grants are immutable records and cannot be deleted.")
