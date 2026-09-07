"""Typed persistence for the central policy lifecycle and DPO appointment."""

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q
from django.utils import timezone

from apps.common.models import TimestampedModel
from apps.governance.choices import (
    DPOAppointmentStatus,
    PolicyEffectivenessChoices,
    PolicyLifecycleStatus,
    PolicyTransitionAction,
)


class PolicyRecord(TimestampedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    key = models.CharField(max_length=120, db_index=True)
    schema_version = models.CharField(max_length=32, default="v1")
    target_type = models.CharField(max_length=120, blank=True, default="")
    target_reference = models.CharField(max_length=160, blank=True, default="")
    status = models.CharField(
        max_length=24,
        choices=PolicyLifecycleStatus.choices,
        default=PolicyLifecycleStatus.DRAFT,
        db_index=True,
    )
    effectiveness = models.CharField(
        max_length=16,
        choices=PolicyEffectivenessChoices.choices,
        default=PolicyEffectivenessChoices.EFFECTIVE,
        db_index=True,
    )
    configuration_json = models.JSONField(default=dict, blank=True)
    effective_from = models.DateTimeField(null=True, blank=True)
    effective_until = models.DateTimeField(null=True, blank=True)
    source_reference = models.CharField(max_length=255, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="created_policy_records")
    submitted_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="submitted_policy_records")
    submitted_at = models.DateTimeField(null=True, blank=True)
    approved_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="approved_policy_records")
    approved_at = models.DateTimeField(null=True, blank=True)
    activated_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="activated_policy_records")
    activated_at = models.DateTimeField(null=True, blank=True)
    retired_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="retired_policy_records")
    retired_at = models.DateTimeField(null=True, blank=True)
    rejected_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="rejected_policy_records")
    rejected_at = models.DateTimeField(null=True, blank=True)
    rejection_reason_code = models.CharField(max_length=80, blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        constraints = [
            models.UniqueConstraint(
                fields=["key", "target_type", "target_reference"],
                condition=Q(
                    effectiveness=PolicyEffectivenessChoices.EFFECTIVE,
                    status=PolicyLifecycleStatus.ACTIVE,
                ),
                name="governance_one_active_policy_target",
            ),
        ]
        indexes = [
            models.Index(fields=["key", "status"]),
            models.Index(fields=["key", "target_type", "target_reference", "status"]),
        ]

    def clean(self):
        super().clean()
        if self.effective_from and self.effective_until and self.effective_until < self.effective_from:
            raise ValidationError({"effective_until": "Effective end cannot precede effective start."})
        if self.status == PolicyLifecycleStatus.ACTIVE and not self.activated_at:
            raise ValidationError({"activated_at": "An active policy requires activation evidence."})
        if bool(self.target_type) != bool(self.target_reference):
            raise ValidationError({"target_reference": "Target type and target reference must be supplied together."})
        if not self.schema_version.strip():
            raise ValidationError({"schema_version": "A policy schema version is required."})

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)


class PolicyTransition(TimestampedModel):
    policy = models.ForeignKey(PolicyRecord, on_delete=models.PROTECT, related_name="transitions")
    action = models.CharField(max_length=30, choices=PolicyTransitionAction.choices)
    from_status = models.CharField(max_length=24, blank=True)
    to_status = models.CharField(max_length=24)
    actor_user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    reason_code = models.CharField(max_length=80)
    safe_evidence = models.JSONField(default=dict, blank=True)
    occurred_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-occurred_at", "-pk"]

    def save(self, *args, **kwargs):
        if self.pk:
            raise ValidationError("Policy transitions are append-only.")
        return super().save(*args, **kwargs)


class DPOAppointment(TimestampedModel):
    """Dated institutional DPO appointment; not a role or workflow grant."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    holder = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="dpo_appointments")
    valid_from = models.DateTimeField()
    valid_until = models.DateTimeField(null=True, blank=True)
    appointment_reference = models.CharField(max_length=255)
    contact_email = models.EmailField(max_length=254)
    status = models.CharField(max_length=20, choices=DPOAppointmentStatus.choices, default=DPOAppointmentStatus.ACTIVE, db_index=True)
    appointed_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="issued_dpo_appointments")
    appointed_at = models.DateTimeField(default=timezone.now)
    retired_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="retired_dpo_appointments")
    retired_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["status"],
                condition=Q(status=DPOAppointmentStatus.ACTIVE),
                name="governance_one_active_dpo_appointment",
            ),
        ]
        indexes = [models.Index(fields=["holder", "status", "valid_from", "valid_until"])]

    def clean(self):
        super().clean()
        if self.valid_until and self.valid_until < self.valid_from:
            raise ValidationError({"valid_until": "DPO appointment expiry must be on or after its start."})
        if not self.appointment_reference.strip():
            raise ValidationError({"appointment_reference": "Appointment evidence is required."})
        if self.status == DPOAppointmentStatus.ACTIVE and self.holder_id:
            holder = type(self.holder).objects.filter(pk=self.holder_id).only("is_active", "is_superuser").first()
            if not holder or not holder.is_active or holder.is_superuser:
                raise ValidationError({"holder": "The DPO holder must be active and non-legacy."})

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)
