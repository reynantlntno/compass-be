# Project: COMPASS
# File: apps/backups/models.py
# Module: apps.backups
# Purpose: Django models for backup and restore metadata foundation

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from apps.backups.choices import (
    BackupJobTypeChoices,
    BackupStatusChoices,
    BackupArtifactTypeChoices,
    EncryptionStatusChoices,
    RetentionClassChoices,
    RestoreScopeChoices,
    RestoreStatusChoices,
    BackupEnvelopeFormatChoices,
    ChecklistStatusChoices,
    InstitutionalAuthorizationTypeChoices,
)
from apps.backups.validation import (
    clean_safe_metadata,
    clean_storage_reference,
    validate_manifest_payload,
    validate_no_key_material,
)


class BackupJob(models.Model):
    """Metadata-only log of a backup operation."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    job_type = models.CharField(
        max_length=50,
        choices=BackupJobTypeChoices.choices,
        default=BackupJobTypeChoices.FULL,
    )
    status = models.CharField(
        max_length=50,
        choices=BackupStatusChoices.choices,
        default=BackupStatusChoices.REQUESTED,
    )
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="requested_backups",
    )
    started_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="started_backups",
    )
    completed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="completed_backups",
    )
    requested_at = models.DateTimeField()
    queued_at = models.DateTimeField(null=True, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    failed_at = models.DateTimeField(null=True, blank=True)
    cancelled_at = models.DateTimeField(null=True, blank=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    safe_failure_reason_code = models.CharField(
        max_length=100,
        null=True,
        blank=True,
    )
    environment = models.CharField(max_length=100)
    includes_database = models.BooleanField(default=False)
    includes_media = models.BooleanField(default=False)
    includes_protected_files = models.BooleanField(default=False)
    includes_manifest = models.BooleanField(default=False)
    includes_key_material = models.BooleanField(default=False)
    storage_target_type = models.CharField(
        max_length=50,
        default="metadata_only",
    )
    manifest_hash_sha256 = models.CharField(
        max_length=64,
        null=True,
        blank=True,
    )
    artifact_count = models.IntegerField(default=0)
    total_size_bytes = models.BigIntegerField(default=0)
    encrypted_at_rest = models.BooleanField(default=False)
    retention_class = models.CharField(
        max_length=50,
        choices=RetentionClassChoices.choices,
        default=RetentionClassChoices.DEMO,
    )
    expires_at = models.DateTimeField(null=True, blank=True)
    metadata_json = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Backup Job"
        verbose_name_plural = "Backup Jobs"

    def __str__(self):
        return f"Backup {self.id} ({self.job_type} - {self.status})"

    def clean(self):
        validate_no_key_material(self.includes_key_material)
        self.metadata_json = clean_safe_metadata(self.metadata_json or {})


class BackupArtifact(models.Model):
    """Metadata-only log of a specific artifact file associated with a backup job."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    backup_job = models.ForeignKey(
        BackupJob,
        on_delete=models.CASCADE,
        related_name="artifacts",
    )
    artifact_type = models.CharField(
        max_length=50,
        choices=BackupArtifactTypeChoices.choices,
    )
    storage_reference = models.CharField(max_length=255)
    checksum_sha256 = models.CharField(max_length=64)
    size_bytes = models.BigIntegerField()
    encryption_status = models.CharField(
        max_length=50,
        choices=EncryptionStatusChoices.choices,
        default=EncryptionStatusChoices.PENDING,
    )
    key_version_reference = models.CharField(
        max_length=100,
        null=True,
        blank=True,
    )
    envelope_format = models.CharField(
        max_length=40,
        choices=BackupEnvelopeFormatChoices.choices,
        default=BackupEnvelopeFormatChoices.FERNET_V1,
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]
        verbose_name = "Backup Artifact"
        verbose_name_plural = "Backup Artifacts"

    def __str__(self):
        return f"Artifact {self.id} for Job {self.backup_job_id}"

    def clean(self):
        self.storage_reference = clean_storage_reference(self.storage_reference)


class BackupManifest(models.Model):
    """One-to-one detailed safe manifest associated with a completed backup job."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    backup_job = models.OneToOneField(
        BackupJob,
        on_delete=models.CASCADE,
        related_name="manifest",
    )
    manifest_schema_version = models.CharField(max_length=20)
    manifest_hash_sha256 = models.CharField(max_length=64)
    payload_json = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Backup Manifest"
        verbose_name_plural = "Backup Manifests"

    def __str__(self):
        return f"Manifest for Job {self.backup_job_id}"

    def clean(self):
        self.payload_json = validate_manifest_payload(self.payload_json or {})


class RestoreRequest(models.Model):
    """Log of a requested restore operation with institutional authorization evidence."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="requested_restores",
    )
    technical_operator = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="operated_restores",
    )
    authorization_recorded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="authorized_restores",
    )
    authorization_recorded_at = models.DateTimeField(null=True, blank=True)
    institutional_authorization_type = models.CharField(
        max_length=50,
        choices=InstitutionalAuthorizationTypeChoices.choices,
    )
    institutional_authorization_reference = models.CharField(max_length=255)
    target_backup_job = models.ForeignKey(
        BackupJob,
        on_delete=models.PROTECT,
        related_name="restore_requests",
    )
    restore_scope = models.CharField(
        max_length=50,
        choices=RestoreScopeChoices.choices,
        default=RestoreScopeChoices.FULL,
    )
    status = models.CharField(
        max_length=50,
        choices=RestoreStatusChoices.choices,
        default=RestoreStatusChoices.DRAFT,
    )
    safe_reason_code = models.CharField(max_length=100)
    dry_run_result_code = models.CharField(
        max_length=100,
        null=True,
        blank=True,
    )
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    failed_at = models.DateTimeField(null=True, blank=True)
    cancelled_at = models.DateTimeField(null=True, blank=True)
    metadata_json = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Restore Request"
        verbose_name_plural = "Restore Requests"

    def __str__(self):
        return f"Restore {self.id} -> Job {self.target_backup_job_id} ({self.status})"

    def clean(self):
        self.metadata_json = clean_safe_metadata(self.metadata_json or {})


class RestoreChecklistItem(models.Model):
    """Step-by-step checklist validation logs for a restore dry-run or process."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    restore_request = models.ForeignKey(
        RestoreRequest,
        on_delete=models.CASCADE,
        related_name="checklist_items",
    )
    step_key = models.CharField(max_length=100)
    status = models.CharField(
        max_length=50,
        choices=ChecklistStatusChoices.choices,
        default=ChecklistStatusChoices.PENDING,
    )
    safe_message_code = models.CharField(
        max_length=255,
        null=True,
        blank=True,
    )
    recorded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="recorded_checklist_items",
    )
    recorded_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["step_key"]
        verbose_name = "Restore Checklist Item"
        verbose_name_plural = "Restore Checklist Items"

    def __str__(self):
        return f"Step {self.step_key} ({self.status}) for Restore {self.restore_request_id}"
