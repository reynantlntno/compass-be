# Project: COMPASS
# File: apps/security/models.py
# Module: apps.security
# Purpose: Protected file metadata and encryption key registry models
# Domain boundary and service policy.

import re
import uuid
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone


class ClassificationChoices(models.TextChoices):
    PUBLIC = "PUBLIC", "Public"
    INTERNAL = "INTERNAL", "Internal"
    PROTECTED = "PROTECTED", "Protected"
    CONFIDENTIAL = "CONFIDENTIAL", "Confidential"
    OFFICIAL_RECORD = "OFFICIAL_RECORD", "Official Record"
    SECURITY_SENSITIVE = "SECURITY_SENSITIVE", "Security Sensitive"


class PurposeChoices(models.TextChoices):
    GENERATED_DOCUMENT = "GENERATED_DOCUMENT", "Generated Document"
    COUNSELING_ATTACHMENT = "COUNSELING_ATTACHMENT", "Counseling Attachment"
    ECOUNSELING_RECORDING = "ECOUNSELING_RECORDING", "E-Counseling Recording"
    ECOUNSELING_TRANSCRIPT = "ECOUNSELING_TRANSCRIPT", "E-Counseling Transcript"
    BACKUP_REFERENCE_PLACEHOLDER = "BACKUP_REFERENCE_PLACEHOLDER", "Backup Reference Placeholder"
    OFFICIAL_RECORD_RELEASE = "OFFICIAL_RECORD_RELEASE", "Official Record Release"
    ASSESSMENT_RESULT_FILE = "ASSESSMENT_RESULT_FILE", "Assessment Result File"
    FORM_SOURCE_ATTACHMENT = "FORM_SOURCE_ATTACHMENT", "Form Source Attachment"
    OTHER = "OTHER", "Other"


class FileStatusChoices(models.TextChoices):
    ACTIVE = "ACTIVE", "Active"
    ARCHIVED = "ARCHIVED", "Archived"
    DELETED_MARKER = "DELETED_MARKER", "Deleted Marker"
    QUARANTINED_PLACEHOLDER = "QUARANTINED_PLACEHOLDER", "Quarantined Placeholder"
    SUPERSEDED = "SUPERSEDED", "Superseded"


class KeyPurposeChoices(models.TextChoices):
    FIELD_ENCRYPTION = "FIELD_ENCRYPTION", "Field Encryption"
    FILE_ENVELOPE_PLACEHOLDER = "FILE_ENVELOPE_PLACEHOLDER", "File Envelope Placeholder"
    AUDIT_HASH_REFERENCE_PLACEHOLDER = "AUDIT_HASH_REFERENCE_PLACEHOLDER", "Audit Hash Reference Placeholder"


class KeyStatusChoices(models.TextChoices):
    ACTIVE = "ACTIVE", "Active"
    DECRYPT_ONLY = "DECRYPT_ONLY", "Decrypt Only"
    RETIRED = "RETIRED", "Retired"
    DISABLED = "DISABLED", "Disabled"


class ProtectedFile(models.Model):
    """Metadata record for private stored files. Never served via public MEDIA_URL."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    storage_backend_alias = models.CharField("storage backend alias", max_length=100)
    bucket_name = models.CharField("bucket name", max_length=100)
    object_key = models.CharField("object key", max_length=255, unique=True)
    original_filename_display = models.CharField(
        "original filename display", max_length=255, null=True, blank=True
    )
    content_type = models.CharField("content type", max_length=100)
    file_size_bytes = models.PositiveBigIntegerField("file size bytes")
    checksum_sha256 = models.CharField("checksum sha256", max_length=64)
    classification = models.CharField(
        "classification", max_length=50, choices=ClassificationChoices.choices
    )
    purpose = models.CharField("purpose", max_length=50, choices=PurposeChoices.choices)

    # Generic relationship pointers
    owning_app_label = models.CharField("owning app label", max_length=100)
    owning_model_name = models.CharField("owning model name", max_length=100)
    owning_object_id = models.CharField("owning object id", max_length=255)

    access_policy_key = models.CharField("access policy key", max_length=100)
    status = models.CharField(
        "status", max_length=50, choices=FileStatusChoices.choices, default=FileStatusChoices.ACTIVE
    )

    retention_hold = models.BooleanField("retention hold", default=False)
    encryption_key_version = models.CharField(
        "encryption key version", max_length=100, null=True, blank=True
    )

    # Audit trail
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_protected_files",
    )
    created_at = models.DateTimeField("created at", auto_now_add=True)
    updated_at = models.DateTimeField("updated at", auto_now=True)

    archived_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="archived_protected_files",
    )
    archived_at = models.DateTimeField("archived at", null=True, blank=True)
    deleted_marker_at = models.DateTimeField("deleted marker at", null=True, blank=True)

    class Meta:
        verbose_name = "protected file"
        verbose_name_plural = "protected files"
        indexes = [
            models.Index(fields=["owning_app_label", "owning_model_name", "owning_object_id"]),
            models.Index(fields=["status"]),
            models.Index(fields=["classification"]),
            models.Index(fields=["checksum_sha256"]),
            models.Index(fields=["created_at"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["owning_app_label", "owning_model_name", "owning_object_id"],
                condition=models.Q(purpose=PurposeChoices.ECOUNSELING_RECORDING),
                name="unique_recording_file_per_owner",
            ),
        ]

    def __str__(self):
        return f"{self.id} ({self.purpose})"


class EncryptionKeyVersion(models.Model):
    """Metadata registry for keys used for encryption. Never stores the key material."""
    key_version = models.CharField("key version", max_length=100, unique=True)
    key_purpose = models.CharField(
        "key purpose", max_length=50, choices=KeyPurposeChoices.choices
    )
    status = models.CharField(
        "status", max_length=50, choices=KeyStatusChoices.choices, default=KeyStatusChoices.ACTIVE
    )
    source_alias = models.CharField("source alias", max_length=100)
    secret_reference = models.CharField("secret reference", max_length=255)
    algorithm = models.CharField("algorithm", max_length=50, default="Fernet")

    # Audit trail
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_key_versions",
    )
    created_at = models.DateTimeField("created at", auto_now_add=True)

    activated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="activated_key_versions",
    )
    activated_at = models.DateTimeField("activated at", null=True, blank=True)

    retired_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="retired_key_versions",
    )
    retired_at = models.DateTimeField("retired at", null=True, blank=True)

    not_before = models.DateTimeField("not before", null=True, blank=True)
    not_after = models.DateTimeField("not after", null=True, blank=True)
    notes = models.TextField("notes", blank=True)

    class Meta:
        verbose_name = "encryption key version"
        verbose_name_plural = "encryption key versions"
        constraints = [
            models.UniqueConstraint(
                fields=["key_purpose"],
                condition=models.Q(status="ACTIVE"),
                name="unique_active_key_per_purpose",
            )
        ]

    def clean(self):
        super().clean()
        # Validation is handled by the caller for specific key purposes.
        pass

    def __str__(self):
        purpose = (
            self.key_purpose
            if self.key_purpose in KeyPurposeChoices.values
            else "UNKNOWN"
        )
        status = self.status if self.status in KeyStatusChoices.values else "UNKNOWN"
        return f"Encryption key metadata ({purpose}/{status})"
