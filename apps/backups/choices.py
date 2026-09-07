# Project: COMPASS
# File: apps/backups/choices.py
# Module: apps.backups
# Purpose: Choices for backup and restore lifecycle models

from django.db import models


class BackupJobTypeChoices(models.TextChoices):
    DATABASE = "database", "Database"
    MEDIA = "media", "Media"
    PROTECTED_FILES = "protected_files", "Protected Files"
    FULL = "full", "Full"
    CONFIG_SNAPSHOT = "config_snapshot", "Config Snapshot"
    VERIFICATION = "verification", "Verification"


class BackupStatusChoices(models.TextChoices):
    REQUESTED = "requested", "Requested"
    QUEUED = "queued", "Queued"
    RUNNING = "running", "Running"
    SUCCEEDED = "succeeded", "Succeeded"
    FAILED = "failed", "Failed"
    CANCELLED = "cancelled", "Cancelled"
    EXPIRED = "expired", "Expired"
    VERIFIED = "verified", "Verified"


class BackupArtifactTypeChoices(models.TextChoices):
    DATABASE_DUMP = "database_dump", "Database Dump"
    MEDIA_MANIFEST = "media_manifest", "Media Manifest"
    MEDIA_ARCHIVE = "media_archive", "Media Archive"
    PROTECTED_FILE_MANIFEST = "protected_file_manifest", "Protected File Manifest"
    REPORT_MANIFEST = "report_manifest", "Report Manifest"
    CONFIG_MANIFEST = "config_manifest", "Config Manifest"


class EncryptionStatusChoices(models.TextChoices):
    NOT_APPLICABLE = "not_applicable", "Not Applicable"
    PENDING = "pending", "Pending"
    ENCRYPTED = "encrypted", "Encrypted"
    VERIFICATION_FAILED = "verification_failed", "Verification Failed"


class BackupEnvelopeFormatChoices(models.TextChoices):
    """On-disk envelope formats used by backup artifacts.

    ``fernet_v1`` is retained only for historical artifacts.  New backups use
    the standard streaming GPG envelope and must never silently fall back to
    the legacy whole-token format.
    """

    FERNET_V1 = "fernet_v1", "Legacy Fernet v1"
    GPG_SYMMETRIC_V1 = "gpg_symmetric_v1", "GPG symmetric v1"


class RetentionClassChoices(models.TextChoices):
    DAILY = "daily", "Daily"
    WEEKLY = "weekly", "Weekly"
    MONTHLY = "monthly", "Monthly"
    MANUAL_HOLD = "manual_hold", "Manual Hold"
    DEMO = "demo", "Demo"


class RestoreScopeChoices(models.TextChoices):
    DATABASE = "database", "Database"
    MEDIA = "media", "Media"
    PROTECTED_FILES = "protected_files", "Protected Files"
    FULL = "full", "Full"
    METADATA_VALIDATION = "metadata_validation", "Metadata Validation"


class RestoreStatusChoices(models.TextChoices):
    DRAFT = "draft", "Draft"
    REQUESTED = "requested", "Requested"
    AUTHORIZATION_PENDING = "authorization_pending", "Authorization Pending"
    AUTHORIZED = "authorized", "Authorized"
    ARCHIVE_VALIDATED = "archive_validated", "Archive Validated"
    RESTORE_EXECUTED_OFFLINE = "restore_executed_offline", "Restore Executed Offline"
    FLOOR_VERIFIED = "floor_verified", "Floor Verified"
    POSTCONDITIONS_VERIFIED = "postconditions_verified", "Postconditions Verified"
    READY_FOR_SEPARATE_GO_NO_GO = (
        "ready_for_separate_go_no_go",
        "Ready for Separate Go/No-Go",
    )
    DRY_RUN_STARTED = "dry_run_started", "Dry Run Started"
    DRY_RUN_PASSED = "dry_run_passed", "Dry Run Passed"
    DRY_RUN_FAILED = "dry_run_failed", "Dry Run Failed"
    RESTORE_READY = "restore_ready", "Restore Ready"
    RESTORE_STARTED = "restore_started", "Restore Started"
    RESTORE_COMPLETED = "restore_completed", "Restore Completed"
    RESTORE_FAILED = "restore_failed", "Restore Failed"
    CANCELLED = "cancelled", "Cancelled"


class ChecklistStatusChoices(models.TextChoices):
    PENDING = "pending", "Pending"
    PASSED = "passed", "Passed"
    FAILED = "failed", "Failed"
    WARNING = "warning", "Warning"
    SKIPPED = "skipped", "Skipped"


class InstitutionalAuthorizationTypeChoices(models.TextChoices):
    HEAD_GUIDANCE_RECORDED = "head_guidance_recorded", "Head Guidance Recorded"
    INSTITUTIONAL_MEMO = "institutional_memo", "Institutional Memo"
    INCIDENT_RESPONSE = "incident_response", "Incident Response"
    OTHER_SAFE_REFERENCE = "other_safe_reference", "Other Safe Reference"
