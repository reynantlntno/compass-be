# Project: COMPASS
# File: apps/backups/services.py
# Module: apps.backups
# Purpose: Service workflows for backup archive creation, restore dry-run/readiness, health check, and audit integrations

import shutil
import tempfile
import uuid
from pathlib import Path
import re
from contextlib import contextmanager

from django.conf import settings
from django.db import DatabaseError, transaction
from django.db import connection
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.audit.services import audit_log
from apps.governance.runtime_config import resolve_runtime_setting
from apps.common.exceptions import (
    DependencyFailureError,
    InternalError,
    NotFoundError,
    PermissionDeniedError as PermissionDenied,
    StaleStateError,
    ValidationError,
)
from apps.backups.commands import (
    BackupArtifactReceipt,
    BackupCompletionReceipt,
    BackupLifecycleCommand,
    BackupRequestCommand,
    RestoreAuthorizationCommand,
    RestoreDryRunCommand,
    RestoreRequestCommand,
    RestoreTransitionCommand,
)
from apps.backups.choices import (
    BackupStatusChoices,
    BackupJobTypeChoices,
    BackupArtifactTypeChoices,
    EncryptionStatusChoices,
    RetentionClassChoices,
    RestoreScopeChoices,
    RestoreStatusChoices,
    ChecklistStatusChoices,
    InstitutionalAuthorizationTypeChoices,
)
from apps.backups.models import (
    BackupJob,
    BackupArtifact,
    BackupManifest,
    RestoreRequest,
    RestoreChecklistItem,
)
from apps.backups.policies import (
    can_request_backup,
    can_run_backup,
    can_verify_backup,
    can_request_restore,
    can_record_restore_authorization,
    can_run_restore_dry_run,
    can_mark_restore_ready,
    can_record_restore_completion,
    can_cancel_restore,
)
from apps.backups.adapters import (
    BackupStorageAdapter,
    BackupArchiveBuilder,
    BackupArchiveEncryptionAdapter,
    PostgresDumpAdapter,
    RestoreDryRunAdapter,
    canonical_backup_storage_target,
)
from apps.backups.validation import (
    clean_authorization_reference,
    clean_reason_code,
    clean_safe_metadata,
    clean_storage_reference,
    validate_checksum,
    canonical_manifest_bytes,
    validate_manifest_payload,
    validate_size,
    validate_strict_reason_code,
)


# A session-level PostgreSQL lock makes the supervised worker singleton-safe
# even if a deployment system accidentally starts a second replica.  SQLite is
# intentionally permitted for focused host tests; staging and production use
# PostgreSQL, where this lock is authoritative for the duration of archive I/O.
BACKUP_WORKER_ADVISORY_LOCK_KEY = 0x434F4D50415353  # "COMPASS", within int64.


@contextmanager
def _backup_worker_lease():
    """Yield whether this process holds the singleton backup-worker lease."""
    if connection.vendor != "postgresql":
        yield True
        return

    acquired = False
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_try_advisory_lock(%s)", [BACKUP_WORKER_ADVISORY_LOCK_KEY])
        row = cursor.fetchone()
        acquired = bool(row and row[0])
    try:
        yield acquired
    finally:
        if acquired:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_unlock(%s)", [BACKUP_WORKER_ADVISORY_LOCK_KEY])


RESTORE_CONFIRMATION_PHRASES = {
    "mark_restore_ready": "MARK RESTORE READY",
    "mark_restore_started": "RECORD RESTORE START",
    "record_restore_completion": "RECORD RESTORE COMPLETE",
    "cancel_restore": "CANCEL RESTORE",
}


def validate_restore_transition_confirmation(action_key: str, confirmation_phrase: str, reason_code: str) -> str:
    """Validate high-risk restore transition confirmation and return a safe reason code."""
    expected_phrase = RESTORE_CONFIRMATION_PHRASES[action_key]
    if (confirmation_phrase or "").strip() != expected_phrase:
        raise ValidationError("Restore transition confirmation is required.")
    return validate_strict_reason_code(reason_code)
# ---------------------------------------------------------------------------
# Backup Services
# ---------------------------------------------------------------------------

def validate_backup_scope(scope: str) -> bool:
    """Validates if the requested backup scope is supported."""
    return scope in BackupJobTypeChoices.values


def _configured_backup_storage_target() -> str:
    target = canonical_backup_storage_target(
        getattr(settings, "BACKUP_STORAGE_BACKEND", "metadata_only")
    )
    if target not in {"local_demo", "s3_compatible"}:
        # A request cannot be queued until a real archive destination is
        # configured.  This is an operational dependency outage, not a
        # malformed operator input, so the API must surface it as 503.
        raise DependencyFailureError()
    # Do not make a deployment-side local-demo choice into a queued job that
    # could later be mistaken for recovery evidence.  Other availability
    # failures remain job failures so operators retain a safe audit trail and
    # remediation reason after a previously valid destination becomes absent.
    if (
        target == "local_demo"
        and BackupStorageAdapter().get_unavailability_reason(target)
        == "local_demo_deployment_disallowed"
    ):
        raise DependencyFailureError()
    return target


@transaction.atomic
def _request_backup(actor, scope: str, request_metadata: dict = None) -> BackupJob:
    """Requests a new backup metadata record."""
    if not can_request_backup(actor):
        raise PermissionDenied("You do not have permission to request backups.")

    if not validate_backup_scope(scope):
        raise ValidationError(f"Invalid backup scope: {scope}")

    clean_metadata = clean_safe_metadata(request_metadata or {})
    configured_target = _configured_backup_storage_target()
    requested_target = clean_metadata.pop("storage_target", None)
    if requested_target is not None and (
        canonical_backup_storage_target(requested_target) != configured_target
    ):
        raise ValidationError("backup_storage_target_not_configured")

    job = BackupJob.objects.create(
        job_type=scope,
        status=BackupStatusChoices.REQUESTED,
        requested_by=actor,
        requested_at=timezone.now(),
        environment=getattr(settings, "COMPASS_ENVIRONMENT", "development"),
        includes_database=(scope in [BackupJobTypeChoices.DATABASE, BackupJobTypeChoices.FULL]),
        includes_media=(scope in [BackupJobTypeChoices.MEDIA, BackupJobTypeChoices.FULL]),
        includes_protected_files=(scope in [BackupJobTypeChoices.PROTECTED_FILES, BackupJobTypeChoices.FULL]),
        storage_target_type=configured_target,
        retention_class=RetentionClassChoices.DEMO,
        metadata_json=clean_metadata,
    )
    job.full_clean()
    job.save(update_fields=["updated_at"])

    audit_log(
        action_type="BACKUP_REQUEST",
        event_category="WORKFLOW",
        target_model="backups.BackupJob",
        target_object_id=str(job.id),
        actor_user=actor,
        metadata={"scope": scope},
    )
    return job


@transaction.atomic
def _record_backup_artifact(actor, job: BackupJob, receipt: BackupArtifactReceipt) -> BackupArtifact:
    """Record an archive artifact using opaque storage references."""
    if not can_run_backup(actor):
        raise PermissionDenied("You do not have permission to record backup artifacts.")

    artifact_type = receipt.artifact_type
    if artifact_type not in BackupArtifactTypeChoices.values:
        raise ValidationError("Invalid backup artifact type.")

    artifact = BackupArtifact(
        id=receipt.artifact_id or uuid.uuid4(),
        backup_job=job,
        artifact_type=artifact_type,
        storage_reference=clean_storage_reference(receipt.storage_reference),
        checksum_sha256=validate_checksum(receipt.checksum_sha256),
        size_bytes=validate_size(receipt.size_bytes),
        encryption_status=receipt.encryption_status or EncryptionStatusChoices.ENCRYPTED,
        key_version_reference=receipt.key_version_reference or None,
        envelope_format=receipt.envelope_format,
    )
    artifact.full_clean()
    artifact.save()

    audit_log(
        action_type="BACKUP_ARTIFACT_RECORDED",
        event_category="WORKFLOW",
        target_model="backups.BackupArtifact",
        target_object_id=str(artifact.id),
        actor_user=actor,
        metadata={
            "job_id": str(job.id),
            "artifact_type": artifact.artifact_type,
            "storage_reference_type": "opaque_internal",
        },
    )
    return artifact


def _record_backup_manifest(actor, job: BackupJob, manifest_payload: dict, manifest_hash: str) -> BackupManifest:
    if not can_run_backup(actor):
        raise PermissionDenied("You do not have permission to build manifests.")
    if hasattr(job, "manifest"):
        job.manifest.delete()

    validated_payload = validate_manifest_payload(manifest_payload)
    manifest = BackupManifest.objects.create(
        backup_job=job,
        manifest_schema_version=str(validated_payload.get("schema_version", "2.0")),
        manifest_hash_sha256=validate_checksum(manifest_hash),
        payload_json=validated_payload,
    )
    manifest.full_clean()
    manifest.save()
    return manifest


@transaction.atomic
def _mark_backup_queued(actor, job: BackupJob) -> BackupJob:
    """Transition backup job to queued status."""
    if not can_run_backup(actor):
        raise PermissionDenied("You do not have permission to run backups.")

    if job.status != BackupStatusChoices.REQUESTED:
        raise ValidationError("Only requested jobs can be queued.")

    job.status = BackupStatusChoices.QUEUED
    job.queued_at = timezone.now()
    job.save()

    audit_log(
        action_type="STATUS_TRANSITION",
        event_category="WORKFLOW",
        target_model="backups.BackupJob",
        target_object_id=str(job.id),
        actor_user=actor,
        metadata={"status": job.status},
    )
    return job


@transaction.atomic
def _mark_backup_running(actor, job: BackupJob) -> BackupJob:
    """Transition backup job to running status."""
    if not can_run_backup(actor):
        raise PermissionDenied("You do not have permission to run backups.")

    if job.status != BackupStatusChoices.QUEUED:
        raise ValidationError("Only queued jobs can start running.")

    job.status = BackupStatusChoices.RUNNING
    job.started_by = actor
    job.started_at = timezone.now()
    job.save()

    audit_log(
        action_type="STATUS_TRANSITION",
        event_category="WORKFLOW",
        target_model="backups.BackupJob",
        target_object_id=str(job.id),
        actor_user=actor,
        metadata={"status": job.status},
    )
    return job


def claim_next_queued_backup() -> tuple[BackupJob, object | None] | None:
    """Claim one queued job for the supervised worker.

    The HTTP request only creates and queues work.  A single supervised worker
    claims the job under a row lock and performs archive work outside that
    transaction so database locks never span ``pg_dump`` or storage I/O.
    """
    with transaction.atomic():
        if BackupJob.objects.select_for_update().filter(
            status=BackupStatusChoices.RUNNING
        ).exists():
            return None
        job = (
            BackupJob.objects.select_for_update()
            .filter(status=BackupStatusChoices.QUEUED)
            .order_by("queued_at", "created_at")
            .first()
        )
        if job is None:
            return None

        actor = job.requested_by
        if (
            actor is None
            or not getattr(actor, "is_active", False)
            or not can_run_backup(actor)
        ):
            job.status = BackupStatusChoices.FAILED
            job.failed_at = timezone.now()
            job.safe_failure_reason_code = "backup_operator_unavailable"
            job.save(
                update_fields=[
                    "status",
                    "failed_at",
                    "safe_failure_reason_code",
                    "updated_at",
                ]
            )
            audit_log(
                action_type="BACKUP_WORKER_REJECTED",
                event_category="SECURITY",
                severity="WARNING",
                target_model="backups.BackupJob",
                target_object_id=str(job.id),
                actor_user=None,
                metadata={"reason_code": "backup_operator_unavailable"},
            )
            return job, None

        _mark_backup_running(actor, job)
        return job, actor


def run_next_queued_backup() -> BackupJob | None:
    """Run one job only while this process holds the singleton worker lease."""
    with _backup_worker_lease() as has_lease:
        if not has_lease:
            return None
        claimed = claim_next_queued_backup()
        if claimed is None:
            return None
        job, actor = claimed
        if actor is None:
            return job
        return execute_backup_job(actor, job)


@transaction.atomic
def build_backup_manifest(actor, job: BackupJob) -> BackupManifest:
    """Reject direct manifest-only completion; real backups must call execute_backup_job()."""
    if not can_run_backup(actor):
        raise PermissionDenied("You do not have permission to build manifests.")
    raise ValidationError("backup_execution_required")


def execute_backup_job(actor, job: BackupJob) -> BackupJob:
    """Create a real encrypted backup archive and record it as an opaque artifact."""
    if not can_run_backup(actor):
        raise PermissionDenied("You do not have permission to run backups.")
    if job.status not in {BackupStatusChoices.QUEUED, BackupStatusChoices.RUNNING}:
        raise ValidationError("backup_job_must_be_queued")

    storage_adapter = BackupStorageAdapter()
    unavailable = storage_adapter.get_unavailability_reason(job.storage_target_type)
    if unavailable:
        _mark_backup_failed(actor, job, unavailable)
        return job

    try:
        if job.includes_database:
            PostgresDumpAdapter().preflight_client_tools()
        if audit_log(
            action_type="BACKUP_VALIDATION_STARTED",
            event_category="SECURITY",
            target_model="backups.BackupJob",
            target_object_id="aggregate",
            actor_user=actor,
            metadata={"result_code": "validation_started"},
        ) is None:
            raise ValidationError("backup_audit_failed")
        # Capacity validation placeholder
        pass
        job.refresh_from_db()
        if job.status == BackupStatusChoices.QUEUED:
            if BackupJob.objects.filter(status=BackupStatusChoices.RUNNING).exclude(
                pk=job.pk
            ).exists():
                raise ValidationError("PJOP.OPSE_BACKUP_CONCURRENCY_BLOCKED")
            _mark_backup_running(actor, job)
        job.refresh_from_db()

        artifact_id = uuid.uuid4()
        temp_parent = Path(getattr(settings, "BACKUP_LOCAL_DEMO_ROOT", "backups")).resolve() / "_staging"
        temp_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if temp_parent.is_symlink():
            raise ValidationError("backup_workspace_invalid")
        temp_parent.chmod(0o700)
        # Workspace capacity validation placeholder
        pass
        staging_dir = Path(tempfile.mkdtemp(prefix=f"{job.id}-", dir=temp_parent))
        staging_dir.chmod(0o700)
        cleanup_failed = False
        operation_error = None
        try:
            archive_result = BackupArchiveBuilder().build_archive(
                job=job,
                actor=actor,
                staging_dir=staging_dir,
            )
            encrypted_result = BackupArchiveEncryptionAdapter().encrypt_archive(
                archive_result.archive_path,
                staging_dir / "backup.tar.gpg",
            )
            stored_result = storage_adapter.store_archive(
                job=job,
                artifact_id=artifact_id,
                encrypted_path=encrypted_result.encrypted_path,
                target_type=job.storage_target_type,
                envelope_format=encrypted_result.envelope_format,
            )
        except Exception as exc:
            operation_error = exc
        finally:
            try:
                shutil.rmtree(staging_dir)
            except Exception:
                cleanup_failed = True
        if cleanup_failed or staging_dir.exists():
            audit_log(
                action_type="BACKUP_CLEANUP_FAILED",
                event_category="SECURITY",
                target_model="backups.BackupJob",
                target_object_id="aggregate",
                actor_user=actor,
                metadata={"result_code": "cleanup_failed"},
            )
            raise ValidationError("backup_plaintext_cleanup_failed")
        if operation_error is not None:
            raise operation_error
        if audit_log(
            action_type="BACKUP_VALIDATION_COMPLETED",
            event_category="SECURITY",
            target_model="backups.BackupJob",
            target_object_id="aggregate",
            actor_user=actor,
            metadata={"result_code": "validation_completed"},
        ) is None:
            raise ValidationError("backup_audit_failed")

        artifact = _record_backup_artifact(
            actor,
            job,
            BackupArtifactReceipt(
                artifact_id=str(artifact_id),
                artifact_type=BackupArtifactTypeChoices.DATABASE_DUMP
                if job.includes_database
                else BackupArtifactTypeChoices.MEDIA_ARCHIVE,
                storage_reference=stored_result.storage_reference,
                checksum_sha256=stored_result.checksum_sha256,
                size_bytes=stored_result.size_bytes,
                encryption_status=EncryptionStatusChoices.ENCRYPTED,
                key_version_reference=encrypted_result.key_version_reference,
                envelope_format=encrypted_result.envelope_format,
            ),
        )
        final_manifest_hash = archive_result.manifest_hash_sha256
        _record_backup_manifest(
            actor,
            job,
            archive_result.manifest_payload,
            final_manifest_hash,
        )
        _mark_backup_succeeded(
            actor,
            job,
            BackupCompletionReceipt(
                manifest_hash=final_manifest_hash,
                artifact_count=1,
                total_size_bytes=artifact.size_bytes,
            ),
        )
    except ValidationError as exc:
        audit_log(
            action_type="BACKUP_VALIDATION_FAILED",
            event_category="SECURITY",
            target_model="backups.BackupJob",
            target_object_id="aggregate",
            actor_user=actor,
            metadata={"result_code": "validation_failed"},
        )
        job.refresh_from_db()
        if job.status != BackupStatusChoices.FAILED:
            reason = "backup_archive_execution_failed"
            if getattr(exc, "messages", None):
                candidate = exc.messages[0]
                if type(candidate) is str and re.fullmatch(r"[a-z][a-z0-9_]{0,99}", candidate):
                    reason = candidate
            _mark_backup_failed(actor, job, reason)
        job.refresh_from_db()
        return job
    except PermissionDenied:
        raise
    except Exception as exc:
        _mark_backup_failed(actor, job, "backup_archive_execution_failed")
        raise InternalError() from exc

    job.refresh_from_db()
    return job


@transaction.atomic
def _mark_backup_succeeded(actor, job: BackupJob, receipt: BackupCompletionReceipt) -> BackupJob:
    """Transition backup job to succeeded status."""
    if not can_run_backup(actor):
        raise PermissionDenied("You do not have permission to complete backups.")

    if job.status != BackupStatusChoices.RUNNING:
        raise ValidationError("Only running backup jobs can succeed.")

    job.status = BackupStatusChoices.SUCCEEDED
    job.completed_by = actor
    job.completed_at = timezone.now()
    job.includes_manifest = True
    job.encrypted_at_rest = True
    job.manifest_hash_sha256 = validate_checksum(receipt.manifest_hash)
    job.artifact_count = receipt.artifact_count
    job.total_size_bytes = receipt.total_size_bytes
    job.save()

    audit_log(
        action_type="BACKUP_COMPLETED",
        event_category="WORKFLOW",
        target_model="backups.BackupJob",
        target_object_id=str(job.id),
        actor_user=actor,
        metadata={"status": job.status, "artifact_count": job.artifact_count},
    )
    return job


@transaction.atomic
def _mark_backup_failed(actor, job: BackupJob, safe_reason_code: str) -> BackupJob:
    """Transition backup job to failed status with safe reason code."""
    if not can_run_backup(actor):
        raise PermissionDenied("You do not have permission to fail backups.")

    job.status = BackupStatusChoices.FAILED
    job.failed_at = timezone.now()
    job.safe_failure_reason_code = clean_reason_code(safe_reason_code)
    job.save()

    audit_log(
        action_type="STATUS_TRANSITION",
        event_category="WORKFLOW",
        target_model="backups.BackupJob",
        target_object_id=str(job.id),
        actor_user=actor,
        metadata={"status": job.status, "reason_code": job.safe_failure_reason_code},
    )
    return job


@transaction.atomic
def _verify_backup_artifacts(actor, job: BackupJob) -> BackupJob:
    """Verifies backup archive artifact checksums and storage availability."""
    if not can_verify_backup(actor):
        raise PermissionDenied("You do not have permission to verify backups.")

    if job.status != BackupStatusChoices.SUCCEEDED:
        raise ValidationError("Only succeeded backups can be verified.")

    if not job.artifacts.exists():
        raise ValidationError("Backup has no recorded archive artifacts.")

    all_artifacts = job.artifacts.all()
    storage_adapter = BackupStorageAdapter()
    for art in all_artifacts:
        validate_checksum(art.checksum_sha256)
        validate_size(art.size_bytes)
        if art.encryption_status != EncryptionStatusChoices.ENCRYPTED:
            job.status = BackupStatusChoices.FAILED
            job.safe_failure_reason_code = "encryption_verification_failed"
            job.save()
            audit_log(
                action_type="BACKUP_VERIFICATION_FAILED",
                event_category="SECURITY",
                severity="WARNING",
                target_model="backups.BackupJob",
                target_object_id=str(job.id),
                actor_user=actor,
                metadata={"reason_code": job.safe_failure_reason_code},
            )
            return job
        if not storage_adapter.verify_archive(job=job, artifact=art):
            job.status = BackupStatusChoices.FAILED
            job.safe_failure_reason_code = "archive_verification_failed"
            job.save()
            audit_log(
                action_type="BACKUP_VERIFICATION_FAILED",
                event_category="SECURITY",
                severity="WARNING",
                target_model="backups.BackupJob",
                target_object_id=str(job.id),
                actor_user=actor,
                metadata={"reason_code": job.safe_failure_reason_code},
            )
            return job

    job.status = BackupStatusChoices.VERIFIED
    job.verified_at = timezone.now()
    job.save()

    audit_log(
        action_type="BACKUP_VERIFIED",
        event_category="WORKFLOW",
        target_model="backups.BackupJob",
        target_object_id=str(job.id),
        actor_user=actor,
        metadata={"status": job.status},
    )
    return job


@transaction.atomic
def _cancel_backup(actor, job: BackupJob, safe_reason_code: str) -> BackupJob:
    """Cancels a requested or queued backup."""
    if not can_run_backup(actor):
        raise PermissionDenied("You do not have permission to cancel backups.")

    if job.status not in [BackupStatusChoices.REQUESTED, BackupStatusChoices.QUEUED, BackupStatusChoices.RUNNING]:
        raise ValidationError("Only running, queued or requested backups can be cancelled.")

    job.status = BackupStatusChoices.CANCELLED
    job.cancelled_at = timezone.now()
    job.safe_failure_reason_code = clean_reason_code(safe_reason_code)
    job.save()

    audit_log(
        action_type="BACKUP_FAILED",
        event_category="WORKFLOW",
        target_model="backups.BackupJob",
        target_object_id=str(job.id),
        actor_user=actor,
        metadata={"status": job.status, "reason_code": job.safe_failure_reason_code},
    )
    return job

# ---------------------------------------------------------------------------
# Restore Services
# ---------------------------------------------------------------------------


@transaction.atomic
def _request_restore(actor, target_backup_job: BackupJob, restore_scope: str, reason_code: str) -> RestoreRequest:
    """Requests a restore operation."""
    if not can_request_restore(actor):
        raise PermissionDenied("You do not have permission to request a restore.")

    if target_backup_job.status not in [BackupStatusChoices.SUCCEEDED, BackupStatusChoices.VERIFIED]:
        raise ValidationError("Can only request restore from successful or verified backups.")

    if restore_scope not in RestoreScopeChoices.values:
        raise ValidationError(f"Invalid restore scope: {restore_scope}")

    req = RestoreRequest.objects.create(
        requested_by=actor,
        target_backup_job=target_backup_job,
        restore_scope=restore_scope,
        status=RestoreStatusChoices.REQUESTED,
        safe_reason_code=clean_reason_code(reason_code),
        institutional_authorization_type=InstitutionalAuthorizationTypeChoices.OTHER_SAFE_REFERENCE,
        institutional_authorization_reference="pending_evidence",
    )

    audit_log(
        action_type="RESTORE_REQUEST",
        event_category="WORKFLOW",
        target_model="backups.RestoreRequest",
        target_object_id=str(req.id),
        actor_user=actor,
        metadata={"scope": restore_scope},
    )
    return req


@transaction.atomic
def _record_restore_authorization(actor, restore_request: RestoreRequest, authorization_metadata: dict) -> RestoreRequest:
    """Records evidence of institutional authorization for the restore request."""
    if not can_record_restore_authorization(actor):
        raise PermissionDenied("You do not have permission to record restore authorization.")

    auth_type = authorization_metadata.get("type")
    auth_ref = authorization_metadata.get("reference")

    if auth_type not in InstitutionalAuthorizationTypeChoices.values:
        raise ValidationError(f"Invalid institutional authorization type: {auth_type}")

    restore_request.institutional_authorization_type = auth_type
    restore_request.institutional_authorization_reference = clean_authorization_reference(auth_ref)
    restore_request.authorization_recorded_by = actor
    restore_request.authorization_recorded_at = timezone.now()

    if restore_request.status == RestoreStatusChoices.REQUESTED:
        restore_request.status = RestoreStatusChoices.AUTHORIZED

    restore_request.save()

    audit_log(
        action_type="RESTORE_AUTHORIZATION_RECORDED",
        event_category="WORKFLOW",
        target_model="backups.RestoreRequest",
        target_object_id=str(restore_request.id),
        actor_user=actor,
        metadata={"status": restore_request.status, "auth_type": auth_type},
    )
    return restore_request


@transaction.atomic
def _run_restore_dry_run(actor, restore_request: RestoreRequest) -> RestoreRequest:
    """Executes the restore dry-run checklists and records outcomes."""
    if not can_run_restore_dry_run(actor):
        raise PermissionDenied("You do not have permission to run restore dry-runs.")

    if restore_request.status not in [RestoreStatusChoices.REQUESTED, RestoreStatusChoices.AUTHORIZED]:
        raise ValidationError("Dry-runs can only be started from requested or authorized restores.")

    restore_request.status = RestoreStatusChoices.DRY_RUN_STARTED
    restore_request.save()

    # Clear prior checklist items
    restore_request.checklist_items.all().delete()

    checklist_results = RestoreDryRunAdapter().execute_dry_run(restore_request)
    all_passed = True

    for item in checklist_results:
        RestoreChecklistItem.objects.create(
            restore_request=restore_request,
            step_key=item["step_key"],
            status=item["status"],
            safe_message_code=item["safe_message_code"],
            recorded_by=actor,
            recorded_at=timezone.now(),
        )
        if item["status"] == ChecklistStatusChoices.FAILED:
            all_passed = False

    if all_passed:
        restore_request.status = RestoreStatusChoices.ARCHIVE_VALIDATED
        restore_request.dry_run_result_code = "passed"
    else:
        restore_request.status = RestoreStatusChoices.DRY_RUN_FAILED
        restore_request.dry_run_result_code = "failed"

    restore_request.save()

    audit_log(
        action_type="RESTORE_DRY_RUN",
        event_category="WORKFLOW",
        target_model="backups.RestoreRequest",
        target_object_id=str(restore_request.id),
        actor_user=actor,
        metadata={"status": restore_request.status, "dry_run_result": restore_request.dry_run_result_code},
    )
    return restore_request


@transaction.atomic
def _mark_restore_ready(actor, restore_request: RestoreRequest, confirmation_phrase: str = "", reason_code: str = "") -> RestoreRequest:
    """Historical entry point cannot bypass the mandatory OPS-E lifecycle."""
    if not can_mark_restore_ready(actor):
        raise PermissionDenied("You do not have permission to mark restores as ready.")

    raise ValidationError("restore_validation_required")


@transaction.atomic
def _mark_restore_failed(actor, restore_request: RestoreRequest, safe_reason_code: str) -> RestoreRequest:
    """Transition restore request to failed status."""
    if not can_record_restore_completion(actor):  # Operator role check
        raise PermissionDenied("You do not have permission to mark restore failure.")

    restore_request.status = RestoreStatusChoices.RESTORE_FAILED
    restore_request.failed_at = timezone.now()
    restore_request.metadata_json["safe_failure_reason_code"] = clean_reason_code(safe_reason_code)
    restore_request.save()

    audit_log(
        action_type="STATUS_TRANSITION",
        event_category="WORKFLOW",
        target_model="backups.RestoreRequest",
        target_object_id=str(restore_request.id),
        actor_user=actor,
        metadata={"status": restore_request.status, "reason_code": restore_request.metadata_json["safe_failure_reason_code"]},
    )
    return restore_request


@transaction.atomic
def _cancel_restore(
    actor,
    restore_request: RestoreRequest,
    safe_reason_code: str,
    confirmation_phrase: str = "",
) -> RestoreRequest:
    """Cancels a restore request."""
    if not can_cancel_restore(actor):
        raise PermissionDenied("You do not have permission to cancel restores.")

    if restore_request.status in [RestoreStatusChoices.RESTORE_COMPLETED, RestoreStatusChoices.RESTORE_FAILED, RestoreStatusChoices.CANCELLED]:
        raise ValidationError("Cannot cancel a completed, failed or already cancelled restore request.")

    safe_reason_code = validate_restore_transition_confirmation(
        "cancel_restore",
        confirmation_phrase,
        safe_reason_code,
    )

    restore_request.status = RestoreStatusChoices.CANCELLED
    restore_request.cancelled_at = timezone.now()
    restore_request.metadata_json["safe_cancellation_reason_code"] = safe_reason_code
    restore_request.full_clean()
    restore_request.save()

    audit_log(
        action_type="STATUS_TRANSITION",
        event_category="WORKFLOW",
        target_model="backups.RestoreRequest",
        target_object_id=str(restore_request.id),
        actor_user=actor,
        metadata={"status": restore_request.status, "reason_code": restore_request.metadata_json["safe_cancellation_reason_code"]},
    )
    return restore_request

# ---------------------------------------------------------------------------
# Latest Backup Health Service
# ---------------------------------------------------------------------------

def build_latest_backup_health_status() -> dict:
    """Builds a safe, read-only summary status of the latest backups.

    This service performs no side effects (no backup runs, uploads, writes).
    """
    from apps.backups.selectors import (
        get_latest_successful_backup,
        get_latest_verified_backup_by_scope,
    )

    latest_success = get_latest_successful_backup()
    latest_failed = BackupJob.objects.filter(status=BackupStatusChoices.FAILED).first()

    # Calculate coverage
    db_backup = get_latest_verified_backup_by_scope(BackupJobTypeChoices.DATABASE)
    media_backup = get_latest_verified_backup_by_scope(BackupJobTypeChoices.MEDIA)

    age_seconds = None
    if latest_success and latest_success.completed_at:
        age_seconds = (timezone.now() - latest_success.completed_at).total_seconds()

    status_summary = {
        "latest_successful_backup_age_seconds": age_seconds,
        "latest_failed_backup_reason_code": latest_failed.safe_failure_reason_code if latest_failed else None,
        "database_backup_coverage": "covered" if db_backup else "uncovered",
        "media_backup_coverage": "covered" if media_backup else "uncovered",
        "verification_status": "verified" if latest_success and latest_success.status == BackupStatusChoices.VERIFIED else "unverified",
        "retention_warning": False,
    }

    # Optional configurable retention class warning
    retention_days = resolve_runtime_setting(
        "technical.backup_metadata",
        "BACKUP_RETENTION_DAILY_DAYS",
    )
    if age_seconds and age_seconds > (retention_days * 86400):
        status_summary["retention_warning"] = True

    return status_summary


# ---------------------------------------------------------------------------
# Stable-ID API command adapters
# ---------------------------------------------------------------------------

def _assert_expected_updated_at(instance, expected_updated_at: str | None) -> None:
    if not expected_updated_at:
        return
    expected = parse_datetime(expected_updated_at)
    if expected is None or instance.updated_at != expected:
        raise StaleStateError()


def _locked_backup_job(job_id: str) -> BackupJob:
    try:
        return BackupJob.objects.select_for_update().prefetch_related("artifacts").get(pk=job_id)
    except BackupJob.DoesNotExist as exc:
        raise NotFoundError() from exc


def _locked_restore_request(request_id: str) -> RestoreRequest:
    try:
        return RestoreRequest.objects.select_for_update().prefetch_related("checklist_items").get(pk=request_id)
    except RestoreRequest.DoesNotExist as exc:
        raise NotFoundError() from exc


@transaction.atomic
def request_backup_command(actor, command: BackupRequestCommand) -> BackupJob:
    if not can_request_backup(actor):
        raise PermissionDenied()
    return _request_backup(actor, command.scope, {"reason": command.reason})


@transaction.atomic
def queue_backup_by_id(actor, job_id: str, command: BackupLifecycleCommand) -> BackupJob:
    if not can_run_backup(actor):
        raise PermissionDenied()
    job = _locked_backup_job(job_id)
    _assert_expected_updated_at(job, command.expected_updated_at)
    return _mark_backup_queued(actor, job)


@transaction.atomic
def verify_backup_by_id(actor, job_id: str, command: BackupLifecycleCommand) -> BackupJob:
    if not can_verify_backup(actor):
        raise PermissionDenied()
    job = _locked_backup_job(job_id)
    _assert_expected_updated_at(job, command.expected_updated_at)
    return _verify_backup_artifacts(actor, job)


@transaction.atomic
def cancel_backup_by_id(actor, job_id: str, command: BackupLifecycleCommand) -> BackupJob:
    if not can_run_backup(actor):
        raise PermissionDenied()
    job = _locked_backup_job(job_id)
    _assert_expected_updated_at(job, command.expected_updated_at)
    return _cancel_backup(actor, job, command.reason or "operator_cancelled")


@transaction.atomic
def request_restore_command(actor, command: RestoreRequestCommand) -> RestoreRequest:
    if not can_request_restore(actor):
        raise PermissionDenied()
    try:
        job = BackupJob.objects.select_for_update().get(pk=command.backup_job_id)
    except BackupJob.DoesNotExist as exc:
        raise NotFoundError() from exc
    return _request_restore(actor, job, command.restore_scope, command.reason)


@transaction.atomic
def authorize_restore_by_id(actor, request_id: str, command: RestoreAuthorizationCommand) -> RestoreRequest:
    if not can_record_restore_authorization(actor):
        raise PermissionDenied()
    restore_request = _locked_restore_request(request_id)
    _assert_expected_updated_at(restore_request, command.expected_updated_at)
    return _record_restore_authorization(
        actor,
        restore_request,
        {"type": command.authorization_type, "reference": command.authorization_reference},
    )


@transaction.atomic
def dry_run_restore_by_id(actor, request_id: str, command: RestoreDryRunCommand) -> RestoreRequest:
    if not can_run_restore_dry_run(actor):
        raise PermissionDenied()
    restore_request = _locked_restore_request(request_id)
    _assert_expected_updated_at(restore_request, command.expected_updated_at)
    return _run_restore_dry_run(actor, restore_request)


@transaction.atomic
def cancel_restore_by_id(actor, request_id: str, command: RestoreTransitionCommand) -> RestoreRequest:
    if not can_cancel_restore(actor):
        raise PermissionDenied()
    restore_request = _locked_restore_request(request_id)
    _assert_expected_updated_at(restore_request, command.expected_updated_at)
    return _cancel_restore(
        actor,
        restore_request,
        command.reason,
        command.confirmation_phrase,
    )
