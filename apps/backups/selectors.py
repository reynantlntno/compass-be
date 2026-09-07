# Project: COMPASS
# File: apps/backups/selectors.py
# Module: apps.backups
# Purpose: Selector query functions for backup jobs, restore requests, and operations dashboards

from django.db.models import Q, QuerySet
from apps.backups.models import BackupJob, RestoreRequest
from apps.backups.choices import (
    BackupJobTypeChoices,
    BackupStatusChoices,
    RestoreStatusChoices,
)
from apps.backups.policies import (
    can_view_backup_dashboard,
    can_view_backup_artifact_metadata,
    can_view_restore_metadata,
    can_request_restore,
)
from apps.common.exceptions import PermissionDeniedError


def list_visible_backup_jobs(actor) -> QuerySet:
    """Returns a list of all backup jobs for authorized actors (IT Admin only)."""
    if not can_view_backup_dashboard(actor):
        return BackupJob.objects.none()
    return BackupJob.objects.all().prefetch_related("artifacts").order_by("-created_at", "-pk")


def get_backup_job_detail(actor, job_id: str) -> BackupJob | None:
    """Fetch one backup job for an authorized actor, or ``None``."""
    if not can_view_backup_dashboard(actor):
        return None
    return BackupJob.objects.prefetch_related("artifacts").filter(pk=job_id).first()


def get_latest_successful_backup() -> BackupJob:
    """Return the latest recorded real archive, never a metadata-only row."""
    return _real_archive_jobs().filter(
        status__in=[BackupStatusChoices.SUCCEEDED, BackupStatusChoices.VERIFIED]
    ).first()


def get_latest_backup_by_scope(scope: str) -> BackupJob:
    """Returns the latest backup job matching a specific scope/type."""
    return BackupJob.objects.filter(job_type=scope).first()


def get_latest_verified_backup_by_scope(scope: str) -> BackupJob:
    """Return the latest verified archive that actually covers a component.

    A verified ``full`` archive is evidence for each component it contains;
    filtering only by ``job_type`` would incorrectly leave database and media
    coverage uncovered after a successful full backup.
    """
    component_flag = {
        BackupJobTypeChoices.DATABASE: "includes_database",
        BackupJobTypeChoices.MEDIA: "includes_media",
        BackupJobTypeChoices.PROTECTED_FILES: "includes_protected_files",
    }.get(scope)
    queryset = _real_archive_jobs().filter(status=BackupStatusChoices.VERIFIED)
    if component_flag is not None:
        # Historical component-specific rows predate the explicit inclusion
        # flags, so retain their verified evidence.  A full archive must carry
        # the component flag before it can claim the same coverage.
        return queryset.filter(
            Q(job_type=scope)
            | Q(job_type=BackupJobTypeChoices.FULL, **{component_flag: True})
        ).first()
    return queryset.filter(job_type=scope).first()


def _real_archive_jobs() -> QuerySet:
    return (
        BackupJob.objects.filter(
            encrypted_at_rest=True,
            includes_manifest=True,
            artifact_count__gt=0,
            artifacts__isnull=False,
        )
        .exclude(storage_target_type="metadata_only")
        .distinct()
    )


def list_restore_requests(actor) -> QuerySet:
    """Returns a list of all restore requests for authorized actors (IT Admin only)."""
    if not can_view_restore_metadata(actor):
        return RestoreRequest.objects.none()
    return RestoreRequest.objects.all().select_related("target_backup_job").order_by("-created_at", "-pk")


def get_restore_request_detail(actor, request_id: str) -> RestoreRequest | None:
    """Fetch one restore request for an authorized actor, or ``None``."""
    if not can_view_restore_metadata(actor):
        return None
    return RestoreRequest.objects.prefetch_related("checklist_items").filter(pk=request_id).first()


def build_backup_dashboard_dto(actor) -> dict:
    """Build a truthful, non-sensitive backup operations summary.

    Requested, queued, and failed rows are operational history, not recovery
    evidence.  An archive is counted only when it has an encrypted manifest
    and at least one recorded artifact; a verified archive is a stricter
    subset.  This deliberately excludes historical ``metadata_only`` rows.
    """
    if not can_view_restore_metadata(actor):
        raise PermissionDeniedError()

    total_jobs = BackupJob.objects.count()
    queued_or_running_count = BackupJob.objects.filter(
        status__in=[
            BackupStatusChoices.REQUESTED,
            BackupStatusChoices.QUEUED,
            BackupStatusChoices.RUNNING,
        ]
    ).count()
    archive_jobs = _real_archive_jobs().filter(
        status__in=[BackupStatusChoices.SUCCEEDED, BackupStatusChoices.VERIFIED],
    )
    archive_count = archive_jobs.count()
    verified_archive_count = archive_jobs.filter(
        status=BackupStatusChoices.VERIFIED,
    ).count()
    failed_count = BackupJob.objects.filter(status=BackupStatusChoices.FAILED).count()
    latest_job = BackupJob.objects.first()

    return {
        "total_jobs": total_jobs,
        "queued_or_running_count": queued_or_running_count,
        "archive_count": archive_count,
        "verified_archive_count": verified_archive_count,
        "failed_count": failed_count,
        "latest_job": latest_job,
    }


def build_restore_dashboard_dto(actor) -> dict:
    """Builds a summary dictionary of restore request statistics."""
    if not can_view_backup_dashboard(actor):
        raise PermissionDeniedError()

    total_requests = RestoreRequest.objects.count()
    completed_count = RestoreRequest.objects.filter(status=RestoreStatusChoices.RESTORE_COMPLETED).count()
    active_count = RestoreRequest.objects.filter(
        status__in=[
            RestoreStatusChoices.DRY_RUN_STARTED,
            RestoreStatusChoices.RESTORE_READY,
            RestoreStatusChoices.RESTORE_STARTED,
        ]
    ).count()

    return {
        "total_requests": total_requests,
        "completed_count": completed_count,
        "active_count": active_count,
        "latest_request": RestoreRequest.objects.first(),
    }
