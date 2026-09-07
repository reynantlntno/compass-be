"""Fixed safe JSON projections for backup and restore metadata."""

import re


_SAFE_CODE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}$")
_STORAGE_CLASSES = {
    "local_demo": "local",
    "s3_compatible": "object_storage",
    "metadata_only": "metadata_only",
}



def _safe_code(value, *, fallback: str = "unknown") -> str:
    candidate = str(value or "").strip()
    return candidate[:100] if _SAFE_CODE.fullmatch(candidate) else fallback


def _timestamp(value):
    return value.isoformat() if value is not None else None


def backup_artifact_projection(artifact) -> dict:
    if artifact is None:
        return {}
    return {
        "id": str(artifact.pk),
        "backup_job_id": str(artifact.backup_job_id),
        "artifact_type": _safe_code(artifact.artifact_type),
        "size_bytes": int(artifact.size_bytes or 0),
        "encryption_status": _safe_code(artifact.encryption_status),
        "created_at": _timestamp(artifact.created_at),
    }
def backup_job_projection(job) -> dict:
    if job is None:
        return {}
    return {
        "id": str(job.pk),
        "scope": _safe_code(job.job_type),
        "status": _safe_code(job.status),
        "environment": _safe_code(job.environment),
        "includes_database": bool(job.includes_database),
        "includes_media": bool(job.includes_media),
        "includes_protected_files": bool(job.includes_protected_files),
        "includes_manifest": bool(job.includes_manifest),
        "encrypted_at_rest": bool(job.encrypted_at_rest),
        "storage_target_type": _STORAGE_CLASSES.get(job.storage_target_type, "other"),
        "retention_class": _safe_code(job.retention_class),
        "artifact_count": int(job.artifact_count or 0),
        "total_size_bytes": int(job.total_size_bytes or 0),
        "safe_failure_reason_code": _safe_code(job.safe_failure_reason_code, fallback="") if job.safe_failure_reason_code else None,
        "requested_at": _timestamp(job.requested_at),
        "queued_at": _timestamp(job.queued_at),
        "started_at": _timestamp(job.started_at),
        "completed_at": _timestamp(job.completed_at),
        "failed_at": _timestamp(job.failed_at),
        "cancelled_at": _timestamp(job.cancelled_at),
        "verified_at": _timestamp(job.verified_at),
        "expires_at": _timestamp(job.expires_at),
        "resource_version": _timestamp(getattr(job, "updated_at", None)),
    }


def restore_checklist_projection(item) -> dict:
    return {
        "id": str(item.pk),
        "step_key": _safe_code(item.step_key),
        "status": _safe_code(item.status),
        "safe_message_code": _safe_code(item.safe_message_code, fallback="") if item.safe_message_code else None,
        "recorded_at": _timestamp(item.recorded_at),
    }


def restore_request_projection(request) -> dict:
    if request is None:
        return {}
    return {
        "id": str(request.pk),
        "target_backup_job_id": str(request.target_backup_job_id),
        "restore_scope": _safe_code(request.restore_scope),
        "status": _safe_code(request.status),
        "safe_reason_code": _safe_code(request.safe_reason_code),
        "dry_run_result_code": _safe_code(request.dry_run_result_code, fallback="") if request.dry_run_result_code else None,
        "institutional_authorization_type": _safe_code(request.institutional_authorization_type),
        "authorization_recorded_at": _timestamp(request.authorization_recorded_at),
        "started_at": _timestamp(request.started_at),
        "completed_at": _timestamp(request.completed_at),
        "failed_at": _timestamp(request.failed_at),
        "cancelled_at": _timestamp(request.cancelled_at),
        "created_at": _timestamp(request.created_at),
        "updated_at": _timestamp(request.updated_at),
        "checklist": [
            restore_checklist_projection(item)
            for item in getattr(request, "checklist_items", []).all()
        ] if hasattr(getattr(request, "checklist_items", None), "all") else [],
    }


def backup_dashboard_projection(summary: dict) -> dict:
    latest = summary.get("latest_job")
    return {
        "total_jobs": int(summary.get("total_jobs", 0)),
        "queued_or_running_count": int(summary.get("queued_or_running_count", 0)),
        "archive_count": int(summary.get("archive_count", 0)),
        "verified_archive_count": int(summary.get("verified_archive_count", 0)),
        "failed_count": int(summary.get("failed_count", 0)),
        "latest_job": backup_job_projection(latest) if latest is not None else None,
    }
def restore_dashboard_projection(summary: dict) -> dict:
    latest = summary.get("latest_request")
    return {
        "total_requests": int(summary.get("total_requests", 0)),
        "completed_count": int(summary.get("completed_count", 0)),
        "active_count": int(summary.get("active_count", 0)),
        "latest_request": restore_request_projection(latest) if latest is not None else None,
    }

