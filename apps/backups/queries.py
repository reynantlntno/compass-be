"""Actor-aware projection queries for backup and restore operations."""

from apps.common.contracts import PageRequest, PageResult, page_queryset
from apps.backups.projections import (
    backup_artifact_projection,
    backup_job_projection,
    restore_request_projection,
)
from apps.backups.selectors import (
    get_backup_job_detail,
    get_restore_request_detail,
    list_restore_requests,
    list_visible_backup_jobs,
)


def backup_job_page(actor, page: PageRequest) -> PageResult:
    return page_queryset(list_visible_backup_jobs(actor), page, backup_job_projection)


def backup_job_detail(actor, job_id: str) -> dict | None:
    value = get_backup_job_detail(actor, job_id)
    return backup_job_projection(value) if value is not None else None


def backup_artifact_page(actor, job_id: str, page: PageRequest) -> PageResult:
    job = get_backup_job_detail(actor, job_id)
    if job is None:
        return PageResult(items=(), page=page.page, page_size=page.page_size, total=0)
    queryset = job.artifacts.all().order_by("created_at", "pk")
    return page_queryset(queryset, page, backup_artifact_projection)


def restore_request_page(actor, page: PageRequest) -> PageResult:
    return page_queryset(list_restore_requests(actor), page, restore_request_projection)


def restore_request_detail(actor, request_id: str) -> dict | None:
    value = get_restore_request_detail(actor, request_id)
    return restore_request_projection(value) if value is not None else None
