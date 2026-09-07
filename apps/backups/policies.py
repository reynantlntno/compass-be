# Project: COMPASS
# File: apps/backups/policies.py
# Module: apps.backups
# Purpose: Access control policies for backup and restore operations
# Notes:
#   - IT Admin only. No Django framework-flag business authorization.
#   - Students, counselors, GCO staff, and Head Guidance are denied technical execution by default.

from apps.access_control.authority import has_fixed_capability
from apps.access_control.capabilities import Capability


def can_view_backup_dashboard(actor) -> bool:
    """IT Admin only can view the backup operations dashboard."""
    return has_fixed_capability(actor, Capability.BACKUPS_VIEW)


def can_request_backup(actor) -> bool:
    """IT Admin only can request/schedule a backup job."""
    return has_fixed_capability(actor, Capability.BACKUPS_OPERATE)


def can_run_backup(actor) -> bool:
    """IT Admin only can execute a backup job."""
    return has_fixed_capability(actor, Capability.BACKUPS_OPERATE)


def can_verify_backup(actor) -> bool:
    """IT Admin only can verify backup artifacts."""
    return has_fixed_capability(actor, Capability.BACKUPS_VIEW)


def can_view_backup_artifact_metadata(actor, artifact) -> bool:
    """IT Admin only can view backup artifact metadata."""
    return has_fixed_capability(actor, Capability.BACKUPS_VIEW)


def can_view_restore_metadata(actor) -> bool:
    """Restore metadata is restricted to the restore-operations capability."""
    return has_fixed_capability(actor, Capability.RESTORES_OPERATE)


def can_request_restore(actor) -> bool:
    """IT Admin only can request a database/media restore."""
    return has_fixed_capability(actor, Capability.RESTORES_OPERATE)


def can_record_restore_authorization(actor) -> bool:
    """IT Admin only can record official authorization for a restore."""
    return has_fixed_capability(actor, Capability.RESTORES_OPERATE)


def can_run_restore_dry_run(actor) -> bool:
    """IT Admin only can run a restore dry-run validation."""
    return has_fixed_capability(actor, Capability.RESTORES_OPERATE)


def can_mark_restore_ready(actor) -> bool:
    """IT Admin only can mark a restore request as ready for execution."""
    return has_fixed_capability(actor, Capability.RESTORES_OPERATE)


def can_record_restore_completion(actor) -> bool:
    """IT Admin only can record the completion of a restore."""
    return has_fixed_capability(actor, Capability.RESTORES_OPERATE)


def can_cancel_restore(actor) -> bool:
    """IT Admin only can cancel a restore request."""
    return has_fixed_capability(actor, Capability.RESTORES_OPERATE)
