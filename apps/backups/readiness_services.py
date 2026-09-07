"""Read-only backup destination and authorization readiness evidence."""

from __future__ import annotations

import os
from pathlib import Path

from django.conf import settings
from apps.access_control.authority import has_fixed_capability
from apps.access_control.capabilities import Capability
from apps.accounts.models import User
from apps.backups.adapters import BackupStorageAdapter, PostgresDumpAdapter
from apps.security.field_operations import IDENTITY_RE
from apps.system.readiness_services import ReadinessCheck, is_deployment_environment
from apps.common.exceptions import ValidationError
from apps.governance.runtime_config import resolve_runtime_setting


def _identity_user(identity):
    if type(identity) is not str or not IDENTITY_RE.fullmatch(identity):
        return None
    try:
        if identity.isascii() and identity.isdecimal():
            return User.objects.get(pk=int(identity))
        return User.objects.get(email__iexact=identity)
    except (User.DoesNotExist, User.MultipleObjectsReturned, ValueError):
        return None


def _authorization_check(identity) -> ReadinessCheck:
    if identity is None:
        return ReadinessCheck(
            name="backup_authorization",
            status="PENDING",
            required=True,
            reason_code="BACKUP_IDENTITY_NOT_PROVIDED",
            message="Provide --system-identity to verify the IT Admin backup authorization boundary.",
            evidence_type="read_only_query",
        )
    actor = _identity_user(identity)
    authorized = has_fixed_capability(actor, Capability.BACKUPS_VIEW)
    return ReadinessCheck(
        name="backup_authorization",
        status="PASS" if authorized else "FAIL",
        required=True,
        reason_code="BACKUP_AUTHORIZED" if authorized else "BACKUP_AUTHORIZATION_DENIED",
        message=(
            "Read-only identity lookup resolved an active IT Admin for backup readiness."
            if authorized
            else "Backup readiness requires an active IT Admin identity."
        ),
        evidence_type="read_only_query",
    )


def _retention_check() -> ReadinessCheck:
    daily = resolve_runtime_setting(
        "technical.backup_metadata", "BACKUP_RETENTION_DAILY_DAYS"
    )
    weekly = resolve_runtime_setting(
        "technical.backup_metadata", "BACKUP_RETENTION_WEEKLY_WEEKS"
    )
    monthly = resolve_runtime_setting(
        "technical.backup_metadata", "BACKUP_RETENTION_MONTHLY_ENABLED"
    )
    valid = (
        type(daily) is int
        and daily > 0
        and type(weekly) is int
        and weekly > 0
        and type(monthly) is bool
    )
    return ReadinessCheck(
        name="backup_retention_configuration",
        status="PASS" if valid else "FAIL",
        required=True,
        reason_code="BACKUP_RETENTION_OK" if valid else "BACKUP_RETENTION_INVALID",
        message=(
            "Backup retention settings are bounded and declared."
            if valid
            else "Backup retention settings are missing or outside safe bounds."
        ),
        evidence_type="configuration",
    )


def _postgres_client_tools_check() -> ReadinessCheck:
    """Check the locally installed tool pair without contacting PostgreSQL."""
    try:
        PostgresDumpAdapter().preflight_client_tools()
    except ValidationError as exc:
        reason = "postgres_client_tools_unavailable"
        if getattr(exc, "messages", None) and type(exc.messages[0]) is str:
            candidate = exc.messages[0]
            if candidate in {
                "pg_dump_unavailable",
                "pg_restore_unavailable",
                "pg_dump_version_unavailable",
                "pg_restore_version_unavailable",
                "pg_dump_version_incompatible",
                "pg_restore_version_incompatible",
            }:
                reason = candidate
        return ReadinessCheck(
            name="backup_postgres_client_tools",
            status="FAIL",
            required=True,
            reason_code=f"BACKUP_{reason.upper()}",
            message="Required PostgreSQL backup client tools are unavailable or incompatible.",
            evidence_type="local_dependency",
        )
    return ReadinessCheck(
        name="backup_postgres_client_tools",
        status="PASS",
        required=True,
        reason_code="BACKUP_POSTGRES_CLIENT_TOOLS_READY",
        message="Version-compatible pg_dump and pg_restore tools are available.",
        evidence_type="local_dependency",
    )


def _local_destination_check() -> ReadinessCheck:
    root_value = getattr(settings, "BACKUP_LOCAL_DEMO_ROOT", "")
    if not root_value:
        return ReadinessCheck(
            name="backup_destination",
            status="FAIL",
            required=True,
            reason_code="BACKUP_LOCAL_ROOT_MISSING",
            message="Local backup destination root is not configured.",
            evidence_type="read_only_query",
        )
    try:
        root = Path(root_value).resolve()
        valid = root.is_dir() and os.access(root, os.R_OK | os.X_OK)
    except Exception:
        valid = False
    if is_deployment_environment():
        valid = False
        reason_code = "BACKUP_LOCAL_DEMO_DEPLOYMENT_DISALLOWED"
        message = "Local demo backup storage is not an accepted staging/production destination."
    else:
        reason_code = "BACKUP_LOCAL_ROOT_READABLE" if valid else "BACKUP_LOCAL_ROOT_UNAVAILABLE"
        message = (
            "Local backup destination exists and is readable without a write probe."
            if valid
            else "Local backup destination is missing or not readable."
        )
    return ReadinessCheck(
        name="backup_destination",
        status="PASS" if valid else "FAIL",
        required=True,
        reason_code=reason_code,
        message=message,
        evidence_type="read_only_query",
    )


def _s3_configuration_check() -> ReadinessCheck:
    adapter = BackupStorageAdapter()
    reason = adapter.get_unavailability_reason("s3_compatible")
    return ReadinessCheck(
        name="backup_destination_configuration",
        status="PASS" if reason is None else "FAIL",
        required=True,
        reason_code="BACKUP_S3_CONFIGURED" if reason is None else f"BACKUP_{reason.upper()}",
        message=(
            "S3-compatible backup destination configuration is complete."
            if reason is None
            else "S3-compatible backup destination configuration is incomplete or unavailable."
        ),
        evidence_type="configuration",
    )


def _s3_probe_check(*, probe_external: bool) -> ReadinessCheck:
    if not probe_external:
        return ReadinessCheck(
            name="backup_destination_connectivity",
            status="PENDING",
            required=True,
            reason_code="BACKUP_S3_PROBE_NOT_REQUESTED",
            message="S3 destination connectivity was not probed; use --probe-external when authorized.",
            evidence_type="read_only_probe",
        )
    try:
        import boto3
        from botocore.config import Config

        client = boto3.client(
            "s3",
            endpoint_url=getattr(settings, "BACKUP_STORAGE_S3_ENDPOINT_URL", ""),
            aws_access_key_id=getattr(settings, "BACKUP_STORAGE_S3_ACCESS_KEY", ""),
            aws_secret_access_key=getattr(settings, "BACKUP_STORAGE_S3_SECRET_KEY", ""),
            region_name=getattr(settings, "BACKUP_STORAGE_S3_REGION_NAME", "us-east-1"),
            config=Config(
                signature_version="s3v4",
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
                s3={
                    "addressing_style": getattr(settings, "BACKUP_STORAGE_S3_ADDRESSING_STYLE", "path"),
                    "payload_signing_enabled": False,
                },
            ),
            use_ssl=getattr(settings, "BACKUP_STORAGE_S3_USE_SSL", True),
        )
        client.head_bucket(Bucket=getattr(settings, "BACKUP_STORAGE_S3_BUCKET", ""))
    except Exception:
        return ReadinessCheck(
            name="backup_destination_connectivity",
            status="FAIL",
            required=True,
            reason_code="BACKUP_S3_HEAD_BUCKET_FAILED",
            message="S3-compatible backup destination read-only connectivity probe failed.",
            evidence_type="read_only_probe",
        )
    return ReadinessCheck(
        name="backup_destination_connectivity",
        status="PASS",
        required=True,
        reason_code="BACKUP_S3_HEAD_BUCKET_OK",
        message="S3-compatible backup destination responded to a read-only head_bucket probe.",
        evidence_type="read_only_probe",
    )


def _destination_checks(*, probe_external: bool) -> list[ReadinessCheck]:
    backend = str(getattr(settings, "BACKUP_STORAGE_BACKEND", "metadata_only") or "").lower()
    if backend == "metadata_only":
        return [
            ReadinessCheck(
                name="backup_destination_configuration",
                status="FAIL",
                required=True,
                reason_code="BACKUP_METADATA_ONLY_NOT_COMPLETING",
                message="Metadata-only backup mode does not provide an operational archive destination.",
                evidence_type="configuration",
            )
        ]
    if backend == "local_demo":
        return [_local_destination_check()]
    if backend == "s3_compatible":
        return [_s3_configuration_check(), _s3_probe_check(probe_external=probe_external)]
    return [
        ReadinessCheck(
            name="backup_destination_configuration",
            status="FAIL",
            required=True,
            reason_code="BACKUP_STORAGE_TARGET_UNKNOWN",
            message="Backup storage backend is not recognized.",
            evidence_type="configuration",
        )
    ]


def collect_backup_readiness(*, system_identity: str | None, probe_external: bool) -> list[ReadinessCheck]:
    """Collect backup readiness without creating operational metadata."""

    checks = [
        _authorization_check(system_identity),
        _retention_check(),
        _postgres_client_tools_check(),
    ]
    checks.extend(_destination_checks(probe_external=probe_external))

    execution_mode = str(getattr(settings, "BACKUP_RESTORE_EXECUTION_MODE", "") or "").lower()
    mode_ok = execution_mode in {"dry_run_only", "readiness_only"}
    checks.append(
        ReadinessCheck(
            name="backup_restore_execution_mode",
            status="PASS" if mode_ok else "FAIL",
            required=True,
            reason_code="BACKUP_EXECUTION_MODE_DECLARED" if mode_ok else "BACKUP_EXECUTION_MODE_INVALID",
            message=(
                "Backup/restore execution mode is recognized; this command performs no execution."
                if mode_ok
                else "Backup/restore execution mode is missing or unrecognized."
            ),
            evidence_type="configuration",
        )
    )
    checks.append(
        ReadinessCheck(
            name="real_backup_restore_execution",
            status="NOT_CLAIMED",
            required=False,
            reason_code="BACKUP_RESTORE_EXECUTION_NOT_CLAIMED",
            message="No real backup, restore, archive upload, or restore rehearsal was performed.",
            evidence_type="manual_authorization",
        )
    )
    return checks
