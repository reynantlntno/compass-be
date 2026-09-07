"""Framework-neutral commands for backup and restore operations.

The HTTP and worker adapters construct these immutable values explicitly. No
ORM instance, uploaded file, arbitrary metadata mapping, or provider payload
crosses this boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Protocol

from apps.backups.choices import (
    BackupArtifactTypeChoices,
    BackupEnvelopeFormatChoices,
    BackupJobTypeChoices,
    EncryptionStatusChoices,
    InstitutionalAuthorizationTypeChoices,
    RestoreScopeChoices,
)
from apps.common.exceptions import ValidationError
from apps.common.form_values import (
    normalize_command_id,
    normalize_command_text,
    normalize_expected_updated_at,
)


class CommandInput(Protocol):
    """Marker protocol for immutable, validated backup commands."""


def _id(value, field: str, *, required: bool = True) -> str | None:
    return normalize_command_id(value, field, required=required)


def _text(value, field: str, *, maximum: int = 255, required: bool = False) -> str:
    return normalize_command_text(value, field, maximum=maximum, required=required)


@dataclass(frozen=True, slots=True)
class BackupRequestCommand:
    scope: str
    reason: str = "scheduled_backup"

    def __post_init__(self) -> None:
        try:
            scope = BackupJobTypeChoices(self.scope).value
        except (TypeError, ValueError) as exc:
            raise ValidationError(field_errors={"scope": ["Unsupported backup scope."]}) from exc
        object.__setattr__(self, "scope", scope)
        object.__setattr__(self, "reason", _text(self.reason, "reason", maximum=100, required=True))


@dataclass(frozen=True, slots=True)
class BackupLifecycleCommand:
    expected_updated_at: str | None = None
    reason: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "expected_updated_at", normalize_expected_updated_at(self.expected_updated_at))
        object.__setattr__(self, "reason", _text(self.reason, "reason", maximum=100))


@dataclass(frozen=True, slots=True)
class BackupArtifactReceipt:
    """Safe worker-produced artifact receipt; never accepted from public API."""

    artifact_id: str
    artifact_type: str
    storage_reference: str
    checksum_sha256: str
    size_bytes: int
    encryption_status: str
    key_version_reference: str = ""
    envelope_format: str = BackupEnvelopeFormatChoices.GPG_SYMMETRIC_V1

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifact_id", _id(self.artifact_id, "artifact_id"))
        try:
            artifact_type = BackupArtifactTypeChoices(self.artifact_type).value
        except (TypeError, ValueError) as exc:
            raise ValidationError(field_errors={"artifact_type": ["Unsupported artifact type."]}) from exc
        object.__setattr__(self, "artifact_type", artifact_type)
        object.__setattr__(self, "storage_reference", _text(self.storage_reference, "storage_reference", maximum=255, required=True))
        object.__setattr__(self, "checksum_sha256", _text(self.checksum_sha256, "checksum_sha256", maximum=64, required=True).lower())
        if isinstance(self.size_bytes, bool) or not isinstance(self.size_bytes, int) or self.size_bytes < 0:
            raise ValidationError(field_errors={"size_bytes": ["Artifact size is invalid."]})
        try:
            encryption_status = EncryptionStatusChoices(self.encryption_status).value
        except (TypeError, ValueError) as exc:
            raise ValidationError(field_errors={"encryption_status": ["Unsupported encryption status."]}) from exc
        object.__setattr__(self, "encryption_status", encryption_status)
        object.__setattr__(self, "key_version_reference", _text(self.key_version_reference, "key_version_reference", maximum=100))
        try:
            envelope_format = BackupEnvelopeFormatChoices(self.envelope_format).value
        except (TypeError, ValueError) as exc:
            raise ValidationError(field_errors={"envelope_format": ["Unsupported envelope format."]}) from exc
        object.__setattr__(self, "envelope_format", envelope_format)


@dataclass(frozen=True, slots=True)
class BackupCompletionReceipt:
    """Worker-only completion evidence for one backup job."""

    manifest_hash: str
    artifact_count: int
    total_size_bytes: int

    def __post_init__(self) -> None:
        manifest_hash = _text(self.manifest_hash, "manifest_hash", maximum=64, required=True).lower()
        if not re.fullmatch(r"[0-9a-f]{64}", manifest_hash):
            raise ValidationError(field_errors={"manifest_hash": ["Manifest hash is invalid."]})
        object.__setattr__(self, "manifest_hash", manifest_hash)
        for field_name in ("artifact_count", "total_size_bytes"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValidationError(field_errors={field_name: ["Completion total is invalid."]})


@dataclass(frozen=True, slots=True)
class RestoreRequestCommand:
    backup_job_id: str
    restore_scope: str
    reason: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "backup_job_id", _id(self.backup_job_id, "backup_job_id"))
        try:
            scope = RestoreScopeChoices(self.restore_scope).value
        except (TypeError, ValueError) as exc:
            raise ValidationError(field_errors={"restore_scope": ["Unsupported restore scope."]}) from exc
        object.__setattr__(self, "restore_scope", scope)
        object.__setattr__(self, "reason", _text(self.reason, "reason", maximum=100, required=True))


@dataclass(frozen=True, slots=True)
class RestoreAuthorizationCommand:
    authorization_type: str
    authorization_reference: str
    expected_updated_at: str | None = None

    def __post_init__(self) -> None:
        try:
            authorization_type = InstitutionalAuthorizationTypeChoices(self.authorization_type).value
        except (TypeError, ValueError) as exc:
            raise ValidationError(field_errors={"authorization_type": ["Unsupported authorization type."]}) from exc
        object.__setattr__(self, "authorization_type", authorization_type)
        object.__setattr__(self, "authorization_reference", _text(self.authorization_reference, "authorization_reference", maximum=255, required=True))
        object.__setattr__(self, "expected_updated_at", normalize_expected_updated_at(self.expected_updated_at))


@dataclass(frozen=True, slots=True)
class RestoreDryRunCommand:
    expected_updated_at: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "expected_updated_at", normalize_expected_updated_at(self.expected_updated_at))


@dataclass(frozen=True, slots=True)
class RestoreTransitionCommand:
    reason: str
    confirmation_phrase: str = ""
    expected_updated_at: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason", _text(self.reason, "reason", maximum=100, required=True))
        object.__setattr__(self, "confirmation_phrase", _text(self.confirmation_phrase, "confirmation_phrase", maximum=100))
        object.__setattr__(self, "expected_updated_at", normalize_expected_updated_at(self.expected_updated_at))
