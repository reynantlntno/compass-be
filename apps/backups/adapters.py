# Project: COMPASS
# File: apps/backups/adapters.py
# Module: apps.backups
# Purpose: Adapter boundaries for real backup archives, pg_dump, storage, encryption, and restore dry-runs

import importlib.util
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import timezone as datetime_timezone
from pathlib import Path
from urllib.parse import urlparse

from cryptography.fernet import Fernet
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils import timezone

from apps.backups.choices import (
    BackupEnvelopeFormatChoices,
    ChecklistStatusChoices,
)
from apps.backups.constants import POSTGRES_CLIENT_MIN_MAJOR
from apps.security.models import (
    EncryptionKeyVersion,
    FileStatusChoices,
    KeyPurposeChoices,
    KeyStatusChoices,
    ProtectedFile,
)
from apps.security.key_sources import load_fernet_for_metadata, load_key_material
from apps.security.storage_adapters import get_storage_adapter
from apps.backups.validation import (
    canonical_manifest_bytes,
    parse_canonical_manifest,
    validate_archive_member_name,
    validate_manifest_payload,
)


POSTGRES_CLIENT_VERSION_RE = re.compile(r"\b(?:pg_dump|pg_restore)\s+\(PostgreSQL\)\s+(\d+)")
GPG_EXECUTABLE = "gpg"
GPG_ENVELOPE_FORMAT = BackupEnvelopeFormatChoices.GPG_SYMMETRIC_V1
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
# Code-owned ceilings remain importable for tests and offline tooling.  The
# deployment settings may only narrow these values; they must never disable
# the bounded recovery contract.
ARCHIVE_MAX_BYTES = 4 * 1024 * 1024 * 1024
LEGACY_FERNET_MAX_BYTES = 64 * 1024 * 1024


def _archive_max_bytes() -> int:
    value = getattr(settings, "BACKUP_ARCHIVE_MAX_BYTES", ARCHIVE_MAX_BYTES)
    if type(value) is not int or value <= 0:
        raise ValidationError("backup_archive_capacity_invalid")
    return value


def _legacy_fernet_max_bytes() -> int:
    value = getattr(settings, "BACKUP_LEGACY_FERNET_MAX_BYTES", LEGACY_FERNET_MAX_BYTES)
    if type(value) is not int or value <= 0:
        raise ValidationError("backup_legacy_fernet_limit_invalid")
    return value


def _tar_member_capacity(size: int) -> int:
    """Return the bounded tar contribution for one regular file."""
    if type(size) is not int or size < 0:
        raise ValidationError("archive_member_size_invalid")
    return 512 + ((size + 511) // 512) * 512


def canonical_backup_storage_target(value: str) -> str:
    """Return the normalized, canonical target spelling used by adapters."""

    return str(value or "").strip().lower()


def _artifact_envelope_format(artifact) -> str:
    return getattr(artifact, "envelope_format", BackupEnvelopeFormatChoices.FERNET_V1)


def _sha256_file(path: Path, *, maximum_bytes=None) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            total += len(chunk)
            if maximum_bytes is not None and total > maximum_bytes:
                raise ValidationError("file_limit_exceeded")
            digest.update(chunk)
    return digest.hexdigest()


def _json_bytes(payload: dict) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _read_bounded(path: Path, maximum_bytes: int) -> bytes:
    """Read only legacy compatibility tokens under a hard size ceiling."""
    size = path.stat().st_size
    if type(maximum_bytes) is not int or maximum_bytes < 0 or size < 0 or size > maximum_bytes:
        raise ValidationError("file_limit_exceeded")
    with path.open("rb") as handle:
        content = handle.read(maximum_bytes + 1)
        if len(content) != size or handle.read(1):
            raise ValidationError("file_limit_exceeded")
    return content


def _write_exclusive(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600)


def _copy_stream_to_file(stream, destination: Path, *, expected_size=None, expected_checksum=None) -> tuple[int, str]:
    """Copy a binary stream to a private file while hashing bounded chunks."""
    if destination.exists() or destination.is_symlink():
        raise ValidationError("backup_storage_destination_invalid")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(destination.parent, 0o700)
    partial = destination.with_name(f".{destination.name}.partial")
    if partial.exists() or partial.is_symlink():
        raise ValidationError("backup_storage_destination_invalid")
    digest = hashlib.sha256()
    total = 0
    descriptor = None
    try:
        descriptor = os.open(
            partial,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                if type(chunk) is not bytes:
                    raise ValidationError("backup_storage_read_invalid")
                total += len(chunk)
                if expected_size is not None and total > expected_size:
                    raise ValidationError("backup_archive_size_mismatch")
                digest.update(chunk)
                handle.write(chunk)
            handle.flush()
            os.fsync(handle.fileno())
        os.close(descriptor)
        descriptor = None
        checksum = digest.hexdigest()
        if expected_size is not None and total != expected_size:
            raise ValidationError("backup_archive_size_mismatch")
        if expected_checksum is not None and checksum != expected_checksum:
            raise ValidationError("backup_archive_checksum_mismatch")
        os.replace(partial, destination)
        os.chmod(destination, 0o600)
        return total, checksum
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        raise
    finally:
        partial.unlink(missing_ok=True)


@dataclass(frozen=True)
class ArchiveBuildResult:
    archive_path: Path
    manifest_payload: dict
    manifest_hash_sha256: str
    archive_hash_sha256: str
    archive_size_bytes: int


@dataclass(frozen=True)
class ArchiveEncryptionResult:
    encrypted_path: Path
    checksum_sha256: str
    size_bytes: int
    key_version_reference: str
    envelope_format: str = GPG_ENVELOPE_FORMAT


@dataclass(frozen=True)
class StoredArchiveResult:
    storage_reference: str
    checksum_sha256: str
    size_bytes: int
    storage_target_type: str


class PostgresDumpAdapter:
    """PostgreSQL dump adapter that keeps secrets out of command strings."""

    def _resolve_client_tool(self, tool_name: str) -> tuple[str, int]:
        """Locate and version-check the client binary without exposing output."""
        executable = shutil.which(tool_name)
        if not executable:
            raise ValidationError(f"{tool_name}_unavailable")
        try:
            completed = subprocess.run(
                [executable, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
                shell=False,
                text=True,
            )
        except OSError as exc:
            raise ValidationError(f"{tool_name}_version_unavailable") from exc
        output = completed.stdout if type(completed.stdout) is str else ""
        match = POSTGRES_CLIENT_VERSION_RE.search(output)
        if completed.returncode != 0 or match is None:
            raise ValidationError(f"{tool_name}_version_unavailable")
        major = int(match.group(1))
        required_major = POSTGRES_CLIENT_MIN_MAJOR
        if required_major < 1 or major < required_major:
            raise ValidationError(f"{tool_name}_version_incompatible")
        return executable, major

    def preflight_client_tools(self) -> dict:
        """Verify both required PostgreSQL tools before archive work starts."""
        _, dump_major = self._resolve_client_tool("pg_dump")
        _, restore_major = self._resolve_client_tool("pg_restore")
        return {
            "pg_dump_major": dump_major,
            "pg_restore_major": restore_major,
            "minimum_major": POSTGRES_CLIENT_MIN_MAJOR,
        }

    def build_command_plan(self, job_id: str, scope: str, destination_path: Path | None = None) -> dict:
        if scope not in ["database", "full"]:
            raise ValidationError("Invalid scope for PostgreSQL dump plan.")

        output_path = destination_path or Path("/tmp") / f"backup_{job_id}.dump"
        return {
            "executable": "pg_dump",
            "arguments": [
                "--host=${DB_HOST}",
                "--port=${DB_PORT}",
                "--username=${DB_USER}",
                "--dbname=${DB_NAME}",
                "--format=custom",
                "--file=${DESTINATION}",
            ],
            "env_vars_required": ["PGPASSWORD", "DB_HOST", "DB_PORT", "DB_USER", "DB_NAME"],
            "destination_placeholder": str(output_path.name),
            "shell": False,
        }

    def execute_dump(
        self,
        job_id: str,
        destination_path: Path,
        scope: str,
    ) -> dict:
        self.build_command_plan(job_id, scope, destination_path)

        executable, _ = self._resolve_client_tool("pg_dump")

        database = settings.DATABASES.get("default", {})
        db_name = database.get("NAME")
        db_user = database.get("USER")
        db_host = database.get("HOST") or "localhost"
        db_port = str(database.get("PORT") or "5432")
        db_password = database.get("PASSWORD") or os.environ.get("PGPASSWORD", "")
        if not db_name or not db_user:
            raise ValidationError("database_dump_config_incomplete")

        destination_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if destination_path.exists() or destination_path.is_symlink():
            raise ValidationError("database_dump_destination_invalid")
        command = [
            executable,
            f"--host={db_host}",
            f"--port={db_port}",
            f"--username={db_user}",
            f"--dbname={db_name}",
            "--format=custom",
            f"--file={destination_path}",
        ]
        env = os.environ.copy()
        if db_password:
            env["PGPASSWORD"] = str(db_password)

        process = subprocess.Popen(
            command,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
        )
        return_code = process.wait()
        if return_code != 0 or not destination_path.exists():
            raise ValidationError("pg_dump_failed")
        os.chmod(destination_path, 0o600)
        size_bytes = destination_path.stat().st_size

        return {
            "component": "database",
            "size_bytes": size_bytes,
            "checksum_sha256": _sha256_file(destination_path),
        }

    def build_toc_command(self, dump_path: Path) -> list[str]:
        executable, _ = self._resolve_client_tool("pg_restore")
        return [executable, "--list", str(dump_path)]

    def inspect_custom_archive_toc(
        self, dump_path: Path, *, runner=None
    ) -> str:
        command = self.build_toc_command(dump_path)
        completed = (runner or subprocess.run)(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            shell=False,
            text=True,
        )
        if completed.returncode != 0 or type(completed.stdout) is not str:
            raise ValidationError("pg_restore_toc_unavailable")
        return completed.stdout


class MediaInventoryAdapter:
    """Build safe public-media inventory metadata and archive members."""

    def build_inventory_metadata(self) -> dict:
        protected_files = ProtectedFile.objects.filter(status=FileStatusChoices.ACTIVE)
        protected_total_size = sum(
            protected_file.file_size_bytes or 0 for protected_file in protected_files
        )
        return {
            "protected_file_count": protected_files.count(),
            "protected_total_size_bytes": protected_total_size,
            "protected_manifest_entries": [
                {
                    "id": str(protected_file.id),
                    "purpose": protected_file.purpose,
                    "classification": protected_file.classification,
                    "status": protected_file.status,
                    "size_bytes": protected_file.file_size_bytes or 0,
                    "checksum_sha256": protected_file.checksum_sha256 or "",
                }
                for protected_file in protected_files
            ],
            "public_media_manifest_entries": self._build_public_media_manifest(),
        }

    def _build_public_media_manifest(self) -> list[dict]:
        return [metadata for _, metadata in self._iter_public_media_sources()]

    def build_public_media_archive_entries(self) -> tuple[list[dict], list[dict]]:
        """Return public-media manifest metadata and deduplicated source paths.

        Public assets remain referenced by an opaque relative-name digest, not
        the original storage path. The digest lets a separately approved
        restore runner match restored database references without placing raw
        local paths in the manifest. A content change during archive creation
        is rejected instead of producing mismatched evidence.
        """
        manifest_entries: list[dict] = []
        archive_entries: dict[str, dict] = {}
        for path, metadata in self._iter_public_media_sources():
            manifest_entries.append(dict(metadata))
            member_name = metadata["member_name"]
            if member_name in archive_entries:
                continue
            if path.stat().st_size != metadata["size_bytes"] or _sha256_file(path) != metadata["checksum_sha256"]:
                raise ValidationError("public_media_changed_during_backup")
            archive_entries[member_name] = {
                "path": path,
                "metadata": dict(metadata),
            }
        return manifest_entries, [archive_entries[key] for key in sorted(archive_entries)]

    def _iter_public_media_sources(self):
        """Return resolved public media paths paired with non-sensitive metadata."""
        entries = []
        try:
            from apps.organizations.models import BrandAsset
        except Exception:
            return []

        media_root = Path(settings.MEDIA_ROOT).resolve()

        def add_field(component: str, object_id: str, field_file):
            name = getattr(field_file, "name", "")
            if not name:
                return
            try:
                path = (media_root / name).resolve()
                path.relative_to(media_root)
            except ValueError:
                return
            if not path.exists() or not path.is_file():
                return
            relative_name_hash = hashlib.sha256(name.encode("utf-8")).hexdigest()
            entries.append(
                (
                    path,
                    {
                        "component": component,
                        "object_id": str(object_id),
                        "relative_name_hash_sha256": relative_name_hash,
                        "member_name": f"public_media/{relative_name_hash}.bin",
                        "size_bytes": path.stat().st_size,
                        "checksum_sha256": _sha256_file(path),
                    },
                )
            )

        for asset in BrandAsset.objects.all():
            add_field("brand_asset", asset.pk, asset.file)
        return entries


class BackupArchiveBuilder:
    """Builds a plaintext tar archive in temporary staging before encryption."""

    def build_archive(
        self, *, job, actor, staging_dir: Path
    ) -> ArchiveBuildResult:
        if staging_dir.is_symlink():
            raise ValidationError("backup_workspace_invalid")
        staging_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(staging_dir, 0o700)

        dump_path = None
        dump_meta = None
        if job.includes_database:
            dump_path = staging_dir / "database.dump"
            dump_adapter = PostgresDumpAdapter()
            dump_meta = dump_adapter.execute_dump(
                str(job.id), dump_path, "full" if job.job_type == "full" else "database"
            )
            # A custom dump that pg_restore cannot inspect is not a valid
            # recovery artifact.  This is a read-only TOC validation; it does
            # not restore data into any database.
            if not dump_adapter.inspect_custom_archive_toc(dump_path).strip():
                raise ValidationError("pg_restore_toc_empty")

        protected_entries = []
        if job.includes_protected_files:
            protected_entries = self._read_protected_file_entries(
                staging_dir / "protected_payload"
            )

        public_media_manifest = []
        public_media_entries = []
        if job.includes_media:
            public_media_manifest, public_media_entries = (
                MediaInventoryAdapter().build_public_media_archive_entries()
            )
        allowlist = [
            {
                "member_name": "manifest.json",
                "member_class": "MANIFEST",
                "required": True,
                "sha256": None,
                "size_bytes": None,
            }
        ]
        if dump_meta is not None:
            allowlist.append(
                {
                    "member_name": "database.dump",
                    "member_class": "DATABASE_DUMP",
                    "required": True,
                    "sha256": dump_meta["checksum_sha256"],
                    "size_bytes": dump_meta["size_bytes"],
                }
            )
        for entry in protected_entries:
            allowlist.append(
                {
                    "member_name": entry["metadata"]["member_name"],
                    "member_class": "PROTECTED_FILE",
                    "required": True,
                    "sha256": entry["metadata"]["sha256"],
                    "size_bytes": entry["metadata"]["size_bytes"],
                }
            )
        for entry in public_media_entries:
            allowlist.append(
                {
                    "member_name": entry["metadata"]["member_name"],
                    "member_class": "PUBLIC_MEDIA",
                    "required": True,
                    "sha256": entry["metadata"]["checksum_sha256"],
                    "size_bytes": entry["metadata"]["size_bytes"],
                }
            )
        allowlist.sort(key=lambda entry: entry["member_name"])

        archive_identifier = str(uuid.uuid4())
        manifest_payload = {
            "schema_version": "3.0",
            "backup_operation_id": str(job.id),
            "archive_identifier": archive_identifier,
            "job_type": job.job_type,
            "environment_class": job.environment,
            "created_at": timezone.now().astimezone(
                datetime_timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "storage_target_type": job.storage_target_type,
            "included": {
                "database": bool(job.includes_database),
                "media": bool(job.includes_media),
                "protected_files": bool(job.includes_protected_files),
                "manifest": True,
            },
            "database_dump": (
                {
                    "member_name": "database.dump",
                    "format": "postgresql-custom",
                    "sha256": dump_meta["checksum_sha256"],
                    "size_bytes": dump_meta["size_bytes"],
                }
                if dump_meta is not None
                else None
            ),
            "archive_member_allowlist": allowlist,
            "transient_state_exclusion": None,
            "protected_file_manifest": [
                dict(entry["metadata"]) for entry in protected_entries
            ],
            "public_media_manifest": public_media_manifest,
            "components": sorted(
                component
                for component, enabled in (
                    ("database", job.includes_database),
                    ("protected_files", job.includes_protected_files),
                    ("public_media_manifest", job.includes_media),
                )
                if enabled
            ),
        }
        manifest_bytes = canonical_manifest_bytes(manifest_payload)
        manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()

        declared_payload_bytes = sum(
            int(entry["size_bytes"])
            for entry in allowlist
            if entry["member_name"] != "manifest.json"
        )
        estimated_archive_bytes = (
            _tar_member_capacity(len(manifest_bytes))
            + sum(_tar_member_capacity(int(entry["size_bytes"])) for entry in allowlist if entry["member_name"] != "manifest.json")
            + 1024
        )
        if declared_payload_bytes < 0 or estimated_archive_bytes > _archive_max_bytes():
            raise ValidationError("backup_archive_capacity_exceeded")

        archive_path = staging_dir / "backup.tar"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(archive_path, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as archive_handle:
                with tarfile.open(fileobj=archive_handle, mode="w") as archive:
                    self._add_manifest(archive, manifest_bytes)
                    if dump_path is not None:
                        self._add_file(
                            archive,
                            "database.dump",
                            dump_path,
                            expected_size=dump_meta["size_bytes"],
                            expected_checksum=dump_meta["checksum_sha256"],
                        )
                    for entry in sorted(
                        protected_entries,
                        key=lambda value: value["metadata"]["member_name"],
                    ):
                        self._add_file(
                            archive,
                            entry["metadata"]["member_name"],
                            entry["path"],
                            expected_size=entry["metadata"]["size_bytes"],
                            expected_checksum=entry["metadata"]["sha256"],
                        )
                    for entry in public_media_entries:
                        self._add_file(
                            archive,
                            entry["metadata"]["member_name"],
                            entry["path"],
                            expected_size=entry["metadata"]["size_bytes"],
                            expected_checksum=entry["metadata"]["checksum_sha256"],
                        )
                archive_handle.flush()
                os.fsync(archive_handle.fileno())
        except Exception:
            if archive_path.exists():
                archive_path.unlink()
            raise
        finally:
            os.close(descriptor)
        os.chmod(archive_path, 0o600)
        if archive_path.stat().st_size > _archive_max_bytes():
            raise ValidationError("backup_archive_capacity_exceeded")
        self.validate_plaintext_archive(
            archive_path,
            expected_manifest_digest=manifest_hash,
        )

        return ArchiveBuildResult(
            archive_path=archive_path,
            manifest_payload=manifest_payload,
            manifest_hash_sha256=manifest_hash,
            archive_hash_sha256=_sha256_file(archive_path),
            archive_size_bytes=archive_path.stat().st_size,
        )

    def _read_protected_file_entries(self, staging_dir: Path) -> list[dict]:
        adapter = get_storage_adapter()
        staging_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(staging_dir, 0o700)
        entries = []
        for protected_file in ProtectedFile.objects.filter(status=FileStatusChoices.ACTIVE).order_by("id"):
            declared_size = protected_file.file_size_bytes or 0
            if type(declared_size) is not int or declared_size < 0:
                raise ValidationError("protected_file_size_invalid")
            payload_path = staging_dir / f"{protected_file.id}.bin"
            try:
                copied_size, checksum = adapter.copy_to_file(
                    protected_file.object_key,
                    payload_path,
                    expected_size=declared_size,
                    expected_checksum=protected_file.checksum_sha256 or None,
                )
            except (AttributeError, NotImplementedError) as exc:
                raise ValidationError("protected_storage_stream_unavailable") from exc
            if copied_size != declared_size:
                raise ValidationError("protected_file_size_mismatch")
            member_name = f"protected_files/{protected_file.id}.bin"
            validate_archive_member_name(member_name)
            entries.append({
                "path": payload_path,
                "metadata": {
                    "member_name": member_name,
                    "purpose": protected_file.purpose,
                    "classification": protected_file.classification,
                    "status": protected_file.status,
                    "size_bytes": copied_size,
                    "sha256": checksum,
                },
            })
        return entries

    def _add_manifest(self, archive, content):
        """Write the small bounded manifest; payload members are file streams."""
        arcname = "manifest.json"
        validate_archive_member_name(arcname)
        if type(content) is not bytes:
            raise ValidationError("archive_member_content_invalid")
        if len(content) > MAX_MANIFEST_BYTES:
            raise ValidationError("archive_manifest_invalid")
        info = tarfile.TarInfo(arcname)
        info.size = len(content)
        info.mode = 0o600
        info.mtime = 0
        archive.addfile(info, io.BytesIO(content))

    def _add_file(self, archive, arcname, source_path, *, expected_size=None, expected_checksum=None):
        validate_archive_member_name(arcname)
        if source_path.is_symlink() or not source_path.is_file():
            raise ValidationError("archive_member_source_invalid")
        size = source_path.stat().st_size
        if expected_size is not None and size != expected_size:
            raise ValidationError("archive_member_size_invalid")
        info = tarfile.TarInfo(arcname)
        info.size = size
        info.mode = 0o600
        info.mtime = 0
        digest = hashlib.sha256()
        total = 0

        class _DigestReader:
            def read(self, requested=-1):
                nonlocal total
                if requested is None or requested < 0:
                    requested = 1024 * 1024
                chunk = source.read(requested)
                if chunk:
                    total += len(chunk)
                    digest.update(chunk)
                return chunk

        with source_path.open("rb") as source:
            archive.addfile(info, _DigestReader())
        if total != size or (expected_checksum is not None and digest.hexdigest() != expected_checksum):
            raise ValidationError("archive_member_hash_invalid")

    def validate_plaintext_archive(
        self, archive_path: Path, *, expected_manifest_digest=None
    ) -> dict:
        if archive_path.is_symlink() or not archive_path.is_file():
            raise ValidationError("archive_validation_failed")
        if archive_path.stat().st_size > _archive_max_bytes():
            raise ValidationError("backup_archive_capacity_exceeded")
        members = []
        normalized_names = set()
        with tarfile.open(archive_path, "r:") as archive:
            for member in archive:
                name = validate_archive_member_name(member.name)
                normalized = unicodedata.normalize("NFKC", name)
                if normalized in normalized_names or not member.isfile():
                    raise ValidationError("archive_member_invalid")
                normalized_names.add(normalized)
                if type(member.size) is not int or member.size < 0:
                    raise ValidationError("archive_member_size_invalid")
                members.append(member)
            manifest_members = [
                member for member in members if member.name == "manifest.json"
            ]
            if len(manifest_members) != 1:
                raise ValidationError("archive_manifest_invalid")
            manifest_member = manifest_members[0]
            manifest_stream = archive.extractfile(manifest_member)
            if manifest_stream is None:
                raise ValidationError("archive_manifest_invalid")
            if manifest_member.size > MAX_MANIFEST_BYTES:
                raise ValidationError("archive_manifest_invalid")
            manifest_bytes = manifest_stream.read(MAX_MANIFEST_BYTES + 1)
            if len(manifest_bytes) > MAX_MANIFEST_BYTES:
                raise ValidationError("archive_manifest_invalid")
            manifest = parse_canonical_manifest(manifest_bytes)
            digest = hashlib.sha256(manifest_bytes).hexdigest()
            if expected_manifest_digest is not None and digest != expected_manifest_digest:
                raise ValidationError("archive_manifest_invalid")
            allowlist = {
                entry["member_name"]: entry
                for entry in manifest["archive_member_allowlist"]
            }
            if set(allowlist) != {member.name for member in members}:
                raise ValidationError("archive_allowlist_mismatch")
            for member in members:
                if member.name == "manifest.json":
                    continue
                entry = allowlist[member.name]
                if member.size != entry["size_bytes"]:
                    raise ValidationError("archive_member_size_invalid")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValidationError("archive_member_invalid")
                member_digest = hashlib.sha256()
                total = 0
                while True:
                    chunk = stream.read(min(1024 * 1024, member.size - total + 1))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > member.size:
                        raise ValidationError("archive_member_size_invalid")
                    member_digest.update(chunk)
                if total != member.size or member_digest.hexdigest() != entry["sha256"]:
                    raise ValidationError("archive_member_hash_invalid")
        return manifest


class BackupArchiveEncryptionAdapter:
    """Encrypt staged archives with a standard streaming GPG envelope.

    The key-source contract still supplies the active
    ``FILE_ENVELOPE_PLACEHOLDER`` material.  The legacy Fernet decoder is
    intentionally bounded and only exists for historical artifacts.
    """

    def encrypt_archive(self, archive_path: Path, encrypted_path: Path) -> ArchiveEncryptionResult:
        if (
            archive_path.is_symlink()
            or not archive_path.is_file()
            or encrypted_path.exists()
            or encrypted_path.is_symlink()
        ):
            raise ValidationError("backup_archive_capacity_invalid")
        if archive_path.stat().st_size > _archive_max_bytes():
            raise ValidationError("backup_archive_capacity_exceeded")
        try:
            key_metadata = EncryptionKeyVersion.objects.get(
                key_purpose=KeyPurposeChoices.FILE_ENVELOPE_PLACEHOLDER,
                status=KeyStatusChoices.ACTIVE,
            )
        except EncryptionKeyVersion.DoesNotExist as exc:
            raise ValidationError("backup_archive_key_unavailable") from exc
        except EncryptionKeyVersion.MultipleObjectsReturned as exc:
            raise ValidationError("backup_archive_key_ambiguous") from exc

        key_material = load_key_material(key_metadata.key_version, key_metadata.secret_reference)
        encrypted_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(encrypted_path.parent, 0o700)
        self._run_gpg(
            operation="encrypt",
            source_path=archive_path,
            destination_path=encrypted_path,
            key_material=key_material,
        )
        archive_path.unlink(missing_ok=True)

        if archive_path.exists():
            raise ValidationError("backup_plaintext_cleanup_failed")

        return ArchiveEncryptionResult(
            encrypted_path=encrypted_path,
            checksum_sha256=_sha256_file(encrypted_path),
            size_bytes=encrypted_path.stat().st_size,
            key_version_reference=key_metadata.key_version,
            envelope_format=GPG_ENVELOPE_FORMAT,
        )

    def decrypt_archive(
        self,
        encrypted_path: Path,
        plaintext_path: Path,
        *,
        key_version_reference: str,
        envelope_format: str = GPG_ENVELOPE_FORMAT,
    ) -> Path:
        """Decrypt a bounded generated/offline archive envelope."""
        if (
            encrypted_path.is_symlink()
            or not encrypted_path.is_file()
            or plaintext_path.exists()
            or plaintext_path.is_symlink()
        ):
            raise ValidationError("backup_archive_capacity_invalid")
        try:
            key_metadata = EncryptionKeyVersion.objects.get(
                key_version=key_version_reference,
                key_purpose=KeyPurposeChoices.FILE_ENVELOPE_PLACEHOLDER,
                status__in=[KeyStatusChoices.ACTIVE, KeyStatusChoices.DECRYPT_ONLY],
            )
        except (EncryptionKeyVersion.DoesNotExist, EncryptionKeyVersion.MultipleObjectsReturned) as exc:
            raise ValidationError("backup_archive_key_unavailable") from exc
        key_material = load_key_material(
            key_metadata.key_version, key_metadata.secret_reference
        )
        plaintext_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(plaintext_path.parent, 0o700)
        if envelope_format == BackupEnvelopeFormatChoices.FERNET_V1:
            token = _read_bounded(encrypted_path, _legacy_fernet_max_bytes())
            try:
                plaintext = Fernet(key_material).decrypt(token)
            except Exception as exc:
                raise ValidationError("backup_archive_authentication_failed") from exc
            _write_exclusive(plaintext_path, plaintext)
        elif envelope_format == GPG_ENVELOPE_FORMAT:
            self._run_gpg(
                operation="decrypt",
                source_path=encrypted_path,
                destination_path=plaintext_path,
                key_material=key_material,
            )
        else:
            raise ValidationError("backup_archive_format_unsupported")
        return plaintext_path

    @staticmethod
    def _run_gpg(*, operation: str, source_path: Path, destination_path: Path, key_material: bytes) -> None:
        executable = shutil.which(GPG_EXECUTABLE)
        if not executable:
            raise ValidationError("gpg_unavailable")
        if source_path.is_symlink() or not source_path.is_file():
            raise ValidationError("backup_archive_capacity_invalid")
        if destination_path.exists() or destination_path.is_symlink():
            raise ValidationError("backup_archive_capacity_invalid")
        homedir = None
        try:
            homedir = tempfile.mkdtemp(prefix="compass-gpg-")
            os.chmod(homedir, 0o700)
            action = "--symmetric" if operation == "encrypt" else "--decrypt"
            command = [
                executable,
                "--batch",
                "--quiet",
                "--yes",
                "--no-options",
                "--homedir",
                homedir,
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                "0",
                action,
            ]
            if operation == "encrypt":
                command.extend(["--cipher-algo", "AES256"])
            command.extend(["--output", str(destination_path), str(source_path)])
            completed = subprocess.run(
                command,
                input=key_material,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                shell=False,
            )
            if completed.returncode != 0 or not destination_path.is_file() or destination_path.stat().st_size <= 0:
                destination_path.unlink(missing_ok=True)
                raise ValidationError("backup_archive_encryption_failed")
            os.chmod(destination_path, 0o600)
        except OSError as exc:
            destination_path.unlink(missing_ok=True)
            raise ValidationError("backup_archive_encryption_failed") from exc
        finally:
            if homedir:
                shutil.rmtree(homedir, ignore_errors=True)


class BackupStorageAdapter:
    """Backup storage target abstraction for local demo and S3-compatible archives."""

    def verify_target_availability(self, target_type: str) -> bool:
        return self.get_unavailability_reason(target_type) is None

    def get_unavailability_reason(self, target_type: str) -> str | None:
        target_type = canonical_backup_storage_target(target_type)
        if target_type == "metadata_only":
            return "metadata_only_not_completing"
        if target_type == "local_demo":
            environment = str(
                getattr(settings, "COMPASS_ENVIRONMENT", "development") or "development"
            ).strip().lower()
            if environment in {"staging", "stage", "production", "prod"}:
                return "local_demo_deployment_disallowed"
            root = getattr(settings, "BACKUP_LOCAL_DEMO_ROOT", None)
            return None if root else "local_demo_root_missing"
        if target_type == "s3_compatible":
            required = [
                "BACKUP_STORAGE_S3_ENDPOINT_URL",
                "BACKUP_STORAGE_S3_BUCKET",
                "BACKUP_STORAGE_S3_ACCESS_KEY",
                "BACKUP_STORAGE_S3_SECRET_KEY",
            ]
            if any(not getattr(settings, setting_name, "") for setting_name in required):
                return "s3_config_incomplete"
            if not self._endpoint_has_safe_shape():
                return "s3_endpoint_invalid"
            if not self._s3_dependency_available():
                return "s3_dependency_missing"
            return None
        return "backup_storage_target_unknown"

    def store_archive(
        self,
        *,
        job,
        artifact_id,
        encrypted_path: Path,
        target_type: str,
        envelope_format: str = GPG_ENVELOPE_FORMAT,
    ) -> StoredArchiveResult:
        target_type = canonical_backup_storage_target(target_type)
        if (
            encrypted_path.is_symlink()
            or not encrypted_path.is_file()
        ):
            raise ValidationError("backup_archive_capacity_invalid")
        reason = self.get_unavailability_reason(target_type)
        if reason:
            raise ValidationError(reason)

        if target_type == "local_demo":
            destination = self._local_archive_path(job.id, artifact_id, envelope_format)
            self._atomic_local_copy(encrypted_path, destination)
        elif target_type == "s3_compatible":
            self._store_s3(job.id, artifact_id, encrypted_path, envelope_format)
        else:
            raise ValidationError("backup_storage_target_unknown")

        return StoredArchiveResult(
            storage_reference=f"backup-artifact:{artifact_id}",
            checksum_sha256=_sha256_file(encrypted_path),
            size_bytes=encrypted_path.stat().st_size,
            storage_target_type=target_type,
        )

    def verify_archive(self, *, job, artifact) -> bool:
        target_type = canonical_backup_storage_target(job.storage_target_type)
        envelope_format = _artifact_envelope_format(artifact)
        if target_type == "local_demo":
            path = self._local_archive_path(job.id, artifact.id, envelope_format)
            return (
                path.exists()
                and path.is_file()
                and path.stat().st_size == artifact.size_bytes
                and _sha256_file(path) == artifact.checksum_sha256
            )
        if target_type == "s3_compatible":
            if artifact.storage_reference != f"backup-artifact:{artifact.id}":
                return False
            try:
                response = self._s3_client().get_object(
                    Bucket=settings.BACKUP_STORAGE_S3_BUCKET,
                    Key=self._s3_object_key(job.id, artifact.id, envelope_format),
                )
                body = response.get("Body")
                if body is None:
                    return False
                digest = hashlib.sha256()
                total_size = 0
                try:
                    while True:
                        chunk = body.read(1024 * 1024)
                        if not chunk:
                            break
                        if type(chunk) is not bytes:
                            return False
                        total_size += len(chunk)
                        digest.update(chunk)
                finally:
                    close = getattr(body, "close", None)
                    if callable(close):
                        close()
                return (
                    response.get("ContentLength") == artifact.size_bytes
                    and total_size == artifact.size_bytes
                    and digest.hexdigest() == artifact.checksum_sha256
                )
            except Exception:
                return False
        return False

    def retrieve_archive(self, *, job, artifact, destination_path: Path) -> Path:
        """Copy one encrypted artifact into a private worker workspace.

        The destination is created exclusively and is never returned through
        an HTTP response.  S3 reads are bounded by the recorded artifact size
        and checksum before the caller can decrypt or inspect the archive.
        """
        if destination_path.exists() or destination_path.is_symlink():
            raise ValidationError("restore_workspace_invalid")
        destination_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(destination_path.parent, 0o700)
        target_type = canonical_backup_storage_target(job.storage_target_type)
        envelope_format = _artifact_envelope_format(artifact)
        if target_type == "local_demo":
            source = self._local_archive_path(job.id, artifact.id, envelope_format)
            if source.is_symlink() or not source.is_file():
                raise ValidationError("backup_archive_unavailable")
            with source.open("rb") as handle:
                _copy_stream_to_file(
                    handle,
                    destination_path,
                    expected_size=int(artifact.size_bytes),
                    expected_checksum=artifact.checksum_sha256,
                )
            return destination_path
        if target_type != "s3_compatible" or artifact.storage_reference != f"backup-artifact:{artifact.id}":
            raise ValidationError("backup_archive_unavailable")
        try:
            response = self._s3_client().get_object(
                Bucket=settings.BACKUP_STORAGE_S3_BUCKET,
                Key=self._s3_object_key(job.id, artifact.id, envelope_format),
            )
            body = response.get("Body")
            if body is None:
                raise ValidationError("backup_archive_unavailable")
            digest = hashlib.sha256()
            total = 0
            descriptor = os.open(
                destination_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                with os.fdopen(descriptor, "wb", closefd=False) as handle:
                    while True:
                        chunk = body.read(1024 * 1024)
                        if not chunk:
                            break
                        if type(chunk) is not bytes:
                            raise ValidationError("backup_archive_unavailable")
                        total += len(chunk)
                        if total > int(artifact.size_bytes):
                            raise ValidationError("backup_archive_size_mismatch")
                        digest.update(chunk)
                        handle.write(chunk)
                    handle.flush()
                    os.fsync(handle.fileno())
            finally:
                os.close(descriptor)
                close = getattr(body, "close", None)
                if callable(close):
                    close()
            if total != int(artifact.size_bytes) or digest.hexdigest() != artifact.checksum_sha256:
                raise ValidationError("backup_archive_checksum_mismatch")
            os.chmod(destination_path, 0o600)
            return destination_path
        except ValidationError:
            destination_path.unlink(missing_ok=True)
            raise
        except Exception as exc:
            destination_path.unlink(missing_ok=True)
            raise ValidationError("backup_archive_unavailable") from exc

    def _local_archive_path(self, job_id, artifact_id, envelope_format: str) -> Path:
        root = Path(getattr(settings, "BACKUP_LOCAL_DEMO_ROOT", "backups")).resolve()
        suffix = ".tar.gpg" if envelope_format == GPG_ENVELOPE_FORMAT else ".tar.fernet"
        return root / str(job_id) / f"{artifact_id}{suffix}"

    def _atomic_local_copy(self, source: Path, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(destination.parent, 0o700)
        if destination.exists() or destination.is_symlink():
            raise ValidationError("backup_storage_destination_invalid")
        partial = destination.with_name(f".{destination.name}.partial")
        if partial.exists() or partial.is_symlink():
            raise ValidationError("backup_storage_destination_invalid")
        try:
            with source.open("rb") as handle:
                _copy_stream_to_file(handle, partial)
            os.replace(partial, destination)
            os.chmod(destination, 0o600)
            try:
                directory_fd = os.open(destination.parent, os.O_RDONLY)
            except OSError:
                directory_fd = None
            if directory_fd is not None:
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        finally:
            partial.unlink(missing_ok=True)

    def _store_s3(self, job_id, artifact_id, encrypted_path: Path, envelope_format: str) -> None:
        client = self._s3_client()
        object_key = self._s3_object_key(job_id, artifact_id, envelope_format)
        try:
            checksum = _sha256_file(encrypted_path)
            from boto3.s3.transfer import TransferConfig

            client.upload_file(
                str(encrypted_path),
                settings.BACKUP_STORAGE_S3_BUCKET,
                object_key,
                ExtraArgs={
                    "ContentType": "application/octet-stream",
                    "Metadata": {"sha256": checksum},
                },
                Config=TransferConfig(
                    multipart_threshold=8 * 1024 * 1024,
                    multipart_chunksize=8 * 1024 * 1024,
                    max_concurrency=2,
                    use_threads=True,
                ),
            )
        except Exception as exc:
            raise ValidationError("s3_upload_failed") from exc

    @staticmethod
    def _s3_object_key(job_id, artifact_id, envelope_format: str) -> str:
        suffix = ".tar.gpg" if envelope_format == GPG_ENVELOPE_FORMAT else ".tar.fernet"
        return f"backups/{job_id}/{artifact_id}{suffix}"

    @staticmethod
    def _s3_client():
        try:
            import boto3
            from botocore.config import Config
        except ImportError as exc:
            raise ValidationError("s3_dependency_missing") from exc
        return boto3.client(
            "s3",
            endpoint_url=settings.BACKUP_STORAGE_S3_ENDPOINT_URL,
            aws_access_key_id=settings.BACKUP_STORAGE_S3_ACCESS_KEY,
            aws_secret_access_key=settings.BACKUP_STORAGE_S3_SECRET_KEY,
            region_name=getattr(settings, "BACKUP_STORAGE_S3_REGION_NAME", "us-east-1"),
            config=Config(
                signature_version="s3v4",
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
                s3={
                    "addressing_style": getattr(
                        settings, "BACKUP_STORAGE_S3_ADDRESSING_STYLE", "path"
                    ),
                    "payload_signing_enabled": False,
                },
            ),
            use_ssl=getattr(settings, "BACKUP_STORAGE_S3_USE_SSL", True),
        )

    def _endpoint_has_safe_shape(self) -> bool:
        endpoint = str(getattr(settings, "BACKUP_STORAGE_S3_ENDPOINT_URL", "") or "")
        parsed = urlparse(endpoint)
        return (
            parsed.scheme in {"http", "https"}
            and bool(parsed.netloc)
            and not parsed.username
            and not parsed.password
        )

    def _s3_dependency_available(self) -> bool:
        try:
            return (
                importlib.util.find_spec("boto3") is not None
                and importlib.util.find_spec("botocore") is not None
            )
        except (ImportError, ValueError):
            return False


class BackupEncryptionAdapter:
    """Boundary for encryption status and metadata."""

    def get_encryption_metadata(self) -> dict:
        active_keys = EncryptionKeyVersion.objects.filter(
            key_purpose=KeyPurposeChoices.FILE_ENVELOPE_PLACEHOLDER,
            status=KeyStatusChoices.ACTIVE,
        )
        if active_keys.exists():
            key_ver = active_keys.first()
            return {
                "key_version_reference": key_ver.key_version,
                "encryption_status": "encrypted",
            }
        return {
            "key_version_reference": "",
            "encryption_status": "pending",
        }


class RestoreDryRunAdapter:
    """Dry-run validation checks for restore requests."""

    def execute_dry_run(self, restore_request) -> list:
        job = restore_request.target_backup_job
        checklist = []

        manifest_ok = hasattr(job, "manifest") and job.manifest is not None
        checklist.append({
            "step_key": "manifest_exists",
            "status": ChecklistStatusChoices.PASSED if manifest_ok else ChecklistStatusChoices.FAILED,
            "safe_message_code": "manifest_found" if manifest_ok else "manifest_missing",
        })

        checksum_ok = job.artifacts.exists() and all(bool(a.checksum_sha256) for a in job.artifacts.all())
        checklist.append({
            "step_key": "checksum_present",
            "status": ChecklistStatusChoices.PASSED if checksum_ok else ChecklistStatusChoices.FAILED,
            "safe_message_code": "checksums_verified" if checksum_ok else "checksums_missing",
        })

        storage_ok = all(BackupStorageAdapter().verify_archive(job=job, artifact=a) for a in job.artifacts.all())
        checklist.append({
            "step_key": "archive_artifact_available",
            "status": ChecklistStatusChoices.PASSED if storage_ok else ChecklistStatusChoices.FAILED,
            "safe_message_code": "archive_available" if storage_ok else "archive_unavailable",
        })

        enc_ok = job.encrypted_at_rest
        checklist.append({
            "step_key": "encryption_marker_present",
            "status": ChecklistStatusChoices.PASSED if enc_ok else ChecklistStatusChoices.FAILED,
            "safe_message_code": "encryption_marker_verified" if enc_ok else "encryption_marker_missing",
        })

        key_ref = None
        for artifact in job.artifacts.all():
            if artifact.key_version_reference:
                key_ref = artifact.key_version_reference
                break

        key_source_ok = False
        if key_ref:
            key_source_ok = EncryptionKeyVersion.objects.filter(key_version=key_ref).exists()

        checklist.append({
            "step_key": "key_source_available",
            "status": ChecklistStatusChoices.PASSED if key_source_ok else ChecklistStatusChoices.WARNING,
            "safe_message_code": "key_source_registered" if key_source_ok else "key_source_reference_warning",
        })

        checklist.append({
            "step_key": "restore_execution_mode",
            "status": ChecklistStatusChoices.WARNING,
            "safe_message_code": "restore_dry_run_only",
        })

        return checklist
