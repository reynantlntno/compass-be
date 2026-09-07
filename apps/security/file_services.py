# Project: COMPASS
# File: apps/security/file_services.py
# Module: apps.security
# Purpose: Service actions for file validation, storage, and permission-checked retrieval
# Domain boundary and service policy.

import datetime
import hashlib
import os
import uuid
from django.conf import settings
from django.db import transaction
from django.urls import reverse
from apps.audit.services import audit_log
from apps.security.models import ProtectedFile, FileStatusChoices
from apps.security.constants import (
    PROTECTED_STORAGE_ALLOWED_CONTENT_TYPES,
    PROTECTED_STORAGE_ALLOWED_EXTENSIONS,
)
from apps.security.storage_adapters import get_storage_adapter
from apps.security.file_policies import verify_file_access
from apps.security.file_selectors import get_active_protected_file
from apps.security.exceptions import SecurityError, PolicyValidationError, StorageError, ProtectedFileNotFoundError
from apps.governance.runtime_config import resolve_runtime_setting
from apps.governance.selectors import resolve_effective_policy


ASSESSMENT_UPLOAD_CONTENT_TYPES = frozenset({
    "application/pdf",
    "image/jpeg",
    "image/png",
})
ASSESSMENT_UPLOAD_EXTENSIONS = frozenset({".pdf", ".jpg", ".jpeg", ".png"})
ASSESSMENT_UPLOAD_MAX_BYTES = 10 * 1024 * 1024


def _assessment_upload_policy():
    """Read the purpose-specific assessment policy at request time."""
    policy = resolve_effective_policy("security.assessment_upload_controls")
    if policy is None:
        return ASSESSMENT_UPLOAD_CONTENT_TYPES, ASSESSMENT_UPLOAD_EXTENSIONS, ASSESSMENT_UPLOAD_MAX_BYTES
    configuration = policy.configuration_json or {}
    return (
        frozenset(configuration.get("allowed_content_types") or ASSESSMENT_UPLOAD_CONTENT_TYPES),
        frozenset(configuration.get("allowed_extensions") or ASSESSMENT_UPLOAD_EXTENSIONS),
        int(configuration.get("max_file_size_bytes", ASSESSMENT_UPLOAD_MAX_BYTES)),
    )


def calculate_sha256(content: bytes) -> str:
    """Calculates the SHA-256 hash of binary content."""
    return hashlib.sha256(content).hexdigest()


def sanitize_display_filename(filename: str) -> str:
    """Sanitizes filename for safe disposition display."""
    if not filename:
        return "unnamed_file"
    base = os.path.basename(filename)
    sanitized = "".join(c for c in base if c.isalnum() or c in "._-").strip()
    return sanitized or "unnamed_file"


def validate_upload_metadata(content_type: str, file_size_bytes: int, filename: str) -> None:
    """Validates file upload metadata against configured limits and allowlists."""
    max_size = resolve_runtime_setting(
        "security.protected_storage",
        "PROTECTED_STORAGE_MAX_FILE_SIZE_BYTES",
    )
    allowed_types = PROTECTED_STORAGE_ALLOWED_CONTENT_TYPES
    allowed_exts = PROTECTED_STORAGE_ALLOWED_EXTENSIONS

    if file_size_bytes <= 0:
        raise SecurityError("Upload rejected: File is empty.")

    if file_size_bytes > max_size:
        raise SecurityError("Upload rejected: File size exceeds the maximum limit.")

    if content_type not in allowed_types:
        raise SecurityError(f"Upload rejected: Content type '{content_type}' is not allowed.")

    _, ext = os.path.splitext(filename)
    ext_lower = ext.lower()
    if ext_lower not in allowed_exts:
        raise SecurityError(f"Upload rejected: File extension '{ext_lower}' is not allowed.")


def _upload_stream(uploaded_file):
    """Return the seekable binary stream owned by a Django UploadedFile."""
    stream = getattr(uploaded_file, "file", uploaded_file)
    if not hasattr(stream, "read"):
        raise SecurityError("Upload rejected: File stream is unavailable.")
    return stream


def validate_assessment_upload(uploaded_file) -> None:
    """Validate an assessment attachment without trusting browser MIME metadata.

    The size check happens before any content read.  Signature checks only read
    bounded prefixes/suffixes; Pillow verifies image structure after that early
    rejection and the stream is rewound for the storage pass.
    """
    size = getattr(uploaded_file, "size", None)
    filename = getattr(uploaded_file, "name", "")
    content_type = getattr(uploaded_file, "content_type", "")
    if size is None:
        raise SecurityError("Upload rejected: File size is unavailable.")
    allowed_types, allowed_extensions, max_bytes = _assessment_upload_policy()
    # Do not inherit the broad generic protected-storage allowlist: this
    # purpose has its own size, extension, and configured MIME policy.
    size = int(size)
    if size <= 0:
        raise SecurityError("Upload rejected: File is empty.")
    if size > max_bytes:
        raise SecurityError("Upload rejected: File size exceeds the assessment limit.")
    if content_type not in allowed_types:
        raise SecurityError("Upload rejected: Assessment files must be PDF, JPEG, or PNG.")
    _, extension = os.path.splitext(filename)
    if extension.lower() not in allowed_extensions:
        raise SecurityError("Upload rejected: Assessment file format is not allowed.")

    stream = _upload_stream(uploaded_file)
    try:
        stream.seek(0)
        prefix = stream.read(16)
        if not prefix:
            raise SecurityError("Upload rejected: File is empty.")
        if content_type == "application/pdf":
            if not prefix.startswith(b"%PDF-"):
                raise SecurityError("Upload rejected: File content does not match PDF format.")
            stream.seek(max(0, int(size) - 1024))
            suffix = stream.read(1024)
            if b"%%EOF" not in suffix:
                raise SecurityError("Upload rejected: PDF file is incomplete.")
        elif content_type == "image/png":
            if prefix[:8] != b"\x89PNG\r\n\x1a\n":
                raise SecurityError("Upload rejected: File content does not match PNG format.")
            from PIL import Image
            stream.seek(0)
            with Image.open(stream) as image:
                image.verify()
        elif content_type == "image/jpeg":
            if prefix[:3] != b"\xff\xd8\xff":
                raise SecurityError("Upload rejected: File content does not match JPEG format.")
            from PIL import Image
            stream.seek(0)
            with Image.open(stream) as image:
                image.verify()
    except SecurityError:
        raise
    except Exception as exc:
        raise SecurityError("Upload rejected: File content could not be verified.") from exc
    finally:
        try:
            stream.seek(0)
        except Exception:
            pass


class _HashingStream:
    """Read-through wrapper that keeps streamed size and SHA-256 evidence."""

    def __init__(self, stream):
        self.stream = stream
        self.digest = hashlib.sha256()
        self.size = 0

    def read(self, amount=-1):
        chunk = self.stream.read(amount)
        if chunk:
            self.digest.update(chunk)
            self.size += len(chunk)
        return chunk


def store_protected_file_stream(
    user,
    uploaded_file,
    *,
    purpose: str,
    classification: str,
    app_label: str,
    model_name: str,
    object_id: str,
    access_policy_key: str,
    allowed_content_types=None,
    allowed_extensions=None,
    max_file_size_bytes=None,
) -> ProtectedFile:
    """Validate and store a Django upload in bounded chunks.

    The assessment policy is intentionally explicit at the call site.  The
    existing byte-oriented ``store_protected_file`` remains for legacy/internal
    callers and unrelated storage purposes.
    """
    if purpose == "ASSESSMENT_RESULT_FILE":
        validate_assessment_upload(uploaded_file)
    else:
        size = getattr(uploaded_file, "size", None)
        if size is None:
            raise SecurityError("Upload rejected: File size is unavailable.")
        if max_file_size_bytes is not None and int(size) > int(max_file_size_bytes):
            raise SecurityError("Upload rejected: File size exceeds the maximum limit.")
        validate_upload_metadata(
            getattr(uploaded_file, "content_type", ""),
            int(size),
            getattr(uploaded_file, "name", ""),
        )

    stream = _upload_stream(uploaded_file)
    try:
        stream.seek(0)
    except Exception as exc:
        raise SecurityError("Upload rejected: File stream is not seekable.") from exc

    object_key = generate_opaque_object_key(purpose)
    adapter = get_storage_adapter()
    backend_alias = getattr(settings, "PROTECTED_STORAGE_BACKEND", "local")
    bucket_name = "local-root" if backend_alias == "local" else getattr(settings, "PROTECTED_STORAGE_S3_BUCKET_NAME", "compass-private")
    hashing_stream = _HashingStream(stream)
    try:
        adapter.store_stream(object_key, hashing_stream, getattr(uploaded_file, "content_type", ""))
        expected_size = int(getattr(uploaded_file, "size", hashing_stream.size))
        if hashing_stream.size != expected_size:
            raise SecurityError("Upload rejected: Streamed file size changed during upload.")
        with transaction.atomic():
            protected_file = ProtectedFile.objects.create(
                storage_backend_alias=backend_alias,
                bucket_name=bucket_name,
                object_key=object_key,
                original_filename_display=sanitize_display_filename(getattr(uploaded_file, "name", "")),
                content_type=getattr(uploaded_file, "content_type", ""),
                file_size_bytes=hashing_stream.size,
                checksum_sha256=hashing_stream.digest.hexdigest(),
                classification=classification,
                purpose=purpose,
                owning_app_label=app_label,
                owning_model_name=model_name,
                owning_object_id=str(object_id),
                access_policy_key=access_policy_key,
                created_by=user,
            )
    except Exception:
        try:
            adapter.delete(object_key)
        except Exception:
            pass
        raise

    audit_log(
        action_type="FILE_UPLOAD_STREAMED",
        event_category="DATA_ACCESS",
        target_model="ProtectedFile",
        target_object_id=str(protected_file.id),
        actor_user=user,
        metadata={
            "classification": protected_file.classification,
            "purpose": protected_file.purpose,
            "content_type": protected_file.content_type,
            "file_size_bytes": protected_file.file_size_bytes,
            "status": protected_file.status,
        },
    )
    return protected_file


def generate_opaque_object_key(purpose: str) -> str:
    """
    Generates a secure, non-PII, opaque object key partitioned by year and month.
    Contains no student identifiers, names, or topics.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    year = now.strftime("%Y")
    month = now.strftime("%m")
    unique_id = uuid.uuid4()
    # e.g., protected/2026/06/<uuid>
    return f"protected/{year}/{month}/{unique_id}"


def _generic_not_found_or_denied() -> ProtectedFileNotFoundError:
    return ProtectedFileNotFoundError("Protected file not found or access denied.")


def _get_authorized_active_file_for_content(user, file_id) -> ProtectedFile:
    """Public-facing content lookup that does not reveal missing-vs-denied state."""
    try:
        protected_file = ProtectedFile.objects.get(id=file_id)
        if protected_file.status != FileStatusChoices.ACTIVE:
            raise ProtectedFileNotFoundError("Protected file not found or access denied.")
        verify_file_access(user, protected_file, action="read_content")
        return protected_file
    except Exception as exc:
        audit_log(
            action_type="FILE_ACCESS_DENIED",
            event_category="SECURITY",
            severity="WARNING",
            target_model="ProtectedFile",
            target_object_id=str(file_id),
            actor_user=user,
            metadata={"reason": "not_found_or_denied"},
        )
        raise _generic_not_found_or_denied() from exc


def audit_proxy_download_served(user, protected_file: ProtectedFile) -> None:
    """Audit successful proxy delivery with metadata that excludes private names and keys."""
    audit_log(
        action_type="PROXY_DOWNLOAD_SERVED",
        event_category="DATA_ACCESS",
        target_model="ProtectedFile",
        target_object_id=str(protected_file.id),
        actor_user=user,
        metadata={
            "classification": protected_file.classification,
            "purpose": protected_file.purpose,
            "content_type": protected_file.content_type,
            "file_size_bytes": protected_file.file_size_bytes,
            "status": protected_file.status,
        },
    )


def store_protected_file(
    user,
    content: bytes,
    original_filename: str,
    content_type: str,
    purpose: str,
    classification: str,
    app_label: str,
    model_name: str,
    object_id: str,
    access_policy_key: str,
    encryption_key_version: str = None
) -> ProtectedFile:
    """
    Validates, uploads, and registers metadata for a protected file.
    Fail-closed transaction design.
    """
    validate_upload_metadata(content_type, len(content), original_filename)

    checksum = calculate_sha256(content)
    object_key = generate_opaque_object_key(purpose)

    adapter = get_storage_adapter()

    # Store key prefix or class
    backend_alias = getattr(settings, "PROTECTED_STORAGE_BACKEND", "local")
    bucket_name = getattr(settings, "PROTECTED_STORAGE_S3_BUCKET_NAME", "compass-private")
    if backend_alias == "local":
        bucket_name = "local-root"

    sanitized_filename = sanitize_display_filename(original_filename)

    with transaction.atomic():
        protected_file = ProtectedFile.objects.create(
            storage_backend_alias=backend_alias,
            bucket_name=bucket_name,
            object_key=object_key,
            original_filename_display=sanitized_filename,
            content_type=content_type,
            file_size_bytes=len(content),
            checksum_sha256=checksum,
            classification=classification,
            purpose=purpose,
            owning_app_label=app_label,
            owning_model_name=model_name,
            owning_object_id=str(object_id),
            access_policy_key=access_policy_key,
            encryption_key_version=encryption_key_version,
            created_by=user,
        )

        # Write to physical storage
        try:
            adapter.store(object_key, content, content_type)
        except Exception as exc:
            # Re-raise to trigger DB transaction rollback
            raise StorageError("storage_write_failed") from exc

    # Audit logging
    audit_log(
        action_type="FILE_UPLOAD",
        event_category="DATA_ACCESS",
        target_model="ProtectedFile",
        target_object_id=str(protected_file.id),
        actor_user=user,
        metadata={
            "classification": protected_file.classification,
            "purpose": protected_file.purpose,
            "content_type": protected_file.content_type,
            "file_size_bytes": protected_file.file_size_bytes,
            "status": protected_file.status,
        }
    )

    return protected_file


def store_protected_file_from_path(
    user,
    source_path,
    *,
    original_filename: str,
    content_type: str,
    purpose: str,
    classification: str,
    app_label: str,
    model_name: str,
    object_id: str,
    access_policy_key: str,
    max_file_size_bytes: int,
) -> ProtectedFile:
    """Stream a trusted, prevalidated local source into protected storage."""
    source_path = os.fspath(source_path)
    stat = os.stat(source_path, follow_symlinks=False)
    if not os.path.isfile(source_path) or os.path.islink(source_path):
        raise SecurityError("recording_source_rejected")
    if stat.st_size <= 0 or stat.st_size > max_file_size_bytes:
        raise SecurityError("recording_size_rejected")

    digest = hashlib.sha256()
    with open(source_path, "rb") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)

    object_key = generate_opaque_object_key(purpose)
    adapter = get_storage_adapter()
    backend_alias = getattr(settings, "PROTECTED_STORAGE_BACKEND", "local")
    bucket_name = (
        "local-root"
        if backend_alias == "local"
        else getattr(settings, "PROTECTED_STORAGE_S3_BUCKET_NAME", "compass-private")
    )
    try:
        with open(source_path, "rb") as source:
            adapter.store_stream(object_key, source, content_type)
        with transaction.atomic():
            protected_file = ProtectedFile.objects.create(
                storage_backend_alias=backend_alias,
                bucket_name=bucket_name,
                object_key=object_key,
                original_filename_display=sanitize_display_filename(original_filename),
                content_type=content_type,
                file_size_bytes=stat.st_size,
                checksum_sha256=digest.hexdigest(),
                classification=classification,
                purpose=purpose,
                owning_app_label=app_label,
                owning_model_name=model_name,
                owning_object_id=str(object_id),
                access_policy_key=access_policy_key,
                created_by=user,
            )
    except Exception:
        try:
            adapter.delete(object_key)
        except Exception:
            pass
        raise

    audit_log(
        action_type="FILE_UPLOAD_STREAMED",
        event_category="DATA_ACCESS",
        target_model="ProtectedFile",
        target_object_id=str(protected_file.id),
        actor_user=user,
        metadata={
            "classification": protected_file.classification,
            "purpose": protected_file.purpose,
            "content_type": protected_file.content_type,
            "file_size_bytes": protected_file.file_size_bytes,
            "status": protected_file.status,
        },
    )
    return protected_file


def open_protected_file_range(user, file_id, start: int, end: int):
    protected_file = _get_authorized_active_file_for_content(user, file_id)
    adapter = get_storage_adapter()
    content, total = adapter.open_range(protected_file.object_key, start, end)
    return content, total, protected_file


def open_protected_file(user, file_id) -> tuple[bytes, ProtectedFile]:
    """
    Permission-checked retrieval of file binary content.
    Fails closed if the policy check fails.
    """
    protected_file = _get_authorized_active_file_for_content(user, file_id)

    adapter = get_storage_adapter()
    try:
        content = adapter.open(protected_file.object_key)
    except Exception as exc:
        raise StorageError("storage_read_failed") from exc

    # Audit success
    audit_log(
        action_type="FILE_ACCESS",
        event_category="DATA_ACCESS",
        target_model="ProtectedFile",
        target_object_id=str(protected_file.id),
        actor_user=user,
        metadata={
            "classification": protected_file.classification,
            "purpose": protected_file.purpose,
            "content_type": protected_file.content_type,
            "file_size_bytes": protected_file.file_size_bytes,
            "status": protected_file.status,
        }
    )

    return content, protected_file


def open_protected_file_stream(user, file_id):
    """Return authorized protected content as ``(stream, size, metadata)``.

    The policy lookup deliberately happens before the storage adapter is
    opened.  Callers own the returned stream and must close it after the
    response has finished sending it.
    """
    protected_file = _get_authorized_active_file_for_content(user, file_id)
    adapter = get_storage_adapter()
    try:
        stream, total_size = adapter.open_stream(protected_file.object_key)
    except Exception as exc:
        raise StorageError("storage_read_failed") from exc
    if int(total_size) != int(protected_file.file_size_bytes):
        try:
            stream.close()
        except Exception:
            pass
        raise StorageError("storage_size_mismatch")
    return stream, int(total_size), protected_file


def get_signed_url_or_proxy_fallback(user, file_id) -> str:
    """
    Permission-checked generation of signed URL or proxy fallback path.
    """
    protected_file = _get_authorized_active_file_for_content(user, file_id)

    adapter = get_storage_adapter()
    ttl = resolve_runtime_setting(
        "security.protected_storage",
        "PROTECTED_STORAGE_SIGNED_URL_TTL_SECONDS",
    )

    if adapter.has_signed_url_support():
        url = adapter.generate_signed_url(
            protected_file.object_key,
            ttl_seconds=ttl,
            original_filename="protected-file",
        )

        audit_log(
            action_type="SIGNED_URL_GENERATED",
            event_category="DATA_ACCESS",
            target_model="ProtectedFile",
            target_object_id=str(protected_file.id),
            actor_user=user,
            metadata={
                "ttl_seconds": ttl,
                "classification": protected_file.classification,
                "purpose": protected_file.purpose,
                "content_type": protected_file.content_type,
                "file_size_bytes": protected_file.file_size_bytes,
                "status": protected_file.status,
            }
        )
        return url
    else:
        # Proxy URL fallback using local view reverse
        proxy_url = reverse(
            "compass-api-v1:protected_file_download",
            args=[str(protected_file.id)],
        )

        return proxy_url


def archive_protected_file(user, file_id) -> ProtectedFile:
    """Transition a file to ARCHIVED status."""
    protected_file = get_active_protected_file(user, file_id)
    verify_file_access(user, protected_file, action="archive")

    protected_file.status = FileStatusChoices.ARCHIVED
    protected_file.archived_by = user
    protected_file.archived_at = datetime.datetime.now(datetime.timezone.utc)
    protected_file.save()

    audit_log(
        action_type="FILE_ARCHIVE",
        event_category="WORKFLOW",
        target_model="ProtectedFile",
        target_object_id=str(protected_file.id),
        actor_user=user,
        metadata={
            "classification": protected_file.classification,
            "purpose": protected_file.purpose,
        }
    )
    return protected_file


def delete_marker_protected_file(user, file_id) -> ProtectedFile:
    """Marks a file with a DELETED_MARKER status. Does not physically delete."""
    protected_file = get_active_protected_file(user, file_id)
    verify_file_access(user, protected_file, action="delete")

    if protected_file.retention_hold:
        raise SecurityError("Cannot delete file: Retention hold is active.")

    protected_file.status = FileStatusChoices.DELETED_MARKER
    protected_file.deleted_marker_at = datetime.datetime.now(datetime.timezone.utc)
    protected_file.save()

    audit_log(
        action_type="FILE_DELETE_MARKER",
        event_category="WORKFLOW",
        target_model="ProtectedFile",
        target_object_id=str(protected_file.id),
        actor_user=user,
        metadata={
            "classification": protected_file.classification,
            "purpose": protected_file.purpose,
        }
    )
    return protected_file
