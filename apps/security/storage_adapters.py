# Project: COMPASS
# File: apps/security/storage_adapters.py
# Module: apps.security
# Purpose: Storage adapter interface and concrete local/S3 private storage implementations
# Domain boundary and service policy.

import os
import hashlib
from pathlib import Path
from urllib.parse import urlparse
from django.conf import settings
from apps.security.exceptions import StorageError, ProtectedFileNotFoundError, StorageUnavailableError, SecurityError


def _copy_stream_to_path(stream, destination: Path, *, expected_size=None, expected_checksum=None) -> tuple[int, str]:
    """Copy a private object to disk without materializing its contents."""
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(destination.parent, 0o700)
    if destination.exists() or destination.is_symlink():
        raise StorageError("storage_destination_invalid")
    partial = destination.with_name(f".{destination.name}.partial")
    if partial.exists() or partial.is_symlink():
        raise StorageError("storage_destination_invalid")
    digest = hashlib.sha256()
    total = 0
    try:
        with partial.open("xb") as target:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                if type(chunk) is not bytes:
                    raise StorageError("storage_read_failed")
                total += len(chunk)
                if expected_size is not None and total > expected_size:
                    raise StorageError("storage_size_mismatch")
                digest.update(chunk)
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        checksum = digest.hexdigest()
        if expected_size is not None and total != expected_size:
            raise StorageError("storage_size_mismatch")
        if expected_checksum is not None and checksum != expected_checksum:
            raise StorageError("storage_checksum_mismatch")
        os.replace(partial, destination)
        os.chmod(destination, 0o600)
        return total, checksum
    finally:
        partial.unlink(missing_ok=True)


class BaseStorageAdapter:
    """Interface for protected storage adapters."""
    def store(self, object_key: str, content: bytes, content_type: str = None) -> None:
        """Stores binary content under the given object_key."""
        raise NotImplementedError("Subclasses must implement store()")

    def store_stream(self, object_key: str, stream, content_type: str = None) -> None:
        """Stores a seekable binary stream without loading it all into memory."""
        raise NotImplementedError("Subclasses must implement store_stream()")

    def copy_to_file(self, object_key: str, destination: Path, *, expected_size=None, expected_checksum=None) -> tuple[int, str]:
        """Stream an object to a private file and return size/checksum evidence."""
        raise NotImplementedError("Subclasses must implement copy_to_file()")

    def open(self, object_key: str) -> bytes:
        """Retrieves binary content for the given object_key."""
        raise NotImplementedError("Subclasses must implement open()")

    def open_stream(self, object_key: str):
        """Open protected content as a bounded stream and return its size.

        Implementations must return ``(stream, total_size)`` and leave closing
        the stream to the caller.  This keeps private-file delivery from
        loading a recording into process memory before it reaches the client.
        """
        raise NotImplementedError("Subclasses must implement open_stream()")

    def open_range(self, object_key: str, start: int, end: int) -> tuple[bytes, int]:
        """Returns an inclusive byte range and the total object size."""
        raise NotImplementedError("Subclasses must implement open_range()")

    def delete(self, object_key: str) -> None:
        """Deletes the object under the given object_key."""
        raise NotImplementedError("Subclasses must implement delete()")

    def generate_signed_url(self, object_key: str, ttl_seconds: int, original_filename: str = None) -> str:
        """Generates a temporary signed access URL. Returns None/empty if unsupported."""
        raise NotImplementedError("Subclasses must implement generate_signed_url()")

    def has_signed_url_support(self) -> bool:
        """Returns True if the adapter natively supports temporary signed URLs."""
        raise NotImplementedError("Subclasses must implement has_signed_url_support()")


class LocalStorageAdapter(BaseStorageAdapter):
    """Private storage adapter using local filesystem. Used for dev and testing."""
    def __init__(self):
        self.root_path = Path(settings.PROTECTED_STORAGE_LOCAL_ROOT).resolve()
        self.root_path.mkdir(parents=True, exist_ok=True)

    def _get_safe_path(self, object_key: str) -> Path:
        target_path = (self.root_path / object_key).resolve()
        try:
            # Enforce path traversal guard
            target_path.relative_to(self.root_path)
            return target_path
        except ValueError:
            raise SecurityError("storage_path_rejected")

    def store(self, object_key: str, content: bytes, content_type: str = None) -> None:
        target_path = self._get_safe_path(object_key)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(target_path, "wb") as f:
                f.write(content)
        except Exception as exc:
            raise StorageError("storage_write_failed") from exc

    def store_stream(self, object_key: str, stream, content_type: str = None) -> None:
        target_path = self._get_safe_path(object_key)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(target_path, "wb") as target:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    target.write(chunk)
        except Exception as exc:
            raise StorageError("storage_write_failed") from exc

    def open(self, object_key: str) -> bytes:
        target_path = self._get_safe_path(object_key)
        if not target_path.exists() or not target_path.is_file():
            raise ProtectedFileNotFoundError("storage_object_missing")
        try:
            with open(target_path, "rb") as f:
                return f.read()
        except Exception as exc:
            raise StorageError("storage_read_failed") from exc

    def open_stream(self, object_key: str):
        target_path = self._get_safe_path(object_key)
        if not target_path.exists() or not target_path.is_file():
            raise ProtectedFileNotFoundError("storage_object_missing")
        try:
            return open(target_path, "rb"), target_path.stat().st_size
        except Exception as exc:
            raise StorageError("storage_read_failed") from exc

    def copy_to_file(self, object_key: str, destination: Path, *, expected_size=None, expected_checksum=None) -> tuple[int, str]:
        source_path = self._get_safe_path(object_key)
        if not source_path.exists() or not source_path.is_file():
            raise ProtectedFileNotFoundError("storage_object_missing")
        try:
            with source_path.open("rb") as source:
                return _copy_stream_to_path(
                    source,
                    destination,
                    expected_size=expected_size,
                    expected_checksum=expected_checksum,
                )
        except (ProtectedFileNotFoundError, StorageError):
            raise
        except Exception as exc:
            raise StorageError("storage_read_failed") from exc

    def open_range(self, object_key: str, start: int, end: int) -> tuple[bytes, int]:
        target_path = self._get_safe_path(object_key)
        if not target_path.exists() or not target_path.is_file():
            raise ProtectedFileNotFoundError("storage_object_missing")
        total = target_path.stat().st_size
        if start < 0 or end < start or start >= total:
            raise SecurityError("storage_range_rejected")
        end = min(end, total - 1)
        try:
            with open(target_path, "rb") as source:
                source.seek(start)
                return source.read(end - start + 1), total
        except Exception as exc:
            raise StorageError("storage_read_failed") from exc

    def delete(self, object_key: str) -> None:
        target_path = self._get_safe_path(object_key)
        if target_path.exists() and target_path.is_file():
            try:
                target_path.unlink()
            except Exception as exc:
                raise StorageError("storage_delete_failed") from exc

    def generate_signed_url(self, object_key: str, ttl_seconds: int, original_filename: str = None) -> str:
        # Local storage doesn't support signed URLs natively. Proxy fallback is used.
        return ""

    def has_signed_url_support(self) -> bool:
        return False


class S3StorageAdapter(BaseStorageAdapter):
    """
    S3 compatible private storage adapter using boto3.
    Dynamically attempts to import boto3 so it remains optional in environments that don't need it.
    """
    def __init__(self):
        try:
            import boto3
            from botocore.config import Config
        except ImportError:
            raise StorageUnavailableError(
                "storage_provider_unavailable"
            )

        endpoint_url = settings.PROTECTED_STORAGE_S3_ENDPOINT_URL
        access_key = settings.PROTECTED_STORAGE_S3_ACCESS_KEY
        secret_key = settings.PROTECTED_STORAGE_S3_SECRET_KEY
        bucket_name = settings.PROTECTED_STORAGE_S3_BUCKET_NAME
        region_name = getattr(settings, "PROTECTED_STORAGE_S3_REGION_NAME", "us-east-1")
        addressing_style = getattr(settings, "PROTECTED_STORAGE_S3_ADDRESSING_STYLE", "path")

        if not endpoint_url or not access_key or not secret_key or not bucket_name:
            raise StorageUnavailableError("storage_provider_unavailable")
        parsed_endpoint = urlparse(str(endpoint_url))
        if (
            parsed_endpoint.scheme not in {"http", "https"}
            or not parsed_endpoint.netloc
            or parsed_endpoint.username
            or parsed_endpoint.password
        ):
            raise StorageUnavailableError("storage_provider_unavailable")

        try:
            self.s3_client = boto3.client(
                "s3",
                endpoint_url=endpoint_url,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region_name,
                config=Config(
                    signature_version="s3v4",
                    request_checksum_calculation="when_required",
                    response_checksum_validation="when_required",
                    s3={
                        "addressing_style": addressing_style,
                        "payload_signing_enabled": False,
                    },
                ),
                use_ssl=settings.PROTECTED_STORAGE_S3_USE_SSL,
            )
            self.bucket_name = bucket_name
        except Exception as exc:
            raise StorageUnavailableError("storage_provider_unavailable") from exc

    def store(self, object_key: str, content: bytes, content_type: str = None) -> None:
        extra_args = {}
        if content_type:
            extra_args["ContentType"] = content_type

        try:
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=object_key,
                Body=content,
                **extra_args
            )
        except Exception as exc:
            raise StorageError("storage_write_failed") from exc

    def store_stream(self, object_key: str, stream, content_type: str = None) -> None:
        extra_args = {"ContentType": content_type} if content_type else {}
        try:
            kwargs = {"ExtraArgs": extra_args} if extra_args else {}
            self.s3_client.upload_fileobj(stream, self.bucket_name, object_key, **kwargs)
        except Exception as exc:
            raise StorageError("storage_write_failed") from exc

    def open(self, object_key: str) -> bytes:
        try:
            response = self.s3_client.get_object(Bucket=self.bucket_name, Key=object_key)
            return response["Body"].read()
        except Exception as exc:
            # Check for NoSuchKey in dynamic client exception or standard ClientError response
            error_name = exc.__class__.__name__
            if error_name == "NoSuchKey":
                raise ProtectedFileNotFoundError("storage_object_missing") from exc
            if hasattr(exc, "response") and isinstance(exc.response, dict):
                code = exc.response.get("Error", {}).get("Code")
                if code == "NoSuchKey":
                    raise ProtectedFileNotFoundError("storage_object_missing") from exc
            raise StorageError("storage_read_failed") from exc

    def open_stream(self, object_key: str):
        stream = None
        try:
            response = self.s3_client.get_object(Bucket=self.bucket_name, Key=object_key)
            stream = response["Body"]
            total = int(response["ContentLength"])
            return stream, total
        except Exception as exc:
            if stream is not None:
                try:
                    stream.close()
                except Exception:
                    pass
            if hasattr(exc, "response") and isinstance(exc.response, dict):
                code = exc.response.get("Error", {}).get("Code")
                if code == "NoSuchKey":
                    raise ProtectedFileNotFoundError("storage_object_missing") from exc
            raise StorageError("storage_read_failed") from exc

    def copy_to_file(self, object_key: str, destination: Path, *, expected_size=None, expected_checksum=None) -> tuple[int, str]:
        try:
            response = self.s3_client.get_object(Bucket=self.bucket_name, Key=object_key)
            body = response["Body"]
            try:
                content_length = response.get("ContentLength")
                if expected_size is not None and content_length is not None and int(content_length) != expected_size:
                    raise StorageError("storage_size_mismatch")
                return _copy_stream_to_path(
                    body,
                    destination,
                    expected_size=expected_size,
                    expected_checksum=expected_checksum,
                )
            finally:
                close = getattr(body, "close", None)
                if callable(close):
                    close()
        except (ProtectedFileNotFoundError, StorageError):
            raise
        except Exception as exc:
            error_name = exc.__class__.__name__
            if error_name == "NoSuchKey" or (
                hasattr(exc, "response")
                and isinstance(exc.response, dict)
                and exc.response.get("Error", {}).get("Code") == "NoSuchKey"
            ):
                raise ProtectedFileNotFoundError("storage_object_missing") from exc
            raise StorageError("storage_read_failed") from exc

    def open_range(self, object_key: str, start: int, end: int) -> tuple[bytes, int]:
        try:
            response = self.s3_client.get_object(
                Bucket=self.bucket_name,
                Key=object_key,
                Range=f"bytes={start}-{end}",
            )
            total = int(response["ContentRange"].rsplit("/", 1)[1])
            return response["Body"].read(), total
        except Exception as exc:
            raise StorageError("storage_read_failed") from exc

    def delete(self, object_key: str) -> None:
        try:
            self.s3_client.delete_object(Bucket=self.bucket_name, Key=object_key)
        except Exception as exc:
            raise StorageError("storage_delete_failed") from exc

    def generate_signed_url(self, object_key: str, ttl_seconds: int, original_filename: str = None) -> str:
        params = {
            "Bucket": self.bucket_name,
            "Key": object_key,
        }
        if original_filename:
            # Force download disposition with sanitized name
            sanitized_name = "".join(c for c in original_filename if c.isalnum() or c in "._-")
            params["ResponseContentDisposition"] = f"attachment; filename=\"{sanitized_name}\""

        try:
            url = self.s3_client.generate_presigned_url(
                "get_object",
                Params=params,
                ExpiresIn=ttl_seconds
            )
            return url
        except Exception as exc:
            raise StorageError("storage_signing_unavailable") from exc

    def has_signed_url_support(self) -> bool:
        return True


def get_storage_adapter() -> BaseStorageAdapter:
    """Factory function to instantiate the active storage adapter based on settings."""
    backend = getattr(settings, "PROTECTED_STORAGE_BACKEND", "local").lower()
    if backend == "local":
        return LocalStorageAdapter()
    elif backend == "s3":
        return S3StorageAdapter()
    else:
        raise StorageError("storage_backend_unknown")
