"""Protected-file HTTP download boundary for API clients."""

from django.http import FileResponse

from apps.common.api.headers import apply_noindex_header
from apps.common.api.response_docs import binary_response_openapi
from apps.security.constants import PROTECTED_STORAGE_ALLOWED_CONTENT_TYPES
from apps.security.exceptions import PolicyValidationError, SecurityError, StorageError
from apps.security.file_services import (
    audit_proxy_download_served,
    open_protected_file_stream,
)


class ProtectedFileDownloadDenied(Exception):
    """Stable internal boundary for indistinguishable file denial responses."""


def protected_file_download_openapi() -> dict:
    """Return the OpenAPI fragment for protected-file content."""

    return binary_response_openapi(
        *sorted(PROTECTED_STORAGE_ALLOWED_CONTENT_TYPES),
        description="Authorized protected file content",
    )


def build_protected_file_download_response(user, file_id):
    """Return an authorized protected file as a bounded streaming response."""

    return build_protected_file_stream_download_response(
        user,
        file_id,
        filename="protected-file",
    )


def build_protected_file_stream_download_response(
    user,
    file_id,
    *,
    filename="ecounseling-recording",
):
    """Return an authorized protected file without buffering it in memory."""

    if not user or not user.is_authenticated:
        raise ProtectedFileDownloadDenied

    try:
        stream, total_size, protected_file = open_protected_file_stream(user, file_id)
        response = FileResponse(
            stream,
            as_attachment=True,
            filename=filename,
            content_type=protected_file.content_type,
        )
        response["Content-Length"] = str(total_size)
        response["Cache-Control"] = "no-store, private"
        response["Pragma"] = "no-cache"
        response["Expires"] = "0"
        response["X-Content-Type-Options"] = "nosniff"
        audit_proxy_download_served(user, protected_file)
        return apply_noindex_header(response)
    except (SecurityError, StorageError, PolicyValidationError) as exc:
        raise ProtectedFileDownloadDenied from exc
