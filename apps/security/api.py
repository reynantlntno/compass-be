"""Protected-file operations for API v1."""

from __future__ import annotations

from uuid import UUID

from ninja import Router

from apps.common.api.operations import prepare_api_operation
from apps.common.exceptions import NotFoundError
from apps.security.downloads import (
    ProtectedFileDownloadDenied,
    build_protected_file_download_response,
    protected_file_download_openapi,
)


router = Router(tags=["files"])


@router.get(
    "/{file_id}/download/",
    response=None,
    openapi_extra=protected_file_download_openapi(),
    operation_id="protected_file_download",
)
def protected_file_download(request, file_id: UUID):
    prepare_api_operation(request, "protected_file_download")
    try:
        return build_protected_file_download_response(request.auth.user, file_id)
    except ProtectedFileDownloadDenied:
        raise NotFoundError()
