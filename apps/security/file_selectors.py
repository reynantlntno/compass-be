# Project: COMPASS
# File: apps/security/file_selectors.py
# Module: apps.security
# Purpose: Metadata queries and selectors for ProtectedFile records
# Domain boundary and service policy.

from django.core.exceptions import ObjectDoesNotExist, ValidationError
from apps.security.models import ProtectedFile, FileStatusChoices
from apps.security.file_policies import verify_file_access
from apps.security.exceptions import ProtectedFileNotFoundError, PolicyValidationError


class ProtectedFileMetadataDTO:
    """Safe data transfer object for protected file metadata. Omit object_key and credentials."""
    def __init__(self, protected_file: ProtectedFile):
        self.id = protected_file.id
        self.content_type = protected_file.content_type
        self.file_size_bytes = protected_file.file_size_bytes
        self.classification = protected_file.classification
        self.purpose = protected_file.purpose
        self.owning_app_label = protected_file.owning_app_label
        self.owning_model_name = protected_file.owning_model_name
        self.owning_object_id = protected_file.owning_object_id
        self.access_policy_key = protected_file.access_policy_key
        self.status = protected_file.status
        self.created_at = protected_file.created_at
        self.encryption_key_version = protected_file.encryption_key_version

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "content_type": self.content_type,
            "file_size_bytes": self.file_size_bytes,
            "classification": self.classification,
            "purpose": self.purpose,
            "owning_app_label": self.owning_app_label,
            "owning_model_name": self.owning_model_name,
            "owning_object_id": self.owning_object_id,
            "access_policy_key": self.access_policy_key,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "encryption_key_version": self.encryption_key_version,
        }


def get_protected_file_by_id(user, file_id) -> ProtectedFile:
    """
    Retrieves a ProtectedFile by ID.
    Performs verification checking for metadata visibility.
    Fails closed and avoids leaking metadata if not allowed.
    """
    try:
        protected_file = ProtectedFile.objects.get(id=file_id)
    except (ObjectDoesNotExist, ValidationError, ValueError):
        raise ProtectedFileNotFoundError("Protected file not found.")

    # Verify if user can inspect/view metadata
    verify_file_access(user, protected_file, action="read_metadata")
    return protected_file


def get_active_protected_file(user, file_id) -> ProtectedFile:
    """Retrieves an active ProtectedFile by ID, verifying permissions."""
    file_obj = get_protected_file_by_id(user, file_id)
    if file_obj.status != FileStatusChoices.ACTIVE:
        raise ProtectedFileNotFoundError("Protected file is not active.")
    return file_obj


def lookup_files_by_owner(user, app_label: str, model_name: str, object_id: str):
    """
    Retrieves all active ProtectedFiles matching the owner metadata tuple.
    Verifies user permissions before returning the files.
    """
    qs = ProtectedFile.objects.filter(
        owning_app_label=app_label,
        owning_model_name=model_name,
        owning_object_id=str(object_id),
        status=FileStatusChoices.ACTIVE,
    )

    allowed_files = []
    for f in qs:
        try:
            verify_file_access(user, f, action="read_metadata")
            allowed_files.append(f)
        except PolicyValidationError:
            continue

    return allowed_files
