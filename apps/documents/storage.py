# Project: COMPASS
# File: apps/documents/storage.py
# Module: apps.documents
# Purpose: Narrow storage wrappers delegating to apps.security
# Domain boundary and service policy.
# Notes:
#   Generated outputs use apps.security.ProtectedFile.
#   No direct MEDIA_URL, no .url private file exposure, no public object URLs.
#   Generic safe filenames by default (e.g. 'generated-document.pdf').
#   No PII in object keys, filenames, or storage paths.

from apps.security.file_services import store_protected_file
from apps.security.models import PurposeChoices, ClassificationChoices


def store_generated_document_file(
    *,
    user,
    content: bytes,
    content_type: str,
    generated_document,
    classification: str = ClassificationChoices.OFFICIAL_RECORD,
):
    """Store a generated document output through apps.security.

    Uses generic safe filenames. No PII in filenames or object keys.

    Args:
        user: The user performing the action.
        content: The rendered file content bytes.
        content_type: MIME type of the file (e.g. 'application/pdf', 'text/html').
        generated_document: The GeneratedDocument instance.
        classification: Security classification for the file.

    Returns:
        The created ProtectedFile instance.
    """
    # Determine safe generic filename based on content type
    if content_type == "application/pdf":
        safe_filename = "generated-document.pdf"
    elif content_type == "text/html":
        safe_filename = "generated-document.html"
    else:
        safe_filename = "generated-document"

    return store_protected_file(
        user=user,
        content=content,
        original_filename=safe_filename,
        content_type=content_type,
        purpose=PurposeChoices.GENERATED_DOCUMENT,
        classification=classification,
        app_label="documents",
        model_name="GeneratedDocument",
        object_id=str(generated_document.pk),
        access_policy_key=generated_document.access_policy_key or "generated_document",
    )
