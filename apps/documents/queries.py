"""Model-free document metadata query boundary."""

from apps.documents.cache import (
    get_cached_document_family_metadata,
    get_cached_template_metadata,
    get_cached_template_version_metadata,
)

__all__ = [
    "get_cached_template_metadata",
    "get_cached_template_version_metadata",
    "get_cached_document_family_metadata",
]
