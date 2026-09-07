"""Shared human workflow reference-code mechanics."""

from .allocator import (
    CANONICAL_REFERENCE_SPECS,
    MAX_REFERENCE_SEQUENCE,
    ReferenceCodeSpec,
    academic_year_to_segment,
    allocate_reference_code,
    format_reference_code,
    validate_reference_code,
)

__all__ = [
    "CANONICAL_REFERENCE_SPECS",
    "MAX_REFERENCE_SEQUENCE",
    "ReferenceCodeSpec",
    "academic_year_to_segment",
    "allocate_reference_code",
    "format_reference_code",
    "validate_reference_code",
]
