"""Canonical academic-year resolution for term-sensitive workflows.

``AcademicTerm(status=ACTIVE)`` is the only source of truth for the current
academic year.  This module deliberately does not provide a date-based
fallback or consult a compatibility projection.
"""

from __future__ import annotations

import re

from apps.common.exceptions import CompassError


ACADEMIC_YEAR_PATTERN = re.compile(r"\A\d{4}-\d{4}\Z")


class AcademicYearConfigurationError(CompassError):
    """Raised when the active academic-term configuration is not resolvable."""


def validate_academic_year(value: str) -> str:
    """Validate and return a canonical consecutive ``YYYY-YYYY`` value."""

    if not isinstance(value, str) or not value.strip():
        raise AcademicYearConfigurationError("Academic year must be a non-blank string.")

    normalized = value.strip()
    if not ACADEMIC_YEAR_PATTERN.fullmatch(normalized):
        raise AcademicYearConfigurationError(
            "Academic year must match YYYY-YYYY format (e.g. 2025-2026)."
        )

    start_year, end_year = (int(part) for part in normalized.split("-"))
    if end_year - start_year != 1:
        raise AcademicYearConfigurationError(
            "Academic year years must be consecutive (e.g. 2025-2026)."
        )
    return normalized


def get_current_academic_term():
    """Return the one active academic term, failing closed if ambiguous/missing."""

    from apps.organizations.models import AcademicTerm, AcademicTermStatusChoices

    active_terms = list(
        AcademicTerm.objects.filter(status=AcademicTermStatusChoices.ACTIVE)
        .only("id", "academic_year", "status")[:2]
    )
    if not active_terms:
        raise AcademicYearConfigurationError(
            "No active academic term is configured."
        )
    if len(active_terms) > 1:
        raise AcademicYearConfigurationError(
            "More than one active academic term is configured."
        )
    return active_terms[0]


def resolve_current_academic_year() -> str:
    """Return the validated academic year from the active AcademicTerm."""

    return validate_academic_year(get_current_academic_term().academic_year)
