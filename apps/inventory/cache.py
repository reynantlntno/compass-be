"""Safe cache for current academic-term display metadata."""

from apps.common.cache.backend import cached_read
from apps.common.cache.invalidation import invalidate_after_commit


def get_cached_current_academic_term_metadata() -> dict:
    def load():
        from apps.organizations.academic_year import AcademicYearConfigurationError, get_current_academic_term

        try:
            term = get_current_academic_term()
        except AcademicYearConfigurationError:
            return {}
        return {
            "id": str(term.pk),
            "academic_year": term.academic_year,
            "semester": term.semester,
            "start_date": term.start_date.isoformat(),
            "end_date": term.end_date.isoformat(),
            "status": term.status,
            "is_current": True,
        }

    return cached_read("catalog_reference", "academic-term", ("academic-term",), load)


def invalidate_academic_term_after_commit() -> None:
    invalidate_after_commit("catalog_reference", "academic-term")
