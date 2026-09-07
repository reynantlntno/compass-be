"""Safe cached catalog metadata for onboarding display only."""

from apps.common.cache.backend import cached_read
from apps.common.cache.invalidation import invalidate_after_commit


def get_cached_onboarding_catalog_metadata() -> dict:
    def load():
        from apps.imports.catalog import active_catalog

        version, placements, demo_only = active_catalog()
        return {
            "version": version,
            "demo_only": bool(demo_only),
            "placements": [
                {
                    "program_code": item.program_code,
                    "campus": item.campus,
                    "college": item.college,
                    "department": item.department,
                    "program": item.program,
                    "max_year_level": item.max_year_level,
                    "catalog_version": item.catalog_version,
                }
                for item in placements
            ],
        }

    return cached_read("catalog_reference", "onboarding", ("onboarding",), load)


def invalidate_onboarding_catalog_after_commit() -> None:
    invalidate_after_commit("catalog_reference", "onboarding")
