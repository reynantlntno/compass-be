"""Governed catalog boundary for the student onboarding importer.

The importer never treats the public/demo catalog as institutional authority.
Local development may opt into the synthetic catalog so the workflow can be
demonstrated; staging and production must load an approved database catalog.
"""

from dataclasses import dataclass

from django.conf import settings
from django.core.exceptions import ValidationError

from apps.imports.models import (
    OnboardingCatalog,
    OnboardingCatalogAuthority,
    OnboardingProgram,
)


@dataclass(frozen=True)
class CatalogPlacement:
    program_code: str
    campus: str
    college: str
    department: str
    program: str
    max_year_level: int
    catalog_version: str
    demo_only: bool = False


def _environment() -> str:
    return str(getattr(settings, "COMPASS_ENVIRONMENT", "development") or "development").lower()


def _allow_demo_catalog() -> bool:
    return bool(getattr(settings, "COMPASS_ONBOARDING_ALLOW_DEMO_CATALOG", False)) and _environment() in {
        "development", "dev", "demo", "local", "testing", "test"
    }


def _demo_catalog() -> list[CatalogPlacement]:
    from apps.system.demo_catalog import UCN_CATALOG_VERSION, UCN_PROGRAM_CATALOG

    return [
        CatalogPlacement(
            program_code=item.key,
            campus=item.campus,
            college=item.college,
            department=item.department,
            program=item.program,
            max_year_level=item.levels,
            catalog_version=UCN_CATALOG_VERSION,
            demo_only=True,
        )
        for item in UCN_PROGRAM_CATALOG
    ]


def active_catalog() -> tuple[str, list[CatalogPlacement], bool]:
    """Return the active catalog version, placements, and demo marker.

    Raises a generic validation error instead of silently accepting arbitrary
    placement strings.  The error intentionally contains no student data.
    """
    configured_version = str(getattr(settings, "COMPASS_ONBOARDING_CATALOG_VERSION", "") or "").strip()
    query = OnboardingCatalog.objects.filter(is_active=True)
    if configured_version:
        query = query.filter(version=configured_version)
    active_catalogs = list(query.prefetch_related("programs").order_by("-updated_at", "-pk")[:2])
    if len(active_catalogs) > 1:
        raise ValidationError("Multiple active onboarding catalogs are configured.")
    catalog = active_catalogs[0] if active_catalogs else None
    if catalog:
        if catalog.authority == OnboardingCatalogAuthority.APPROVED and (
            not catalog.approved_at or not catalog.approved_by_id or not catalog.source_reference.strip()
        ):
            raise ValidationError("The approved onboarding catalog is missing approval metadata.")
        if catalog.authority == OnboardingCatalogAuthority.DEMO_ONLY and not _allow_demo_catalog():
            raise ValidationError("The onboarding catalog is demo-only and cannot be used here.")
        placements = [
            CatalogPlacement(
                program_code=program.program_code,
                campus=program.campus,
                college=program.college,
                department=program.department,
                program=program.program,
                max_year_level=program.max_year_level,
                catalog_version=catalog.version,
                demo_only=catalog.authority == OnboardingCatalogAuthority.DEMO_ONLY,
            )
            for program in catalog.programs.all()
            if program.is_active
        ]
        if not placements:
            raise ValidationError("The configured onboarding catalog has no active programs.")
        return catalog.version, placements, catalog.authority == OnboardingCatalogAuthority.DEMO_ONLY

    if _allow_demo_catalog():
        placements = _demo_catalog()
        return placements[0].catalog_version, placements, True

    raise ValidationError("An approved onboarding catalog is not configured.")


def placement_map() -> tuple[str, dict[str, CatalogPlacement], bool]:
    version, placements, demo_only = active_catalog()
    return version, {item.program_code.strip().upper(): item for item in placements}, demo_only


def seed_demo_catalog(*, replace: bool = False) -> OnboardingCatalog:
    """Populate the DB catalog from the existing synthetic demo catalog."""
    from apps.system.demo_catalog import UCN_CATALOG_VERSION, UCN_PROGRAM_CATALOG

    catalog, created = OnboardingCatalog.objects.get_or_create(
        version=UCN_CATALOG_VERSION,
        defaults={
            "authority": OnboardingCatalogAuthority.DEMO_ONLY,
            "is_active": True,
            "source_reference": "Synthetic UCN catalog; local demo only.",
        },
    )
    if not created and catalog.authority != OnboardingCatalogAuthority.DEMO_ONLY:
        raise ValidationError("The approved onboarding catalog cannot be replaced by demo data.")
    if not catalog.is_active:
        catalog.is_active = True
        catalog.save(update_fields=["is_active", "updated_at"])
    if replace:
        catalog.programs.all().delete()
    for item in UCN_PROGRAM_CATALOG:
        OnboardingProgram.objects.update_or_create(
            catalog=catalog,
            program_code=item.key,
            defaults={
                "campus": item.campus,
                "college": item.college,
                "department": item.department,
                "program": item.program,
                "max_year_level": item.levels,
                "is_active": True,
            },
        )
    return catalog
