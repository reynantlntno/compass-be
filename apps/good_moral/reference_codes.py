"""Good Moral reference-code declaration."""

from apps.common.references import CANONICAL_REFERENCE_SPECS, allocate_reference_code


def generate_good_moral_reference_code(academic_year: str) -> str:
    return allocate_reference_code(CANONICAL_REFERENCE_SPECS["GMC"], academic_year)
