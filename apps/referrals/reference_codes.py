"""Referral-specific reference-code declaration."""

from apps.common.references import CANONICAL_REFERENCE_SPECS, allocate_reference_code
from apps.organizations.academic_year import resolve_current_academic_year


def generate_referral_reference_code() -> str:
    return allocate_reference_code(
        CANONICAL_REFERENCE_SPECS["REF"],
        resolve_current_academic_year(),
    )
