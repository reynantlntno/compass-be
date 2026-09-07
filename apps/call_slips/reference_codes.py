"""Call-slip-specific reference-code declaration."""

from apps.common.references import CANONICAL_REFERENCE_SPECS, allocate_reference_code
from apps.organizations.academic_year import resolve_current_academic_year


def generate_call_slip_reference_code() -> str:
    return allocate_reference_code(
        CANONICAL_REFERENCE_SPECS["CSL"],
        resolve_current_academic_year(),
    )
