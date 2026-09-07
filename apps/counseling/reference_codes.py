"""Counseling-specific reference-code declarations."""

from apps.common.references import CANONICAL_REFERENCE_SPECS, allocate_reference_code
from apps.organizations.academic_year import resolve_current_academic_year


def _allocate(prefix: str, period_key: str | None = None) -> str:
    return allocate_reference_code(
        CANONICAL_REFERENCE_SPECS[prefix],
        period_key or resolve_current_academic_year(),
    )


def generate_session_reference_code() -> str:
    return _allocate("SES")


def generate_counseling_case_reference_code() -> str:
    return _allocate("CAS")


def generate_ecounseling_reference_code() -> str:
    return _allocate("ECS")


def generate_urgent_support_request_reference_code() -> str:
    return _allocate("ESC")
