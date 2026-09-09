"""Safe account-facing access-control projections."""

from apps.access_control.models import CounselorCoverage


_SCOPE_LABEL_FIELDS = (
    ("Campus", "campus"),
    ("College", "college"),
    ("Department", "department"),
    ("Program", "program"),
)
MAX_SCOPE_LABEL_LENGTH = 240


def _scope_label(coverage: CounselorCoverage) -> str:
    parts = [
        f"{label}: {value.strip()}"
        for label, field in _SCOPE_LABEL_FIELDS
        if (value := getattr(coverage, field, None) or "").strip()
    ]
    if not parts:
        return "All current coverage"
    return "; ".join(parts)[:MAX_SCOPE_LABEL_LENGTH]


def project_counselor_coverage(coverage: CounselorCoverage) -> dict[str, object]:
    """Expose only the current counselor's safe organizational scope."""

    return {
        "scope_label": _scope_label(coverage),
        "campus": coverage.campus,
        "college": coverage.college,
        "department": coverage.department,
        "program": coverage.program,
        "is_primary": coverage.is_primary,
    }
