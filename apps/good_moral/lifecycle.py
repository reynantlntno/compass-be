"""Lifecycle-derived Good Moral variant rules."""

from apps.good_moral.models import RequestTypeChoices
from apps.profiles.models import StudentLifecycleChoices


class GoodMoralVariantError(ValueError):
    """Raised when a request's immutable lifecycle snapshot is inconsistent."""


LIFECYCLE_REQUEST_TYPE = {
    StudentLifecycleChoices.ACTIVE: RequestTypeChoices.STUDENT,
    StudentLifecycleChoices.GRADUATING: RequestTypeChoices.STUDENT,
    StudentLifecycleChoices.GRADUATED: RequestTypeChoices.GRADUATE,
    StudentLifecycleChoices.ALUMNI: RequestTypeChoices.GRADUATE,
}

GRADUATION_DATE_REQUIRED_STATUSES = frozenset({
    StudentLifecycleChoices.GRADUATING,
    StudentLifecycleChoices.GRADUATED,
    StudentLifecycleChoices.ALUMNI,
})


def derive_request_type(student_profile):
    lifecycle_status = getattr(student_profile, "lifecycle_status", "")
    request_type = LIFECYCLE_REQUEST_TYPE.get(lifecycle_status)
    if request_type is None:
        raise GoodMoralVariantError(
            f"Good Moral requests are unavailable for lifecycle status {lifecycle_status!r}."
        )
    return request_type


def validate_request_variant(request):
    """Validate a persisted snapshot without rewriting historical data."""
    expected = LIFECYCLE_REQUEST_TYPE.get(request.applicant_lifecycle_status)
    if expected is None or request.request_type != expected:
        raise GoodMoralVariantError(
            "The recorded Good Moral variant does not match the applicant lifecycle snapshot."
        )
    if request.applicant_lifecycle_status in GRADUATION_DATE_REQUIRED_STATUSES and not request.applicant_graduation_date:
        raise GoodMoralVariantError(
            "A graduation date is required for graduating, graduated, or alumni requests."
        )
    return expected
