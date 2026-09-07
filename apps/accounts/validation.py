"""Account-bound input validation adapters.

Framework validators are translated here at the application boundary so
account services only depend on Compass domain errors.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import validate_email

from apps.common.exceptions import ValidationError


def normalize_staff_email(value: object) -> str:
    """Normalize and validate a staff email as a Compass domain value."""

    if type(value) is not str:
        raise ValidationError("A valid email address is required.")
    email = value.strip().lower()
    try:
        validate_email(email)
    except DjangoValidationError as exc:
        raise ValidationError("A valid email address is required.") from exc
    return email
