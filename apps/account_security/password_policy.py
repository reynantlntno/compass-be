"""Shared password policy enforcement for account-security flows.

The configured Django validators remain the source of truth.  This module
keeps their framework-specific errors behind the account-security boundary so
API callers receive bounded, safe guidance rather than validator internals.
"""

from __future__ import annotations

from django.contrib.auth.hashers import check_password
from django.contrib.auth.password_validation import validate_password

from apps.common.django_adapters import ModelValidationError
from apps.common.exceptions import ValidationError


PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 512
PASSWORD_POLICY_ERROR = "The password does not meet the account requirements."
PASSWORD_REUSE_ERROR = "The new password must be different."


def _password_validation_error(message: str = PASSWORD_POLICY_ERROR) -> ValidationError:
    return ValidationError(field_errors={"new_password": [message]})


def validate_new_password(
    password: str,
    *,
    user=None,
    reject_reuse: bool = False,
) -> None:
    """Validate a new password against the configured account policy.

    ``user`` is intentionally optional because recovery requests are checked
    once before token resolution and again after the token identifies the
    account.  The second check enables user-attribute similarity validation
    and, when requested, rejection of the current password.
    """
    if type(password) is not str or not password or len(password) > PASSWORD_MAX_LENGTH:
        raise _password_validation_error()

    try:
        validate_password(password, user=user)
    except ModelValidationError as exc:
        raise _password_validation_error() from exc

    if reject_reuse and user is not None and check_password(password, user.password):
        raise _password_validation_error(PASSWORD_REUSE_ERROR)

