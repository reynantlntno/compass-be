"""Fresh OTP assurance for API sessions.

Remembered devices are intentionally excluded from this module: they are a
login convenience and never satisfy a sensitive-operation step-up.
"""

from datetime import timedelta

from django.utils import timezone

from apps.governance.runtime_config import resolve_runtime_setting


ASSURANCE_POLICY_VERSION = "internal-2fa-v1"
ASSURANCE_CONTEXT = "internal_required"


def _sensitive_assurance_max_age_seconds() -> int:
    return int(
        resolve_runtime_setting(
            "security.account_security_controls",
            "ACCOUNT_SECURITY_SENSITIVE_ASSURANCE_MAX_AGE_SECONDS",
        )
    )


def validate_api_session_assurance(user, session):
    """Validate OTP provenance stored on the real token-family session."""

    if session is None:
        return False, "missing_session"
    from apps.account_security.models import (
        ApiSessionAuthenticationMethodChoices,
        ApiSessionStatusChoices,
    )

    if getattr(session, "user_id", None) != getattr(user, "pk", None):
        return False, "mismatched_user"
    if getattr(session, "status", "") != ApiSessionStatusChoices.ACTIVE:
        return False, "inactive_session"
    absolute_expires_at = getattr(session, "absolute_expires_at", None)
    if absolute_expires_at is None or absolute_expires_at <= timezone.now():
        return False, "expired_session"
    if str(getattr(session, "security_stamp", "")) != str(getattr(user, "auth_security_stamp", "")):
        return False, "mismatched_security_stamp"
    if getattr(session, "authentication_method", "") != ApiSessionAuthenticationMethodChoices.OTP:
        return False, "otp_required"
    verified_at = getattr(session, "last_otp_verified_at", None)
    if verified_at is None or timezone.is_naive(verified_at):
        return False, "missing_otp_provenance"
    now = timezone.now()
    if verified_at > now + timedelta(minutes=5):
        return False, "future_otp_verified_at"
    if verified_at < now - timedelta(seconds=_sensitive_assurance_max_age_seconds()):
        return False, "stale_otp_verified_at"
    return True, "valid"


def validate_api_token_assurance(user, token):
    """Validate fresh OTP assurance through an already-resolved access token."""

    if token is None:
        return False, "missing_token"
    from apps.account_security.models import ApiTokenStatusChoices, ApiTokenTypeChoices

    if getattr(token, "status", None) != ApiTokenStatusChoices.ACTIVE:
        return False, "inactive_token"
    if getattr(token, "token_type", None) != ApiTokenTypeChoices.ACCESS:
        return False, "wrong_token_type"
    token_expires_at = getattr(token, "expires_at", None)
    if token_expires_at is None or token_expires_at <= timezone.now():
        return False, "expired_token"
    if str(getattr(token, "user_id", "")) != str(user.pk):
        return False, "mismatched_user"
    if not getattr(user, "is_active", False) or getattr(user, "is_superuser", False):
        return False, "ineligible_user"
    if str(getattr(token, "security_stamp", "")) != str(getattr(user, "auth_security_stamp", "")):
        return False, "mismatched_security_stamp"
    if getattr(token, "assurance_policy_version", "") != ASSURANCE_POLICY_VERSION:
        return False, "mismatched_policy_version"
    if getattr(token, "assurance_context", "") != ASSURANCE_CONTEXT:
        return False, "mismatched_context"
    return validate_api_session_assurance(user, getattr(token, "session", None))


def validate_internal_assurance_token(user, token):
    """Backward-compatible name for the API-session validator."""

    return validate_api_token_assurance(user, token)


def validate_request_assurance(user, *, token=None):
    """Validate only the authenticated API token family's OTP provenance."""

    return validate_api_token_assurance(user, token)
