from datetime import timedelta

from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.account_security.audit import log_security_event
from apps.governance.runtime_config import resolve_runtime_setting


ASSURANCE_SESSION_KEY = "compass_internal_assurance"
ASSURANCE_POLICY_VERSION = "internal-2fa-v1"
ASSURANCE_CONTEXT = "internal_required"
ASSURANCE_METHODS = frozenset({"otp", "trusted_device"})


def _assurance_max_age_seconds() -> int:
    return int(resolve_runtime_setting(
        "security.account_security_controls",
        "ACCOUNT_SECURITY_ASSURANCE_MAX_AGE_SECONDS",
    ))


def build_internal_assurance_marker(user, *, method, verified_at=None):
    if method not in ASSURANCE_METHODS:
        raise ValueError("Unsupported internal assurance method.")
    verified_at = verified_at or timezone.now()
    return {
        "user_id": str(user.pk),
        "role": str(getattr(user, "role", "")),
        "is_superuser": bool(getattr(user, "is_superuser", False)),
        "security_stamp": str(user.auth_security_stamp),
        "policy_version": ASSURANCE_POLICY_VERSION,
        "context": ASSURANCE_CONTEXT,
        "method": method,
        "verified_at": verified_at.isoformat(),
    }


def establish_internal_assurance(request, user, *, method, ip=None, user_agent=None):
    request.session[ASSURANCE_SESSION_KEY] = build_internal_assurance_marker(
        user, method=method
    )
    log_security_event(
        action_type="internal_assurance_established",
        target_model="accounts.User",
        target_object_id=str(user.pk),
        actor_user=user,
        ip_address=ip,
        user_agent=user_agent,
        metadata={
            "assurance_method": method,
            "assurance_version": ASSURANCE_POLICY_VERSION,
            "assurance_context": ASSURANCE_CONTEXT,
        },
    )


def clear_internal_assurance(request):
    request.session.pop(ASSURANCE_SESSION_KEY, None)


def validate_internal_assurance_marker(user, marker):
    if not isinstance(marker, dict):
        return False, "missing_or_malformed"
    expected = {
        "user_id": str(user.pk),
        "role": str(getattr(user, "role", "")),
        "is_superuser": bool(getattr(user, "is_superuser", False)),
        "security_stamp": str(user.auth_security_stamp),
        "policy_version": ASSURANCE_POLICY_VERSION,
        "context": ASSURANCE_CONTEXT,
    }
    for key, expected_value in expected.items():
        if marker.get(key) != expected_value:
            return False, f"mismatched_{key}"
    if marker.get("method") not in ASSURANCE_METHODS:
        return False, "unsupported_method"
    verified_at = marker.get("verified_at")
    if not isinstance(verified_at, str):
        return False, "invalid_verified_at"
    parsed = parse_datetime(verified_at)
    if parsed is None or timezone.is_naive(parsed):
        return False, "invalid_verified_at"
    now = timezone.now()
    max_age = _assurance_max_age_seconds()
    if parsed > now + timedelta(minutes=5) or parsed < now - timedelta(seconds=max_age):
        return False, "stale_verified_at"
    return True, "valid"


def validate_api_token_assurance(user, token):
    """Validate fresh internal assurance carried by an already verified token.

    The token has already been resolved by the API authentication boundary,
    but the security-sensitive lifecycle fields are rechecked here before an
    assured internal mutation is allowed.
    """

    if token is None:
        return False, "missing_token"

    from apps.account_security.models import ApiTokenStatusChoices, ApiTokenTypeChoices

    if getattr(token, "status", None) != ApiTokenStatusChoices.ACTIVE:
        return False, "inactive_token"
    if getattr(token, "token_type", None) != ApiTokenTypeChoices.ACCESS:
        return False, "wrong_token_type"
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

    issued_at = getattr(token, "issued_at", None)
    if issued_at is None or timezone.is_naive(issued_at):
        return False, "invalid_issued_at"
    now = timezone.now()
    if issued_at > now + timedelta(minutes=5) or issued_at < now - timedelta(seconds=_assurance_max_age_seconds()):
        return False, "stale_issued_at"
    return True, "valid"


def validate_internal_assurance_token(user, token):
    """Backward-compatible name for token assurance validation."""

    return validate_api_token_assurance(user, token)


def validate_request_assurance(user, *, marker=None, token=None):
    """Accept a validated Django-session marker or fresh token evidence."""

    assured, reason = validate_internal_assurance_marker(user, marker)
    if assured:
        return True, reason
    return validate_api_token_assurance(user, token)
