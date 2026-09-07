"""Strict Release 1 referral compatibility configuration validation."""

from dataclasses import dataclass
from datetime import datetime, timezone as datetime_timezone
import re

from django.conf import settings
from django.core import checks
from django.utils import timezone


_DEADLINE_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
CONFIGURATION_INVALID = "referrals_compatibility_configuration_invalid"
DEADLINE_EXPIRED = "referrals_compatibility_deadline_expired"
COMPATIBILITY_AVAILABLE = "referrals_compatibility_available"
COMPATIBILITY_DISABLED = "referrals_compatibility_disabled"


@dataclass(frozen=True)
class ReferralCompatibilityConfiguration:
    enabled: bool
    deadline: datetime | None
    valid: bool
    expired: bool
    result_code: str

    @property
    def permits_legacy_fallback(self):
        return self.valid and self.enabled and not self.expired


def _parse_deadline(raw):
    if type(raw) is not str or not _DEADLINE_RE.fullmatch(raw):
        return None
    try:
        parsed = datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None
    normalized = parsed.replace(tzinfo=datetime_timezone.utc)
    return normalized if normalized.strftime("%Y-%m-%dT%H:%M:%SZ") == raw else None


def validate_referral_compatibility_settings(*, now=None, settings_obj=settings):
    """Validate settings without database, key-provider, or secret-store reads."""
    enabled = getattr(settings_obj, "REFERRALS_ENCRYPTION_COMPATIBILITY_ENABLED", False)
    raw_deadline = getattr(settings_obj, "REFERRALS_ENCRYPTION_COMPATIBILITY_DEADLINE", None)
    if enabled is False:
        return ReferralCompatibilityConfiguration(
            False, None, True, False, COMPATIBILITY_DISABLED
        )
    if enabled is not True:
        return ReferralCompatibilityConfiguration(
            False, None, False, False, CONFIGURATION_INVALID
        )
    deadline = _parse_deadline(raw_deadline)
    if deadline is None:
        return ReferralCompatibilityConfiguration(
            True, None, False, False, CONFIGURATION_INVALID
        )
    current = now if now is not None else timezone.now()
    if not timezone.is_aware(current):
        return ReferralCompatibilityConfiguration(
            True, deadline, False, False, CONFIGURATION_INVALID
        )
    expired = current >= deadline
    return ReferralCompatibilityConfiguration(
        True,
        deadline,
        True,
        expired,
        DEADLINE_EXPIRED if expired else COMPATIBILITY_AVAILABLE,
    )


@checks.register(checks.Tags.security)
def referral_encryption_compatibility_check(app_configs, **kwargs):
    result = validate_referral_compatibility_settings()
    if result.valid and not result.expired:
        return []
    message = (
        "Referral encryption compatibility deadline has expired."
        if result.expired
        else "Referral encryption compatibility configuration is invalid."
    )
    return [checks.Error(message, id="referrals.E001")]
