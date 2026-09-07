"""Strict Release 1 Call Slip compatibility configuration validation."""

from dataclasses import dataclass
from datetime import datetime, timezone as datetime_timezone
import re

from django.conf import settings
from django.core import checks
from django.utils import timezone


_DEADLINE_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
CONFIGURATION_INVALID = "call_slips_compatibility_configuration_invalid"
DEADLINE_EXPIRED = "call_slips_compatibility_deadline_expired"
COMPATIBILITY_AVAILABLE = "call_slips_compatibility_available"
COMPATIBILITY_DISABLED = "call_slips_compatibility_disabled"


@dataclass(frozen=True)
class CallSlipCompatibilityConfiguration:
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


def validate_call_slip_compatibility_settings(*, now=None, settings_obj=settings):
    enabled = getattr(settings_obj, "CALL_SLIPS_ENCRYPTION_COMPATIBILITY_ENABLED", False)
    raw_deadline = getattr(settings_obj, "CALL_SLIPS_ENCRYPTION_COMPATIBILITY_DEADLINE", None)
    if enabled is False:
        return CallSlipCompatibilityConfiguration(False, None, True, False, COMPATIBILITY_DISABLED)
    if enabled is not True:
        return CallSlipCompatibilityConfiguration(False, None, False, False, CONFIGURATION_INVALID)
    deadline = _parse_deadline(raw_deadline)
    if deadline is None:
        return CallSlipCompatibilityConfiguration(True, None, False, False, CONFIGURATION_INVALID)
    current = now if now is not None else timezone.now()
    if not timezone.is_aware(current):
        return CallSlipCompatibilityConfiguration(True, deadline, False, False, CONFIGURATION_INVALID)
    expired = current >= deadline
    return CallSlipCompatibilityConfiguration(
        True, deadline, True, expired,
        DEADLINE_EXPIRED if expired else COMPATIBILITY_AVAILABLE,
    )


@checks.register(checks.Tags.security)
def call_slip_encryption_compatibility_check(app_configs, **kwargs):
    result = validate_call_slip_compatibility_settings()
    if result.valid and not result.expired:
        return []
    message = (
        "Call Slip encryption compatibility deadline has expired."
        if result.expired
        else "Call Slip encryption compatibility configuration is invalid."
    )
    return [checks.Error(message, id="call_slips.E001")]
