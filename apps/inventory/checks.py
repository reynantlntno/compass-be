"""Strict, shared validation for Release 1 inventory compatibility settings."""

from dataclasses import dataclass
from datetime import datetime, timezone as datetime_timezone
import re

from django.conf import settings
from django.core import checks
from django.utils import timezone


_DEADLINE_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
CONFIGURATION_INVALID = "inventory_compatibility_configuration_invalid"
DEADLINE_EXPIRED = "inventory_compatibility_deadline_expired"
COMPATIBILITY_AVAILABLE = "inventory_compatibility_available"
COMPATIBILITY_DISABLED = "inventory_compatibility_disabled"


@dataclass(frozen=True)
class InventoryCompatibilityConfiguration:
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
    if normalized.strftime("%Y-%m-%dT%H:%M:%SZ") != raw:
        return None
    return normalized


def validate_inventory_compatibility_settings(*, now=None, settings_obj=settings):
    """Return a normalized, content-free result without DB or secret reads."""
    enabled = getattr(settings_obj, "INVENTORY_ENCRYPTION_COMPATIBILITY_ENABLED", False)
    raw_deadline = getattr(settings_obj, "INVENTORY_ENCRYPTION_COMPATIBILITY_DEADLINE", None)
    if enabled is False:
        return InventoryCompatibilityConfiguration(
            enabled=False,
            deadline=None,
            valid=True,
            expired=False,
            result_code=COMPATIBILITY_DISABLED,
        )
    if enabled is not True:
        return InventoryCompatibilityConfiguration(
            enabled=False,
            deadline=None,
            valid=False,
            expired=False,
            result_code=CONFIGURATION_INVALID,
        )
    deadline = _parse_deadline(raw_deadline)
    if deadline is None:
        return InventoryCompatibilityConfiguration(
            enabled=True,
            deadline=None,
            valid=False,
            expired=False,
            result_code=CONFIGURATION_INVALID,
        )
    current = now if now is not None else timezone.now()
    if not timezone.is_aware(current):
        return InventoryCompatibilityConfiguration(
            enabled=True,
            deadline=deadline,
            valid=False,
            expired=False,
            result_code=CONFIGURATION_INVALID,
        )
    expired = current >= deadline
    return InventoryCompatibilityConfiguration(
        enabled=True,
        deadline=deadline,
        valid=True,
        expired=expired,
        result_code=DEADLINE_EXPIRED if expired else COMPATIBILITY_AVAILABLE,
    )


@checks.register(checks.Tags.security)
def inventory_encryption_compatibility_check(app_configs, **kwargs):
    result = validate_inventory_compatibility_settings()
    if not result.valid:
        return [
            checks.Error(
                "Inventory encryption compatibility configuration is invalid.",
                id="inventory.E001",
            )
        ]
    return []
