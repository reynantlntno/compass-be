"""Typed access helpers for central, non-secret runtime controls."""

from django.conf import settings
from django.db import DatabaseError

from apps.governance.selectors import resolve_effective_policy
from config.runtime_settings import get_runtime_setting_spec


RUNTIME_SETTING_TARGET_TYPE = "governance.RuntimeSetting"


def is_policy_active(policy_key: str, *, target=None, target_type: str = "", target_reference: str = "", at=None) -> bool:
    """Return whether a governed control is currently active.

    Marker policies are intentionally small typed records.  Their effective
    presence is the runtime gate for the corresponding domain governance
    surface; they do not replace object-level authorization.
    """
    return resolve_effective_policy(
        policy_key,
        target=target,
        target_type=target_type,
        target_reference=target_reference,
        at=at,
    ) is not None


def resolve_runtime_setting(policy_key: str, setting_key: str, *, at=None):
    """Return the effective value using the setting's declared source.

    Environment-owned technical controls are read from typed Django settings;
    legacy PolicyRecord rows for those keys are intentionally ignored. Policy-
    owned controls continue through Governance and use the code-owned default
    when the database is unavailable or malformed.
    """
    spec = get_runtime_setting_spec(setting_key)
    default = spec.default
    if spec.source == "environment":
        value = getattr(settings, setting_key, default)
        try:
            return spec.validate(value)
        except ValueError:
            # Startup settings are validated by config.settings; this fallback
            # protects health checks and test overrides from unsafe values.
            return default

    try:
        policy = resolve_effective_policy(
            policy_key,
            target_type=RUNTIME_SETTING_TARGET_TYPE,
            target_reference=setting_key,
            at=at,
        )
    except DatabaseError:
        # The source-owned fallback must remain available during bootstrap,
        # rollback, and health checks before the Governance table exists.
        policy = None
    if policy is None:
        return default
    config = policy.configuration_json or {}
    if config.get("setting_key") != setting_key or "value" not in config:
        return default
    value = config["value"]
    if isinstance(default, bool):
        return value if isinstance(value, bool) else default
    if isinstance(default, int) and not isinstance(default, bool):
        return value if isinstance(value, int) and not isinstance(value, bool) else default
    if isinstance(default, str):
        return value if isinstance(value, str) else default
    return value
