# Project: COMPASS
# File: apps/security/file_policies.py
# Module: apps.security
# Purpose: Protected file access policies and dynamic key delegation
# Domain boundary and service policy.

from apps.access_control.authority import has_fixed_capability
from apps.access_control.capabilities import Capability
from apps.security.exceptions import PolicyValidationError


# Global registry for access policy callbacks
_POLICY_REGISTRY = {}


def register_file_policy(policy_key: str, callback_fn):
    """
    Registers a policy function for a specific access_policy_key.
    The callback_fn signature must be: callback_fn(user, protected_file, action: str) -> bool
    """
    if not policy_key or not callable(callback_fn):
        raise PolicyValidationError("Invalid protected file policy registration.")
    _POLICY_REGISTRY[policy_key] = callback_fn


def unregister_file_policy(policy_key: str):
    """Unregisters a registered policy function."""
    if policy_key in _POLICY_REGISTRY:
        del _POLICY_REGISTRY[policy_key]


def default_policy_check(user, protected_file, action: str) -> bool:
    """
    Conservative default fallback policy.
    - Anonymous / Public: denied.
    - Student / Alumni: denied (requires workflow delegation).
    - GCO Staff: denied (requires workflow delegation).
    - Counselor: denied (requires workflow delegation).
    - Head Guidance: denied for content by default; requires workflow delegation.
    - IT Admin: allowed ONLY for metadata inspection (no content access).
    """
    if not user or not user.is_authenticated or not user.is_active:
        return False

    if has_fixed_capability(user, Capability.PROTECTED_FILES_METADATA_INSPECT):
        # Technical metadata inspection only
        return action in ("read_metadata", "inspect")

    # All other roles, including Head Guidance, fail closed under default policy.
    # Sensitive content access must come from an object/workflow-specific policy.
    return False


def verify_file_access(user, protected_file, action: str = "read_content") -> None:
    """
    Verifies if a user has permission to perform an action on a protected file.
    Raises PolicyValidationError if access is denied.
    """
    policy_key = protected_file.access_policy_key

    # Delegate to registered policy if available, otherwise fallback to default
    check_fn = _POLICY_REGISTRY.get(policy_key, default_policy_check)

    try:
        allowed = bool(check_fn(user, protected_file, action))
    except Exception:
        allowed = False

    if not allowed:
        raise PolicyValidationError(
            "Protected file access denied."
        )
