"""Authorization gates for controlled staff-account lifecycle operations."""

from apps.access_control.authority import has_fixed_capability
from apps.access_control.capabilities import Capability
from apps.access_control.rules import is_active_nonlegacy_actor, is_head_guidance
from apps.accounts.models import RoleChoices


def can_manage_staff_accounts(actor, target_role=None) -> bool:
    """Only an active Head may provision regular staff accounts."""
    if target_role not in {RoleChoices.COUNSELOR, RoleChoices.GCO_STAFF}:
        return False
    return bool(
        is_active_nonlegacy_actor(actor)
        and is_head_guidance(actor)
        and has_fixed_capability(actor, Capability.STAFF_ACCOUNTS_MANAGE)
    )


def can_manage_head_guidance(actor, target=None) -> bool:
    """Gate designation changes; self-designation is never allowed."""
    if not (
        is_active_nonlegacy_actor(actor)
        and has_fixed_capability(actor, Capability.HEAD_GUIDANCE_DESIGNATION_MANAGE)
    ):
        return False
    return target is None or getattr(actor, "pk", None) != getattr(target, "pk", None)
