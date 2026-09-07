from apps.access_control.authority import has_capability
from apps.access_control.capabilities import Capability


def can_view_workflow_metadata(user) -> bool:
    """Only IT Admin and Head Guidance are allowed to view idempotency or outbox metadata."""
    if not user or not user.is_authenticated or not user.is_active:
        return False
    return has_capability(user, Capability.WORKFLOW_METADATA_VIEW)
