# Project: COMPASS
# File: apps/student_activation/policies.py
# Module: apps.student_activation
# Purpose: Policies for managing student activation invitations
# Domain boundary and service policy.

from apps.access_control.authority import has_capability
from apps.access_control.capabilities import Capability


def can_manage_activation_invitations(user) -> bool:
    """Authorize access to manage (generate/reissue) student activation tokens.

    Only IT Admins and Head Guidance counselors are permitted.
    """
    return bool(
        has_capability(user, Capability.STUDENT_ACTIVATION_INVITATIONS_MANAGE)
        or has_capability(user, Capability.STUDENT_ACTIVATION_DELIVERY_OPERATE)
        or has_capability(user, Capability.STUDENT_IMPORTS_EXECUTE)
    )
