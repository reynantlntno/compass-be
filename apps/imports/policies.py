# Project: COMPASS
# File: apps/imports/policies.py
# Module: apps.imports
# Purpose: Policies for managing student imports and account provisioning
# Domain boundary and service policy.

from apps.access_control.authority import has_capability
from apps.access_control.capabilities import Capability
from apps.accounts.models import User


def can_manage_student_imports(user) -> bool:
    """Check if the user is authorized to manage student imports.

    Access is granted to:
    - Head Guidance counselors.
    - IT_ADMIN (for technical provisioning/import-job support only).
    Denied to regular counselors, GCO staff, and students.
    """
    if not user or not user.is_authenticated or not getattr(user, "is_active", False) or getattr(user, "is_superuser", False):
        return False

    # Head retains fixed governance authority; IT remains technical-only for
    # provisioning support; local preparation/review is individually granted.
    if has_capability(user, Capability.STUDENT_IMPORTS_APPROVE) or has_capability(
        user, Capability.STUDENT_IMPORTS_EXECUTE
    ):
        return True
    return has_capability(user, Capability.STUDENT_IMPORTS_PREPARE) or has_capability(
        user, Capability.STUDENT_IMPORTS_REVIEW
    )


def can_view_student_onboarding(user) -> bool:
    return can_manage_student_imports(user)


def can_edit_student_onboarding(user) -> bool:
    return bool(
        can_manage_student_imports(user)
        and has_capability(user, Capability.STUDENT_IMPORTS_PREPARE)
    )


def can_review_student_onboarding(user) -> bool:
    """Preparation/review workspace access, excluding technical execution-only actors."""
    if not can_manage_student_imports(user):
        return False
    return bool(
        has_capability(user, Capability.STUDENT_IMPORTS_PREPARE)
        or has_capability(user, Capability.STUDENT_IMPORTS_REVIEW)
        or has_capability(user, Capability.STUDENT_IMPORTS_APPROVE)
    )


def can_approve_student_onboarding(user) -> bool:
    return bool(can_manage_student_imports(user) and has_capability(user, Capability.STUDENT_IMPORTS_APPROVE))


def can_execute_student_onboarding(user, *, batch=None) -> bool:
    """Allow only fixed Head/IT execution after an unchanged approval."""
    if not can_manage_student_imports(user):
        return False
    if not has_capability(user, Capability.STUDENT_IMPORTS_EXECUTE) or batch is None:
        return False
    approver = User.objects.filter(pk=getattr(batch, "approved_by_id", None), is_active=True).first()
    return bool(
        getattr(batch, "status", "") == "APPROVED"
        and approver is not None
        and has_capability(approver, Capability.STUDENT_IMPORTS_APPROVE)
        and getattr(batch, "approved_digest", "")
        and not getattr(batch, "approval_revoked_at", None)
    )


def can_operate_activation_delivery(user) -> bool:
    return bool(
        can_manage_student_imports(user)
        and has_capability(user, Capability.STUDENT_IMPORTS_EXECUTE)
    )
