from apps.access_control.rules import (
    is_active_nonlegacy_actor,
    is_counselor,
    is_gco_staff,
    is_it_admin,
    is_student,
)
from apps.governance.runtime_config import resolve_runtime_setting


def is_student_two_factor_enabled(user) -> bool:
    """Return explicit student enrollment state; absent rows are disabled."""
    if not user or not getattr(user, "is_authenticated", False) or not is_student(user):
        return False
    from apps.account_security.models import StudentTwoFactorEnrollment

    return bool(
        StudentTwoFactorEnrollment.objects.filter(user=user, enabled=True).exists()
    )


def is_2fa_required_for_user(user) -> bool:
    """Determine if 2FA is required for the user based on their COMPASS role.

    Counselors, Head Guidance, GCO Staff, and IT Admins must satisfy the 2FA policy.
    Students have optional 2FA.
    """
    if not user or not user.is_authenticated:
        return False

    # Student enrollment is self-service state: once enabled, it must require
    # OTP regardless of the separate internal-staff enforcement switch.
    if is_student(user):
        return is_student_two_factor_enabled(user)

    if not resolve_runtime_setting(
        "security.account_security_controls",
        "ACCOUNT_SECURITY_ENFORCE_2FA_FOR_INTERNAL_USERS",
    ):
        return False

    if getattr(user, "is_superuser", False):
        return True

    # Check roles using COMPASS access control rules (business authority)
    if is_it_admin(user):
        return True
    if is_counselor(user):
        return True
    if is_gco_staff(user):
        return True

    return False


def is_internal_assurance_required(user) -> bool:
    """Require assurance for internal/root actors at the API boundary."""
    if not user or not user.is_authenticated:
        return False
    return is_2fa_required_for_user(user)


def get_trusted_device_duration_days(user) -> int:
    """Get the trusted device duration in days for a user based on their role.

    Returns 0 if trusted devices are disabled for the user's role.
    """
    if not user or not user.is_authenticated:
        return 0

    # IT Admins always complete OTP.  The legacy duration/disable controls
    # remain in the governed catalog for compatibility, but cannot enable a
    # remembered-device bypass for this role.
    if getattr(user, "is_superuser", False) or is_it_admin(user):
        return 0

    if is_counselor(user) or is_gco_staff(user):
        return resolve_runtime_setting(
            "security.account_security_controls",
            "ACCOUNT_SECURITY_TRUSTED_DEVICE_DAYS_STAFF",
        )

    if is_student(user):
        if not is_student_two_factor_enabled(user):
            return 0
        return resolve_runtime_setting(
            "security.account_security_controls",
            "ACCOUNT_SECURITY_TRUSTED_DEVICE_DAYS_STUDENT",
        )

    return 0


def can_user_recover_online(user) -> bool:
    """Determine if a user is allowed to perform self-service online account recovery.

    Internal users (IT Admin, Counselor, GCO Staff) require stronger verification
    or staff-assisted recovery.
    """
    if not user or not getattr(user, "is_active", False):
        return False
    if not is_student(user):
        return False
    from apps.account_security.email_evidence import has_verified_current_email
    return has_verified_current_email(user)


def can_start_staff_assisted_recovery(actor, target) -> bool:
    """Policy-only check for the assured IT Admin staff-recovery route.

    Head Guidance is a designation on a Counselor account, so it remains a
    valid staff-recovery target while retaining the same IT Admin-only
    authorization boundary as other internal staff.
    """
    from apps.access_control.authority import has_fixed_capability
    from apps.access_control.capabilities import Capability

    if not (
        is_active_nonlegacy_actor(actor)
        and is_it_admin(actor)
        and has_fixed_capability(actor, Capability.ACCOUNT_SECURITY_RECOVERY_ASSIST)
    ):
        return False
    if not is_active_nonlegacy_actor(target):
        return False
    if actor.pk == target.pk:
        return False
    return bool(is_counselor(target) or is_gco_staff(target))
