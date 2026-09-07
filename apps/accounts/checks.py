"""Readiness diagnostics for provisioned staff profiles."""

from django.core.checks import Warning, register

from apps.accounts.models import RoleChoices, User


@register()
def staff_profile_readiness(app_configs, **kwargs):
    warnings = []
    try:
        missing_counselors = User.objects.filter(
            is_active=True, role=RoleChoices.COUNSELOR, counselor_profile__isnull=True,
        ).count()
        missing_gco = User.objects.filter(
            is_active=True, role=RoleChoices.GCO_STAFF, staff_profile__isnull=True,
        ).count()
    except Exception:
        return warnings
    if missing_counselors:
        warnings.append(Warning(
            f"{missing_counselors} active counselor account(s) have no CounselorProfile.",
            id="accounts.W001",
        ))
    if missing_gco:
        warnings.append(Warning(
            f"{missing_gco} active GCO Staff account(s) have no GCOStaffProfile.",
            id="accounts.W002",
        ))
    return warnings
