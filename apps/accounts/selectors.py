"""Internal staff-account ORM selectors."""

from apps.accounts.models import RoleChoices, StaffAccountInvitation, User


def get_staff_accounts(*, role=None):
    qs = User.objects.filter(role__in=[RoleChoices.COUNSELOR, RoleChoices.GCO_STAFF, RoleChoices.IT_ADMIN]).select_related(
        "counselor_profile", "staff_profile",
    ).order_by("email")
    return qs.filter(role=role) if role else qs


def get_staff_account_by_id(user_id):
    return get_staff_accounts().filter(pk=user_id).first()


def get_pending_staff_invitation(user):
    return StaffAccountInvitation.objects.filter(
        user=user, used_at__isnull=True, revoked_at__isnull=True,
    ).order_by("-created_at").first()
