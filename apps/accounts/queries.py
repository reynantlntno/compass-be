"""Actor-aware staff-account reads for the administration adapter."""

from apps.accounts.policies import can_manage_staff_accounts, can_manage_head_guidance
from apps.accounts.projections import project_staff_account
from apps.accounts.selectors import get_pending_staff_invitation, get_staff_account_by_id, get_staff_accounts
from apps.accounts.models import RoleChoices
from apps.common.contracts import PageRequest


def staff_accounts_visible_to(actor):
    if not can_manage_staff_accounts(actor, RoleChoices.COUNSELOR):
        return []
    return [project_staff_account(user, get_pending_staff_invitation(user)) for user in get_staff_accounts()]


def staff_accounts_page_visible_to(actor, page: PageRequest):
    """Return one bounded staff-account page without materializing the list."""
    if not can_manage_staff_accounts(actor, RoleChoices.COUNSELOR):
        return {"items": [], "page": page.page, "page_size": page.page_size, "total": 0}
    queryset = get_staff_accounts()
    total = queryset.count()
    users = queryset[page.offset:page.offset + page.page_size]
    return {
        "items": [project_staff_account(user, get_pending_staff_invitation(user)) for user in users],
        "page": page.page,
        "page_size": page.page_size,
        "total": total,
    }


def staff_account_visible_to(actor, user_id):
    if not can_manage_staff_accounts(actor, RoleChoices.COUNSELOR):
        return None
    user = get_staff_account_by_id(user_id)
    return project_staff_account(user, get_pending_staff_invitation(user)) if user else None


def head_designation_visible_to(actor):
    if not can_manage_head_guidance(actor):
        return None
    from apps.profiles.models import CounselorProfile
    profile = CounselorProfile.objects.filter(is_head_guidance=True).select_related("user").first()
    from apps.accounts.projections import project_head_designation
    return project_head_designation(profile)
